//! Wayland-native screen capture via `zwlr_screencopy_manager_v1`
//! (wlr-screencopy-unstable-v1) - in-process, no external binaries.
//!
//! Connects to `$WAYLAND_DISPLAY`, binds `wl_shm` + the screencopy manager,
//! copies the first `wl_output` (or a region of it) into a SHM pool backed by
//! an anonymous temp file, then converts the frame to PNG via `image`.
//!
//! `cursor_position`/`screen_info` prefer `hyprctl` (live on Hyprland) and
//! degrade to `wl_output` geometry when it is absent. The binary is the
//! canonicalized path pinned at construction via
//! [`crate::security::whitelist`] and spawned under the scrubbed
//! environment + timeout of [`crate::security::spawn`].

use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::AsFd;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};
use wayland_client::protocol::{
    wl_buffer::WlBuffer, wl_output, wl_registry, wl_shm, wl_shm_pool::WlShmPool,
};
use wayland_client::{Connection, Dispatch, QueueHandle, delegate_noop};
use wayland_protocols_wlr::screencopy::v1::client::{
    zwlr_screencopy_frame_v1::{self, ZwlrScreencopyFrameV1},
    zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1,
};

use crate::traits::{CaptureProvider, Frame, Rect};

use super::common::{OutputInfo, hyprctl_cursorpos, hyprctl_monitors};

/// In-process wlr-screencopy capture backend.
///
/// Stateless: every call opens a short-lived Wayland connection, which keeps
/// the provider `Send + Sync` without holding protocol objects across awaits.
pub struct WlrCapture {
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction - `cursor_position`/`screen_info` helpers (S-1).
    hyprctl: Option<std::path::PathBuf>,
}

impl WlrCapture {
    /// Probe the session: `WAYLAND_DISPLAY` must resolve and the compositor
    /// must advertise `zwlr_screencopy_manager_v1`, `wl_shm` and an output.
    pub fn new() -> Option<Self> {
        std::env::var_os("WAYLAND_DISPLAY")?;
        probe().ok()?;
        Some(Self {
            hyprctl: crate::security::whitelist::resolve_binaries()
                .get("hyprctl")
                .map(std::path::Path::to_path_buf),
        })
    }
}

/// Per-connection protocol state. Created fresh for every capture/probe so
/// all dispatch happens synchronously inside one `EventQueue`.
#[derive(Default)]
struct State {
    shm: Option<wl_shm::WlShm>,
    screencopy: Option<ZwlrScreencopyManagerV1>,
    outputs: Vec<wl_output::WlOutput>,
    output_info: Vec<OutputInfo>,

    // ---- screencopy frame state ----
    pending: Option<PendingBuf>,
    copy_sent: bool,
    y_invert: bool,
    ready: bool,
    failed: Option<String>,
    buf_meta: Option<BufMeta>,
    pool_file: Option<File>,
    // Keep the pool + buffer alive until the frame completes.
    _pool: Option<WlShmPool>,
    _buffer: Option<WlBuffer>,
}

/// A `buffer` event we can actually serve (wl_shm 8888 formats only).
struct PendingBuf {
    format: wl_shm::Format,
    width: u32,
    height: u32,
    stride: u32,
}

#[derive(Clone, Copy)]
struct BufMeta {
    format: wl_shm::Format,
    width: u32,
    height: u32,
    stride: u32,
}

// ---------------------------------------------------------------------------
// Dispatch impls
// ---------------------------------------------------------------------------

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match interface.as_str() {
                "wl_shm" => {
                    state.shm = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "zwlr_screencopy_manager_v1" => {
                    state.screencopy = Some(registry.bind(name, version.min(3), qh, ()));
                }
                "wl_output" => {
                    let idx = state.output_info.len();
                    let out: wl_output::WlOutput = registry.bind(name, version.min(4), qh, idx);
                    state.outputs.push(out);
                    state.output_info.push(OutputInfo {
                        scale: 1,
                        ..OutputInfo::default()
                    });
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_output::WlOutput, usize> for State {
    fn event(
        state: &mut Self,
        _: &wl_output::WlOutput,
        event: wl_output::Event,
        idx: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(info) = state.output_info.get_mut(*idx) else {
            return;
        };
        match event {
            wl_output::Event::Geometry {
                x, y, make, model, ..
            } => {
                info.x = x;
                info.y = y;
                info.make = make;
                info.model = model;
            }
            wl_output::Event::Mode {
                flags,
                width,
                height,
                refresh,
            } => {
                let current = flags
                    .into_result()
                    .map(|f| f.contains(wl_output::Mode::Current))
                    .unwrap_or(false);
                if current || info.width == 0 {
                    info.width = width;
                    info.height = height;
                    info.refresh_millihz = refresh;
                }
            }
            wl_output::Event::Scale { factor } => info.scale = factor,
            wl_output::Event::Name { name } => info.name = name,
            _ => {}
        }
    }
}

impl Dispatch<ZwlrScreencopyFrameV1, ()> for State {
    fn event(
        state: &mut Self,
        frame: &ZwlrScreencopyFrameV1,
        event: zwlr_screencopy_frame_v1::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        use zwlr_screencopy_frame_v1::Event;
        match event {
            Event::Buffer {
                format,
                width,
                height,
                stride,
            } => {
                if state.pending.is_some() {
                    return; // first usable format wins
                }
                if let Ok(fmt) = format.into_result()
                    && shm_format_supported(fmt)
                {
                    state.pending = Some(PendingBuf {
                        format: fmt,
                        width,
                        height,
                        stride,
                    });
                }
            }
            Event::Flags { flags } => {
                if let Ok(f) = flags.into_result() {
                    state.y_invert = f.contains(zwlr_screencopy_frame_v1::Flags::YInvert);
                }
            }
            Event::BufferDone => {
                if state.copy_sent {
                    return;
                }
                let Some(pending) = state.pending.take() else {
                    state.failed = Some("compositor offered no usable wl_shm format".into());
                    return;
                };
                let Some(shm) = state.shm.clone() else {
                    state.failed = Some("wl_shm lost before buffer_done".into());
                    return;
                };
                match make_shm_buffer(&shm, &pending, qh) {
                    Ok((file, pool, buffer)) => {
                        state.buf_meta = Some(BufMeta {
                            format: pending.format,
                            width: pending.width,
                            height: pending.height,
                            stride: pending.stride,
                        });
                        state.pool_file = Some(file);
                        state._pool = Some(pool);
                        frame.copy(&buffer);
                        state._buffer = Some(buffer);
                        state.copy_sent = true;
                    }
                    Err(e) => state.failed = Some(format!("shm pool: {e:#}")),
                }
            }
            Event::Ready { .. } => state.ready = true,
            Event::Failed => {
                state.failed = Some("compositor reported frame failure".into());
            }
            _ => {}
        }
    }
}

// `wl_shm` emits `format` events after bind - `delegate_noop!` would
// panic on them; give it an explicit swallow-everything impl.
impl Dispatch<wl_shm::WlShm, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_shm::WlShm,
        _: wl_shm::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: WlShmPool);
delegate_noop!(State: WlBuffer);
delegate_noop!(State: ZwlrScreencopyManagerV1);

// ---------------------------------------------------------------------------
// Blocking protocol plumbing
// ---------------------------------------------------------------------------

/// Allocate an anonymous (unlinked) temp file as the SHM pool backing store.
fn make_shm_buffer(
    shm: &wl_shm::WlShm,
    p: &PendingBuf,
    qh: &QueueHandle<State>,
) -> Result<(File, WlShmPool, WlBuffer)> {
    let size = u64::from(p.stride) * u64::from(p.height);
    let file = tempfile::tempfile().context("create shm pool file")?;
    file.set_len(size).context("size shm pool file")?;
    let pool = shm.create_pool(file.as_fd(), size as i32, qh, ());
    let buffer = pool.create_buffer(
        0,
        p.width as i32,
        p.height as i32,
        p.stride as i32,
        p.format,
        qh,
        (),
    );
    Ok((file, pool, buffer))
}

/// Connect and perform the initial registry roundtrip.
fn connect() -> Result<(wayland_client::EventQueue<State>, State)> {
    let conn = Connection::connect_to_env().context("connect to WAYLAND_DISPLAY")?;
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let mut state = State::default();
    conn.display().get_registry(&qh, ());
    queue.roundtrip(&mut state).context("registry roundtrip")?;
    Ok((queue, state))
}

/// `new()` probe: globals only, no frame copy.
fn probe() -> Result<()> {
    let (_queue, state) = connect()?;
    if state.shm.is_none() {
        bail!("wl_shm not advertised");
    }
    if state.screencopy.is_none() {
        bail!("zwlr_screencopy_manager_v1 not advertised");
    }
    if state.outputs.is_empty() {
        bail!("no wl_output advertised");
    }
    Ok(())
}

/// Full synchronous capture. Must run off the async executor
/// (`spawn_blocking`) since it performs blocking roundtrips.
fn capture_blocking(region: Option<Rect>) -> Result<Frame> {
    let (mut queue, mut state) = connect()?;

    let mgr = state
        .screencopy
        .clone()
        .ok_or_else(|| anyhow!("zwlr_screencopy_manager_v1 unavailable"))?;
    if state.shm.is_none() {
        bail!("wl_shm unavailable");
    }
    let output = state
        .outputs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("compositor advertised no wl_output"))?;

    let frame = match region {
        Some(r) => mgr.capture_output_region(0, &output, r.x, r.y, r.w, r.h, &queue.handle(), ()),
        None => mgr.capture_output(0, &output, &queue.handle(), ()),
    };

    // Pump events until `ready`/`failed` or a 5 s deadline. Each roundtrip
    // is bounded by the compositor's sync reply, but the copy itself is
    // asynchronous - `ready` arrives when the GPU work completes, often
    // several display frames later, so a fixed roundtrip count races it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !(state.ready || state.failed.is_some()) {
        if std::time::Instant::now() >= deadline {
            break;
        }
        queue
            .roundtrip(&mut state)
            .context("screencopy roundtrip")?;
        if !(state.ready || state.failed.is_some()) {
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
    }
    frame.destroy();
    mgr.destroy();

    if let Some(err) = state.failed.take() {
        bail!("wlr-screencopy failed: {err}");
    }
    if !state.ready {
        bail!("wlr-screencopy timed out waiting for ready");
    }

    let meta = state
        .buf_meta
        .ok_or_else(|| anyhow!("frame ready without buffer metadata"))?;
    let mut file = state
        .pool_file
        .take()
        .ok_or_else(|| anyhow!("frame ready without shm pool file"))?;
    file.rewind().ok();
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).context("read shm pool")?;

    let rgba = shm_to_rgba(
        &raw,
        meta.format,
        meta.width,
        meta.height,
        meta.stride,
        state.y_invert,
    );
    let png = encode_png(&rgba, meta.width, meta.height)?;
    Ok(Frame {
        png,
        width: meta.width,
        height: meta.height,
    })
}

/// wl_output inventory as JSON - fallback for `screen_info` when `hyprctl`
/// is absent (non-Hyprland wlroots compositors).
fn screen_info_blocking() -> Result<Value> {
    let (_queue, state) = connect()?;
    let outputs: Vec<Value> = state
        .output_info
        .iter()
        .map(|o| {
            json!({
                "name": o.name,
                "make": o.make,
                "model": o.model,
                "x": o.x,
                "y": o.y,
                "width": o.width,
                "height": o.height,
                "refreshMillihz": o.refresh_millihz,
                "scale": o.scale,
            })
        })
        .collect();
    Ok(json!({ "backend": "wlr-screencopy", "outputs": outputs }))
}

// ---------------------------------------------------------------------------
// Pixel conversion + PNG
// ---------------------------------------------------------------------------

/// wl_shm formats [`shm_to_rgba`] can decode - the four 32-bit 8888
/// layouts only; anything else the compositor offers is declined so the
/// `buffer` event loop keeps looking for a usable one.
pub(crate) fn shm_format_supported(fmt: wl_shm::Format) -> bool {
    matches!(
        fmt,
        wl_shm::Format::Xrgb8888
            | wl_shm::Format::Argb8888
            | wl_shm::Format::Xbgr8888
            | wl_shm::Format::Abgr8888
    )
}

/// Unpack a wl_shm 8888 frame into tightly-packed RGBA8888.
/// XRGB/ARGB arrive in memory as B,G,R,X (little-endian); XBGR/ABGR as R,G,B,X.
pub(crate) fn shm_to_rgba(
    raw: &[u8],
    format: wl_shm::Format,
    width: u32,
    height: u32,
    stride: u32,
    y_invert: bool,
) -> Vec<u8> {
    let mut out = vec![0u8; (width * height * 4) as usize];
    let w = width as usize;
    for y in 0..height {
        let src_y = if y_invert { height - 1 - y } else { y };
        let src_start = (src_y * stride) as usize;
        let src_end = src_start + w * 4;
        if src_end > raw.len() {
            break;
        }
        let src = &raw[src_start..src_end];
        let dst = &mut out[(y as usize) * w * 4..(y as usize + 1) * w * 4];
        for px in 0..w {
            let (b0, b1, b2) = (src[px * 4], src[px * 4 + 1], src[px * 4 + 2]);
            let (r, g, b) = match format {
                wl_shm::Format::Xbgr8888 | wl_shm::Format::Abgr8888 => (b0, b1, b2),
                _ => (b2, b1, b0),
            };
            dst[px * 4] = r;
            dst[px * 4 + 1] = g;
            dst[px * 4 + 2] = b;
            dst[px * 4 + 3] = 0xFF;
        }
    }
    out
}

pub(crate) fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    use image::ImageEncoder;
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(rgba, width, height, image::ExtendedColorType::Rgba8)
        .context("PNG encode")?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// CaptureProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl CaptureProvider for WlrCapture {
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame> {
        tokio::task::spawn_blocking(move || capture_blocking(region))
            .await
            .context("screencopy task")?
    }

    async fn cursor_position(&self) -> Result<(i32, i32)> {
        match &self.hyprctl {
            Some(bin) => hyprctl_cursorpos(bin).await,
            None => Err(anyhow!("hyprctl unavailable (not pinned at startup)")),
        }
    }

    /// `WlrCapture::new` already probed a live Wayland session, so a
    /// damage-driven stream session is always worth attempting here -
    /// `open` still degrades to `None` (then per-tick polling) on
    /// compositors advertising neither capture protocol.
    fn stream_sessions_supported(&self) -> bool {
        true
    }

    /// Damage-driven session for `screen_stream` - ext-image-copy-capture
    /// when advertised, else wlr-screencopy `copy_with_damage`.
    fn stream_capture(&self) -> Option<Box<dyn crate::traits::StreamCapture>> {
        super::wlr_stream::open().ok()
    }

    /// A live Wayland connection was already proven at construction, so
    /// a window-scoped session is worth attempting - `open_window`
    /// reports honestly when the ext protocol trio is not advertised.
    fn window_stream_supported(&self) -> bool {
        true
    }

    /// Per-window session via `ext_foreign_toplevel_image_capture_source_manager_v1`.
    fn stream_capture_window(
        &self,
        window_id: &str,
    ) -> Result<Box<dyn crate::traits::StreamCapture>> {
        super::wlr_stream::open_window(window_id)
    }

    /// Single frame of one toplevel window for `screenshot {window}`.
    async fn capture_window(&self, window_id: &str) -> Result<Frame> {
        let id = window_id.to_string();
        tokio::task::spawn_blocking(move || super::wlr_stream::capture_window_frame(&id))
            .await
            .context("window capture task")?
    }

    async fn screen_info(&self) -> Result<Value> {
        if let Some(bin) = &self.hyprctl
            && let Ok(v) = hyprctl_monitors(bin).await
        {
            return Ok(v);
        }
        tokio::task::spawn_blocking(screen_info_blocking)
            .await
            .context("screen_info task")?
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_png_produces_decodable_png() {
        // 2x2: red, green, blue, yellow.
        let rgba = [
            255, 0, 0, 255, //
            0, 255, 0, 255, //
            0, 0, 255, 255, //
            255, 255, 0, 255,
        ];
        let png = encode_png(&rgba, 2, 2).unwrap();
        assert_eq!(&png[..4], b"\x89PNG");
        let img = image::load_from_memory(&png).unwrap();
        assert_eq!((img.width(), img.height()), (2, 2));
    }

    #[test]
    fn shm_xrgb8888_unpacks_bgrx_to_rgba() {
        // One XRGB8888 pixel in memory order: B=0x20, G=0x40, R=0x60, X pad.
        let raw = [0x20, 0x40, 0x60, 0x00];
        let rgba = shm_to_rgba(&raw, wl_shm::Format::Xrgb8888, 1, 1, 4, false);
        assert_eq!(rgba, vec![0x60, 0x40, 0x20, 0xFF]);
    }

    #[test]
    fn shm_xbgr8888_unpacks_rgbx_to_rgba() {
        // One XBGR8888 pixel in memory order: R=0x60, G=0x40, B=0x20, X pad.
        let raw = [0x60, 0x40, 0x20, 0x00];
        let rgba = shm_to_rgba(&raw, wl_shm::Format::Xbgr8888, 1, 1, 4, false);
        assert_eq!(rgba, vec![0x60, 0x40, 0x20, 0xFF]);
    }

    #[test]
    fn shm_yinvert_flips_rows() {
        // 1x2 XRGB8888: top = red(0,0,0xFF), bottom = blue(0xFF,0,0) in BGRX.
        let raw = [
            0x00, 0x00, 0xFF, 0x00, // row0: red
            0xFF, 0x00, 0x00, 0x00, // row1: blue
        ];
        let rgba = shm_to_rgba(&raw, wl_shm::Format::Xrgb8888, 1, 2, 4, true);
        assert_eq!(&rgba[..4], &[0x00, 0x00, 0xFF, 0xFF]); // blue first
        assert_eq!(&rgba[4..], &[0xFF, 0x00, 0x00, 0xFF]); // red second
    }

    #[test]
    fn shm_stride_padding_is_skipped() {
        // 1px wide, stride 8 (4 bytes padding).
        let raw = [0x10, 0x20, 0x30, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let rgba = shm_to_rgba(&raw, wl_shm::Format::Xrgb8888, 1, 1, 8, false);
        assert_eq!(rgba, vec![0x30, 0x20, 0x10, 0xFF]);
    }

    #[test]
    fn shm_alpha_variants_match_their_companions() {
        // ARGB8888 unpacks identically to XRGB8888 (alpha byte is
        // discarded, output alpha forced opaque).
        let bgrx = [0x20, 0x40, 0x60, 0x00];
        assert_eq!(
            shm_to_rgba(&bgrx, wl_shm::Format::Argb8888, 1, 1, 4, false),
            vec![0x60, 0x40, 0x20, 0xFF]
        );
        // ABGR8888 unpacks identically to XBGR8888.
        let rgbx = [0x60, 0x40, 0x20, 0x00];
        assert_eq!(
            shm_to_rgba(&rgbx, wl_shm::Format::Abgr8888, 1, 1, 4, false),
            vec![0x60, 0x40, 0x20, 0xFF]
        );
    }

    #[test]
    fn shm_short_buffer_leaves_tail_zeroed() {
        // Declared 2x2 but the buffer ends after one row - the row loop
        // breaks instead of reading out of bounds; unwritten rows stay 0.
        let raw = [0x20, 0x40, 0x60, 0x00, 0x21, 0x41, 0x61, 0x00];
        let rgba = shm_to_rgba(&raw, wl_shm::Format::Xrgb8888, 2, 2, 8, false);
        assert_eq!(
            rgba,
            vec![
                0x60, 0x40, 0x20, 0xFF, 0x61, 0x41, 0x21, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn shm_format_supported_accepts_only_8888() {
        use wl_shm::Format;
        assert!(shm_format_supported(Format::Xrgb8888));
        assert!(shm_format_supported(Format::Argb8888));
        assert!(shm_format_supported(Format::Xbgr8888));
        assert!(shm_format_supported(Format::Abgr8888));
        // 16-bit and palette formats must be declined - `shm_to_rgba`
        // assumes 4 bytes per pixel.
        assert!(!shm_format_supported(Format::Rgb565));
        assert!(!shm_format_supported(Format::C8));
        assert!(!shm_format_supported(Format::Nv12));
    }

    #[test]
    fn parse_cursorpos_json_and_pair() {
        use crate::providers::common::parse_cursorpos;
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("  -12,3 \n"), Some((-12, 3)));
        assert_eq!(parse_cursorpos("garbage"), None);
        assert_eq!(parse_cursorpos("{}"), None);
    }

    #[test]
    #[ignore = "requires a live wlr-screencopy compositor"]
    fn live_capture_produces_real_png() {
        if WlrCapture::new().is_none() {
            eprintln!("no wayland session; skipping");
            return;
        }
        let frame = capture_blocking(None).unwrap();
        assert_eq!(&frame.png[..4], b"\x89PNG");
        assert!(frame.width > 0 && frame.height > 0);
        let img = image::load_from_memory(&frame.png).unwrap();
        assert_eq!((img.width(), img.height()), (frame.width, frame.height));
    }

    #[test]
    fn new_returns_none_without_wayland_display() {
        // Temporarily clear WAYLAND_DISPLAY; restore after (other tests or
        // the host session may legitimately have it set).
        let saved = std::env::var_os("WAYLAND_DISPLAY");
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        assert!(WlrCapture::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("WAYLAND_DISPLAY", v) };
        }
    }
}
