//! On-screen highlight overlay via `zwlr_layer_shell_v1`
//! (wlr-layer-shell-unstable-v1) — in-process, no external binaries.
//!
//! Connects to `$WAYLAND_DISPLAY`, binds `wl_compositor` + `wl_shm` + the
//! layer shell, and draws a short-lived translucent rectangle on the
//! `overlay` layer. The surface gets an **empty input region** so clicks
//! pass straight through — the highlight is purely visual feedback and
//! never affects capture or input.
//!
//! Stateless like [`wlr_capture`](crate::providers::wlr_capture): every
//! `highlight` call opens a short-lived Wayland connection, which keeps
//! the provider `Send + Sync` without holding protocol objects across
//! awaits.

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use wayland_client::protocol::{
    wl_buffer::WlBuffer, wl_compositor::WlCompositor, wl_output, wl_region::WlRegion, wl_registry,
    wl_shm, wl_shm_pool::WlShmPool, wl_surface::WlSurface,
};
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, delegate_noop};
use wayland_protocols_wlr::layer_shell::v1::client::{
    zwlr_layer_shell_v1::{self, ZwlrLayerShellV1},
    zwlr_layer_surface_v1::{self, ZwlrLayerSurfaceV1},
};

use crate::traits::{OverlayProvider, Rect};

/// In-process wlr-layer-shell highlight backend.
///
/// Construction only probes: `WAYLAND_DISPLAY` must resolve and the
/// compositor must advertise `zwlr_layer_shell_v1`, `wl_compositor` and
/// `wl_shm`.
pub struct Overlay {
    _private: (),
}

impl Overlay {
    /// Probe the session for layer-shell support. Returns `None` on
    /// headless sessions and on compositors without
    /// `zwlr_layer_shell_v1` — `screen_highlight` then reports
    /// `ProviderUnavailable` rather than silently no-oping.
    pub fn new() -> Option<Self> {
        std::env::var_os("WAYLAND_DISPLAY")?;
        probe().ok()?;
        Some(Self { _private: () })
    }
}

/// Per-connection protocol state. Created fresh for every highlight/probe
/// so all dispatch happens synchronously inside one `EventQueue`.
#[derive(Default)]
struct State {
    compositor: Option<WlCompositor>,
    shm: Option<wl_shm::WlShm>,
    layer_shell: Option<ZwlrLayerShellV1>,
    outputs: Vec<wl_output::WlOutput>,
    output_info: Vec<OutputInfo>,

    // ---- layer surface state ----
    configured: bool,
    closed: bool,
}

#[derive(Clone, Default)]
struct OutputInfo {
    x: i32,
    y: i32,
    /// Current-mode pixel size; divided by `scale` for logical units.
    width: i32,
    height: i32,
    scale: i32,
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
                "wl_compositor" => {
                    state.compositor = Some(registry.bind(name, version.min(4), qh, ()));
                }
                "wl_shm" => {
                    state.shm = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "zwlr_layer_shell_v1" => {
                    // v4 covers everything used (shell destroy is since
                    // v3, keyboard-interactivity enum since v4).
                    state.layer_shell = Some(registry.bind(name, version.min(4), qh, ()));
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
            wl_output::Event::Geometry { x, y, .. } => {
                info.x = x;
                info.y = y;
            }
            wl_output::Event::Mode {
                flags,
                width,
                height,
                ..
            } => {
                let current = flags
                    .into_result()
                    .map(|f| f.contains(wl_output::Mode::Current))
                    .unwrap_or(false);
                if current || info.width == 0 {
                    info.width = width;
                    info.height = height;
                }
            }
            wl_output::Event::Scale { factor } => info.scale = factor,
            _ => {}
        }
    }
}

impl Dispatch<ZwlrLayerSurfaceV1, ()> for State {
    fn event(
        state: &mut Self,
        layer_surface: &ZwlrLayerSurfaceV1,
        event: zwlr_layer_surface_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            // `configure` MUST be acked before the next commit or the
            // compositor kills the client (wlr-layer-shell error
            // invalid_surface_state). The size it dictates is advisory
            // for our fixed-geometry use — we keep our own.
            zwlr_layer_surface_v1::Event::Configure { serial, .. } => {
                layer_surface.ack_configure(serial);
                state.configured = true;
            }
            zwlr_layer_surface_v1::Event::Closed => state.closed = true,
            _ => {}
        }
    }
}

// Event-emitting interfaces get explicit swallow-everything impls —
// `delegate_noop!` is not safe on objects that can receive events
// (wl_shm `format`, wl_surface `enter`/`leave`, wl_buffer `release`).
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

impl Dispatch<WlSurface, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlSurface,
        _: wayland_client::protocol::wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlBuffer,
        _: wayland_client::protocol::wl_buffer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

// Event-free interfaces only: compositor, region, shm pool, and the
// layer-shell manager itself emit nothing.
delegate_noop!(State: WlCompositor);
delegate_noop!(State: WlRegion);
delegate_noop!(State: WlShmPool);
delegate_noop!(State: ZwlrLayerShellV1);

// ---------------------------------------------------------------------------
// Blocking protocol plumbing
// ---------------------------------------------------------------------------

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

/// `new()` probe: globals only, no surface.
fn probe() -> Result<()> {
    let (_queue, state) = connect()?;
    if state.compositor.is_none() {
        bail!("wl_compositor not advertised");
    }
    if state.shm.is_none() {
        bail!("wl_shm not advertised");
    }
    if state.layer_shell.is_none() {
        bail!("zwlr_layer_shell_v1 not advertised");
    }
    Ok(())
}

/// Pick the `wl_output` whose logical rect contains `rect`'s centre and
/// return it with the top-left margin relative to that output. Falls
/// back to `None` (the compositor chooses) with the raw coordinates when
/// no output geometry matches — e.g. a compositor that never reports it.
fn pick_output(state: &State, rect: &Rect) -> (Option<wl_output::WlOutput>, i32, i32) {
    match pick_output_idx(&state.output_info, rect) {
        Some((i, mx, my)) => (Some(state.outputs[i].clone()), mx, my),
        None => (None, rect.x.max(0), rect.y.max(0)),
    }
}

/// Pure core of [`pick_output`]: index into `infos` of the output whose
/// logical rect (pixel size ÷ scale) contains `rect`'s centre, plus the
/// clamped top-left margin. `None` when no output matches.
fn pick_output_idx(infos: &[OutputInfo], rect: &Rect) -> Option<(usize, i32, i32)> {
    let cx = rect.x + rect.w / 2;
    let cy = rect.y + rect.h / 2;
    for (i, info) in infos.iter().enumerate() {
        let scale = info.scale.max(1);
        let w = info.width / scale;
        let h = info.height / scale;
        if w <= 0 || h <= 0 {
            continue;
        }
        if cx >= info.x && cx < info.x + w && cy >= info.y && cy < info.y + h {
            return Some((i, (rect.x - info.x).max(0), (rect.y - info.y).max(0)));
        }
    }
    None
}

/// Fill `buf` (w*h*4 bytes) with a translucent fill + opaque border in
/// premultiplied ARGB8888 — `wl_shm::Format::Argb8888` is mandatory in
/// every compositor and the byte order is little-endian 0xAARRGGBB.
fn paint_highlight(buf: &mut [u8], w: u32, h: u32) {
    /// rgba 0x3399ff66 — accent blue at ~40 % alpha.
    const FILL: (u8, u8, u8, u8) = (0x33, 0x99, 0xFF, 0x66);
    /// Same hue, fully opaque, for the edge.
    const EDGE: (u8, u8, u8, u8) = (0x33, 0x99, 0xFF, 0xFF);
    let fill = premul_argb(FILL).to_le_bytes();
    let edge = premul_argb(EDGE).to_le_bytes();
    // ~6 % of the short side as border, 1–6 px, never more than half
    // the rect (a 1×1 highlight is a solid edge pixel).
    let border = (w.min(h) / 16).clamp(1, 6).min(w.min(h).div_ceil(2));
    for y in 0..h {
        for x in 0..w {
            let px = if x < border || y < border || x >= w - border || y >= h - border {
                edge
            } else {
                fill
            };
            let i = ((y * w + x) * 4) as usize;
            buf[i..i + 4].copy_from_slice(&px);
        }
    }
}

/// (r, g, b, a) → premultiplied `0xAARRGGBB` (wl_shm ARGB8888 requires
/// premultiplied alpha).
fn premul_argb((r, g, b, a): (u8, u8, u8, u8)) -> u32 {
    let p = |c: u8| (u32::from(c) * u32::from(a) + 127) / 255;
    (u32::from(a) << 24) | (p(r) << 16) | (p(g) << 8) | p(b)
}

/// SHM buffer holding the painted highlight pixels.
fn make_highlight_buffer(
    shm: &wl_shm::WlShm,
    w: u32,
    h: u32,
    qh: &QueueHandle<State>,
) -> Result<(File, WlShmPool, WlBuffer)> {
    let stride = w * 4;
    let size = u64::from(stride) * u64::from(h);
    let mut file = tempfile::tempfile().context("create shm pool file")?;
    file.set_len(size).context("size shm pool file")?;
    let mut pixels = vec![0u8; size as usize];
    paint_highlight(&mut pixels, w, h);
    file.write_all(&pixels).context("paint shm pool")?;
    let pool = shm.create_pool(file.as_fd(), size as i32, qh, ());
    let buffer = pool.create_buffer(
        0,
        w as i32,
        h as i32,
        stride as i32,
        wl_shm::Format::Argb8888,
        qh,
        (),
    );
    Ok((file, pool, buffer))
}

/// Full synchronous highlight. Must run off the async executor
/// (`spawn_blocking`) since it performs blocking roundtrips and a
/// timed event-loop wait.
fn highlight_blocking(rect: Rect, duration_ms: u64) -> Result<()> {
    let (mut queue, mut state) = connect()?;
    let compositor = state
        .compositor
        .clone()
        .ok_or_else(|| anyhow!("wl_compositor unavailable"))?;
    let layer_shell = state
        .layer_shell
        .clone()
        .ok_or_else(|| anyhow!("zwlr_layer_shell_v1 unavailable"))?;
    let shm = state
        .shm
        .clone()
        .ok_or_else(|| anyhow!("wl_shm unavailable"))?;

    // Second roundtrip: wl_output geometry arrives after the binds above.
    queue
        .roundtrip(&mut state)
        .context("output geometry roundtrip")?;

    let qh = queue.handle();
    let (output, mx, my) = pick_output(&state, &rect);

    let surface = compositor.create_surface(&qh, ());
    // Empty input region → the overlay is click-through.
    let region = compositor.create_region(&qh, ());
    surface.set_input_region(Some(&region));

    let layer_surface = layer_shell.get_layer_surface(
        &surface,
        output.as_ref(),
        zwlr_layer_shell_v1::Layer::Overlay,
        "ultranix-highlight".to_string(),
        &qh,
        (),
    );
    layer_surface
        .set_anchor(zwlr_layer_surface_v1::Anchor::Top | zwlr_layer_surface_v1::Anchor::Left);
    layer_surface.set_margin(my, 0, 0, mx);
    // Defense in depth: the tool layer caps w/h at 16384; without it a
    // caller could force a w*h*4-byte SHM allocation (stride also
    // overflows u32 above w > 2³⁰).
    let w = rect.w.clamp(1, 16_384) as u32;
    let h = rect.h.clamp(1, 16_384) as u32;
    layer_surface.set_size(w, h);
    layer_surface.set_exclusive_zone(-1);
    layer_surface.set_keyboard_interactivity(zwlr_layer_surface_v1::KeyboardInteractivity::None);
    // Initial commit: the compositor must answer with `configure` before
    // the surface may attach a buffer.
    surface.commit();

    let configure_deadline = Instant::now() + Duration::from_secs(5);
    while !(state.configured || state.closed) && Instant::now() < configure_deadline {
        queue
            .roundtrip(&mut state)
            .context("layer-surface configure")?;
    }
    if state.closed {
        // Compositor dismissed the surface before first configure —
        // clean exit per the tool contract.
        return Ok(());
    }
    if !state.configured {
        bail!("layer surface timed out waiting for configure");
    }

    let (_file, _pool, buffer) = make_highlight_buffer(&shm, w, h, &qh)?;
    surface.attach(Some(&buffer), 0, 0);
    surface.damage(0, 0, w as i32, h as i32);
    surface.commit();
    queue.flush().context("flush overlay commit")?;

    // Hold the surface until `duration_ms` elapses or the compositor
    // closes it. Poll the socket with the remaining time as the timeout:
    // no sync-request spam, and the wait wakes early on `closed`.
    let show_until = Instant::now() + Duration::from_millis(duration_ms);
    while !state.closed {
        let remaining = show_until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        queue
            .dispatch_pending(&mut state)
            .context("dispatch pending overlay events")?;
        if state.closed {
            break;
        }
        let Some(guard) = queue.prepare_read() else {
            // Events already queued — loop dispatches them above.
            continue;
        };
        let fd = guard.connection_fd();
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: `pfd` is a live stack struct and the fd borrows from
        // the connection, which outlives this poll.
        let n = unsafe { libc::poll(&mut pfd, 1, timeout) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            guard.read().context("read wayland events")?;
        } else if n > 0 && pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            bail!("wayland socket closed mid-highlight");
        }
        // n == 0 → this poll slice timed out; the loop head re-checks
        // the deadline. Dropping the guard cancels the read prep.
    }

    // Orderly teardown; dropping the connection reaps anything left.
    buffer.destroy();
    layer_surface.destroy();
    surface.destroy();
    region.destroy();
    if layer_shell.version() >= 3 {
        layer_shell.destroy();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OverlayProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl OverlayProvider for Overlay {
    async fn highlight(&self, rect: Rect, duration_ms: u64) -> Result<()> {
        tokio::task::spawn_blocking(move || highlight_blocking(rect, duration_ms))
            .await
            .context("layer-shell overlay task")?
    }
}

// ---------------------------------------------------------------------------
// Tests — paint math and the probe only. `highlight_blocking` never runs
// in automated tests; the live smoke test is opt-in.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn premul_argb_multiplies_channels() {
        // Opaque pixels pass through unchanged.
        assert_eq!(premul_argb((0x33, 0x99, 0xFF, 0xFF)), 0xFF3399FF);
        // Fully transparent collapses to zero.
        assert_eq!(premul_argb((0xFF, 0xFF, 0xFF, 0x00)), 0);
        // Alpha is preserved verbatim in the high byte.
        assert_eq!(premul_argb((0x33, 0x99, 0xFF, 0x66)) >> 24, 0x66);
        // Premultiplied blue channel: 0xFF * 0x66/255 ≈ 0x66.
        assert_eq!(premul_argb((0x33, 0x99, 0xFF, 0x66)) & 0xFF, 0x66);
    }

    #[test]
    fn paint_highlight_draws_edge_and_fill() {
        let (w, h) = (32u32, 24u32);
        let mut buf = vec![0u8; (w * h * 4) as usize];
        paint_highlight(&mut buf, w, h);
        let px = |x: u32, y: u32| -> u32 {
            let i = ((y * w + x) * 4) as usize;
            u32::from_le_bytes(buf[i..i + 4].try_into().unwrap())
        };
        // Corner + mid-edge: opaque border.
        assert_eq!(px(0, 0) >> 24, 0xFF);
        assert_eq!(px(w / 2, 0) >> 24, 0xFF);
        // Centre: translucent fill.
        assert_eq!(px(w / 2, h / 2) >> 24, 0x66);
        // Fill keeps the accent hue ordering (b > g > r).
        let c = px(w / 2, h / 2);
        assert!((c & 0xFF) > ((c >> 8) & 0xFF) && ((c >> 8) & 0xFF) > ((c >> 16) & 0xFF));
    }

    #[test]
    fn paint_highlight_tiny_rect_is_all_edge() {
        let mut buf = vec![0u8; 4];
        paint_highlight(&mut buf, 1, 1);
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()) >> 24, 0xFF);
    }

    // ---- output selection (pure geometry over OutputInfo) -------------

    fn out(x: i32, y: i32, width: i32, height: i32, scale: i32) -> OutputInfo {
        OutputInfo {
            x,
            y,
            width,
            height,
            scale,
        }
    }

    #[test]
    fn pick_output_idx_finds_containing_output() {
        let infos = vec![out(0, 0, 1920, 1080, 1), out(1920, 0, 2560, 1440, 1)];
        // Rect centred on the second output → index 1, margin relative
        // to that output's origin.
        let r = Rect {
            x: 2000,
            y: 100,
            w: 200,
            h: 100,
        };
        assert_eq!(pick_output_idx(&infos, &r), Some((1, 80, 100)));
        // First output.
        let r = Rect {
            x: 10,
            y: 10,
            w: 20,
            h: 20,
        };
        assert_eq!(pick_output_idx(&infos, &r), Some((0, 10, 10)));
    }

    #[test]
    fn pick_output_idx_applies_scale_to_logical_size() {
        // A 3840x2160 output at scale 2 occupies 1920x1080 logical units.
        let infos = vec![out(0, 0, 3840, 2160, 2)];
        let inside = Rect {
            x: 1000,
            y: 500,
            w: 10,
            h: 10,
        };
        assert_eq!(pick_output_idx(&infos, &inside), Some((0, 1000, 500)));
        // Centre beyond the logical extent → no output.
        let outside = Rect {
            x: 2000,
            y: 500,
            w: 10,
            h: 10,
        };
        assert_eq!(pick_output_idx(&infos, &outside), None);
        // A bogus scale ≤ 0 is treated as 1 rather than dividing by zero.
        let infos = vec![out(0, 0, 100, 100, 0)];
        let r = Rect {
            x: 50,
            y: 50,
            w: 4,
            h: 4,
        };
        assert_eq!(pick_output_idx(&infos, &r), Some((0, 50, 50)));
    }

    #[test]
    fn pick_output_idx_skips_degenerate_and_misses() {
        // An output that never reported a mode (0x0) cannot contain a
        // point — the later real output still wins.
        let infos = vec![out(0, 0, 0, 0, 1), out(500, 0, 800, 600, 1)];
        let r = Rect {
            x: 600,
            y: 10,
            w: 10,
            h: 10,
        };
        assert_eq!(pick_output_idx(&infos, &r), Some((1, 100, 10)));

        // Centre outside every output → compositor chooses (None).
        let infos = vec![out(0, 0, 100, 100, 1)];
        let r = Rect {
            x: -200,
            y: -200,
            w: 10,
            h: 10,
        };
        assert_eq!(pick_output_idx(&infos, &r), None);
        assert!(pick_output_idx(&[], &r).is_none());
    }

    #[test]
    fn pick_output_idx_clamps_negative_margins() {
        // Rect straddling the left/top edge of its containing output:
        // the top-left margin is clamped to 0, never negative.
        let infos = vec![out(100, 100, 800, 600, 1)];
        let r = Rect {
            x: 50,
            y: 50,
            w: 200,
            h: 200,
        };
        // centre = (150,150) inside the output; raw margins -50 → 0.
        assert_eq!(pick_output_idx(&infos, &r), Some((0, 0, 0)));
    }

    /// Probe-only: `new()` must report `None` when there is no Wayland
    /// session, and must never panic.
    #[test]
    fn new_is_none_without_wayland_display() {
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            assert!(Overlay::new().is_none());
        }
    }

    /// Live compositor smoke test — opt-in via
    /// `ULTRANIX_MCP_LIVE_TESTS`, never part of `cargo test` runs.
    #[test]
    #[ignore = "requires a live wlr-layer-shell compositor"]
    fn live_highlight_smoke() {
        if std::env::var_os("ULTRANIX_MCP_LIVE_TESTS").is_none() {
            return;
        }
        let Some(_o) = Overlay::new() else {
            return; // no layer-shell compositor in this env
        };
        highlight_blocking(
            Rect {
                x: 40,
                y: 40,
                w: 200,
                h: 100,
            },
            300,
        )
        .unwrap();
    }
}
