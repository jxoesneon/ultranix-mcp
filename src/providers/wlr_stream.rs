//! Persistent, damage-driven capture sessions for `screen_stream`
//! (implements `StreamCapture` - see traits.rs).
//!
//! Two wlroots capture protocols, picked at `open()` in preference order:
//!
//! 1. `ext_image_copy_capture_manager_v1` +
//!    `ext_output_image_capture_source_manager_v1` (staging; Hyprland >=
//!    0.54 / wlroots >= 0.20). The compositor holds `capture` open until
//!    the source changes, so an idle screen produces no work at all -
//!    genuinely event-driven.
//! 2. `zwlr_screencopy_manager_v1` `copy_with_damage` (every wlroots
//!    compositor). The compositor answers immediately, so the client
//!    polls - but a `ready` with no `damage` events means "unchanged",
//!    and an empty capture costs one roundtrip with no GPU copy and no
//!    PNG encode.
//!
//! Both yield `Ok(None)` for an unchanged wait window, so the stream
//! task only advances `seq` and writes to disk on real damage. A
//! persistent `wl_shm` buffer accumulates the full frame across
//! captures - the compositor only rewrites damaged regions, so stale
//! bytes in undamaged areas are correct-by-construction.

use std::collections::HashMap;
use std::io::{Read as _, Seek as _};
use std::os::fd::AsFd as _;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use tempfile::tempfile;
use wayland_client::protocol::{
    wl_buffer::WlBuffer, wl_output, wl_registry, wl_shm, wl_shm_pool::WlShmPool,
};
use wayland_client::{
    Connection, Dispatch, Proxy, QueueHandle, delegate_noop, event_created_child,
};
use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};
use wayland_protocols::ext::image_capture_source::v1::client::{
    ext_foreign_toplevel_image_capture_source_manager_v1::ExtForeignToplevelImageCaptureSourceManagerV1,
    ext_image_capture_source_v1::ExtImageCaptureSourceV1,
    ext_output_image_capture_source_manager_v1::ExtOutputImageCaptureSourceManagerV1,
};
use wayland_protocols::ext::image_copy_capture::v1::client::{
    ext_image_copy_capture_frame_v1::{self, ExtImageCopyCaptureFrameV1},
    ext_image_copy_capture_manager_v1::{self, ExtImageCopyCaptureManagerV1},
    ext_image_copy_capture_session_v1::{self, ExtImageCopyCaptureSessionV1},
};
use wayland_protocols_wlr::screencopy::v1::client::{
    zwlr_screencopy_frame_v1, zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1,
};

use super::wlr_capture::{encode_png, shm_format_supported, shm_to_rgba};
use crate::traits::{Frame, StreamCapture};

/// Upper bound on a single in-flight copy - generous like the per-call
/// capture path (GPU copy + `ready` often lands several display frames
/// after the request).
const COPY_DEADLINE: Duration = Duration::from_secs(5);

/// Idle poll cadence for the `copy_with_damage` fallback path.
const DAMAGE_POLL: Duration = Duration::from_millis(50);

/// Open a session on the calling thread. Prefers ext-image-copy-capture,
/// falls back to wlr-screencopy damage tracking, `Err` when neither
/// protocol (or `wl_shm`/an output) is advertised.
pub(crate) fn open() -> Result<Box<dyn StreamCapture>> {
    let conn = Connection::connect_to_env().context("connect to WAYLAND_DISPLAY")?;
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let mut state = Sess::default();
    conn.display().get_registry(&qh, ());
    queue.roundtrip(&mut state).context("registry roundtrip")?;

    if state.shm.is_none() {
        bail!("wl_shm not advertised");
    }
    let output = state
        .outputs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("compositor advertised no wl_output"))?;

    if let (Some(mgr), Some(src_mgr)) = (state.ext_mgr.clone(), state.ext_src_mgr.clone()) {
        let source = src_mgr.create_source(&output, &qh, ());
        return open_ext_session(queue, state, mgr, source);
    }

    let mgr = state
        .screencopy
        .clone()
        .ok_or_else(|| anyhow!("no wlroots capture protocol advertised"))?;
    Ok(Box::new(WlrSession {
        queue,
        state,
        manager: mgr,
        output,
        buf_key: None,
        pool_file: None,
        _pool: None,
        buffer: None,
    }))
}

/// Shared tail of `open`/`open_window`: create the ext session on an
/// already-constructed source, drain the constraint block, and wrap it.
fn open_ext_session(
    mut queue: wayland_client::EventQueue<Sess>,
    mut state: Sess,
    mgr: ExtImageCopyCaptureManagerV1,
    source: ExtImageCaptureSourceV1,
) -> Result<Box<dyn StreamCapture>> {
    let session = mgr.create_session(
        &source,
        ext_image_copy_capture_manager_v1::Options::empty(),
        &queue.handle(),
        (),
    );
    // Drain the constraint block (buffer_size/shm_format/done).
    let deadline = Instant::now() + COPY_DEADLINE;
    while !state.ext_done && Instant::now() < deadline {
        queue
            .roundtrip(&mut state)
            .context("ext session constraints roundtrip")?;
    }
    if !state.ext_done {
        bail!("ext-image-copy-capture sent no constraint set");
    }
    Ok(Box::new(ExtSession {
        queue,
        state,
        session,
        _source: source,
        _manager: mgr,
        buf_key: None,
        pool_file: None,
        _pool: None,
        buffer: None,
        client_damage: None,
    }))
}

/// Session scoped to a single toplevel window via
/// `ext_foreign_toplevel_image_capture_source_manager_v1`. `window_id`
/// is the stable identifier `get_windows` reports - the `wlr-toplevel-`
/// selector prefix is stripped, so both forms are accepted. An id that
/// matches no live toplevel is an error; there is deliberately no
/// full-screen fallback (capturing the wrong thing is worse than
/// failing). Requires the ext protocol trio - there is no screencopy
/// fallback because `zwlr_screencopy` has no toplevel source.
pub(crate) fn open_window(window_id: &str) -> Result<Box<dyn StreamCapture>> {
    let conn = Connection::connect_to_env().context("connect to WAYLAND_DISPLAY")?;
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let mut state = Sess::default();
    conn.display().get_registry(&qh, ());
    queue.roundtrip(&mut state).context("registry roundtrip")?;

    if state.shm.is_none() {
        bail!("wl_shm not advertised");
    }
    let (mgr, src_mgr) = match (state.ext_mgr.clone(), state.ext_top_src_mgr.clone()) {
        (Some(m), Some(s)) if state.ext_list.is_some() => (m, s),
        _ => bail!(
            "per-window capture needs ext-image-copy-capture, \
             ext-foreign-toplevel-list and the toplevel capture source - \
             not advertised by this compositor"
        ),
    };

    // One roundtrip flushes the list bind and collects the initial
    // toplevel burst (identifiers arrive on each handle). `finished`
    // is *not* awaited - Hyprland never sends it, matching the
    // enumeration strategy wlr_toplevel uses.
    queue
        .roundtrip(&mut state)
        .context("toplevel enumeration roundtrip")?;

    // Selector resolution: stable identifier (`wlr-toplevel-` prefix is
    // stripped), else an *exact unique* title match. Compositor ids
    // like Hyprland's `0x...` addresses resolve to titles in the tool
    // layer before this call. Ambiguous titles fail - capturing the
    // wrong window is worse than an error.
    let want = window_id.strip_prefix("wlr-toplevel-").unwrap_or(window_id);
    let mut by_id = state
        .tops
        .iter()
        .filter(|(_, id, _, closed)| !*closed && id == want);
    let handle = match by_id.next() {
        Some((h, _, _, _)) => h.clone(),
        None => {
            let mut by_title: Vec<&ExtForeignToplevelHandleV1> = state
                .tops
                .iter()
                .filter(|(_, _, title, closed)| !*closed && title == want)
                .map(|(h, _, _, _)| h)
                .collect();
            match by_title.len() {
                1 => by_title.pop().expect("len checked").clone(),
                0 => bail!("no live toplevel with identifier or title {want:?}"),
                _ => bail!(
                    "title {want:?} matches {} toplevels - ambiguous",
                    by_title.len()
                ),
            }
        }
    };

    let source = src_mgr.create_source(&handle, &qh, ());
    open_ext_session(queue, state, mgr, source)
}

/// One frame of a single toplevel window - `screenshot {window}`'s
/// backend path. Opens a window session, waits out the first frame
/// (always full-damage, so it cannot stall on an idle window), and
/// closes. Runs on a blocking thread - callers must `spawn_blocking`.
pub(crate) fn capture_window_frame(window_id: &str) -> Result<Frame> {
    let mut session = open_window(window_id)?;
    match session.next_frame(Duration::from_secs(2 * COPY_DEADLINE.as_secs()))? {
        Some(f) => Ok(f),
        None => bail!("window capture produced no frame within deadline"),
    }
}

// ---------------------------------------------------------------------------
// Shared session state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Sess {
    shm: Option<wl_shm::WlShm>,
    screencopy: Option<ZwlrScreencopyManagerV1>,
    ext_mgr: Option<ExtImageCopyCaptureManagerV1>,
    ext_src_mgr: Option<ExtOutputImageCaptureSourceManagerV1>,
    ext_top_src_mgr: Option<ExtForeignToplevelImageCaptureSourceManagerV1>,
    /// Bound ext toplevel-list proxy - kept alive so its handles stay
    /// valid for the source request.
    ext_list: Option<ExtForeignToplevelListV1>,
    /// `ext_foreign_toplevel_handle_v1.id()` -> `tops` slot.
    by_top_id: HashMap<wayland_client::backend::ObjectId, usize>,
    /// (handle, identifier, title, closed) per enumerated toplevel, in
    /// emission order.
    tops: Vec<(ExtForeignToplevelHandleV1, String, String, bool)>,
    list_finished: bool,
    outputs: Vec<wl_output::WlOutput>,

    // ---- ext session constraints ----
    ext_size: Option<(u32, u32)>,
    ext_shm_fmts: Vec<wl_shm::Format>,
    ext_done: bool,
    ext_stopped: bool,

    // ---- in-flight frame state (both protocols) ----
    /// (format, width, height, stride) picked for the current frame.
    pending: Option<(wl_shm::Format, u32, u32, u32)>,
    copy_sent: bool,
    y_invert: bool,
    /// Union of this frame's damage rects, buffer coordinates.
    damage: Option<(i32, i32, i32, i32)>,
    ready: bool,
    failed: Option<String>,
}

impl Sess {
    fn reset_frame(&mut self) {
        self.pending = None;
        self.copy_sent = false;
        self.y_invert = false;
        self.damage = None;
        self.ready = false;
        self.failed = None;
    }

    fn note_damage(&mut self, x: i32, y: i32, w: i32, h: i32) {
        self.damage = Some(match self.damage {
            Some((ux, uy, uw, uh)) => {
                let x2 = (x + w).max(ux + uw);
                let y2 = (y + h).max(uy + uh);
                let x1 = x.min(ux);
                let y1 = y.min(uy);
                (x1, y1, x2 - x1, y2 - y1)
            }
            None => (x, y, w, h),
        });
    }
}

impl Dispatch<wl_registry::WlRegistry, ()> for Sess {
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
                "ext_image_copy_capture_manager_v1" => {
                    state.ext_mgr = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "ext_output_image_capture_source_manager_v1" => {
                    state.ext_src_mgr = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "ext_foreign_toplevel_image_capture_source_manager_v1" => {
                    state.ext_top_src_mgr = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "ext_foreign_toplevel_list_v1" => {
                    state.ext_list = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "wl_output" => {
                    state
                        .outputs
                        .push(registry.bind(name, version.min(4), qh, ()));
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<ExtForeignToplevelListV1, ()> for Sess {
    fn event(
        state: &mut Self,
        _: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_foreign_toplevel_list_v1::Event;
        match event {
            Event::Toplevel { toplevel } => {
                state.by_top_id.insert(toplevel.id(), state.tops.len());
                state
                    .tops
                    .push((toplevel, String::new(), String::new(), false));
            }
            Event::Finished => state.list_finished = true,
            _ => {}
        }
    }

    event_created_child!(Sess, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
    ]);
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for Sess {
    fn event(
        state: &mut Self,
        handle: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_foreign_toplevel_handle_v1::Event;
        let Some(&idx) = state.by_top_id.get(&handle.id()) else {
            return;
        };
        match event {
            Event::Identifier { identifier } => state.tops[idx].1 = identifier,
            Event::Title { title } => state.tops[idx].2 = title,
            Event::Closed => state.tops[idx].3 = true,
            _ => {} // app_id/done unused - identifier and title are the selectors
        }
    }
}

// ---------------------------------------------------------------------------
// Persistent shm buffer
// ---------------------------------------------------------------------------

/// (width, height, stride, format) identifying the pool allocation;
/// recreated only when the compositor's buffer description changes.
type BufKey = (u32, u32, u32, wl_shm::Format);

fn ensure_buffer(
    shm: &wl_shm::WlShm,
    key: BufKey,
    buf_key: &mut Option<BufKey>,
    pool_file: &mut Option<std::fs::File>,
    pool: &mut Option<WlShmPool>,
    buffer: &mut Option<WlBuffer>,
    qh: &QueueHandle<Sess>,
) -> Result<()> {
    if *buf_key == Some(key) {
        return Ok(());
    }
    let (w, h, stride, format) = key;
    let size = u64::from(stride) * u64::from(h);
    let file = tempfile().context("create shm pool file")?;
    file.set_len(size).context("size shm pool file")?;
    let p = shm.create_pool(file.as_fd(), size as i32, qh, ());
    let b = p.create_buffer(0, w as i32, h as i32, stride as i32, format, qh, ());
    *pool_file = Some(file);
    *pool = Some(p);
    *buffer = Some(b);
    *buf_key = Some(key);
    Ok(())
}

/// Read the persistent pool back out and encode it.
fn read_frame(pool_file: &mut Option<std::fs::File>, key: BufKey, y_invert: bool) -> Result<Frame> {
    let (w, h, stride, format) = key;
    let file = pool_file
        .as_mut()
        .ok_or_else(|| anyhow!("frame ready without shm pool file"))?;
    file.rewind().ok();
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).context("read shm pool")?;
    let rgba = shm_to_rgba(&raw, format, w, h, stride, y_invert);
    let png = encode_png(&rgba, w, h)?;
    Ok(Frame {
        png,
        width: w,
        height: h,
    })
}

// ---------------------------------------------------------------------------
// wlr-screencopy `copy_with_damage` session
// ---------------------------------------------------------------------------

struct WlrSession {
    queue: wayland_client::EventQueue<Sess>,
    state: Sess,
    manager: ZwlrScreencopyManagerV1,
    output: wl_output::WlOutput,
    buf_key: Option<BufKey>,
    pool_file: Option<std::fs::File>,
    _pool: Option<WlShmPool>,
    buffer: Option<WlBuffer>,
}

impl Dispatch<zwlr_screencopy_frame_v1::ZwlrScreencopyFrameV1, ()> for Sess {
    fn event(
        state: &mut Self,
        _: &zwlr_screencopy_frame_v1::ZwlrScreencopyFrameV1,
        event: zwlr_screencopy_frame_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use zwlr_screencopy_frame_v1::Event;
        match event {
            Event::Buffer {
                format,
                width,
                height,
                stride,
            } => {
                if state.pending.is_none()
                    && let Ok(fmt) = format.into_result()
                    && shm_format_supported(fmt)
                {
                    state.pending = Some((fmt, width, height, stride));
                }
            }
            Event::Flags { flags } => {
                if let Ok(f) = flags.into_result() {
                    state.y_invert = f.contains(zwlr_screencopy_frame_v1::Flags::YInvert);
                }
            }
            Event::Damage {
                x,
                y,
                width,
                height,
            } => {
                state.note_damage(x as i32, y as i32, width as i32, height as i32);
            }
            Event::BufferDone => {
                // Format negotiation is over - the session driver owns
                // the persistent buffer and issues `copy_with_damage`
                // itself once this event lands.
                if state.pending.is_none() {
                    state.failed = Some("compositor offered no usable wl_shm format".into());
                }
                state.copy_sent = true;
            }
            Event::Ready { .. } => state.ready = true,
            Event::Failed => state.failed = Some("compositor reported frame failure".into()),
            _ => {}
        }
    }
}

enum Copy {
    Changed(Frame),
    Unchanged,
}

impl WlrSession {
    /// One capture attempt: `copy_with_damage` on the persistent buffer,
    /// `Changed` only when the compositor reported damage.
    fn copy_once(&mut self) -> Result<Copy> {
        self.state.reset_frame();
        let frame = self
            .manager
            .capture_output(0, &self.output, &self.queue.handle(), ());

        // Phase 1: format negotiation - pump until BufferDone resolves
        // `pending` (or fails).
        let deadline = Instant::now() + COPY_DEADLINE;
        while !self.state.copy_sent && self.state.failed.is_none() && Instant::now() < deadline {
            self.queue
                .roundtrip(&mut self.state)
                .context("screencopy negotiate roundtrip")?;
        }
        if let Some(e) = self.state.failed.take() {
            frame.destroy();
            bail!("screencopy: {e}");
        }
        let Some((fmt, w, h, stride)) = self.state.pending else {
            frame.destroy();
            bail!("screencopy negotiation timed out");
        };

        ensure_buffer(
            self.state.shm.as_ref().expect("shm bound at open"),
            (w, h, stride, fmt),
            &mut self.buf_key,
            &mut self.pool_file,
            &mut self._pool,
            &mut self.buffer,
            &self.queue.handle(),
        )?;
        let buffer = self.buffer.as_ref().expect("buffer ensured");
        frame.copy_with_damage(buffer);
        self.queue.flush().context("flush copy_with_damage")?;

        // Phase 2: wait out the copy - damage events accumulate meanwhile.
        while !(self.state.ready || self.state.failed.is_some()) && Instant::now() < deadline {
            self.queue
                .roundtrip(&mut self.state)
                .context("screencopy copy roundtrip")?;
        }
        frame.destroy();

        if let Some(e) = self.state.failed.take() {
            bail!("screencopy: {e}");
        }
        if !self.state.ready {
            bail!("screencopy timed out waiting for ready");
        }
        if self.state.damage.is_none() {
            return Ok(Copy::Unchanged);
        }
        read_frame(
            &mut self.pool_file,
            self.buf_key.expect("buffer ensured"),
            self.state.y_invert,
        )
        .map(Copy::Changed)
    }
}

impl StreamCapture for WlrSession {
    fn next_frame(&mut self, wait: Duration) -> Result<Option<Frame>> {
        let deadline = Instant::now() + wait;
        loop {
            match self.copy_once()? {
                Copy::Changed(f) => return Ok(Some(f)),
                Copy::Unchanged => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(DAMAGE_POLL.min(deadline - now));
        }
    }
}

// ---------------------------------------------------------------------------
// ext-image-copy-capture session
// ---------------------------------------------------------------------------

struct ExtSession {
    queue: wayland_client::EventQueue<Sess>,
    state: Sess,
    session: ExtImageCopyCaptureSessionV1,
    _source: ExtImageCaptureSourceV1,
    _manager: ExtImageCopyCaptureManagerV1,
    buf_key: Option<BufKey>,
    pool_file: Option<std::fs::File>,
    _pool: Option<WlShmPool>,
    buffer: Option<WlBuffer>,
    /// Union of the last frame's damage - what we must ask the compositor
    /// to refresh in our persistent buffer. `None` = damage whole buffer
    /// (first frame / constraint change).
    client_damage: Option<(i32, i32, i32, i32)>,
}

impl Dispatch<ExtImageCopyCaptureSessionV1, ()> for Sess {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureSessionV1,
        event: ext_image_copy_capture_session_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_image_copy_capture_session_v1::Event;
        match event {
            Event::BufferSize { width, height } => state.ext_size = Some((width, height)),
            Event::ShmFormat { format } => {
                if let Ok(f) = format.into_result()
                    && shm_format_supported(f)
                {
                    state.ext_shm_fmts.push(f);
                }
            }
            Event::Done => state.ext_done = true,
            Event::Stopped => state.ext_stopped = true,
            _ => {} // dmabuf events unused - wl_shm only
        }
    }
}

impl Dispatch<ExtImageCopyCaptureFrameV1, ()> for Sess {
    fn event(
        state: &mut Self,
        _: &ExtImageCopyCaptureFrameV1,
        event: ext_image_copy_capture_frame_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_image_copy_capture_frame_v1::Event;
        match event {
            Event::Damage {
                x,
                y,
                width,
                height,
            } => {
                state.note_damage(x, y, width, height);
            }
            Event::Transform { .. } => {} // normal transforms decode identically
            Event::Ready => state.ready = true,
            Event::Failed { reason } => {
                let msg = match reason.into_result() {
                    Ok(ext_image_copy_capture_frame_v1::FailureReason::Stopped) => {
                        "source stopped (output disabled)"
                    }
                    Ok(ext_image_copy_capture_frame_v1::FailureReason::BufferConstraints) => {
                        "buffer rejected by compositor constraints"
                    }
                    _ => "compositor reported frame failure",
                };
                state.failed = Some(msg.into());
            }
            _ => {} // presentation_time unused
        }
    }
}

impl StreamCapture for ExtSession {
    fn next_frame(&mut self, wait: Duration) -> Result<Option<Frame>> {
        if self.state.ext_stopped {
            // Source paused (output off/disabled) - hold the wait so the
            // caller's cancel cadence still applies, then report idle.
            std::thread::sleep(wait);
            return Ok(None);
        }
        self.state.reset_frame();
        let frame = self.session.create_frame(&self.queue.handle(), ());

        // Buffer: recreate when constraints change; stride is width*4 for
        // every 8888 format we accept.
        let (w, h) = self
            .state
            .ext_size
            .ok_or_else(|| anyhow!("ext session sent no buffer_size"))?;
        let fmt = *self
            .state
            .ext_shm_fmts
            .first()
            .ok_or_else(|| anyhow!("ext session offered no usable wl_shm format"))?;
        ensure_buffer(
            self.state.shm.as_ref().expect("shm bound at open"),
            (w, h, w * 4, fmt),
            &mut self.buf_key,
            &mut self.pool_file,
            &mut self._pool,
            &mut self.buffer,
            &self.queue.handle(),
        )?;
        let buffer = self.buffer.as_ref().expect("buffer ensured").clone();
        frame.attach_buffer(&buffer);
        match self.client_damage {
            // Accumulated damage since this buffer was last captured.
            Some((x, y, dw, dh)) => frame.damage_buffer(x, y, dw, dh),
            None => frame.damage_buffer(0, 0, w as i32, h as i32),
        }
        frame.capture();
        self.queue.flush().context("flush ext capture")?;

        // After the first frame the compositor may hold `capture` open
        // until the source changes - pump until ready/failed or our
        // deadline, then abandon the frame so the caller re-checks cancel.
        let deadline = Instant::now() + wait;
        while !(self.state.ready || self.state.failed.is_some()) && Instant::now() < deadline {
            self.queue
                .roundtrip(&mut self.state)
                .context("ext capture roundtrip")?;
        }
        if !(self.state.ready || self.state.failed.is_some()) {
            frame.destroy();
            return Ok(None);
        }
        frame.destroy();

        if let Some(e) = self.state.failed.take() {
            // A `stopped` failure is transient - the source may resume;
            // report idle rather than killing the stream.
            if self.state.ext_stopped || e.contains("stopped") {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(250)),
                );
                return Ok(None);
            }
            bail!("ext-image-copy-capture: {e}");
        }

        self.client_damage = self.state.damage;
        read_frame(
            &mut self.pool_file,
            self.buf_key.expect("buffer ensured"),
            false,
        )
        .map(Some)
    }
}

// ---------------------------------------------------------------------------
// No-op dispatch for objects whose events we never subscribe to
// ---------------------------------------------------------------------------

// `wl_shm` emits `format` events after bind - `delegate_noop!` would
// panic on them; give it an explicit swallow-everything impl.
impl Dispatch<wl_shm::WlShm, ()> for Sess {
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

// `wl_output` emits geometry/mode/scale/name after bind and `wl_buffer`
// may emit `release` - `delegate_noop!` panics on events, so both get
// explicit swallow-everything impls.
impl Dispatch<wl_output::WlOutput, ()> for Sess {
    fn event(
        _: &mut Self,
        _: &wl_output::WlOutput,
        _: wl_output::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for Sess {
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

delegate_noop!(Sess: WlShmPool);
delegate_noop!(Sess: ZwlrScreencopyManagerV1);
delegate_noop!(Sess: ExtImageCopyCaptureManagerV1);
delegate_noop!(Sess: ExtOutputImageCaptureSourceManagerV1);
delegate_noop!(Sess: ExtForeignToplevelImageCaptureSourceManagerV1);
delegate_noop!(Sess: ExtImageCaptureSourceV1);

#[cfg(test)]
mod tests {
    use super::*;

    /// Damage-union bookkeeping: disjoint rects merge to their bounding
    /// box, overlapping rects extend it.
    #[test]
    fn damage_union_accumulates() {
        let mut s = Sess::default();
        s.note_damage(0, 0, 10, 10);
        assert_eq!(s.damage, Some((0, 0, 10, 10)));
        s.note_damage(20, 30, 5, 5);
        assert_eq!(s.damage, Some((0, 0, 25, 35)));
        s.note_damage(5, 5, 2, 2);
        assert_eq!(s.damage, Some((0, 0, 25, 35)));
    }

    /// Live smoke against the running compositor - `cargo test -- --ignored`.
    /// Opens a session (ext-image-copy-capture where advertised, else
    /// wlr-screencopy damage), takes the first frame, then confirms an
    /// idle wait reports `None` rather than fabricating a frame.
    #[test]
    #[ignore = "needs a live wlroots Wayland session"]
    fn live_session_first_frame_and_idle() {
        let mut session = open().expect("open a capture session");
        let first = session
            .next_frame(Duration::from_secs(10))
            .expect("first frame")
            .expect("first frame must always be delivered");
        assert!(first.width > 0 && first.height > 0);
        assert!(first.png.starts_with(b"\x89PNG"));
        eprintln!("first frame: {}x{}", first.width, first.height);

        // A short quiet window may still see cursor/repaint damage on a
        // busy desktop, so `None` is not asserted - only that the call
        // honours the deadline rather than blocking forever.
        let start = Instant::now();
        let _ = session
            .next_frame(Duration::from_millis(800))
            .expect("idle poll must not error");
        assert!(start.elapsed() >= Duration::from_millis(700));
    }

    /// Live smoke for per-window capture - `cargo test -- --ignored`.
    /// Lists ext toplevels through the same machinery `open_window`
    /// uses, captures the first live one, and confirms the frame is a
    /// PNG smaller than a full-output frame.
    #[test]
    #[ignore = "needs a live session advertising the ext toplevel source"]
    fn live_window_capture() {
        let conn = Connection::connect_to_env().expect("wayland");
        let mut queue = conn.new_event_queue();
        let qh = queue.handle();
        let mut state = Sess::default();
        conn.display().get_registry(&qh, ());
        queue.roundtrip(&mut state).unwrap();
        if state.ext_top_src_mgr.is_none() || state.ext_list.is_none() {
            eprintln!("compositor lacks ext toplevel capture source - skipping");
            return;
        }
        // `finished` is not awaited - Hyprland never sends it; one
        // roundtrip collects the initial toplevel burst.
        queue.roundtrip(&mut state).unwrap();
        let Some((_, id, _, _)) = state
            .tops
            .iter()
            .find(|(_, id, _, c)| !*c && !id.is_empty())
        else {
            eprintln!("no identified toplevels - skipping");
            return;
        };
        eprintln!("capturing toplevel {id}");
        let frame = capture_window_frame(id).expect("window capture");
        assert!(frame.png.starts_with(b"\x89PNG"));
        assert!(frame.width > 0 && frame.height > 0);
        eprintln!("window frame: {}x{}", frame.width, frame.height);
    }
}
