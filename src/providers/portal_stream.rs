//! Held RemoteDesktop PipeWire session - the cross-compositor
//! `StreamCapture` rung for `screen_stream`.
//!
//! Consent boundary: the portal's `Start` dialog appears **once** when
//! the stream opens; the compositor then pushes frames through the held
//! PipeWire stream for the session's lifetime. Nothing is persisted -
//! no `persist_mode`/`restore_token` is sent or stored (identical
//! policy to `portal_capture`/`portal_input`; THREAT_MODEL.md §4.2), so
//! `screen_stream stop` closes the session and the next `start`
//! re-consents. This is strictly better consent UX than the ephemeral
//! `pipewire_screenshot` path, which would raise a dialog per frame on
//! RemoteDesktop-only portals.
//!
//! PipeWire and zbus objects are `!Send`, so the entire session -
//! D-Bus handshake, mainloop, stream, teardown `Session.Close` - lives
//! inside one worker thread spawned by [`open`]. What crosses the
//! boundary is the [`PortalStream`] handle: shared frame state, a
//! shutdown flag, and the join handle - all `Send`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use atspi::zbus::{self, zvariant};
use pipewire::spa;
use zvariant::OwnedObjectPath;

use super::portal_capture::{
    self, Options, await_response, close_portal_session, convert_frame, create_session_options,
    encode_frame, new_handle_token, pixel_layout, portal_call, portal_proxy, raw_video_format_pod,
    response_stream, select_sources_options, session_path_from, start_options, stream_node_ids,
};
use crate::traits::{Frame, StreamCapture};

/// Longest a stream consumer waits inside one mainloop pump; the
/// shutdown flag is re-checked every slice so `stop` stays prompt.
const PUMP_SLICE: Duration = Duration::from_millis(50);

/// Frame state shared between the PipeWire callbacks (worker thread)
/// and [`PortalStream::next_frame`] (session-driver thread).
#[derive(Default)]
struct PwStreamState {
    /// Negotiated layout + dimensions, set by the `Format` param.
    layout: Option<portal_capture::PixelLayout>,
    width: u32,
    height: u32,
    /// Latest decoded frame, tightly packed RGBA.
    latest: Option<Vec<u8>>,
    /// `latest` holds a frame not yet handed to the consumer.
    fresh: bool,
    /// Fatal error observed inside a callback or the pump loop.
    error: Option<String>,
}

fn lock(st: &Mutex<PwStreamState>) -> MutexGuard<'_, PwStreamState> {
    st.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Send` handle returned to the session-driver thread. The `!Send`
/// session objects never leave the worker spawned in [`open`].
pub(crate) struct PortalStream {
    state: Arc<Mutex<PwStreamState>>,
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl StreamCapture for PortalStream {
    fn next_frame(&mut self, wait: Duration) -> Result<Option<Frame>> {
        let deadline = Instant::now() + wait;
        loop {
            let ready = {
                let mut st = lock(&self.state);
                if let Some(e) = st.error.take() {
                    bail!("portal stream: {e}");
                }
                if st.fresh {
                    st.fresh = false;
                    Some((st.width, st.height, st.latest.take()))
                } else {
                    None
                }
            };
            if let Some((w, h, rgba)) = ready {
                let rgba = rgba.ok_or_else(|| anyhow!("fresh frame without pixel data"))?;
                let (png, w, h) = encode_frame(w, h, rgba)?;
                return Ok(Some(Frame {
                    png,
                    width: w,
                    height: h,
                }));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10).min(deadline - now));
        }
    }
}

impl Drop for PortalStream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take()
            && j.join().is_err()
        {
            tracing::warn!("portal stream worker panicked during shutdown");
        }
    }
}

/// Open a held RemoteDesktop session on a new worker thread. The
/// handshake's outcome is relayed synchronously so `stream_capture`
/// only returns `Some` for a session that reached PipeWire `connect` -
/// consent declined, missing sources, and bus failures all surface as
/// `Err` here (then `stream_capture` yields `None` and the stream falls
/// back to per-tick polling).
pub(crate) fn open() -> Result<Box<dyn StreamCapture>> {
    let state = Arc::new(Mutex::new(PwStreamState::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<()>>(1);
    let st = Arc::clone(&state);
    let sd = Arc::clone(&shutdown);
    let join = std::thread::Builder::new()
        .name("portal-stream".into())
        .spawn(move || {
            if let Err(e) = worker(&ready_tx, &st, &sd) {
                // Post-ready failures land on the shared error slot the
                // consumer checks; pre-ready ones still reach open()
                // when the channel is unconsumed.
                lock(&st).error = Some(format!("{e:#}"));
                let _ = ready_tx.send(Err(e));
            }
        })
        .context("spawn portal stream worker")?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(Box::new(PortalStream {
            state,
            shutdown,
            join: Some(join),
        })),
        Ok(Err(e)) => {
            let _ = join.join();
            Err(e.context("portal stream session failed to start"))
        }
        Err(_) => {
            let _ = join.join();
            Err(anyhow!("portal stream worker died before reporting ready"))
        }
    }
}

/// The whole session, on the worker thread: portal handshake ->
/// PipeWire connect -> pump loop until `shutdown` or a stream error ->
/// `Session.Close` teardown. Every `!Send` object stays in this frame.
fn worker(
    ready: &mpsc::SyncSender<Result<()>>,
    state: &Arc<Mutex<PwStreamState>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("portal stream runtime")?;

    // RemoteDesktop handshake - CreateSession -> SelectSources ->
    // Start (the single consent dialog) -> OpenPipeWireRemote. No
    // persist_mode/restore_token (module docs).
    let (conn, session_path, node_id, fd) = rt.block_on(async {
        let conn = portal_call(zbus::Connection::session())
            .await
            .context("session bus connect")?;
        let proxy = portal_proxy(&conn, portal_capture::REMOTE_DESKTOP_IFACE).await?;
        let mut responses = response_stream(&conn).await?;

        let opts = create_session_options(new_handle_token(), new_handle_token());
        let req: OwnedObjectPath = portal_call(proxy.call("CreateSession", &(&opts,)))
            .await
            .context("portal CreateSession call")?;
        let results = await_response(&mut responses, &req).await?;
        let session_path = session_path_from(&results)?;

        let opts = select_sources_options(new_handle_token());
        let req: OwnedObjectPath =
            portal_call(proxy.call("SelectSources", &(&session_path, &opts)))
                .await
                .context("portal SelectSources call")?;
        await_response(&mut responses, &req).await?;

        let opts = start_options(new_handle_token());
        let req: OwnedObjectPath = portal_call(proxy.call("Start", &(&session_path, "", &opts)))
            .await
            .context("portal Start call")?;
        let results = await_response(&mut responses, &req).await?;
        let node = stream_node_ids(&results)
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("portal RemoteDesktop granted no streams"))?;

        let fd: zvariant::OwnedFd =
            portal_call(proxy.call("OpenPipeWireRemote", &(&session_path, &Options::new())))
                .await
                .context("portal OpenPipeWireRemote call")?;

        Ok::<_, anyhow::Error>((conn, session_path, node, fd))
    })?;

    // PipeWire side - same negotiation contract as the ephemeral path
    // (`raw_video_format_pod`), but the stream stays open and every
    // pushed buffer refreshes `latest` instead of grabbing once.
    use pipewire::context::ContextBox;
    use pipewire::keys::{MEDIA_CATEGORY, MEDIA_ROLE, MEDIA_TYPE};
    use pipewire::loop_::Timeout;
    use pipewire::main_loop::MainLoopBox;
    use pipewire::properties::properties;
    use pipewire::stream::{StreamBox, StreamFlags};

    let mainloop = MainLoopBox::new(None).context("pipewire main loop")?;
    let context = ContextBox::new(mainloop.loop_(), None).context("pipewire context")?;
    let core = context
        .connect_fd(fd.into(), None)
        .context("pipewire connect_fd")?;
    let stream = StreamBox::new(
        &core,
        "ultranix-portal-stream",
        properties! {
            *MEDIA_TYPE => "Video",
            *MEDIA_CATEGORY => "Capture",
            *MEDIA_ROLE => "Screen",
        },
    )
    .context("pipewire stream")?;

    let st = Arc::clone(state);
    let _listener = stream
        .add_local_listener_with_user_data(st)
        .param_changed(|_stream, st, id, param| {
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Some(param) = param else { return };
            let mut info = spa::param::video::VideoInfoRaw::new();
            if info.parse(param).is_err() {
                return;
            }
            let mut st = lock(st);
            // Only linear data is decodable here (see portal_capture).
            let modifier = info.modifier();
            if modifier != 0 && modifier != u64::MAX {
                st.error = Some(format!("non-linear video modifier {modifier:#x}"));
                return;
            }
            match pixel_layout(info.format()) {
                Some(layout) => {
                    let size = info.size();
                    st.layout = Some(layout);
                    st.width = size.width;
                    st.height = size.height;
                }
                None => {
                    st.error = Some(format!("unsupported video format {:?}", info.format()));
                }
            }
        })
        .process(|stream, st| {
            let mut st = lock(st);
            if st.error.is_some() {
                return;
            }
            let Some(layout) = st.layout else { return };
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else {
                st.error = Some("pipewire buffer with no data planes".into());
                return;
            };
            let (offset, size, stride) = {
                let chunk = d.chunk();
                if chunk.flags().contains(spa::buffer::ChunkFlags::CORRUPTED) {
                    return;
                }
                (
                    chunk.offset() as usize,
                    chunk.size() as usize,
                    chunk.stride(),
                )
            };
            if size == 0 {
                return;
            }
            match d.data() {
                Some(map) => match map.get(offset..offset + size) {
                    Some(plane) => {
                        match convert_frame(plane, st.width, st.height, stride, layout) {
                            Ok(rgba) => {
                                st.latest = Some(rgba);
                                st.fresh = true;
                            }
                            Err(e) => st.error = Some(format!("frame decode: {e:#}")),
                        }
                    }
                    None => st.error = Some("chunk range outside mapped plane".into()),
                },
                None => st.error = Some(format!("unmapped pipewire buffer (type {:?})", d.type_())),
            }
        })
        .register()
        .map_err(|e| anyhow!("pipewire stream listener: {e}"))?;

    let pod_bytes = raw_video_format_pod()?;
    let pod = spa::pod::Pod::from_bytes(&pod_bytes).context("EnumFormat pod bytes")?;
    let mut params = [pod];
    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .context("pipewire stream connect")?;

    // Handshake complete - open() unblocks, the stream task begins
    // polling `next_frame`.
    let _ = ready.send(Ok(()));

    // Pump the mainloop until shutdown or a fatal stream error; the
    // compositor drives buffer pushes on damage.
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        if lock(state).error.is_some() {
            break;
        }
        if mainloop.loop_().iterate(Timeout::Finite(PUMP_SLICE)) < 0 {
            lock(state).error = Some("pipewire main loop iterate failed".into());
            break;
        }
    }
    let _ = stream.disconnect();

    // D-Bus teardown on the session's own runtime - best-effort, same
    // policy as the ephemeral path.
    if let Err(e) = rt
        .block_on(close_portal_session(&conn, &session_path))
        .context("portal session Close")
    {
        tracing::debug!("portal stream session Close failed (ignored): {e:#}");
    }
    Ok(())
}
