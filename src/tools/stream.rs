//! Continuous live screen streaming — `screen_stream` (the live
//! counterpart to `screen_record`'s bounded burst).
//!
//! Lifecycle: `start` spawns a background capture task on the tokio
//! runtime that grabs one frame per `fps` interval into a fresh
//! `stream-<ulid>` `0700` dir under the captures root, keeping a bounded
//! *rolling window* on disk — when `max_frames` or `max_bytes` would be
//! crossed the **oldest** frames are evicted and counted as
//! `dropped_frames`. `status` reports shared stats; `latest` returns the
//! newest frame as image content (same wire shape as `screenshot`, so
//! clients can poll frames); `stop` cancels the task, joins it under a
//! 15 s wall-clock bound (aborting a task that refuses to die, reported
//! as `"aborted": true`), and returns final stats. The task writes
//! `manifest.json` on every exit path — stop, capture error, io error —
//! and a drop guard writes a best-effort manifest (`stop_reason`
//! `"terminated"`/`"panic"`) even on unwind, so a stream that died on
//! its own is still self-describing on disk.
//!
//! **Single stream server-wide.** The registry is process-global (HTTP
//! and stdio callers share it); a second `start` while a task is alive
//! is rejected. A dead task does not block a fresh `start` — its
//! finished handle is displaced, and `stop`/`status` still report the
//! dead stream's stats until then.
//!
//! Shutdown: there is no server-level cancel hook (the registry lives
//! here so `server.rs` needs no changes); dropping the tokio runtime
//! aborts the task. Frames already on disk survive — recording dirs are
//! kept by design, matching `screen_record`.
//!
//! Not consent-gated — same posture as `screen_record`: pixels are read
//! and written only into a fresh server-owned `0700` directory; nothing
//! caller-chosen is written or destroyed.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Duration;

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::{
    base64_encode, invalid_params, json_result, parse_args, provider_unavailable, tool, tool_error,
};
use crate::providers::Providers;
use crate::traits::CaptureProvider;

/// `fps` bounds — spec: default 2, 1..=10. Ten fps is the fastest cadence
/// real capture backends sustain; tests exercise the high end so a
/// `start`→`sleep`→`status` cycle produces several frames.
const MIN_FPS: u64 = 1;
const MAX_FPS: u64 = 10;
const DEFAULT_FPS: u64 = 2;
/// Rolling-window frame bound — spec: default 600, 1..=1800 (3×
/// `screen_record`'s hard cap: eviction, not the window, is the guard).
const MIN_MAX_FRAMES: u64 = 1;
const MAX_MAX_FRAMES: u64 = 1_800;
const DEFAULT_MAX_FRAMES: u64 = 600;
/// `max_bytes` bounds — default and hard ceiling 512 MiB, the same
/// server-side byte cap `screen_record` enforces ([`MAX_RECORD_BYTES`]
/// in record.rs). The window can never hold more than this on disk.
const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STREAM_BYTES: u64 = 512 * 1024 * 1024;

fn default_fps() -> u64 {
    DEFAULT_FPS
}

fn default_max_frames() -> u64 {
    DEFAULT_MAX_FRAMES
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StreamParams {
    /// Lifecycle action: start | status | latest | stop
    action: StreamAction,
    /// Capture rate in frames/second (default 2, 1..=10); `start` only
    #[serde(default = "default_fps")]
    #[schemars(range(min = 1, max = 10))]
    fps: u64,
    /// Rolling window size in frames (default 600, 1..=1800); `start` only
    #[serde(default = "default_max_frames")]
    #[schemars(range(min = 1, max = 1800))]
    max_frames: u64,
    /// Rolling window byte budget (default and ceiling 512 MiB); `start` only
    #[serde(default = "default_max_bytes")]
    #[schemars(range(min = 1, max = 536870912))]
    max_bytes: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum StreamAction {
    Start,
    Status,
    Latest,
    Stop,
}

/// Live counters shared between the capture task and `status`/`latest`/
/// `stop`. `std::sync::Mutex` is deliberate: critical sections are a few
/// field writes and never held across `.await`.
#[derive(Debug, Default)]
struct Stats {
    /// Cumulative frames written to disk (evicted frames included).
    frames_written: u64,
    /// Cumulative bytes written to disk (evicted frames included).
    bytes_written: u64,
    /// Frames evicted by the rolling window, or dropped for exceeding
    /// `max_bytes` outright.
    dropped_frames: u64,
    /// Frames currently on disk.
    buffered_frames: u64,
    /// Bytes currently on disk (excl. manifest.json).
    buffered_bytes: u64,
    /// Basename of the newest frame file plus its dimensions.
    latest_frame: Option<String>,
    latest_width: u32,
    latest_height: u32,
    /// Terminal fault that killed the task (`capture_error`/`io_error`).
    last_error: Option<String>,
    /// Why the loop exited: stopped | capture_error | io_error.
    stop_reason: Option<&'static str>,
    finished_at: Option<String>,
}

/// One live (or finished-not-yet-reaped) stream in the process-global
/// registry. The `watch` sender is the cancel edge; `join` reaps the
/// task on `stop`.
struct StreamHandle {
    id: String,
    dir: PathBuf,
    /// Basename only — the full path never crosses the wire.
    dir_name: String,
    started_at: String,
    fps: u64,
    cancel: watch::Sender<bool>,
    join: JoinHandle<()>,
    stats: Arc<StdMutex<Stats>>,
}

/// Process-global single-slot stream registry. `Mutex::const_new` keeps
/// this a plain `static` (no OnceCell dance); the lock serializes
/// concurrent `start`/`stop` pairs and is held only for bookkeeping —
/// never across the task join.
static REGISTRY: Mutex<Option<StreamHandle>> = Mutex::const_new(None);

fn lock_stats(s: &StdMutex<Stats>) -> std::sync::MutexGuard<'_, Stats> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `providers.backend_names` is pushed capture-slot-first by both
/// `detect_providers` and `all_mocks` — same convention record.rs uses.
fn capture_backend_name(providers: &Providers) -> &'static str {
    providers
        .backend_names
        .first()
        .copied()
        .unwrap_or("unknown")
}

/// `-32603` for stream-dir plumbing faults — same mapping record.rs
/// gives its recording-dir creation.
fn stream_dir_error(e: anyhow::Error) -> ErrorData {
    ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("screen_stream: stream dir: {e:#}"),
        None,
    )
}

/// Fresh `stream-<ulid>` `0700` dir under the captures root.
///
/// The captures layer only mints `rec-<ulid>` leaves publicly
/// ([`crate::security::captures::fresh_recording_dir`] /
/// [`crate::security::captures::recording_leaf`]); renaming the fresh
/// leaf inside the same parent is atomic, preserves the `0700` mode, and
/// keeps the anti-symlink-preplacement properties — so streams get their
/// own greppable `stream-` prefix without new allocation logic there.
fn stream_dir() -> Result<PathBuf, ErrorData> {
    let dir = {
        #[cfg(test)]
        {
            match test_stream_base() {
                Some(base) => crate::security::captures::recording_leaf(&base),
                None => crate::security::captures::fresh_recording_dir(),
            }
        }
        #[cfg(not(test))]
        {
            crate::security::captures::fresh_recording_dir()
        }
    }
    .map_err(stream_dir_error)?;
    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
        return Ok(dir);
    };
    let Some(ulid) = name.strip_prefix("rec-") else {
        return Ok(dir);
    };
    let renamed = dir.with_file_name(format!("stream-{ulid}"));
    std::fs::rename(&dir, &renamed).map_err(|e| {
        stream_dir_error(anyhow::Error::new(e).context("rename rec- -> stream- leaf"))
    })?;
    Ok(renamed)
}

#[cfg(test)]
static TEST_STREAM_BASE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn test_stream_base() -> Option<PathBuf> {
    TEST_STREAM_BASE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub(super) fn tools() -> Vec<Tool> {
    vec![tool::<StreamParams>(
        "screen_stream",
        "Continuous live screen capture with a start/status/latest/stop lifecycle. `start` \
         spawns a background task capturing one PNG frame per fps into a fresh stream-<ulid> \
         dir under the captures root, keeping a rolling window (max_frames / max_bytes — \
         oldest frames evicted, counted as dropped_frames). `latest` returns the newest frame \
         as image content like `screenshot`; `stop` writes manifest.json and returns stats. \
         One stream at a time server-wide.",
    )]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "screen_stream" => screen_stream(args, providers).await,
        _ => return None,
    })
}

/// `screen_stream` entry point — same signature as `screen_record`'s
/// handler so the mod.rs dispatch arm is mechanical.
pub async fn screen_stream(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: StreamParams = parse_args("screen_stream", args)?;
    match p.action {
        StreamAction::Start => stream_start(&p, args, providers).await,
        StreamAction::Status => Ok(stream_status().await),
        StreamAction::Latest => Ok(stream_latest().await),
        StreamAction::Stop => Ok(stream_stop().await),
    }
}

async fn stream_start(
    p: &StreamParams,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    if !(MIN_FPS..=MAX_FPS).contains(&p.fps) {
        return Err(invalid_params(format!(
            "screen_stream: fps must be between {MIN_FPS} and {MAX_FPS}"
        )));
    }
    if !(MIN_MAX_FRAMES..=MAX_MAX_FRAMES).contains(&p.max_frames) {
        return Err(invalid_params(format!(
            "screen_stream: max_frames must be between {MIN_MAX_FRAMES} and {MAX_MAX_FRAMES}"
        )));
    }
    if !(1..=MAX_STREAM_BYTES).contains(&p.max_bytes) {
        return Err(invalid_params(format!(
            "screen_stream: max_bytes must be between 1 and {MAX_STREAM_BYTES}"
        )));
    }
    // The task needs a 'static capture handle — clone the Arc slot
    // directly rather than borrowing through `capture_provider`.
    let capture = providers
        .capture
        .clone()
        .ok_or_else(|| provider_unavailable("CaptureProvider"))?;

    // Cheap occupied check before any blocking work; the authoritative
    // check re-runs under the insert lock below (TOCTOU between the two
    // is closed by the recheck).
    {
        let reg = REGISTRY.lock().await;
        if let Some(h) = reg.as_ref()
            && !h.join.is_finished()
        {
            return Ok(tool_error(format!(
                "screen_stream: stream {} already active — stop it before starting another",
                h.id
            )));
        }
    }

    // Minting the dir does blocking std::fs work (mkdir + rename) — it
    // must happen *outside* the registry lock so a slow filesystem never
    // stalls status/latest/stop for the live stream.
    let dir = stream_dir()?;
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("stream-unknown")
        .to_string();
    let id = dir_name
        .strip_prefix("stream-")
        .unwrap_or(&dir_name)
        .to_string();
    let started_at = chrono::Utc::now().to_rfc3339();
    let stats = Arc::new(StdMutex::new(Stats::default()));
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let join = tokio::spawn(run_stream(
        dir.clone(),
        capture,
        capture_backend_name(providers),
        args.clone(),
        p.fps,
        p.max_frames,
        p.max_bytes,
        started_at.clone(),
        Arc::clone(&stats),
        cancel_rx,
    ));
    let mut reg = REGISTRY.lock().await;
    if let Some(h) = reg.as_ref() {
        if h.join.is_finished() {
            // Dead stream (capture_error/io_error): displace the
            // finished handle so a new stream can start. Its dir +
            // manifest stay on disk; stats were already snapshotted
            // into the manifest.
            *reg = None;
        } else {
            // Lost a start race — another stream grabbed the slot while
            // we minted. Release the registry before cleanup: abort,
            // await (so the drop-guard manifest write can't race the
            // dir removal), then remove the dir — it may already hold
            // a first-tick frame.
            let winner = h.id.clone();
            drop(reg);
            let _ = cancel_tx.send(true);
            join.abort();
            let _ = join.await;
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(tool_error(format!(
                "screen_stream: stream {winner} already active — stop it before starting another"
            )));
        }
    }
    *reg = Some(StreamHandle {
        id: id.clone(),
        dir,
        dir_name: dir_name.clone(),
        started_at: started_at.clone(),
        fps: p.fps,
        cancel: cancel_tx,
        join,
        stats,
    });
    Ok(json_result(&json!({
        "stream_id": id,
        "dir": dir_name,
        "fps": p.fps,
        "interval_ms": 1_000 / p.fps,
        "max_frames": p.max_frames,
        "max_bytes": p.max_bytes,
        "started_at": started_at,
    })))
}

async fn stream_status() -> CallToolResult {
    let reg = REGISTRY.lock().await;
    let Some(h) = reg.as_ref() else {
        return json_result(&json!({"active": false}));
    };
    let s = lock_stats(&h.stats);
    json_result(&json!({
        "active": !h.join.is_finished(),
        "stream_id": h.id,
        "dir": h.dir_name,
        "fps": h.fps,
        "started_at": h.started_at,
        "frames_written": s.frames_written,
        "bytes_written": s.bytes_written,
        "buffered_frames": s.buffered_frames,
        "buffered_bytes": s.buffered_bytes,
        "dropped_frames": s.dropped_frames,
        "latest_frame": s.latest_frame,
        "last_error": s.last_error,
        "stop_reason": s.stop_reason,
        "finished_at": s.finished_at,
    }))
}

/// Newest frame file as image content — same two-block wire shape as
/// `screenshot` (text description + base64 PNG) so clients can poll.
async fn stream_latest() -> CallToolResult {
    // Snapshot under the lock, drop it, then do file IO: the read must
    // not hold the registry across an await.
    let (dir, id, file, w, h) = {
        let reg = REGISTRY.lock().await;
        let Some(h) = reg.as_ref() else {
            return tool_error("screen_stream: no stream — start one first");
        };
        let s = lock_stats(&h.stats);
        let Some(file) = s.latest_frame.clone() else {
            return tool_error("screen_stream: no frames captured yet");
        };
        (
            h.dir.clone(),
            h.id.clone(),
            file,
            s.latest_width,
            s.latest_height,
        )
    };
    match read_latest(&dir, &file).await {
        Ok(bytes) => CallToolResult::success(vec![
            ContentBlock::text(format!("Latest frame {file} ({w}x{h} PNG) of stream {id}")),
            ContentBlock::image(base64_encode(&bytes), "image/png"),
        ]),
        Err(e) => tool_error(format!("screen_stream: read {file}: {e:#}")),
    }
}

/// Leaf-open with `O_NOFOLLOW`, the async mirror of
/// [`crate::security::captures::open_nofollow`]: stream dirs are
/// long-lived and `frame_%05d.png`/`manifest.json` are predictable, so a
/// same-UID process could pre-place a symlink — the leaf flag fails the
/// open with `ELOOP` instead of silently redirecting the read or write.
/// `write` opens read+write+create at `0600` (forcing the mode on
/// pre-existing leaves, same as `open_nofollow`).
async fn open_leaf(path: &std::path::Path, write: bool) -> anyhow::Result<tokio::fs::File> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    if write {
        opts.write(true).create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        // `mode`/`custom_flags` are inherent unix methods on tokio's
        // OpenOptions — no extension trait needed.
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let f = opts.open(path).await.map_err(|e| {
        anyhow::Error::new(e).context(format!("open {} (O_NOFOLLOW)", path.display()))
    })?;
    if write {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| anyhow::Error::new(e).context(format!("chmod 0600 {}", path.display())))?;
    }
    Ok(f)
}

/// Read a whole leaf with `O_NOFOLLOW` — see [`open_leaf`].
async fn read_leaf(path: PathBuf) -> anyhow::Result<Vec<u8>> {
    let mut f = open_leaf(&path, false).await?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .await
        .map_err(|e| anyhow::Error::new(e).context(format!("read {}", path.display())))?;
    Ok(buf)
}

/// Write a whole leaf with `O_NOFOLLOW` at `0600` — see [`open_leaf`].
async fn write_leaf(path: PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = open_leaf(&path, true).await?;
    f.write_all(bytes)
        .await
        .map_err(|e| anyhow::Error::new(e).context(format!("write {}", path.display())))
}

/// Read `file` inside `dir`, retrying once against the *current* latest
/// frame when the snapshot lost an eviction race (a newer frame landed
/// and evicted it between the stat snapshot and the read).
async fn read_latest(dir: &std::path::Path, file: &str) -> anyhow::Result<Vec<u8>> {
    match read_leaf(dir.join(file)).await {
        Ok(b) => Ok(b),
        Err(first) => {
            // Did the latest pointer move? Re-snapshot dir *and* frame
            // without holding the registry across the retry read — a
            // displaced stream could otherwise return a same-named stale
            // frame from the old dir.
            let newer = {
                let reg = REGISTRY.lock().await;
                reg.as_ref()
                    .map(|h| (h.dir.clone(), lock_stats(&h.stats).latest_frame.clone()))
            };
            if let Some((new_dir, Some(newer))) = newer
                && (newer != file || new_dir != dir)
            {
                return read_leaf(new_dir.join(&newer)).await;
            }
            Err(first.context(format!("read {file}")))
        }
    }
}

/// `stop` — take the slot, cancel, join, report. Idempotent at the
/// result level: no active stream is an `isError` result, never a panic.
/// A dead-but-unreaped stream still reports its final stats (the task
/// already wrote its own manifest).
async fn stream_stop() -> CallToolResult {
    let h = REGISTRY.lock().await.take();
    let Some(h) = h else {
        return tool_error("screen_stream: no active stream to stop");
    };
    // Send may fail if the task already finished (receiver dropped) —
    // joining a finished task is fine either way. The join is bounded
    // by a *wall-clock* watchdog (a blocking-pool `thread::sleep`, not
    // `tokio::time::timeout`): the capture loop is cancel-aware so the
    // bound should never fire — but a genuinely wedged task must not
    // hang `stop` forever, and a paused test clock must not turn a
    // never-expected timer into an instant abort. On expiry the task is
    // aborted and the reply reports best-effort stats with
    // `aborted: true` rather than erroring: the stream *is* stopped.
    let _ = h.cancel.send(true);
    let mut join = h.join;
    let mut watchdog = tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(15)));
    let aborted = tokio::select! {
        r = &mut join => match r {
            Ok(()) => false,
            Err(e) => {
                return tool_error(format!(
                    "screen_stream: stream task {} join failed: {e}",
                    h.id
                ));
            }
        },
        _ = &mut watchdog => {
            join.abort();
            // Reap the abort so the drop-guard manifest write lands
            // before stats are read — same real-clock trick, short fuse.
            let mut reap =
                tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(2)));
            tokio::select! {
                _ = &mut join => {}
                _ = &mut reap => {}
            }
            true
        }
    };
    watchdog.abort();
    let s = lock_stats(&h.stats);
    json_result(&json!({
        "stopped": true,
        "aborted": aborted,
        "stream_id": h.id,
        "dir": h.dir_name,
        "fps": h.fps,
        "started_at": h.started_at,
        "finished_at": s.finished_at,
        "frames_written": s.frames_written,
        "bytes_written": s.bytes_written,
        "buffered_frames": s.buffered_frames,
        "buffered_bytes": s.buffered_bytes,
        "dropped_frames": s.dropped_frames,
        "latest_frame": s.latest_frame,
        "stop_reason": s.stop_reason,
        "last_error": s.last_error,
        "manifest": "manifest.json",
    }))
}

/// The background capture loop. Owns the extant-frame deque so it can
/// write a complete `manifest.json` on every exit path; mirrors counters
/// into the shared [`Stats`] each iteration for `status`/`latest`.
///
/// Loop contract: first tick fires immediately (a frame exists as soon
/// as the backend can produce one), `MissedTickBehavior::Delay` keeps
/// captures at least `interval` apart (a slow backend never triggers a
/// catch-up burst), and `biased` selects check the cancel edge before
/// every tick *and* race each in-flight `capture_frame`, so `stop` is
/// prompt even mid-capture. Eviction runs *before* each write:
/// pop oldest while the window is full (`== max_frames`) or the byte
/// budget would overflow; a frame larger than the whole `max_bytes`
/// budget is dropped unwritten so `buffered_bytes <= max_bytes` holds
/// unconditionally.
#[allow(clippy::too_many_arguments)]
async fn run_stream(
    dir: PathBuf,
    capture: Arc<dyn CaptureProvider>,
    backend_name: &'static str,
    args: Map<String, Value>,
    fps: u64,
    max_frames: u64,
    max_bytes: u64,
    started_at: String,
    stats: Arc<StdMutex<Stats>>,
    mut cancel: watch::Receiver<bool>,
) {
    let interval = Duration::from_millis(1_000 / fps.max(1));
    let start = Instant::now();
    let mut ticker = tokio::time::interval_at(start, interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Stream state lives in `st` — its `Drop` writes manifest.json with
    // whatever counters exist at exit, so even a panic mid-capture
    // leaves a self-describing directory.
    let mut st = StreamState {
        dir,
        backend_name,
        args,
        fps,
        interval_ms: interval.as_millis() as u64,
        max_frames,
        max_bytes,
        started_at,
        frames: VecDeque::new(),
        buffered_bytes: 0,
        written_bytes: 0,
        dropped: 0,
        seq: 0,
        error: None,
        reason: "terminated",
        start,
        stats: Arc::clone(&stats),
        manifest_written: false,
    };

    let reason: &'static str = loop {
        tokio::select! {
            biased;
            _ = cancel.changed() => break "stopped",
            _ = ticker.tick() => {}
        }
        // `stop` must not wait out an in-flight capture — the frame
        // future is raced against the cancel edge. Dropping it is safe:
        // spawned helpers are `kill_on_drop` (security/spawn.rs).
        let frame = tokio::select! {
            biased;
            _ = cancel.changed() => break "stopped",
            f = capture.capture_frame(None) => match f {
                Ok(f) => f,
                Err(e) => {
                    st.error = Some(format!("{e:#}"));
                    break "capture_error";
                }
            },
        };
        let size = frame.png.len() as u64;
        // Rolling eviction: oldest first until the incoming frame fits
        // both caps. `>= max_frames` because the new frame is not yet in
        // the deque.
        while !st.frames.is_empty()
            && (st.frames.len() as u64 >= max_frames || st.buffered_bytes + size > max_bytes)
        {
            let old = st.frames.pop_front().expect("deque checked non-empty");
            if let Some(f) = old["file"].as_str()
                && let Err(e) = tokio::fs::remove_file(st.dir.join(f)).await
            {
                // The file stays on disk unaccounted — `buffered_bytes`
                // still shrinks (it no longer counts as buffered), so a
                // warn keeps the accounting honest.
                tracing::warn!(
                    error = %e,
                    file = %f,
                    "screen_stream: eviction unlink failed — frame orphaned on disk"
                );
            }
            st.buffered_bytes = st
                .buffered_bytes
                .saturating_sub(old["bytes"].as_u64().unwrap_or(0));
            st.dropped += 1;
        }
        if size > max_bytes {
            // A frame that can never fit the byte budget is dropped
            // unwritten — the on-disk byte cap is never crossed.
            st.dropped += 1;
        } else {
            st.seq += 1;
            let file = format!("frame_{:05}.png", st.seq);
            if let Err(e) = write_leaf(st.dir.join(&file), &frame.png).await {
                st.error = Some(format!("write {file}: {e:#}"));
                break "io_error";
            }
            st.buffered_bytes += size;
            st.written_bytes += size;
            st.frames.push_back(json!({
                "file": file,
                "bytes": size,
                "width": frame.width,
                "height": frame.height,
                "t_ms": start.elapsed().as_millis() as u64,
            }));
            let mut s = lock_stats(&stats);
            s.latest_frame = Some(file);
            s.latest_width = frame.width;
            s.latest_height = frame.height;
        }
        let mut s = lock_stats(&stats);
        s.frames_written = st.seq;
        s.bytes_written = st.written_bytes;
        s.dropped_frames = st.dropped;
        s.buffered_frames = st.frames.len() as u64;
        s.buffered_bytes = st.buffered_bytes;
    };
    st.reason = reason;

    let finished_at = chrono::Utc::now().to_rfc3339();
    {
        let mut s = lock_stats(&stats);
        s.stop_reason = Some(reason);
        s.finished_at = Some(finished_at.clone());
        s.last_error = st.error.clone();
    }

    // The task writes the manifest itself so a stream that died of a
    // capture/io fault — not just an explicit stop — is self-describing.
    let manifest = st.manifest_json(&finished_at, start.elapsed().as_millis() as u64);
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).expect("manifest serialization cannot fail");
    if let Err(e) = write_leaf(st.dir.join("manifest.json"), &manifest_bytes).await {
        tracing::warn!(
            error = %e,
            dir = %st.dir.display(),
            "screen_stream: manifest write failed"
        );
        lock_stats(&stats).last_error = Some(format!("manifest write: {e:#}"));
    }
    st.manifest_written = true;
}

/// Mutable capture-loop state; `Drop` writes `manifest.json`
/// synchronously whenever the task exits without a completed manifest —
/// covering panics (provider faults, serialization bugs) that unwind
/// past the async manifest write. The file is small, so the blocking
/// `std::fs::write` on the unwind path is acceptable.
struct StreamState {
    dir: PathBuf,
    backend_name: &'static str,
    args: Map<String, Value>,
    fps: u64,
    interval_ms: u64,
    max_frames: u64,
    max_bytes: u64,
    started_at: String,
    /// Extant frames, oldest at the front — the manifest's `frames` list
    /// is exactly this deque at exit (evicted frames appear only in
    /// `dropped`).
    frames: VecDeque<Value>,
    buffered_bytes: u64,
    written_bytes: u64,
    dropped: u64,
    seq: u64,
    error: Option<String>,
    /// `stopped`/`capture_error`/`io_error` on the normal path;
    /// `"terminated"` is the unwind default — `Drop` narrows it to
    /// `"panic"` when the task is actually unwinding.
    reason: &'static str,
    start: Instant,
    stats: Arc<StdMutex<Stats>>,
    manifest_written: bool,
}

impl StreamState {
    fn manifest_json(&self, finished_at: &str, elapsed_ms: u64) -> Value {
        let mut manifest = json!({
            "tool": "screen_stream",
            "schema": 1,
            "stream": true,
            "args": Value::Object(self.args.clone()),
            "backend": self.backend_name,
            "dir": self.dir.to_string_lossy(),
            "fps": self.fps,
            "interval_ms": self.interval_ms,
            "max_frames": self.max_frames,
            "max_bytes": self.max_bytes,
            "started_at": self.started_at,
            "finished_at": finished_at,
            "elapsed_ms": elapsed_ms,
            // Extant frames only — the rolling window on disk at exit.
            "frames": self.frames,
            "buffered_frames": self.frames.len(),
            "buffered_bytes": self.buffered_bytes,
            "frames_written": self.seq,
            "bytes_written": self.written_bytes,
            "dropped_frames": self.dropped,
            "stop_reason": self.reason,
        });
        if let Some(e) = &self.error {
            manifest["error"] = json!(e);
        }
        manifest
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        if self.manifest_written {
            return;
        }
        // Panic/abort path — the loop never reached its manifest write.
        // Mark the stats so `status`/`stop` report the end state, then
        // write whatever manifest the extant counters describe.
        if std::thread::panicking() {
            self.reason = "panic";
        }
        let finished_at = chrono::Utc::now().to_rfc3339();
        {
            let mut s = lock_stats(&self.stats);
            s.stop_reason = Some(self.reason);
            if s.finished_at.is_none() {
                s.finished_at = Some(finished_at.clone());
            }
            if s.last_error.is_none() {
                s.last_error = self.error.clone();
            }
        }
        let manifest = self.manifest_json(&finished_at, self.start.elapsed().as_millis() as u64);
        if let Ok(b) = serde_json::to_vec_pretty(&manifest) {
            let res = crate::security::captures::open_nofollow(&self.dir.join("manifest.json"))
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(&b)
                        .map_err(|e| anyhow::Error::new(e).context("manifest write"))
                });
            if let Err(e) = res {
                tracing::warn!(
                    error = %e,
                    dir = %self.dir.display(),
                    "screen_stream: drop-guard manifest write failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Frame;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The registry is process-global — every test that touches it
    /// serializes on this lock. (`tokio::sync::Mutex`, not a poisoning
    /// std mutex: a panicking test releases it rather than wedging the
    /// rest.)
    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().expect("test args must be an object").clone()
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    fn json_of(result: &CallToolResult) -> Value {
        serde_json::from_str(&text_of(result)).expect("result text is JSON")
    }

    /// Install a hermetic stream base for the test; returns it. Caller
    /// clears it before releasing TEST_LOCK.
    fn use_base(tmp: &tempfile::TempDir) -> PathBuf {
        let base = tmp.path().join("streams");
        std::fs::create_dir(&base).unwrap();
        *TEST_STREAM_BASE.lock().unwrap() = Some(base.clone());
        base
    }

    fn clear_base() {
        *TEST_STREAM_BASE.lock().unwrap() = None;
    }

    fn providers_with(capture: Arc<dyn CaptureProvider>) -> Providers {
        Providers {
            capture: Some(capture),
            ..Providers::all_mocks()
        }
    }

    /// Fails every capture — the dead-stream path.
    struct FailingCapture;

    #[async_trait]
    impl CaptureProvider for FailingCapture {
        async fn capture_frame(&self, _r: Option<crate::traits::Rect>) -> anyhow::Result<Frame> {
            anyhow::bail!("screencopy gone")
        }
        async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
            Ok((0, 0))
        }
        async fn screen_info(&self) -> anyhow::Result<Value> {
            Ok(json!({"monitors": []}))
        }
    }

    /// Succeeds `ok_frames` times then fails — mid-stream death.
    struct FlakyCapture {
        ok_frames: usize,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CaptureProvider for FlakyCapture {
        async fn capture_frame(&self, _r: Option<crate::traits::Rect>) -> anyhow::Result<Frame> {
            if self.calls.fetch_add(1, Ordering::SeqCst) >= self.ok_frames {
                anyhow::bail!("backend died mid-stream")
            }
            Ok(Frame {
                png: vec![7u8; 64],
                width: 2,
                height: 2,
            })
        }
        async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
            Ok((0, 0))
        }
        async fn screen_info(&self) -> anyhow::Result<Value> {
            Ok(json!({"monitors": []}))
        }
    }

    async fn call(action_args: Value, providers: &Providers) -> CallToolResult {
        dispatch("screen_stream", &args(action_args), providers)
            .await
            .expect("dispatch claims screen_stream")
            .expect("tool call must not be a JSON-RPC error")
    }

    // ---- schema / registration shape ------------------------------------

    #[test]
    fn tool_schema_shape() {
        let t = &tools()[0];
        assert_eq!(t.name.as_ref(), "screen_stream");
        assert_eq!(
            t.input_schema.get("type").and_then(Value::as_str),
            Some("object")
        );
        assert_eq!(
            t.input_schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let required = t.input_schema["required"].as_array().unwrap();
        assert_eq!(required, &vec![json!("action")]);
        // schemars emits the enum behind a `$defs` ref — accept either shape.
        let action = &t.input_schema["properties"]["action"];
        let action_enum = action
            .get("enum")
            .or_else(|| t.input_schema["$defs"]["StreamAction"].get("enum"))
            .and_then(Value::as_array)
            .expect("action enum advertised");
        for a in ["start", "status", "latest", "stop"] {
            assert!(action_enum.contains(&json!(a)), "missing action {a}");
        }
    }

    // ---- argument validation --------------------------------------------

    #[tokio::test]
    async fn action_and_bounds_are_enforced() {
        for v in [
            json!({}),                  // missing action
            json!({"action": "bogus"}), // unknown action
            json!({"action": "start", "fps": 0}),
            json!({"action": "start", "fps": 11}),
            json!({"action": "start", "max_frames": 0}),
            json!({"action": "start", "max_frames": 1801}),
            json!({"action": "start", "max_bytes": 0}),
            json!({"action": "start", "max_bytes": MAX_STREAM_BYTES + 1}),
            json!({"action": "start", "bogus": true}), // deny_unknown_fields
        ] {
            let err = screen_stream(&args(v.clone()), &Providers::all_mocks())
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "args: {v}");
        }
        // defaults apply
        let p: StreamParams =
            parse_args("screen_stream", &args(json!({"action": "start"}))).unwrap();
        assert_eq!(p.fps, DEFAULT_FPS);
        assert_eq!(p.max_frames, DEFAULT_MAX_FRAMES);
        assert_eq!(p.max_bytes, DEFAULT_MAX_BYTES);
    }

    #[tokio::test]
    async fn missing_capture_provider_is_32010() {
        let err = screen_stream(&args(json!({"action": "start"})), &Providers::empty())
            .await
            .unwrap_err();
        assert_eq!(err.code.0, -32010);
        assert!(err.message.contains("CaptureProvider"));
    }

    // ---- lifecycle --------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn start_status_latest_stop_lifecycle() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        let base = use_base(&tmp);
        let providers = Providers::all_mocks();

        let res = call(json!({"action": "start", "fps": 10}), &providers).await;
        assert_eq!(res.is_error, Some(false));
        let v = json_of(&res);
        let dir_name = v["dir"].as_str().unwrap().to_string();
        assert!(dir_name.starts_with("stream-"), "stream- leaf: {dir_name}");
        assert_eq!(v["fps"], 10);
        assert!(!v["stream_id"].as_str().unwrap().is_empty());

        tokio::time::sleep(Duration::from_millis(350)).await;

        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert_eq!(v["active"], true);
        assert!(v["frames_written"].as_u64().unwrap() >= 2, "{v}");
        assert_eq!(v["dropped_frames"], 0);
        assert!(v["latest_frame"].as_str().is_some());

        // `latest` mirrors `screenshot`'s two-block shape.
        let res = call(json!({"action": "latest"}), &providers).await;
        assert_eq!(res.is_error, Some(false));
        assert_eq!(res.content.len(), 2);
        assert!(res.content[1].as_image().is_some());
        assert!(text_of(&res).contains("Latest frame"));

        let v = json_of(&call(json!({"action": "stop"}), &providers).await);
        assert_eq!(v["stopped"], true);
        assert_eq!(v["stop_reason"], "stopped");
        assert!(v["frames_written"].as_u64().unwrap() >= 2);

        // manifest.json written by the task, stream:true flagged.
        let dir = base.join(&dir_name);
        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m["tool"], "screen_stream");
        assert_eq!(m["stream"], true);
        assert_eq!(m["stop_reason"], "stopped");
        assert_eq!(m["backend"], "mock-capture");
        assert_eq!(m["dropped_frames"], 0);
        assert_eq!(
            m["frames"].as_array().unwrap().len() as u64,
            m["frames_written"].as_u64().unwrap(),
            "no eviction → every written frame is extant"
        );
        // Dir mode and leaf name.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        // Post-stop status is quiet; a second stop is an error result.
        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert_eq!(v["active"], false);
        assert!(v.get("stream_id").is_none() || v["stream_id"].is_null());
        let res = call(json!({"action": "stop"}), &providers).await;
        assert_eq!(res.is_error, Some(true), "stop when inactive must error");

        clear_base();
    }

    #[tokio::test(start_paused = true)]
    async fn second_start_is_rejected() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        use_base(&tmp);
        let providers = Providers::all_mocks();

        call(json!({"action": "start", "fps": 2}), &providers).await;
        let res = call(json!({"action": "start"}), &providers).await;
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("already active"));
        // First stream is still the live one.
        call(json!({"action": "stop"}), &providers).await;
        clear_base();
    }

    #[tokio::test(start_paused = true)]
    async fn rolling_eviction_respects_frame_cap() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        let base = use_base(&tmp);
        let providers = Providers::all_mocks();

        let res = call(
            json!({"action": "start", "fps": 10, "max_frames": 5}),
            &providers,
        )
        .await;
        let dir_name = json_of(&res)["dir"].as_str().unwrap().to_string();

        // ~1.5 s at 10 fps → ~15 frames, window holds 5.
        tokio::time::sleep(Duration::from_millis(1_500)).await;

        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        let written = v["frames_written"].as_u64().unwrap();
        assert!(written > 5, "enough frames for eviction: {v}");
        assert_eq!(v["buffered_frames"], 5);
        assert_eq!(v["dropped_frames"].as_u64().unwrap(), written - 5);

        let dir = base.join(&dir_name);
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| {
                let n = e.unwrap().file_name().to_string_lossy().to_string();
                n.starts_with("frame_").then_some(n)
            })
            .collect();
        assert_eq!(files.len(), 5, "window size on disk: {files:?}");
        // Oldest files are gone — the window moved forward.
        assert!(!dir.join("frame_00001.png").exists());

        let v = json_of(&call(json!({"action": "stop"}), &providers).await);
        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m["frames"].as_array().unwrap().len(), 5);
        assert_eq!(m["dropped_frames"].as_u64().unwrap(), v["dropped_frames"]);
        assert_eq!(m["frames_written"].as_u64().unwrap(), written);
        clear_base();
    }

    #[tokio::test(start_paused = true)]
    async fn rolling_eviction_respects_byte_cap() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        use_base(&tmp);
        let providers = Providers::all_mocks();

        // MockCapture's 1x1 PNG is ~76 bytes; a 160-byte window holds
        // at most two.
        call(
            json!({"action": "start", "fps": 10, "max_frames": 1800, "max_bytes": 160}),
            &providers,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(1_000)).await;

        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert!(v["buffered_bytes"].as_u64().unwrap() <= 160, "{v}");
        assert!(v["buffered_frames"].as_u64().unwrap() <= 2, "{v}");
        assert!(v["dropped_frames"].as_u64().unwrap() > 0, "{v}");
        call(json!({"action": "stop"}), &providers).await;
        clear_base();
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_frame_is_dropped_unwritten() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        use_base(&tmp);
        let providers = Providers::all_mocks();

        // No frame can ever fit a 10-byte budget — all dropped.
        call(
            json!({"action": "start", "fps": 10, "max_bytes": 10}),
            &providers,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert_eq!(v["frames_written"], 0);
        assert_eq!(v["buffered_bytes"], 0);
        assert!(v["dropped_frames"].as_u64().unwrap() >= 2, "{v}");
        call(json!({"action": "stop"}), &providers).await;
        clear_base();
    }

    // ---- failure paths ----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn capture_error_kills_stream_and_status_reports() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        let base = use_base(&tmp);
        let providers = providers_with(Arc::new(FailingCapture));

        let res = call(json!({"action": "start", "fps": 10}), &providers).await;
        let dir_name = json_of(&res)["dir"].as_str().unwrap().to_string();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert_eq!(v["active"], false, "task died on capture error");
        assert_eq!(v["stop_reason"], "capture_error");
        assert!(
            v["last_error"]
                .as_str()
                .unwrap()
                .contains("screencopy gone")
        );

        // Dead stream still wrote its manifest.
        let m: Value = serde_json::from_str(
            &std::fs::read_to_string(base.join(&dir_name).join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(m["stop_reason"], "capture_error");
        assert!(m["error"].as_str().unwrap().contains("screencopy gone"));

        // stop still reports final stats; a *new* start is allowed past
        // the dead handle.
        let v = json_of(&call(json!({"action": "stop"}), &providers).await);
        assert_eq!(v["stop_reason"], "capture_error");
        clear_base();
    }

    #[tokio::test(start_paused = true)]
    async fn mid_stream_death_then_fresh_start() {
        let _g = TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        use_base(&tmp);
        let flaky = providers_with(Arc::new(FlakyCapture {
            ok_frames: 3,
            calls: AtomicUsize::new(0),
        }));

        call(json!({"action": "start", "fps": 10}), &flaky).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let v = json_of(&call(json!({"action": "status"}), &flaky).await);
        assert_eq!(v["active"], false);
        assert_eq!(v["frames_written"], 3);

        // A new start displaces the dead handle without an explicit stop.
        let res = call(
            json!({"action": "start", "fps": 2}),
            &Providers::all_mocks(),
        )
        .await;
        assert_eq!(
            res.is_error,
            Some(false),
            "dead stream must not block start"
        );
        call(json!({"action": "stop"}), &Providers::all_mocks()).await;
        clear_base();
    }

    // ---- inactive-state behaviour -----------------------------------------

    #[tokio::test]
    async fn status_latest_stop_with_no_stream() {
        let _g = TEST_LOCK.lock().await;
        let providers = Providers::all_mocks();
        let v = json_of(&call(json!({"action": "status"}), &providers).await);
        assert_eq!(v["active"], false);
        for a in ["latest", "stop"] {
            let res = call(json!({"action": a}), &providers).await;
            assert_eq!(res.is_error, Some(true), "action {a} with no stream");
        }
    }
}
