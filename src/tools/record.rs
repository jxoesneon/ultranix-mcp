//! Bounded screen recording - `screen_record` (ROADMAP post-v1
//! "Streaming capture"). This is the honest bounded version of the idea,
//! not a live stream: the tool captures one frame per `interval_ms` for
//! up to `duration_ms`, writes each frame's PNG into a fresh
//! `rec-<ulid>` dir under the captures root plus a `manifest.json`, and
//! returns the directory + manifest. Hard caps: 600 frames and
//! [`MAX_RECORD_BYTES`] written, whichever hits first.
//!
//! Mid-record cancellation is deliberately out of scope: the call runs
//! to its bound (duration, frame cap, or byte cap) and then returns -
//! `duration_ms <= 30_000` keeps that bounded by construction. Callers
//! wanting "live" UX should re-invoke with small `duration_ms` values.
//!
//! The tool is **not**consent-gated: it reads pixels and writes only
//! into a fresh server-owned `0700` directory - nothing caller-chosen
//! is written or destroyed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rmcp::model::{CallToolResult, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::time::{Instant, MissedTickBehavior};

use super::{
    backend_error, bounds_json, capture_provider, invalid_params, json_result, parse_args, tool,
    tool_error,
};
use crate::providers::Providers;
use crate::traits::{CaptureProvider, Rect};

/// `duration_ms` bounds - spec: 100..=30_000.
const MIN_DURATION_MS: u64 = 100;
const MAX_DURATION_MS: u64 = 30_000;
/// `interval_ms` bounds - spec: default 250, 50..=5_000.
const DEFAULT_INTERVAL_MS: u64 = 250;
const MIN_INTERVAL_MS: u64 = 50;
const MAX_INTERVAL_MS: u64 = 5_000;
/// Hard frame cap - independent of the duration/interval product.
const MAX_FRAMES: u64 = 600;
/// Hard cap on total bytes written per recording (512 MiB). Exceeding it
/// aborts the loop cleanly with `truncated: true` and a partial result.
const MAX_RECORD_BYTES: u64 = 512 * 1024 * 1024;

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordParams {
    /// Total recording length in milliseconds (100..=30000)
    #[schemars(range(min = 100, max = 30000))]
    duration_ms: u64,
    /// Capture interval in milliseconds (default 250, 50..=5000)
    #[serde(default = "default_interval_ms")]
    #[schemars(range(min = 50, max = 5000))]
    interval_ms: u64,
    /// Crop rect in logical coordinates (same convention as `screenshot`)
    region: Option<RecordRegion>,
    /// Output name from screen_info (e.g. "eDP-1"); omit for all outputs
    display: Option<String>,
}

/// `screenshot`'s `region` shape - vision.rs keeps its `RegionParam`
/// private, so the convention is mirrored here (x/y logical layout
/// coords, w/h >= 1).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordRegion {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
    /// Width in logical pixels (>= 1)
    #[schemars(range(min = 1))]
    w: i32,
    /// Height in logical pixels (>= 1)
    #[schemars(range(min = 1))]
    h: i32,
}

impl RecordRegion {
    fn to_rect(&self) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            w: self.w,
            h: self.h,
        }
    }
}

/// Target frame count: `duration/interval` floor, at least one frame
/// (duration < interval still yields a single-frame recording), at most
/// [`MAX_FRAMES`].
fn frame_target(duration_ms: u64, interval_ms: u64) -> usize {
    (duration_ms / interval_ms).clamp(1, MAX_FRAMES) as usize
}

/// `providers.backend_names` is pushed capture-slot-first by both
/// `detect_providers` and `all_mocks`, so entry 0 is the capture
/// backend's name whenever `capture` is populated. Hand-built registries
/// that break the ordering degrade to `"unknown"` rather than lying.
fn capture_backend_name(providers: &Providers) -> &'static str {
    providers
        .backend_names
        .first()
        .copied()
        .unwrap_or("unknown")
}

/// `-32603` for recording-dir plumbing faults - the same mapping
/// `exec_system_command` uses for its capture-dir creation.
fn recording_dir_error(e: anyhow::Error) -> ErrorData {
    ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("screen_record: recording dir: {e:#}"),
        None,
    )
}

/// Resolve this call's recording directory: a fresh `rec-<ulid>` leaf
/// under the captures root (`<state>/captures` preferred, `/tmp`
/// fallback - [`crate::security::captures::fresh_recording_dir`]). The
/// `#[cfg(test)]` base override keeps dispatch-level tests hermetic.
fn recording_dir() -> Result<PathBuf, ErrorData> {
    #[cfg(test)]
    {
        if let Some(base) = test_recording_base() {
            return crate::security::captures::recording_leaf(&base).map_err(recording_dir_error);
        }
    }
    crate::security::captures::fresh_recording_dir().map_err(recording_dir_error)
}

#[cfg(test)]
static TEST_RECORDING_BASE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn test_recording_base() -> Option<PathBuf> {
    TEST_RECORDING_BASE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// `display` -> output layout-rect resolution, mirroring `screenshot`'s
/// rules: backend `screen_info` -> named output rect. Unknown names are
/// `-32602`; a backend with no output geometry is an honest `isError`.
enum DisplayResolve {
    Backend(anyhow::Error),
    Unsupported,
    Unknown(Vec<String>),
}

async fn display_region(
    capture: &dyn CaptureProvider,
    display: &str,
) -> Result<Rect, DisplayResolve> {
    let info = capture
        .screen_info()
        .await
        .map_err(DisplayResolve::Backend)?;
    let outputs = super::vision::output_rects(&info);
    if outputs.is_empty() {
        return Err(DisplayResolve::Unsupported);
    }
    outputs
        .iter()
        .find(|(name, _)| name == display)
        .map(|(_, r)| *r)
        .ok_or_else(|| {
            DisplayResolve::Unknown(outputs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>())
        })
}

pub(super) fn tools() -> Vec<Tool> {
    vec![tool::<RecordParams>(
        "screen_record",
        "Record a bounded burst of screen captures: one PNG frame every interval_ms \
         for up to duration_ms (hard caps: 600 frames, 512 MiB written). Frames plus \
         a manifest.json land in a fresh rec-<ulid> dir under the captures root. The \
         call always runs to its bound - mid-record cancellation is not supported.",
    )]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "screen_record" => screen_record(args, providers).await,
        _ => return None,
    })
}

async fn screen_record(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: RecordParams = parse_args("screen_record", args)?;
    if !(MIN_DURATION_MS..=MAX_DURATION_MS).contains(&p.duration_ms) {
        return Err(invalid_params(format!(
            "screen_record: duration_ms must be between {MIN_DURATION_MS} and {MAX_DURATION_MS}"
        )));
    }
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&p.interval_ms) {
        return Err(invalid_params(format!(
            "screen_record: interval_ms must be between {MIN_INTERVAL_MS} and {MAX_INTERVAL_MS}"
        )));
    }
    if let Some(r) = &p.region
        && (r.w < 1 || r.h < 1)
    {
        return Err(invalid_params("screen_record: region w and h must be >= 1"));
    }
    let capture = capture_provider(providers)?;
    // Scope precedence mirrors `screenshot`: explicit `region` wins,
    // then `display` resolves to that output's layout rect, else the
    // full layout. (The session spatial-focus rect is a vision.rs
    // private and is deliberately not consulted here.)
    let region = if let Some(r) = &p.region {
        Some(r.to_rect())
    } else if let Some(d) = &p.display {
        match display_region(capture, d).await {
            Ok(r) => Some(r),
            Err(DisplayResolve::Backend(e)) => return Ok(backend_error(e)),
            Err(DisplayResolve::Unsupported) => {
                return Ok(tool_error(
                    "screen_record: per-output capture not supported by this backend \
                     (screen_info reported no output geometry)",
                ));
            }
            Err(DisplayResolve::Unknown(known)) => {
                return Err(invalid_params(format!(
                    "screen_record: unknown display {d:?} (known outputs: {})",
                    known.join(", ")
                )));
            }
        }
    } else {
        None
    };
    let dir = recording_dir()?;
    record_run(
        args,
        &p,
        capture,
        capture_backend_name(providers),
        region,
        &dir,
        MAX_RECORD_BYTES,
    )
    .await
}

/// The capture/write loop, factored out of [`screen_record`] so tests
/// drive it against an explicit `dir` + `byte_cap` - no env mutation,
/// no real state-dir writes.
///
/// Loop contract: tick the interval, capture, byte-cap check, async-fs
/// write, repeat - until `frame_target` frames are written, `duration`
/// elapses, the byte cap would be crossed, or the backend/FS fails.
/// `MissedTickBehavior::Delay` keeps successive captures at least
/// `interval_ms` apart (a slow capture never triggers a catch-up burst).
/// Every exit path still writes `manifest.json` so a partial or failed
/// recording is self-describing on disk.
async fn record_run(
    args: &Map<String, Value>,
    p: &RecordParams,
    capture: &dyn CaptureProvider,
    backend_name: &str,
    region: Option<Rect>,
    dir: &Path,
    byte_cap: u64,
) -> Result<CallToolResult, ErrorData> {
    let duration = Duration::from_millis(p.duration_ms);
    let interval = Duration::from_millis(p.interval_ms);
    let target = frame_target(p.duration_ms, p.interval_ms);

    let started_at = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();
    let mut ticker = tokio::time::interval_at(start, interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut frames: Vec<Value> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut truncated = false;
    let mut stop_reason = "duration";
    let mut error: Option<String> = None;

    while frames.len() < target && start.elapsed() < duration {
        ticker.tick().await;
        let frame = match capture.capture_frame(region).await {
            Ok(f) => f,
            Err(e) => {
                stop_reason = "capture_error";
                error = Some(format!("{e:#}"));
                break;
            }
        };
        let size = frame.png.len() as u64;
        // The frame that would cross the cap is dropped, not written -
        // `total_bytes` therefore never exceeds `byte_cap`.
        if total_bytes + size > byte_cap {
            truncated = true;
            stop_reason = "byte_cap";
            break;
        }
        let file = format!("frame_{:04}.png", frames.len() + 1);
        if let Err(e) = tokio::fs::write(dir.join(&file), &frame.png).await {
            stop_reason = "io_error";
            error = Some(format!("write {file}: {e:#}"));
            break;
        }
        total_bytes += size;
        frames.push(json!({
            "file": file,
            "bytes": size,
            "width": frame.width,
            "height": frame.height,
            "t_ms": start.elapsed().as_millis() as u64,
        }));
    }

    let frames_written = frames.len();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let mut manifest = json!({
        "tool": "screen_record",
        "schema": 1,
        "args": Value::Object(args.clone()),
        "backend": backend_name,
        "dir": dir.to_string_lossy(),
        "region": region.map(|r| bounds_json(&r)),
        "display": p.display.as_deref(),
        "requested_duration_ms": p.duration_ms,
        "requested_interval_ms": p.interval_ms,
        "frame_target": target,
        "started_at": started_at,
        "finished_at": chrono::Utc::now().to_rfc3339(),
        "elapsed_ms": elapsed_ms,
        "frames": frames,
        "frames_written": frames_written,
        "total_bytes": total_bytes,
        "byte_cap": byte_cap,
        "truncated": truncated,
        "stop_reason": stop_reason,
    });
    if let Some(e) = &error {
        manifest["error"] = json!(e);
    }

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).expect("manifest serialization cannot fail");
    if let Err(e) = tokio::fs::write(dir.join("manifest.json"), &manifest_bytes).await {
        return Ok(tool_error(format!(
            "screen_record: manifest write failed in {}: {e}",
            dir.display()
        )));
    }

    // Zero frames + a capture fault = the recording never happened:
    // report an honest tool error rather than an empty "success".
    if frames_written == 0
        && let Some(e) = &error
    {
        return Ok(tool_error(format!("screen_record: {e}")));
    }
    Ok(json_result(&json!({
        "dir": dir.to_string_lossy(),
        "frames": frames_written,
        "duration_ms": elapsed_ms,
        "truncated": truncated,
        "manifest": manifest,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Frame;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().expect("test args must be an object").clone()
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(rmcp::model::ContentBlock::as_text)
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    fn params(v: Value) -> RecordParams {
        parse_args("screen_record", &args(v)).expect("params must parse")
    }

    fn rec_dir(tmp: &tempfile::TempDir) -> PathBuf {
        let dir = tmp.path().join("rec-test");
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// A capture backend whose frames are `bytes` of payload - the tool
    /// never decodes PNG, so raw bytes exercise the byte-cap path.
    struct BigFrameCapture {
        bytes: usize,
    }

    /// Fails every capture - the no-backend-frames path.
    struct FailingCapture;

    /// Succeeds `ok_frames` times, then fails - the mid-record fault path.
    struct FlakyCapture {
        ok_frames: usize,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CaptureProvider for BigFrameCapture {
        async fn capture_frame(&self, _r: Option<Rect>) -> anyhow::Result<Frame> {
            Ok(Frame {
                png: vec![0u8; self.bytes],
                width: 1,
                height: 1,
            })
        }
        async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
            Ok((0, 0))
        }
        async fn screen_info(&self) -> anyhow::Result<Value> {
            Ok(json!({"monitors": []}))
        }
    }

    #[async_trait]
    impl CaptureProvider for FailingCapture {
        async fn capture_frame(&self, _r: Option<Rect>) -> anyhow::Result<Frame> {
            anyhow::bail!("screencopy denied")
        }
        async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
            Ok((0, 0))
        }
        async fn screen_info(&self) -> anyhow::Result<Value> {
            Ok(json!({"monitors": []}))
        }
    }

    #[async_trait]
    impl CaptureProvider for FlakyCapture {
        async fn capture_frame(&self, _r: Option<Rect>) -> anyhow::Result<Frame> {
            if self.calls.fetch_add(1, Ordering::SeqCst) >= self.ok_frames {
                anyhow::bail!("backend died mid-record")
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

    // ---- schema / registration shape ------------------------------------

    #[test]
    fn tool_schema_shape() {
        let t = &tools()[0];
        assert_eq!(t.name.as_ref(), "screen_record");
        assert_eq!(
            t.input_schema.get("type").and_then(Value::as_str),
            Some("object")
        );
        assert_eq!(
            t.input_schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let required = t.input_schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("duration_ms")));
        assert!(!required.contains(&json!("interval_ms")), "has a default");
    }

    // ---- argument validation --------------------------------------------

    #[tokio::test]
    async fn duration_bounds_are_enforced() {
        for v in [
            json!({}),                      // missing required
            json!({"duration_ms": 99}),     // below min
            json!({"duration_ms": 30_001}), // above max
            json!({"duration_ms": "1000"}), // wrong type
        ] {
            let err = screen_record(&args(v.clone()), &Providers::all_mocks())
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "args: {v}");
        }
    }

    #[tokio::test]
    async fn interval_bounds_are_enforced() {
        for ms in [49u64, 5_001] {
            let err = screen_record(
                &args(json!({"duration_ms": 1_000, "interval_ms": ms})),
                &Providers::all_mocks(),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        }
        // default applies
        let p = params(json!({"duration_ms": 1_000}));
        assert_eq!(p.interval_ms, DEFAULT_INTERVAL_MS);
    }

    #[tokio::test]
    async fn region_bounds_and_unknown_fields_rejected() {
        for v in [
            json!({"duration_ms": 500, "region": {"x": 0, "y": 0, "w": 0, "h": 10}}),
            json!({"duration_ms": 500, "region": {"x": 0, "y": 0, "w": 10, "h": -1}}),
            json!({"duration_ms": 500, "bogus": true}),
        ] {
            let err = screen_record(&args(v.clone()), &Providers::all_mocks())
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "args: {v}");
        }
    }

    // ---- provider / display plumbing ------------------------------------

    #[tokio::test]
    async fn missing_capture_provider_is_32010() {
        let err = screen_record(&args(json!({"duration_ms": 200})), &Providers::empty())
            .await
            .unwrap_err();
        assert_eq!(err.code.0, -32010);
        assert!(err.message.contains("CaptureProvider"));
    }

    #[tokio::test]
    async fn unknown_display_is_invalid_params() {
        let err = screen_record(
            &args(json!({"duration_ms": 200, "display": "nope"})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("mock"), "lists known outputs");
    }

    // ---- frame-count math -------------------------------------------------

    #[test]
    fn frame_target_math() {
        assert_eq!(frame_target(1_000, 250), 4);
        assert_eq!(frame_target(30_000, 50), 600); // exact cap
        assert_eq!(frame_target(30_000, 49), 600); // clamped to cap
        assert_eq!(frame_target(100, 5_000), 1); // floor is one frame
        assert_eq!(frame_target(500, 250), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn writes_duration_interval_frames_then_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let p = params(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let res = record_run(
            &a,
            &p,
            &crate::providers::mock::MockCapture,
            "mock-capture",
            None,
            &dir,
            MAX_RECORD_BYTES,
        )
        .await
        .unwrap();
        let v: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(v["frames"], 4);
        assert_eq!(v["truncated"], false);
        for n in 1..=4 {
            assert!(dir.join(format!("frame_{n:04}.png")).is_file());
        }
        assert!(!dir.join("frame_0005.png").exists());
        assert!(dir.join("manifest.json").is_file());
    }

    // ---- manifest correctness -------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn manifest_records_args_backend_and_frame_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({
            "duration_ms": 750, "interval_ms": 250,
            "region": {"x": 10, "y": 20, "w": 30, "h": 40},
        }));
        let p = params(json!({
            "duration_ms": 750, "interval_ms": 250,
            "region": {"x": 10, "y": 20, "w": 30, "h": 40},
        }));
        let region = p.region.as_ref().unwrap().to_rect();
        let res = record_run(
            &a,
            &p,
            &crate::providers::mock::MockCapture,
            "mock-capture",
            Some(region),
            &dir,
            MAX_RECORD_BYTES,
        )
        .await
        .unwrap();
        assert_eq!(res.is_error, Some(false));

        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m["tool"], "screen_record");
        assert_eq!(m["backend"], "mock-capture");
        assert_eq!(m["args"]["duration_ms"], 750);
        assert_eq!(m["args"]["interval_ms"], 250);
        assert_eq!(m["region"]["w"], 30, "resolved rect recorded");
        assert_eq!(m["requested_duration_ms"], 750);
        assert_eq!(m["frame_target"], 3);
        assert_eq!(m["stop_reason"], "duration");
        assert_eq!(m["truncated"], false);
        chrono::DateTime::parse_from_rfc3339(m["started_at"].as_str().unwrap()).unwrap();
        chrono::DateTime::parse_from_rfc3339(m["finished_at"].as_str().unwrap()).unwrap();

        let frames = m["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(m["frames_written"], 3);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f["file"], format!("frame_{:04}.png", i + 1));
            let real_len = std::fs::metadata(dir.join(f["file"].as_str().unwrap()))
                .unwrap()
                .len();
            assert_eq!(f["bytes"].as_u64().unwrap(), real_len);
        }
        let total: u64 = frames.iter().map(|f| f["bytes"].as_u64().unwrap()).sum();
        assert_eq!(m["total_bytes"], total);
    }

    // ---- byte-cap truncation --------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn byte_cap_truncates_with_partial_result() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({"duration_ms": 30_000, "interval_ms": 50}));
        let p = params(json!({"duration_ms": 30_000, "interval_ms": 50}));
        // 1024-byte frames, 1500-byte cap: frame 1 lands, frame 2 is dropped.
        let res = record_run(
            &a,
            &p,
            &BigFrameCapture { bytes: 1024 },
            "big",
            None,
            &dir,
            1_500,
        )
        .await
        .unwrap();
        let v: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(v["truncated"], true);
        assert_eq!(v["frames"], 1);
        assert_eq!(v["manifest"]["stop_reason"], "byte_cap");
        assert_eq!(v["manifest"]["total_bytes"], 1_024);
        assert!(dir.join("frame_0001.png").is_file());
        assert!(!dir.join("frame_0002.png").exists());
        assert!(dir.join("manifest.json").is_file());
    }

    #[tokio::test(start_paused = true)]
    async fn frame_larger_than_cap_yields_empty_recording() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let p = params(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let res = record_run(
            &a,
            &p,
            &BigFrameCapture { bytes: 1_024 },
            "big",
            None,
            &dir,
            10,
        )
        .await
        .unwrap();
        let v: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(v["truncated"], true);
        assert_eq!(v["frames"], 0);
        assert_eq!(v["manifest"]["stop_reason"], "byte_cap");
        assert!(!dir.join("frame_0001.png").exists());
    }

    // ---- failure paths ----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn first_frame_capture_failure_is_tool_error_with_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let p = params(json!({"duration_ms": 1_000, "interval_ms": 250}));
        let res = record_run(
            &a,
            &p,
            &FailingCapture,
            "failing",
            None,
            &dir,
            MAX_RECORD_BYTES,
        )
        .await
        .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(text_of(&res).contains("screencopy denied"));
        // The failure is still self-describing on disk.
        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m["frames_written"], 0);
        assert_eq!(m["stop_reason"], "capture_error");
        assert!(m["error"].as_str().unwrap().contains("screencopy denied"));
    }

    #[tokio::test(start_paused = true)]
    async fn mid_record_capture_failure_returns_partial_result() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rec_dir(&tmp);
        let a = args(json!({"duration_ms": 2_000, "interval_ms": 50}));
        let p = params(json!({"duration_ms": 2_000, "interval_ms": 50}));
        let flaky = FlakyCapture {
            ok_frames: 3,
            calls: AtomicUsize::new(0),
        };
        let res = record_run(&a, &p, &flaky, "flaky", None, &dir, MAX_RECORD_BYTES)
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
        let v: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(v["frames"], 3);
        assert_eq!(v["manifest"]["stop_reason"], "capture_error");
        assert!(
            v["manifest"]["error"]
                .as_str()
                .unwrap()
                .contains("backend died mid-record")
        );
        for n in 1..=3 {
            assert!(dir.join(format!("frame_{n:04}.png")).is_file());
        }
    }

    // ---- end-to-end through dispatch (hermetic via the test base) ---------

    #[tokio::test(start_paused = true)]
    async fn end_to_end_through_call_tool() {
        let tmp = tempfile::tempdir().unwrap();
        *TEST_RECORDING_BASE.lock().unwrap() = Some(tmp.path().to_path_buf());
        let res = crate::tools::call_tool(
            "screen_record",
            args(json!({"duration_ms": 500, "interval_ms": 250})),
            &Providers::all_mocks(),
        )
        .await;
        *TEST_RECORDING_BASE.lock().unwrap() = None;
        let res = res.expect("call_tool must succeed");
        assert_eq!(res.is_error, Some(false));
        let v: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(v["frames"], 2);
        assert_eq!(v["manifest"]["backend"], "mock-capture");
        let dir = PathBuf::from(v["dir"].as_str().unwrap());
        assert!(dir.starts_with(tmp.path()), "dir under test base: {dir:?}");
        assert!(
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("rec-"),
            "rec-<ulid> leaf name"
        );
        assert!(dir.join("frame_0001.png").is_file());
        assert!(dir.join("frame_0002.png").is_file());
        assert!(dir.join("manifest.json").is_file());
    }
}
