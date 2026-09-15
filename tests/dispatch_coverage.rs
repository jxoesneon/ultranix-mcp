//! Secured-dispatch coverage: every tool is driven through
//! `call_tool_secured` (consent gate → dispatch → audit + metrics +
//! history) against deterministic providers — happy paths, per-tool
//! param-validation branches, provider-absent `-32010`s, the consent
//! challenge/verify/bypass arms, and the backend-error arms that only a
//! failing or non-empty mock can reach.
//!
//! Complements `dispatch_mock.rs` (which exercises the unsecured
//! `call_tool` shim) — a few `call_tool` calls remain here only where the
//! secured path deliberately bypasses the code under test (the Phase-0
//! `system_command` validation stub in `automation.rs`).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{args, assert_error_code, assert_success, focus_lock, valid_args};
use rmcp::model::{CallToolResult, ErrorData};
use serde_json::{Map, Value, json};
use ultranix_mcp::providers::Providers;
use ultranix_mcp::providers::mock::{MockCapture, MockInput, MockWindow};
use ultranix_mcp::security::SecurityContext;
use ultranix_mcp::security::history::NewActionRecord;
use ultranix_mcp::tools::{call_tool, call_tool_secured};
use ultranix_mcp::traits::{
    BrowserProvider, CaptureProvider, Detection, Frame, InputProvider, Rect, UIAutomationProvider,
    VisionProvider, WindowInfo, WindowProvider,
};

const INVALID_PARAMS: i32 = -32602;
const METHOD_NOT_FOUND: i32 = -32601;
const PROVIDER_UNAVAILABLE: i32 = -32010;
const SANITIZATION_REJECTED: i32 = -32006;
const ELEMENT_NOT_FOUND: i32 = -32016;
const CONSENT_REQUIRED: i32 = -32015;
/// `-32003` covers both not-whitelisted commands and argument
/// constraint violations (docs/TOOLS.md error table).
const COMMAND_NOT_WHITELISTED: i32 = -32003;
const ARG_CONSTRAINT: i32 = -32003;

const SESSION: &str = "coverage-session";

// ---------------------------------------------------------------------------
// Test context + call helpers
// ---------------------------------------------------------------------------

/// Hermetric context: fresh tmpdir state root (audit log + history store),
/// a `SecurityContext`, and the provider registry under test.
struct Ctx {
    _tmp: tempfile::TempDir,
    sec: SecurityContext,
    providers: Providers,
}

fn ctx(providers: Providers) -> Ctx {
    let tmp = tempfile::tempdir().unwrap();
    let sec = SecurityContext::new(tmp.path(), false, false).unwrap();
    Ctx {
        _tmp: tmp,
        sec,
        providers,
    }
}

/// Same, with `--allow-destructive` — the consent gate is bypassed so
/// validation/dispatch branches of gated tools are reachable.
fn ctx_destructive(providers: Providers) -> Ctx {
    let tmp = tempfile::tempdir().unwrap();
    let sec = SecurityContext::new(tmp.path(), true, false).unwrap();
    Ctx {
        _tmp: tmp,
        sec,
        providers,
    }
}

async fn secured(c: &Ctx, name: &str, a: Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    call_tool_secured(name, a, &c.providers, &c.sec, SESSION, None).await
}

fn text_of(r: &CallToolResult) -> String {
    r.content
        .first()
        .and_then(|b| b.as_text().map(|t| t.text.clone()))
        .unwrap_or_default()
}

fn json_of(r: &CallToolResult) -> Value {
    serde_json::from_str(&text_of(r)).expect("tool result text must be JSON")
}

fn consent_token(err: &ErrorData) -> String {
    err.data.as_ref().expect("consent error carries data")["consent_token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn providers_with(f: impl FnOnce(&mut Providers)) -> Providers {
    let mut p = Providers::empty();
    f(&mut p);
    p
}

fn record(c: &Ctx, tool: &str, args_json: Value) -> ultranix_mcp::security::history::ActionRecord {
    c.sec
        .history()
        .unwrap()
        .record(NewActionRecord {
            tool: tool.to_string(),
            args_json,
            result_summary: format!("{tool} summary"),
            caller: SESSION.to_string(),
            duration_ms: 1,
            outcome: "ok".to_string(),
        })
        .unwrap()
}

// ---------------------------------------------------------------------------
// Custom providers — reach the arms the all-Ok mocks cannot.
// ---------------------------------------------------------------------------

/// Every InputProvider method fails — drives the `backend!` error arms.
struct FailInput;

#[async_trait]
impl InputProvider for FailInput {
    async fn mouse_move(&self, _x: i32, _y: i32) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn mouse_click(&self, _x: i32, _y: i32, _button: &str) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn mouse_button(&self, _button: &str, _down: bool) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn scroll(&self, _dx: f64, _dy: f64) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn key_event(&self, _key: &str, _down: bool) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn type_text(&self, _text: &str) -> anyhow::Result<()> {
        anyhow::bail!("input backend down")
    }
    async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
        anyhow::bail!("input backend down")
    }
}

/// `mouse_move` succeeds once (the move-to-start) then fails — drives the
/// mid-drag `move_err` arm while still exercising the release path.
struct DragFailInput {
    moves: AtomicUsize,
}

#[async_trait]
impl InputProvider for DragFailInput {
    async fn mouse_move(&self, _x: i32, _y: i32) -> anyhow::Result<()> {
        if self.moves.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            anyhow::bail!("mid-drag move failed")
        }
    }
    async fn mouse_click(&self, _x: i32, _y: i32, _button: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn mouse_button(&self, _button: &str, _down: bool) -> anyhow::Result<()> {
        Ok(())
    }
    async fn scroll(&self, _dx: f64, _dy: f64) -> anyhow::Result<()> {
        Ok(())
    }
    async fn key_event(&self, _key: &str, _down: bool) -> anyhow::Result<()> {
        Ok(())
    }
    async fn type_text(&self, _text: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
        Ok((0, 0))
    }
}

/// Modifier keys succeed but the primary key event fails — reaches the
/// `outcome`/`backend!(outcome)` arm with held modifiers released.
struct KeyFailInput;

#[async_trait]
impl InputProvider for KeyFailInput {
    async fn mouse_move(&self, _x: i32, _y: i32) -> anyhow::Result<()> {
        Ok(())
    }
    async fn mouse_click(&self, _x: i32, _y: i32, _button: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn mouse_button(&self, _button: &str, _down: bool) -> anyhow::Result<()> {
        Ok(())
    }
    async fn scroll(&self, _dx: f64, _dy: f64) -> anyhow::Result<()> {
        Ok(())
    }
    async fn key_event(&self, key: &str, _down: bool) -> anyhow::Result<()> {
        if key.ends_with("_L") {
            Ok(()) // modifiers
        } else {
            anyhow::bail!("key event failed")
        }
    }
    async fn type_text(&self, _text: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
        Ok((0, 0))
    }
}

/// `find_element` always matches; `invoke_element` result is configurable.
struct UiFound {
    invoke_ok: bool,
}

#[async_trait]
impl UIAutomationProvider for UiFound {
    async fn get_root_json(&self, _depth: u32) -> anyhow::Result<Value> {
        Ok(json!({"role": "root", "children": []}))
    }
    async fn get_focused_json(&self) -> anyhow::Result<Value> {
        Ok(json!({"role": "application", "name": "hit"}))
    }
    async fn find_element(&self, _query: &str) -> anyhow::Result<Option<Rect>> {
        Ok(Some(Rect {
            x: 10,
            y: 20,
            w: 30,
            h: 40,
        }))
    }
    async fn invoke_element(&self, _query: &str) -> anyhow::Result<bool> {
        Ok(self.invoke_ok)
    }
}

/// Overrides `invoke_element_action`: only `"expand"` is "supported".
/// `invoke_element` returning `true` would make the trait-default's
/// press→default-action mapping report ok — so a `press` call reporting
/// `action_not_supported` proves the *named* method ran.
struct UiNamedAction;

#[async_trait]
impl UIAutomationProvider for UiNamedAction {
    async fn get_root_json(&self, _depth: u32) -> anyhow::Result<Value> {
        Ok(json!({"role": "root", "children": []}))
    }
    async fn get_focused_json(&self) -> anyhow::Result<Value> {
        Ok(json!({"role": "application", "name": "hit"}))
    }
    async fn find_element(&self, _query: &str) -> anyhow::Result<Option<Rect>> {
        Ok(Some(Rect {
            x: 10,
            y: 20,
            w: 30,
            h: 40,
        }))
    }
    async fn invoke_element(&self, _query: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn invoke_element_action(&self, _query: &str, action: &str) -> anyhow::Result<bool> {
        Ok(action == "expand")
    }
}

/// `find_element` fails — drives the `wait_for_ui_element` error arm.
struct UiErr;

#[async_trait]
impl UIAutomationProvider for UiErr {
    async fn get_root_json(&self, _depth: u32) -> anyhow::Result<Value> {
        anyhow::bail!("atspi down")
    }
    async fn get_focused_json(&self) -> anyhow::Result<Value> {
        anyhow::bail!("atspi down")
    }
    async fn find_element(&self, _query: &str) -> anyhow::Result<Option<Rect>> {
        anyhow::bail!("atspi down")
    }
    async fn invoke_element(&self, _query: &str) -> anyhow::Result<bool> {
        anyhow::bail!("atspi down")
    }
}

/// `get_focused_json` returns a fixed value (covers the Null and
/// non-object arms of `get_focused_element`).
struct FocusedVal(Value);

#[async_trait]
impl UIAutomationProvider for FocusedVal {
    async fn get_root_json(&self, _depth: u32) -> anyhow::Result<Value> {
        Ok(json!({"role": "root"}))
    }
    async fn get_focused_json(&self) -> anyhow::Result<Value> {
        Ok(self.0.clone())
    }
    async fn find_element(&self, _query: &str) -> anyhow::Result<Option<Rect>> {
        Ok(None)
    }
    async fn invoke_element(&self, _query: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}

fn window(id: &str, title: &str, focused: bool) -> WindowInfo {
    WindowInfo {
        id: id.to_string(),
        title: title.to_string(),
        class: title.to_string(),
        workspace: 1,
        rect: Rect {
            x: 0,
            y: 0,
            w: 800,
            h: 600,
        },
        focused,
        floating: None,
        fullscreen: None,
        pid: None,
        monitor: None,
    }
}

/// Active window id changes on every query — trips the post-action
/// FocusChanged check in the keyboard tools.
struct FocusFlipper {
    calls: AtomicUsize,
}

#[async_trait]
impl WindowProvider for FocusFlipper {
    async fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        Ok(vec![window("0x1", "flipper", true)])
    }
    async fn active_window(&self) -> anyhow::Result<Option<WindowInfo>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(window(&format!("0x{n}"), "flipper", true)))
    }
    async fn dispatch(&self, _a: &str, _w: &str, _args: &Value) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Active window vanishes between the before/after focus snapshots.
struct FocusVanish {
    calls: AtomicUsize,
}

#[async_trait]
impl WindowProvider for FocusVanish {
    async fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        Ok(vec![])
    }
    async fn active_window(&self) -> anyhow::Result<Option<WindowInfo>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((n == 0).then(|| window("0x0", "vanish", true)))
    }
    async fn dispatch(&self, _a: &str, _w: &str, _args: &Value) -> anyhow::Result<()> {
        Ok(())
    }
}

/// No windows at all — `resolve_window` `NoActive` and the
/// `{"focused": null}` arm.
struct NoWindows;

#[async_trait]
impl WindowProvider for NoWindows {
    async fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        Ok(vec![])
    }
    async fn active_window(&self) -> anyhow::Result<Option<WindowInfo>> {
        Ok(None)
    }
    async fn dispatch(&self, _a: &str, _w: &str, _args: &Value) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Two windows sharing the substring "dup" — `resolve_window` Ambiguous.
struct DupWindows;

#[async_trait]
impl WindowProvider for DupWindows {
    async fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        Ok(vec![
            window("0xA", "dup one", true),
            window("0xB", "dup two", false),
        ])
    }
    async fn active_window(&self) -> anyhow::Result<Option<WindowInfo>> {
        Ok(Some(window("0xA", "dup one", true)))
    }
    async fn dispatch(&self, _a: &str, _w: &str, _args: &Value) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Every window call fails — `resolve_window` Backend arm.
struct FailWindow;

#[async_trait]
impl WindowProvider for FailWindow {
    async fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        anyhow::bail!("compositor ipc down")
    }
    async fn active_window(&self) -> anyhow::Result<Option<WindowInfo>> {
        anyhow::bail!("compositor ipc down")
    }
    async fn dispatch(&self, _a: &str, _w: &str, _args: &Value) -> anyhow::Result<()> {
        anyhow::bail!("compositor ipc down")
    }
}

/// OCR/icon detections — one matching and one non-matching word.
struct OcrVision;

#[async_trait]
impl VisionProvider for OcrVision {
    async fn recognize_text(&self, _frame: &Frame) -> anyhow::Result<Vec<Detection>> {
        Ok(vec![
            Detection {
                text: "Hello".into(),
                rect: Rect {
                    x: 1,
                    y: 2,
                    w: 10,
                    h: 5,
                },
                confidence: 0.9,
            },
            Detection {
                text: "unrelated".into(),
                rect: Rect {
                    x: 0,
                    y: 0,
                    w: 5,
                    h: 5,
                },
                confidence: 0.5,
            },
        ])
    }
    async fn find_icon(&self, _frame: &Frame, desc: &str) -> anyhow::Result<Vec<Detection>> {
        Ok(vec![Detection {
            text: desc.to_string(),
            rect: Rect {
                x: 3,
                y: 4,
                w: 8,
                h: 8,
            },
            confidence: 0.7,
        }])
    }
}

/// `ensure_ready` fails — `web_query`'s readiness `backend!` arm.
struct FailBrowser;

#[async_trait]
impl BrowserProvider for FailBrowser {
    async fn query_selector(&self, _s: &str) -> anyhow::Result<Value> {
        anyhow::bail!("cdp down")
    }
    async fn ensure_ready(&self) -> anyhow::Result<()> {
        anyhow::bail!("cdp down")
    }
}

/// Returns a fixed payload — `web_query` envelope-normalization arms.
struct RawBrowser(Value);

#[async_trait]
impl BrowserProvider for RawBrowser {
    async fn query_selector(&self, _s: &str) -> anyhow::Result<Value> {
        Ok(self.0.clone())
    }
    async fn ensure_ready(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// `capture_frame` fails — screenshot/color_at `backend!` arms.
struct FailCapture;

#[async_trait]
impl CaptureProvider for FailCapture {
    async fn capture_frame(&self, _r: Option<Rect>) -> anyhow::Result<Frame> {
        anyhow::bail!("screencopy failed")
    }
    async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
        anyhow::bail!("screencopy failed")
    }
    async fn screen_info(&self) -> anyhow::Result<Value> {
        anyhow::bail!("screencopy failed")
    }
}

/// Records the `region` passed to `capture_frame` — proves spatial-focus
/// scoping actually reaches the capture backend.
#[derive(Default)]
struct SpyCapture {
    last: Mutex<Option<Rect>>,
}

impl SpyCapture {
    fn last_region(&self) -> Option<Rect> {
        *self.last.lock().unwrap()
    }
}

#[async_trait]
impl CaptureProvider for SpyCapture {
    async fn capture_frame(&self, r: Option<Rect>) -> anyhow::Result<Frame> {
        *self.last.lock().unwrap() = r;
        // Pixel content is irrelevant — the vision fixtures ignore it.
        Ok(Frame {
            png: vec![],
            width: r.map_or(1920, |r| r.w.max(1)) as u32,
            height: r.map_or(1080, |r| r.h.max(1)) as u32,
        })
    }
    async fn cursor_position(&self) -> anyhow::Result<(i32, i32)> {
        Ok((0, 0))
    }
    async fn screen_info(&self) -> anyhow::Result<Value> {
        Ok(json!({"monitors":[{"name":"mock","width":1920,"height":1080}]}))
    }
}

// ---------------------------------------------------------------------------
// 1. Happy paths — every tool through the secured pipeline.
// ---------------------------------------------------------------------------

/// All non-gated tools return Ok with non-empty content under all-mocks.
/// (`screen_highlight` is excluded: it honestly reports -32010 until the
/// layer-shell overlay backend lands — covered below.)
#[tokio::test]
async fn happy_path_every_ungated_tool() {
    // This test installs a spatial-focus rect via valid_args; hold the
    // lock so no other test observes it, and clear before returning.
    let _focus = focus_lock().await;
    let c = ctx(Providers::all_mocks());
    for name in [
        "mouse_click",
        "mouse_double_click",
        "mouse_move",
        "mouse_get_position",
        "mouse_scroll",
        "mouse_drag",
        "mouse_button_control",
        "type_text",
        "key_control",
        "screenshot",
        "screen_info",
        "color_at",
        "set_spatial_focus",
        "get_ui_tree",
        "get_focused_element",
        "find_element",
        "find_text_on_screen",
        "find_icon",
        "wait_for_ui_element",
        "sleep",
        "mouse_move_path",
        "web_query",
        "window_control",
        "get_windows",
        "get_active_window",
        "metrics",
        "get_action_history",
    ] {
        let res = secured(&c, name, valid_args(name)).await;
        assert_success(&res, name);
    }
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
}

#[tokio::test]
async fn happy_path_with_key_id_binds_caller() {
    let c = ctx(Providers::all_mocks());
    let res = call_tool_secured(
        "mouse_click",
        args(json!({"x": 1, "y": 2})),
        &c.providers,
        &c.sec,
        SESSION,
        Some("key-abc"),
    )
    .await;
    assert_success(&res, "mouse_click with key_id");
}

// --- mouse ---

#[tokio::test]
async fn mouse_click_all_button_variants() {
    let c = ctx(Providers::all_mocks());
    for (button, word) in [("left", "left"), ("right", "right"), ("middle", "middle")] {
        let res = secured(
            &c,
            "mouse_click",
            args(json!({"x": 3, "y": 4, "button": button})),
        )
        .await
        .unwrap();
        assert_eq!(text_of(&res), format!("Clicked {word} at (3, 4)"));
    }
    // Default button arm.
    let res = secured(&c, "mouse_click", args(json!({"x": 1, "y": 1})))
        .await
        .unwrap();
    assert_eq!(text_of(&res), "Clicked left at (1, 1)");
}

#[tokio::test]
async fn mouse_double_click_and_move() {
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "mouse_double_click",
        args(json!({"x": 7, "y": 9, "button": "right"})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "Double-clicked right at (7, 9)");

    // Negative logical coords are legal.
    let res = secured(&c, "mouse_move", args(json!({"x": -50, "y": 20})))
        .await
        .unwrap();
    assert_eq!(text_of(&res), "Pointer moved to (-50, 20)");
}

#[tokio::test]
async fn mouse_get_position_prefers_input_then_capture() {
    // Input provider present.
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "mouse_get_position", args(json!({})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["x"], 0);
    assert_eq!(v["y"], 0);
    // (0,0) sits inside the mock 1920×1080 output at origin — the
    // output-under-pointer resolves to the mock monitor's name.
    assert_eq!(v["display"], "mock");

    // Capture-only fallback arm.
    let c = ctx(providers_with(|p| p.capture = Some(Arc::new(MockCapture))));
    let res = secured(&c, "mouse_get_position", args(json!({})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["x"], 0);
}

#[tokio::test]
async fn mouse_scroll_each_axis() {
    let c = ctx(Providers::all_mocks());
    for a in [json!({"dx": 3, "dy": 0}), json!({"dx": 0, "dy": -2})] {
        let res = secured(&c, "mouse_scroll", args(a)).await.unwrap();
        assert!(text_of(&res).starts_with("Scrolled dx="));
    }
}

#[tokio::test]
async fn mouse_drag_instant_and_timed() {
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "mouse_drag",
        args(json!({"from_x": 0, "from_y": 0, "to_x": 50, "to_y": 50, "duration_ms": 0})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "Dragged left from (0, 0) to (50, 50) in 0ms");

    // Timed drag with a non-default button — interpolation + sleep arms.
    let res = secured(
        &c,
        "mouse_drag",
        args(json!({
            "from_x": 0, "from_y": 0, "to_x": 32, "to_y": 0,
            "button": "middle", "duration_ms": 64
        })),
    )
    .await
    .unwrap();
    assert!(text_of(&res).starts_with("Dragged middle"));
}

/// Upper steps-clamp arm without wall-clock cost (paused time).
#[tokio::test(start_paused = true)]
async fn mouse_drag_max_duration_clamped() {
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "mouse_drag",
        args(json!({
            "from_x": 0, "from_y": 0, "to_x": 10, "to_y": 10,
            "duration_ms": 10000
        })),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("in 10000ms"));
}

#[tokio::test]
async fn mouse_drag_mid_move_failure_still_releases() {
    let c = ctx(providers_with(|p| {
        p.input = Some(Arc::new(DragFailInput {
            moves: AtomicUsize::new(0),
        }))
    }));
    let res = secured(
        &c,
        "mouse_drag",
        args(json!({"from_x": 0, "from_y": 0, "to_x": 10, "to_y": 0, "duration_ms": 32})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("mid-drag move failed"));
}

#[tokio::test]
async fn mouse_button_control_down_and_up() {
    let c = ctx(Providers::all_mocks());
    for (action, tail) in [("down", "down"), ("up", "up")] {
        let res = secured(
            &c,
            "mouse_button_control",
            args(json!({"button": "right", "action": action})),
        )
        .await
        .unwrap();
        assert_eq!(text_of(&res), format!("right button {tail}"));
    }
}

/// Button-state tracking (TOOLS.md `mouse_button_control`): releasing an
/// unpressed button is a no-op *success*, as is re-pressing a held one.
/// Uses `middle` — no other test ever holds it.
#[tokio::test]
async fn mouse_button_control_tracks_held_state() {
    let c = ctx(Providers::all_mocks());
    // up without a prior down → no-op success, nothing injected.
    let res = secured(
        &c,
        "mouse_button_control",
        args(json!({"button": "middle", "action": "up"})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "middle button up");
    // down then a redundant down → both succeed; second is a no-op.
    for _ in 0..2 {
        let res = secured(
            &c,
            "mouse_button_control",
            args(json!({"button": "middle", "action": "down"})),
        )
        .await
        .unwrap();
        assert_eq!(text_of(&res), "middle button down");
    }
    let res = secured(
        &c,
        "mouse_button_control",
        args(json!({"button": "middle", "action": "up"})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "middle button up");
}

/// Held state is only mutated on successful injection: a failing backend
/// leaves the tracker untouched and reports isError.
#[tokio::test]
async fn mouse_button_control_failed_down_is_not_tracked() {
    let c = ctx(providers_with(|p| p.input = Some(Arc::new(FailInput))));
    let res = secured(
        &c,
        "mouse_button_control",
        args(json!({"button": "middle", "action": "down"})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    // A subsequent up is still the unpressed no-op success path.
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "mouse_button_control",
        args(json!({"button": "middle", "action": "up"})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(false));
}

#[tokio::test]
async fn mouse_tools_backend_error_is_tool_error() {
    let c = ctx(providers_with(|p| p.input = Some(Arc::new(FailInput))));
    for (name, a) in [
        ("mouse_click", json!({"x": 1, "y": 1})),
        ("mouse_move", json!({"x": 1, "y": 1})),
        ("mouse_scroll", json!({"dx": 1, "dy": 0})),
        (
            "mouse_button_control",
            json!({"button": "left", "action": "down"}),
        ),
    ] {
        let res = secured(&c, name, args(a)).await.unwrap();
        assert_eq!(res.is_error, Some(true), "{name} must be isError");
        assert!(text_of(&res).contains("input backend down"));
    }
}

// --- keyboard ---

#[tokio::test]
async fn type_text_fast_and_delayed_paths() {
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "type_text",
        args(json!({"text": "hello", "delay_ms": 0})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "Typed 5 characters");

    // Per-char path with inter-key delay (peek.is_some both ways).
    let res = secured(&c, "type_text", args(json!({"text": "ab", "delay_ms": 1})))
        .await
        .unwrap();
    assert_eq!(text_of(&res), "Typed 2 characters");

    // \n and \t are the permitted control bytes.
    let res = secured(
        &c,
        "type_text",
        args(json!({"text": "a\nb\tc", "delay_ms": 0})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "Typed 5 characters");
}

/// Mid-sequence abort: the delayed path re-checks the active window
/// between key events (§Focus Safety) instead of waiting for the post-hoc
/// check.
#[tokio::test]
async fn type_text_delayed_aborts_mid_sequence_on_focus_change() {
    let c = ctx(providers_with(|p| {
        p.input = Some(Arc::new(MockInput));
        p.window = Some(Arc::new(FocusFlipper {
            calls: AtomicUsize::new(0),
        }));
    }));
    let res = secured(
        &c,
        "type_text",
        args(json!({"text": "hello", "delay_ms": 1})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    let t = text_of(&res);
    assert!(t.contains("FocusChanged"), "{t}");
    assert!(t.contains("aborted"), "{t}");
}

#[tokio::test]
async fn type_text_focus_change_and_vanish_arms() {
    // Focus flips mid-action → FocusChanged isError result.
    let c = ctx(providers_with(|p| {
        p.input = Some(Arc::new(MockInput));
        p.window = Some(Arc::new(FocusFlipper {
            calls: AtomicUsize::new(0),
        }));
    }));
    let res = secured(&c, "type_text", args(json!({"text": "hi", "delay_ms": 0})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("FocusChanged"), "{res:?}");

    // Focus present before, gone after → unchanged-check `_` arm.
    let c = ctx(providers_with(|p| {
        p.input = Some(Arc::new(MockInput));
        p.window = Some(Arc::new(FocusVanish {
            calls: AtomicUsize::new(0),
        }));
    }));
    let res = secured(&c, "type_text", args(json!({"text": "hi", "delay_ms": 0})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(false));
}

#[tokio::test]
async fn key_control_all_actions_and_modifier_order() {
    let c = ctx(Providers::all_mocks());
    for (action, text) in [("press", "Pressed a"), ("down", "a down"), ("up", "a up")] {
        let res = secured(
            &c,
            "key_control",
            args(json!({"key": "a", "action": action})),
        )
        .await
        .unwrap();
        assert_eq!(text_of(&res), text);
    }

    // All four modifiers, unsorted + duplicated: sort/dedup + every
    // key_name/as_str arm, and the canonical combo order in the text.
    let res = secured(
        &c,
        "key_control",
        args(json!({
            "key": "Return", "action": "press",
            "modifiers": ["super", "alt", "ctrl", "shift"]
        })),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "Pressed ctrl+shift+alt+super+Return");

    let res = secured(
        &c,
        "key_control",
        args(json!({
            "key": "c", "action": "down",
            "modifiers": ["shift", "ctrl", "shift"]
        })),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "ctrl+shift+c down");
}

#[tokio::test]
async fn key_control_key_name_validation() {
    let c = ctx(Providers::all_mocks());
    // Valid: single printable char, F-key in range, known keysym.
    for key in ["å", "F1", "f24", "minus", "kp_enter"] {
        let res = secured(
            &c,
            "key_control",
            args(json!({"key": key, "action": "press"})),
        )
        .await;
        assert_success(&res, &format!("key_control {key:?}"));
    }
    // Invalid: empty, F-key out of range, unknown multi-char, control byte,
    // >4 modifiers, unknown modifier enum.
    for (a, why) in [
        (json!({"key": "", "action": "press"}), "empty key"),
        (
            json!({"key": "F25", "action": "press"}),
            "F-key out of range",
        ),
        (
            json!({"key": "notakey", "action": "press"}),
            "unknown keysym",
        ),
        (
            json!({"key": "a\u{7}", "action": "press"}),
            "control byte in key",
        ),
        (
            json!({"key": "a", "action": "press",
                   "modifiers": ["ctrl", "shift", "alt", "super", "ctrl"]}),
            "five modifiers",
        ),
        (
            json!({"key": "a", "action": "press", "modifiers": ["bogus"]}),
            "bad modifier enum",
        ),
        (json!({"key": "a"}), "missing action"),
        (json!({"key": "a", "action": "tap"}), "bad action enum"),
    ] {
        let res = secured(&c, "key_control", args(a)).await;
        assert_error_code(&res, &[INVALID_PARAMS], why);
    }
}

#[tokio::test]
async fn key_control_backend_failure_releases_modifiers() {
    let c = ctx(providers_with(|p| {
        p.input = Some(Arc::new(KeyFailInput));
        p.window = Some(Arc::new(MockWindow));
    }));
    let res = secured(
        &c,
        "key_control",
        args(json!({"key": "a", "action": "press", "modifiers": ["ctrl"]})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("key event failed"));
}

#[tokio::test]
async fn type_text_backend_failure_is_tool_error() {
    let c = ctx(providers_with(|p| p.input = Some(Arc::new(FailInput))));
    let res = secured(&c, "type_text", args(json!({"text": "hi", "delay_ms": 0})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));
}

// --- vision ---

#[tokio::test]
async fn screenshot_scope_variants_return_image() {
    let _focus = focus_lock().await;
    // Ensure no leftover focus rect skews the "full layout" scope.
    let c = ctx(Providers::all_mocks());
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
    for (a, needle) in [
        (json!({}), "full layout"),
        (
            json!({"region": {"x": 1, "y": 2, "w": 3, "h": 4}}),
            "region (1,2,3,4)",
        ),
        // MockCapture's screen_info advertises one output named "mock".
        (json!({"display": "mock"}), "display mock"),
    ] {
        let res = secured(&c, "screenshot", args(a)).await.unwrap();
        assert_eq!(res.is_error, Some(false));
        assert_eq!(res.content.len(), 2);
        assert!(text_of(&res).contains(needle));
        assert!(res.content[1].as_image().is_some());
    }
}

#[tokio::test]
async fn screenshot_display_resolution_arms() {
    let _focus = focus_lock().await;
    let c = ctx(Providers::all_mocks());
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();

    // Unknown output name → InvalidParams listing the known outputs.
    let res = secured(&c, "screenshot", args(json!({"display": "eDP-9"}))).await;
    assert_error_code(&res, &[INVALID_PARAMS], "unknown display");

    // screen_info failing → isError (not InvalidParams).
    let c = ctx(providers_with(|p| p.capture = Some(Arc::new(FailCapture))));
    let res = secured(&c, "screenshot", args(json!({"display": "x"})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("screencopy failed"));
}

/// `screenshot` with no explicit region captures the spatial-focus rect.
#[tokio::test]
async fn screenshot_uses_spatial_focus_scope() {
    let _focus = focus_lock().await;
    let c = ctx(Providers::all_mocks());
    secured(
        &c,
        "set_spatial_focus",
        args(json!({"x": 7, "y": 8, "w": 9, "h": 10})),
    )
    .await
    .unwrap();
    let res = secured(&c, "screenshot", args(json!({}))).await.unwrap();
    assert!(text_of(&res).contains("spatial focus (7,8,9,10)"));
    // Explicit region still wins over the focus rect.
    let res = secured(
        &c,
        "screenshot",
        args(json!({"region": {"x":0,"y":0,"w":2,"h":2}})),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("region (0,0,2,2)"));
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
}

#[tokio::test]
async fn capture_backend_failure_is_tool_error() {
    let c = ctx(providers_with(|p| p.capture = Some(Arc::new(FailCapture))));
    for (name, a) in [
        ("screenshot", json!({})),
        ("color_at", json!({"x": 0, "y": 0})),
        ("screen_info", json!({})),
    ] {
        let res = secured(&c, name, args(a)).await.unwrap();
        assert_eq!(res.is_error, Some(true), "{name} must be isError");
        assert!(text_of(&res).contains("screencopy failed"), "{name}");
    }
}

#[tokio::test]
async fn screen_info_highlight_color_at() {
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "screen_info", args(json!({}))).await.unwrap();
    assert!(json_of(&res)["monitors"].is_array());

    // No overlay backend exists — the call validates then reports
    // -32010 ProviderUnavailable (a no-op success would be a lie).
    let res = secured(
        &c,
        "screen_highlight",
        args(json!({"x": 5, "y": 6, "w": 7, "h": 8, "duration_ms": 200})),
    )
    .await;
    assert_error_code(&res, &[PROVIDER_UNAVAILABLE], "screen_highlight");
    let e = res.unwrap_err();
    assert_eq!(e.data.unwrap()["provider"], "OverlayProvider");

    // Real 1x1 capture decoded: the mock's PNG is white → #FFFFFF.
    let res = secured(&c, "color_at", args(json!({"x": 9, "y": 9})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["hex"], "#FFFFFF");
    assert_eq!(v["r"], 255);
    assert_eq!(v["g"], 255);
    assert_eq!(v["b"], 255);
    assert_eq!(v["a"], 255);
    assert_eq!(v["x"], 9);
    assert_eq!(v["y"], 9);
}

/// `color_at` rejects points outside the layout bounds with -32602
/// (mock advertises a single 1920x1080 output at the origin).
#[tokio::test]
async fn color_at_out_of_bounds_rejected() {
    let c = ctx(Providers::all_mocks());
    for (x, y) in [(1920, 0), (0, 1080), (-1, 0), (0, -1)] {
        let res = secured(&c, "color_at", args(json!({"x": x, "y": y}))).await;
        assert_error_code(&res, &[INVALID_PARAMS], &format!("color_at {x},{y}"));
    }
    // A backend that cannot enumerate outputs skips the check.
    let c = ctx(providers_with(|p| p.capture = Some(Arc::new(FailCapture))));
    let res = secured(&c, "color_at", args(json!({"x": 9, "y": 9})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true)); // capture fails, not InvalidParams
}

#[tokio::test]
async fn set_spatial_focus_arms() {
    let _focus = focus_lock().await;
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "set_spatial_focus",
        args(json!({"x": 0, "y": 0, "w": 10, "h": 10})),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("Spatial focus set"));

    let res = secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
    assert!(text_of(&res).contains("cleared"));

    for a in [
        json!({}),
        json!({"x": 0}),
        json!({"x": 0, "y": 0, "w": 0, "h": 5}),
        json!({"clear": false}),
    ] {
        let res = secured(&c, "set_spatial_focus", args(a)).await;
        assert_error_code(&res, &[INVALID_PARAMS], "set_spatial_focus");
    }
}

#[tokio::test]
async fn get_ui_tree_and_focused_element() {
    let c = ctx(Providers::all_mocks());
    for depth in [1, 16] {
        let res = secured(&c, "get_ui_tree", args(json!({"depth": depth})))
            .await
            .unwrap();
        assert_eq!(json_of(&res)["role"], "desktop");
    }
    // Object arm of get_focused_element.
    let res = secured(&c, "get_focused_element", args(json!({})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["role"], "application");

    // Null arm.
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(FocusedVal(Value::Null)))
    }));
    let res = secured(&c, "get_focused_element", args(json!({})))
        .await
        .unwrap();
    assert_eq!(json_of(&res), json!({"found": false}));

    // Non-object arm.
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(FocusedVal(json!("raw-scalar"))))
    }));
    let res = secured(&c, "get_focused_element", args(json!({})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["element"], "raw-scalar");
}

#[tokio::test]
async fn find_element_found_and_not_found() {
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "find_element", args(json!({"query": "nope"})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], false);
    assert_eq!(v["count"], 0);

    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(UiFound { invoke_ok: true }))
    }));
    let res = secured(&c, "find_element", args(json!({"query": "hit"})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(
        v["matches"][0]["bounds"],
        json!({"x":10,"y":20,"w":30,"h":40})
    );
    assert_eq!(v["matches"][0]["center"], json!({"x":25,"y":40}));
}

#[tokio::test]
async fn find_text_on_screen_ocr_paths() {
    let _focus = focus_lock().await;
    // Mock OCR → no detections → found:false. (Explicit region wins over
    // the focus rect; ensure none is installed.)
    let c = ctx(Providers::all_mocks());
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
    let res = secured(
        &c,
        "find_text_on_screen",
        args(json!({"text": "hello", "region": {"x":0,"y":0,"w":10,"h":10}})),
    )
    .await
    .unwrap();
    assert_eq!(json_of(&res)["found"], false);

    // Detections with one case-insensitive match and one miss.
    let c = ctx(providers_with(|p| {
        p.vision = Some(Arc::new(OcrVision));
        p.capture = Some(Arc::new(MockCapture));
    }));
    let res = secured(&c, "find_text_on_screen", args(json!({"text": "HELLO"})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["count"], 1);
    assert_eq!(v["matches"][0]["text"], "Hello");
    assert_eq!(v["matches"][0]["center"], json!({"x":6,"y":4}));
}

#[tokio::test]
async fn find_icon_with_detections() {
    let _focus = focus_lock().await;
    let c = ctx(Providers::all_mocks());
    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
    let res = secured(&c, "find_icon", args(json!({"description": "gear"})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["found"], false);

    let c = ctx(providers_with(|p| {
        p.vision = Some(Arc::new(OcrVision));
        p.capture = Some(Arc::new(MockCapture));
    }));
    let res = secured(&c, "find_icon", args(json!({"description": "hamburger"})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["detections"][0]["label"], "hamburger");
}

/// Spatial focus narrows `find_text_on_screen`/`find_icon`: the focus
/// rect is passed to `capture_frame` and frame-local detections are
/// re-mapped into layout coordinates.
#[tokio::test]
async fn find_text_and_icon_scoped_by_spatial_focus() {
    let _focus = focus_lock().await;
    let spy = Arc::new(SpyCapture::default());
    let c = ctx(providers_with(|p| {
        p.vision = Some(Arc::new(OcrVision));
        p.capture = Some(spy.clone());
    }));
    secured(
        &c,
        "set_spatial_focus",
        args(json!({"x": 50, "y": 60, "w": 70, "h": 80})),
    )
    .await
    .unwrap();

    let res = secured(&c, "find_text_on_screen", args(json!({"text": "hello"})))
        .await
        .unwrap();
    assert_eq!(
        spy.last_region(),
        Some(Rect {
            x: 50,
            y: 60,
            w: 70,
            h: 80
        })
    );
    // Detection local (1,2,10,5) → layout (51,62,10,5).
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(
        v["matches"][0]["bounds"],
        json!({"x":51,"y":62,"w":10,"h":5})
    );
    assert_eq!(v["matches"][0]["center"], json!({"x":56,"y":64}));

    // An explicit `region` overrides the focus rect.
    let res = secured(
        &c,
        "find_text_on_screen",
        args(json!({"text": "hello", "region": {"x":0,"y":0,"w":20,"h":20}})),
    )
    .await
    .unwrap();
    assert_eq!(
        spy.last_region(),
        Some(Rect {
            x: 0,
            y: 0,
            w: 20,
            h: 20
        })
    );
    assert_eq!(v["found"], true);
    let v = json_of(&res);
    assert_eq!(v["matches"][0]["bounds"], json!({"x":1,"y":2,"w":10,"h":5}));

    // find_icon scopes the same way — the focus rect applies again (the
    // explicit `region` above was per-call, not persistent).
    let res = secured(&c, "find_icon", args(json!({"description": "gear"})))
        .await
        .unwrap();
    assert_eq!(
        spy.last_region(),
        Some(Rect {
            x: 50,
            y: 60,
            w: 70,
            h: 80
        })
    );
    let v = json_of(&res);
    assert_eq!(
        v["detections"][0]["bounds"],
        json!({"x":53,"y":64,"w":8,"h":8})
    );

    secured(&c, "set_spatial_focus", args(json!({"clear": true})))
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn wait_for_ui_element_all_outcomes() {
    // Timeout → success carrying timed_out (paused clock, no real wait).
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "wait_for_ui_element",
        args(json!({"query": "never", "timeout_ms": 250})),
    )
    .await
    .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], false);
    assert_eq!(v["timed_out"], true);

    // Immediate hit.
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(UiFound { invoke_ok: true }))
    }));
    let res = secured(
        &c,
        "wait_for_ui_element",
        args(json!({"query": "ok", "timeout_ms": 250})),
    )
    .await
    .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["count"], 1);

    // Backend fault inside the poll loop → isError result.
    let c = ctx(providers_with(|p| p.ui_automation = Some(Arc::new(UiErr))));
    let res = secured(
        &c,
        "wait_for_ui_element",
        args(json!({"query": "x", "timeout_ms": 250})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("atspi down"));
}

#[tokio::test]
async fn invoke_element_arms() {
    // No match → -32016 ElementNotFound.
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "invoke_element",
        args(json!({"query": "ghost", "action": "press"})),
    )
    .await;
    assert_error_code(&res, &[ELEMENT_NOT_FOUND], "invoke_element no match");

    // Match + press supported via the trait-default mapping; the other
    // action spellings reach the provider as named actions — a backend
    // without named-action support reports them as action_not_supported.
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(UiFound { invoke_ok: true }))
    }));
    for (action, result) in [
        ("press", "ok"),
        ("focus", "action_not_supported"),
        ("expand", "action_not_supported"),
        ("collapse", "action_not_supported"),
    ] {
        let res = secured(
            &c,
            "invoke_element",
            args(json!({"query": "btn", "action": action})),
        )
        .await
        .unwrap();
        let v = json_of(&res);
        assert_eq!(v["action"], action);
        assert_eq!(v["action_result"], result, "{action}");
        assert_eq!(v["element"]["center"], json!({"x":25,"y":40}));
    }
    // Default action arm.
    let res = secured(&c, "invoke_element", args(json!({"query": "btn"})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["action"], "press");

    // Match + action unsupported → action_not_supported.
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(UiFound { invoke_ok: false }))
    }));
    let res = secured(
        &c,
        "invoke_element",
        args(json!({"query": "btn", "action": "focus"})),
    )
    .await
    .unwrap();
    assert_eq!(json_of(&res)["action_result"], "action_not_supported");
}

/// The requested action name must reach the provider — a backend that
/// honours AT-SPI named actions sees `"expand"`, not a silent `"press"`.
#[tokio::test]
async fn invoke_element_passes_named_action_through() {
    let c = ctx(providers_with(|p| {
        p.ui_automation = Some(Arc::new(UiNamedAction))
    }));
    // "expand" is supported by this backend…
    let res = secured(
        &c,
        "invoke_element",
        args(json!({"query": "btn", "action": "expand"})),
    )
    .await
    .unwrap();
    assert_eq!(json_of(&res)["action_result"], "ok");
    // …and "press" is not — the named method ran (the trait default would
    // have mapped press → invoke_element → ok).
    let res = secured(
        &c,
        "invoke_element",
        args(json!({"query": "btn", "action": "press"})),
    )
    .await
    .unwrap();
    assert_eq!(json_of(&res)["action_result"], "action_not_supported");
}

// --- automation ---

#[tokio::test]
async fn sleep_bounds() {
    let c = ctx(Providers::empty()); // sleep needs no provider
    let res = secured(&c, "sleep", args(json!({"ms": 0}))).await.unwrap();
    assert_eq!(text_of(&res), "Slept 0 ms");
}

#[tokio::test(start_paused = true)]
async fn sleep_max_boundary() {
    let c = ctx(Providers::empty());
    let res = secured(&c, "sleep", args(json!({"ms": 60000})))
        .await
        .unwrap();
    assert_eq!(text_of(&res), "Slept 60000 ms");
}

#[tokio::test]
async fn mouse_move_path_shapes() {
    let c = ctx(Providers::all_mocks());
    // Normal polyline with a degenerate (zero-length) segment inside —
    // covers the `len <= 0.0 continue` and `remaining -= len` arms.
    let res = secured(
        &c,
        "mouse_move_path",
        args(json!({
            "points": [{"x":0,"y":0},{"x":0,"y":0},{"x":10,"y":0},{"x":10,"y":10}],
            "duration_ms": 48
        })),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("Moved along 4-point path"));

    // All-identical points → total_len == 0 arm.
    let res = secured(
        &c,
        "mouse_move_path",
        args(json!({
            "points": [{"x":5,"y":5},{"x":5,"y":5}],
            "duration_ms": 0
        })),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("Moved along 2-point path"));

    // Backend failure mid-path.
    let c = ctx(providers_with(|p| p.input = Some(Arc::new(FailInput))));
    let res = secured(
        &c,
        "mouse_move_path",
        args(json!({"points": [{"x":0,"y":0},{"x":1,"y":1}], "duration_ms": 0})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
}

#[tokio::test]
async fn web_query_envelope_normalization() {
    // Mock browser returns {"matches": []} → found:false inserted.
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "web_query", args(json!({"selector": "button"})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["found"], false);

    // Non-empty matches → first match normalised into the spec element
    // shape, `bounds_space` defaulted, `matches` folded away.
    let c = ctx(providers_with(|p| {
        p.browser = Some(Arc::new(RawBrowser(
            json!({"matches": [{"tag": "a", "rect": {"x":1,"y":2,"w":3,"h":4}}]}),
        )))
    }));
    let res = secured(&c, "web_query", args(json!({"selector": "a"})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["found"], true);
    assert_eq!(v["bounds_space"], "viewport");
    assert_eq!(v["element"]["tag"], "a");
    assert_eq!(v["element"]["classes"], json!([]));
    assert_eq!(v["element"]["attributes"], json!({}));
    assert_eq!(v["element"]["bounds"], json!({"x":1,"y":2,"w":3,"h":4}));
    assert!(v.get("matches").is_none());

    // Envelope already present → passthrough.
    let c = ctx(providers_with(|p| {
        p.browser = Some(Arc::new(RawBrowser(json!({"found": true, "extra": 1}))))
    }));
    let res = secured(&c, "web_query", args(json!({"selector": "a"})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["extra"], 1);

    // Non-object provider payload → no normalization.
    let c = ctx(providers_with(|p| {
        p.browser = Some(Arc::new(RawBrowser(json!(["x"]))))
    }));
    let res = secured(&c, "web_query", args(json!({"selector": "a"})))
        .await
        .unwrap();
    assert_eq!(json_of(&res), json!(["x"]));

    // ensure_ready failure → isError.
    let c = ctx(providers_with(|p| p.browser = Some(Arc::new(FailBrowser))));
    let res = secured(&c, "web_query", args(json!({"selector": "a"})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("cdp down"));
}

#[tokio::test]
async fn web_query_sanitization() {
    let c = ctx(Providers::all_mocks());
    for a in [
        json!({"selector": "javascript:alert(1)"}),
        json!({"selector": "a\u{1}b"}),
    ] {
        let res = secured(&c, "web_query", args(a)).await;
        assert_error_code(&res, &[SANITIZATION_REJECTED], "web_query sanitize");
    }
}

// --- admin ---

#[tokio::test]
async fn window_control_all_actions() {
    let c = ctx(Providers::all_mocks());
    // focus by exact id, by title substring, and implicit-active arms.
    for a in [
        json!({"action": "focus", "window": "0x0"}),
        json!({"action": "focus", "window": "mock-window"}),
        json!({"action": "focus"}),
        json!({"action": "minimize", "window": "0x0"}),
        json!({"action": "move", "window": "0x0", "x": 10, "y": 20}),
        json!({"action": "resize", "window": "0x0", "w": 100, "h": 200}),
    ] {
        let res = secured(&c, "window_control", args(a.clone())).await;
        assert_success(&res, &format!("window_control {a}"));
    }
}

#[tokio::test]
async fn window_control_resolve_window_error_arms() {
    // No match.
    let c = ctx(Providers::all_mocks());
    let res = secured(
        &c,
        "window_control",
        args(json!({"action": "focus", "window": "zzz-nothing"})),
    )
    .await;
    assert_error_code(&res, &[INVALID_PARAMS], "window_control no match");

    // Ambiguous substring.
    let c = ctx(providers_with(|p| p.window = Some(Arc::new(DupWindows))));
    let res = secured(
        &c,
        "window_control",
        args(json!({"action": "focus", "window": "dup"})),
    )
    .await;
    assert_error_code(&res, &[INVALID_PARAMS], "window_control ambiguous");

    // No active window → isError (not a JSON-RPC error).
    let c = ctx(providers_with(|p| p.window = Some(Arc::new(NoWindows))));
    let res = secured(&c, "window_control", args(json!({"action": "focus"})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("no active window"));

    // Backend fault → isError.
    let c = ctx(providers_with(|p| p.window = Some(Arc::new(FailWindow))));
    let res = secured(
        &c,
        "window_control",
        args(json!({"action": "focus", "window": "x"})),
    )
    .await
    .unwrap();
    assert_eq!(res.is_error, Some(true));
    assert!(text_of(&res).contains("compositor ipc down"));
}

#[tokio::test]
async fn get_windows_and_active_window() {
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "get_windows", args(json!({}))).await.unwrap();
    let v = json_of(&res);
    assert_eq!(v[0]["address"], "0x0");
    assert_eq!(v[0]["workspace"]["id"], 1);
    // Mock window reports concrete values; a backend that cannot report
    // a field emits `null` (docs/TOOLS.md get_windows).
    assert_eq!(v[0]["floating"], false);
    assert_eq!(v[0]["fullscreen"], false);
    assert_eq!(v[0]["pid"], 1);
    assert_eq!(v[0]["monitor"], 0);

    let res = secured(&c, "get_active_window", args(json!({})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["focused"], true);

    // Nothing-focused arm.
    let c = ctx(providers_with(|p| p.window = Some(Arc::new(NoWindows))));
    let res = secured(&c, "get_active_window", args(json!({})))
        .await
        .unwrap();
    assert_eq!(json_of(&res), json!({"focused": null}));
}

#[tokio::test]
async fn metrics_returns_exposition() {
    let c = ctx(Providers::empty());
    let res = secured(&c, "metrics", args(json!({}))).await.unwrap();
    assert!(text_of(&res).contains("ultranix_mcp_tool_calls_total"));
}

// ---------------------------------------------------------------------------
// 2. Param-validation branches — -32602 through the secured gate.
//    (allow_destructive so consent never pre-empts validation.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_params_matrix_through_secured_gate() {
    let c = ctx_destructive(Providers::all_mocks());
    let points: Vec<Value> = (0..257).map(|i| json!({"x": i, "y": 0})).collect();
    let cases: &[(&str, Value)] = &[
        ("mouse_click", json!({"y": 1})),
        ("mouse_click", json!({"x": -1, "y": 2, "button": "bogus"})),
        ("mouse_double_click", json!({"x": 1})),
        ("mouse_move", json!({"x": "1", "y": 2})),
        ("mouse_get_position", json!({"bogus": 1})),
        ("mouse_scroll", json!({"dx": 0, "dy": 0})),
        ("mouse_scroll", json!({"dx": "x"})),
        ("mouse_drag", json!({"from_x": 0, "from_y": 0, "to_x": 1})),
        (
            "mouse_drag",
            json!({"from_x": 0, "from_y": 0, "to_x": 1, "to_y": 1, "duration_ms": 10001}),
        ),
        (
            "mouse_button_control",
            json!({"button": "left", "action": "hold"}),
        ),
        ("type_text", json!({"text": ""})),
        ("type_text", json!({"text": "x", "delay_ms": 1001})),
        ("type_text", json!({"text": "x".repeat(65_537)})),
        ("key_control", json!({"key": "a"})),
        ("screenshot", json!({"region": {"x":0,"y":0,"w":0,"h":5}})),
        ("screenshot", json!({"bogus": 1})),
        ("screen_info", json!({"bogus": 1})),
        ("screen_highlight", json!({"x":0,"y":0,"w":0,"h":5})),
        (
            "screen_highlight",
            json!({"x":0,"y":0,"w":5,"h":5,"duration_ms": 50}),
        ),
        (
            "screen_highlight",
            json!({"x":0,"y":0,"w":5,"h":5,"duration_ms": 30001}),
        ),
        ("color_at", json!({"x": 0})),
        ("get_ui_tree", json!({"depth": 0})),
        ("get_ui_tree", json!({"depth": 17})),
        ("get_focused_element", json!({"bogus": 1})),
        ("find_element", json!({"query": ""})),
        ("find_element", json!({"query": "q".repeat(257)})),
        ("find_text_on_screen", json!({})),
        ("find_text_on_screen", json!({"text": ""})),
        (
            "find_text_on_screen",
            json!({"text": "x", "region": {"x":0,"y":0,"w":0,"h":1}}),
        ),
        ("find_icon", json!({"description": ""})),
        ("find_icon", json!({"description": "d".repeat(257)})),
        (
            "wait_for_ui_element",
            json!({"query": "x", "timeout_ms": 249}),
        ),
        (
            "wait_for_ui_element",
            json!({"query": "x", "timeout_ms": 120001}),
        ),
        ("wait_for_ui_element", json!({"query": ""})),
        ("invoke_element", json!({"query": "x", "action": "bogus"})),
        ("invoke_element", json!({"query": ""})),
        ("sleep", json!({"ms": 60001})),
        ("mouse_move_path", json!({"points": [{"x":0,"y":0}]})),
        (
            "mouse_move_path",
            json!({"points": points, "duration_ms": 0}),
        ),
        (
            "mouse_move_path",
            json!({"points": [{"x":0,"y":0},{"x":1,"y":1}], "duration_ms": 30001}),
        ),
        ("system_command", json!({})),
        ("web_query", json!({})),
        ("web_query", json!({"selector": ""})),
        ("web_query", json!({"selector": "s".repeat(1025)})),
        ("window_control", json!({"action": "explode"})),
        ("window_control", json!({"action": "move"})),
        ("window_control", json!({"action": "move", "x": 1})),
        ("window_control", json!({"action": "resize"})),
        (
            "window_control",
            json!({"action": "resize", "w": 0, "h": 5}),
        ),
        ("get_windows", json!({"bogus": 1})),
        ("get_active_window", json!({"bogus": 1})),
        ("metrics", json!({"bogus": 1})),
        ("get_action_history", json!({"limit": 0})),
        ("get_action_history", json!({"limit": 1001})),
        ("replay_action", json!({})),
        (
            "replay_action",
            json!({"index": 0, "id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12"}),
        ),
        ("replay_action", json!({"id": "tooshort"})),
        ("replay_action", json!({"index": 9999})),
        ("clear_action_history", json!({"bogus": 1})),
    ];
    for (name, a) in cases {
        let res = secured(&c, name, args(a.clone())).await;
        assert_error_code(&res, &[INVALID_PARAMS], &format!("{name} {a}"));
    }
}

#[tokio::test]
async fn sanitization_rejected_branches() {
    let c = ctx(Providers::all_mocks());
    // type_text control byte (not \n / \t).
    let res = secured(
        &c,
        "type_text",
        args(json!({"text": "a\u{7}b", "delay_ms": 0})),
    )
    .await;
    assert_error_code(&res, &[SANITIZATION_REJECTED], "type_text control byte");
}

// ---------------------------------------------------------------------------
// 3. Provider-absent branches — -32010 with the right provider name.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_absent_matrix() {
    let c = ctx(Providers::empty());
    let cases: &[(&str, Value, &str)] = &[
        ("mouse_click", json!({"x":1,"y":2}), "InputProvider"),
        ("mouse_double_click", json!({"x":1,"y":2}), "InputProvider"),
        ("mouse_move", json!({"x":1,"y":2}), "InputProvider"),
        ("mouse_get_position", json!({}), "InputProvider"),
        ("mouse_scroll", json!({"dx":1,"dy":0}), "InputProvider"),
        (
            "mouse_drag",
            json!({"from_x":0,"from_y":0,"to_x":1,"to_y":1}),
            "InputProvider",
        ),
        (
            "mouse_button_control",
            json!({"button":"left","action":"down"}),
            "InputProvider",
        ),
        ("type_text", json!({"text":"hi"}), "InputProvider"),
        (
            "key_control",
            json!({"key":"a","action":"press"}),
            "InputProvider",
        ),
        ("screenshot", json!({}), "CaptureProvider"),
        ("screen_info", json!({}), "CaptureProvider"),
        (
            "screen_highlight",
            json!({"x":0,"y":0,"w":5,"h":5,"duration_ms":200}),
            "CaptureProvider",
        ),
        ("color_at", json!({"x":0,"y":0}), "CaptureProvider"),
        ("get_ui_tree", json!({}), "UIAutomationProvider"),
        ("get_focused_element", json!({}), "UIAutomationProvider"),
        ("find_element", json!({"query":"x"}), "UIAutomationProvider"),
        ("find_text_on_screen", json!({"text":"x"}), "VisionProvider"),
        ("find_icon", json!({"description":"x"}), "VisionProvider"),
        (
            "wait_for_ui_element",
            json!({"query":"x","timeout_ms":250}),
            "UIAutomationProvider",
        ),
        (
            "invoke_element",
            json!({"query":"x"}),
            "UIAutomationProvider",
        ),
        (
            "mouse_move_path",
            json!({"points":[{"x":0,"y":0},{"x":1,"y":1}]}),
            "InputProvider",
        ),
        ("web_query", json!({"selector":"a"}), "BrowserProvider"),
        (
            "window_control",
            json!({"action":"focus"}),
            "WindowProvider",
        ),
        ("get_windows", json!({}), "WindowProvider"),
        ("get_active_window", json!({}), "WindowProvider"),
    ];
    for (name, a, provider) in cases {
        let res = secured(&c, name, args(a.clone())).await;
        match res {
            Err(e) => {
                assert_eq!(e.code.0, PROVIDER_UNAVAILABLE, "{name} {a}: {e:?}");
                assert!(
                    e.message.contains(provider),
                    "{name}: expected {provider} in {:?}",
                    e.message
                );
            }
            Ok(r) => panic!("{name} {a}: expected -32010, got Ok({r:?})"),
        }
    }
}

/// Vision present but capture absent → the *second* provider lookup fails.
#[tokio::test]
async fn find_text_and_icon_capture_absent() {
    let c = ctx(providers_with(|p| {
        p.vision = Some(Arc::new(OcrVision));
    }));
    for (name, a) in [
        ("find_text_on_screen", json!({"text": "x"})),
        ("find_icon", json!({"description": "x"})),
    ] {
        let err = secured(&c, name, args(a)).await.unwrap_err();
        assert_eq!(err.code.0, PROVIDER_UNAVAILABLE, "{name}");
        assert!(err.message.contains("CaptureProvider"), "{name}: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// 4. Consent branches.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn destructive_tools_challenge_without_token() {
    let c = ctx(Providers::all_mocks());
    for (name, a) in [
        ("system_command", json!({"command": "slurp"})),
        ("replay_action", json!({"index": 0})),
        ("clear_action_history", json!({})),
        (
            "window_control",
            json!({"action": "close", "window": "0x0"}),
        ),
    ] {
        let err = secured(&c, name, args(a)).await.unwrap_err();
        assert_eq!(err.code.0, CONSENT_REQUIRED, "{name} must challenge");
        let data = err.data.unwrap();
        assert_eq!(data["kind"], "ConsentRequired");
        assert!(data["consent_token"].as_str().unwrap().len() > 8);
        assert!(data["expires_in_ms"].as_u64().unwrap() > 0);
    }
}

/// `window_control{close}` without `window` resolves the active window at
/// challenge time (target-scoped token) — both the Some and None arms.
#[tokio::test]
async fn window_close_target_scoped_challenge() {
    // Active window resolvable → challenge_for_target arm.
    let c = ctx(Providers::all_mocks());
    let err = secured(&c, "window_control", args(json!({"action": "close"})))
        .await
        .unwrap_err();
    assert_eq!(err.code.0, CONSENT_REQUIRED);
    let token = consent_token(&err);

    // Retry with the token: verified against the resolved target ("0x0").
    let res = secured(
        &c,
        "window_control",
        args(json!({"action": "close", "consent_token": token})),
    )
    .await;
    assert_success(&res, "window_control close with valid token");

    // No window provider → target unresolvable → plain challenge arm.
    let c = ctx(Providers::empty());
    let err = secured(&c, "window_control", args(json!({"action": "close"})))
        .await
        .unwrap_err();
    assert_eq!(err.code.0, CONSENT_REQUIRED);
}

/// A wrong / foreign token does not satisfy the gate.
#[tokio::test]
async fn wrong_consent_token_still_challenges() {
    let c = ctx(Providers::all_mocks());
    let err = secured(
        &c,
        "clear_action_history",
        args(json!({"consent_token": "forged-token"})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code.0, CONSENT_REQUIRED);
}

/// Challenge → retry roundtrip: the verified path executes the tool.
#[tokio::test]
async fn consent_token_retry_executes() {
    let c = ctx(Providers::all_mocks());
    let err = secured(&c, "clear_action_history", args(json!({})))
        .await
        .unwrap_err();
    let token = consent_token(&err);
    let res = secured(
        &c,
        "clear_action_history",
        args(json!({"consent_token": token.clone()})),
    )
    .await
    .unwrap();
    assert!(text_of(&res).contains("Action history cleared"));

    // Single-use: a second call with the consumed token is challenged again.
    let err = secured(
        &c,
        "clear_action_history",
        args(json!({"consent_token": token})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code.0, CONSENT_REQUIRED);
}

/// `--allow-destructive` bypasses the gate entirely: gated tools dispatch.
#[tokio::test]
async fn allow_destructive_bypasses_consent() {
    let c = ctx_destructive(Providers::all_mocks());

    let res = secured(&c, "clear_action_history", args(json!({})))
        .await
        .unwrap();
    assert!(text_of(&res).contains("Action history cleared"));

    let res = secured(
        &c,
        "window_control",
        args(json!({"action": "close", "window": "0x0"})),
    )
    .await
    .unwrap();
    assert_eq!(text_of(&res), "close applied to 0x0 (\"mock-window\")");

    // replay_action clears the gate, then fails selector resolution
    // against an empty store — a fresh context, since the calls above
    // already recorded history entries into `c`.
    let c2 = ctx_destructive(Providers::all_mocks());
    let res = secured(&c2, "replay_action", args(json!({"index": 0}))).await;
    assert_error_code(&res, &[INVALID_PARAMS], "replay_action past gate");

    // system_command reaches the real exec path (not the Phase-0 stub).
    let res = secured(&c, "system_command", args(json!({"command": "nope"}))).await;
    assert_error_code(&res, &[COMMAND_NOT_WHITELISTED], "unpinned command");
}

// ---------------------------------------------------------------------------
// 5. system_command — secured exec path + unsecured Phase-0 stub.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_command_secured_exec_paths() {
    let c = ctx_destructive(Providers::empty());

    // Missing `command` → -32602 from exec_system_command itself.
    let res = secured(&c, "system_command", args(json!({}))).await;
    assert_error_code(&res, &[INVALID_PARAMS], "missing command");

    // Non-string args are filtered out of argv (filter_map arm) — the
    // surviving "monitors" read subcommand still validates and executes.
    // (Deliberately `hyprctl`, not `slurp`: slurp blocks on interactive
    // region selection under a live session.)
    let res = secured(
        &c,
        "system_command",
        args(json!({"command": "hyprctl", "args": ["monitors", 5]})),
    )
    .await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert_eq!(e.code.0, ARG_CONSTRAINT, "hyprctl exec: {e:?}"),
    }

    // `grim` exercises the server-supplied capture-dir arm (created then
    // unlinked after use). If grim is absent the pin rejects it — both
    // are deterministic, typed outcomes.
    let res = secured(&c, "system_command", args(json!({"command": "grim"}))).await;
    match res {
        Ok(r) => {
            let v = json_of(&r);
            assert!(v.get("exit_code").is_some() || v.get("timed_out").is_some());
        }
        Err(e) => assert_eq!(e.code.0, ARG_CONSTRAINT, "grim exec: {e:?}"),
    }

    // `hyprctl` read subcommand: spawn path when pinned.
    let res = secured(
        &c,
        "system_command",
        args(json!({"command": "hyprctl", "args": ["monitors"]})),
    )
    .await;
    match res {
        Ok(r) => {
            let v = json_of(&r);
            assert!(v.get("exit_code").is_some(), "hyprctl result: {v}");
        }
        Err(e) => assert_eq!(e.code.0, ARG_CONSTRAINT, "hyprctl exec: {e:?}"),
    }

    // Whitelist rejections map per failure class (docs/TOOLS.md):
    // constraint violations → -32003, metacharacters → -32006.
    for (a, code) in [
        (
            json!({"command": "hyprctl", "args": ["keyword", "gaps_in", "0"]}),
            ARG_CONSTRAINT,
        ),
        (
            json!({"command": "xdotool", "args": ["getactivewindow"]}),
            ARG_CONSTRAINT,
        ),
        (json!({"command": "slurp", "args": ["-o"]}), ARG_CONSTRAINT),
        (
            json!({"command": "grim", "args": ["-t", "png"]}),
            ARG_CONSTRAINT,
        ),
        (
            json!({"command": "slurp", "args": ["a;rm"]}),
            SANITIZATION_REJECTED,
        ),
    ] {
        let res = secured(&c, "system_command", args(a.clone())).await;
        assert_error_code(&res, &[code], &format!("system_command {a}"));
    }
}

/// The Phase-0 validation stub in `automation.rs` is unreachable through
/// `call_tool_secured` (which routes `system_command` to real exec) — it
/// is only reachable via the unsecured `call_tool` shim.
#[tokio::test]
async fn system_command_phase0_stub_via_unsecured() {
    let p = Providers::all_mocks();
    let res = call_tool(
        "system_command",
        args(json!({"command": "slurp", "args": ["-f", "%x"]})),
        &p,
    )
    .await
    .unwrap();
    let v = json_of(&res);
    assert_eq!(v["phase0_stub"], true);
    assert_eq!(v["executed"], false);

    for (a, code) in [
        (
            json!({"command": "slurp", "args": (0..17).map(|i| i.to_string()).collect::<Vec<_>>()}),
            INVALID_PARAMS,
        ),
        (
            json!({"command": "slurp", "args": ["x".repeat(513)]}),
            INVALID_PARAMS,
        ),
        (
            json!({"command": "slurp", "args": ["a;b"]}),
            SANITIZATION_REJECTED,
        ),
        (
            json!({"command": "slurp", "args": ["$(id)"]}),
            SANITIZATION_REJECTED,
        ),
        (json!({}), INVALID_PARAMS),
    ] {
        let res = call_tool("system_command", args(a.clone()), &p).await;
        assert_error_code(&res, &[code], &format!("stub {a}"));
    }
}

// ---------------------------------------------------------------------------
// 6. History / replay through the secured store.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn action_history_roundtrip_through_secured_store() {
    let c = ctx(Providers::all_mocks());
    // Every secured call records into the context-scoped store.
    secured(&c, "sleep", args(json!({"ms": 0}))).await.unwrap();
    secured(&c, "mouse_move", args(json!({"x": 1, "y": 1})))
        .await
        .unwrap();

    let res = secured(&c, "get_action_history", args(json!({})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["count"], 2);
    // Newest first.
    assert_eq!(v["actions"][0]["tool"], "mouse_move");
    assert_eq!(v["actions"][1]["tool"], "sleep");
    assert_eq!(v["actions"][0]["args"], json!({"x":1,"y":1}));

    // limit window.
    let res = secured(&c, "get_action_history", args(json!({"limit": 1})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["count"], 1);
}

#[tokio::test]
async fn replay_action_secured_replays_and_audits() {
    let c = ctx_destructive(Providers::all_mocks());
    let rec = record(&c, "sleep", json!({"ms": 0}));

    // By id — the recorded call re-enters call_tool_secured.
    let res = secured(&c, "replay_action", args(json!({"id": rec.id})))
        .await
        .unwrap();
    let v = json_of(&res);
    assert_eq!(v["replayed"], "sleep");
    assert_eq!(v["id"], rec.id);

    // By index.
    let res = secured(&c, "replay_action", args(json!({"index": rec.index})))
        .await
        .unwrap();
    assert_eq!(json_of(&res)["replayed"], "sleep");

    // Inner isError propagates onto the envelope.
    let fail = providers_with(|p| p.input = Some(Arc::new(FailInput)));
    let c2 = ctx_destructive(fail);
    record(&c2, "mouse_click", json!({"x": 1, "y": 2}));
    let res = secured(&c2, "replay_action", args(json!({"index": 0})))
        .await
        .unwrap();
    assert_eq!(res.is_error, Some(true));

    // Recorded destructive call re-challenges consent (inner Err arm):
    // replay_action itself bypasses, the replayed system_command does not.
    let c3 = ctx(Providers::all_mocks());
    record(&c3, "system_command", json!({"command": "slurp"}));
    let err = secured(&c3, "replay_action", args(json!({"index": 0})))
        .await
        .unwrap_err();
    assert_eq!(err.code.0, CONSENT_REQUIRED);

    // Non-replayable recorded tool → -32602.
    let c4 = ctx_destructive(Providers::all_mocks());
    let rec = record(&c4, "metrics", json!({}));
    let res = secured(&c4, "replay_action", args(json!({"id": rec.id}))).await;
    assert_error_code(&res, &[INVALID_PARAMS], "replay non-replayable");
}

#[tokio::test]
async fn clear_action_history_secured_wipes() {
    let c = ctx_destructive(Providers::all_mocks());
    record(&c, "sleep", json!({"ms": 0}));
    let res = secured(&c, "clear_action_history", args(json!({})))
        .await
        .unwrap();
    assert!(text_of(&res).contains("records removed"));
    assert!(c.sec.history().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 7. Fallback / misc dispatch arms.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_tool_through_secured_gate() {
    let c = ctx(Providers::all_mocks());
    let res = secured(&c, "no_such_tool", args(json!({}))).await;
    assert_error_code(&res, &[METHOD_NOT_FOUND], "unknown tool");
}

/// `window_control` non-close actions skip the destructive class even
/// though the tool name appears in the consent table.
#[tokio::test]
async fn window_control_non_close_not_gated() {
    let c = ctx(Providers::all_mocks());
    for action in ["focus", "minimize"] {
        let res = secured(
            &c,
            "window_control",
            args(json!({"action": action, "window": "0x0"})),
        )
        .await;
        assert_success(&res, action);
    }
}

/// Tool registration (`tools()` builders, schema generation) and the
/// category filter in `list_tools`.
#[test]
fn tool_registration_and_category_filter() {
    let all = ultranix_mcp::tools::list_tools(None);
    assert_eq!(all.len(), 32);
    assert!(
        all.iter()
            .all(|t| t.input_schema.get("type").and_then(Value::as_str) == Some("object"))
    );
    let mouse = ultranix_mcp::tools::list_tools(Some(&["mouse".to_string()]));
    assert_eq!(mouse.len(), 7);
    let none = ultranix_mcp::tools::list_tools(Some(&["bogus".to_string()]));
    assert!(none.is_empty());
}

/// Each category leg of the unsecured `call_tool` → `dispatch` chain,
/// plus its unknown-name fall-through.
#[tokio::test]
async fn unsecured_dispatch_each_category_leg() {
    let p = Providers::all_mocks();
    for (name, a) in [
        ("mouse_move", json!({"x": 1, "y": 1})),
        ("type_text", json!({"text": "x", "delay_ms": 0})),
        ("screen_info", json!({})),
        ("sleep", json!({"ms": 0})),
        ("get_windows", json!({})),
    ] {
        let res = call_tool(name, args(a), &p).await;
        assert_success(&res, name);
    }
    let res = call_tool("nope", Map::new(), &p).await;
    assert_error_code(&res, &[METHOD_NOT_FOUND], "unsecured unknown tool");
}
