//! Shared helpers + the frozen Phase-0 tool catalog for the dispatch
//! test-suite. Mirrors docs/TOOLS.md — the contract under test.
#![allow(dead_code)]

use rmcp::model::{CallToolResult, ErrorData};
use serde_json::{Map, Value, json};
use ultranix_mcp::providers::Providers;

/// The frozen catalog: `(tool_name, category)` — 40 entries, order matches
/// the Tool Summary table in docs/TOOLS.md.
pub const TOOLS: &[(&str, &str)] = &[
    // mouse (7)
    ("mouse_click", "mouse"),
    ("mouse_double_click", "mouse"),
    ("mouse_move", "mouse"),
    ("mouse_get_position", "mouse"),
    ("mouse_scroll", "mouse"),
    ("mouse_drag", "mouse"),
    ("mouse_button_control", "mouse"),
    // keyboard (2)
    ("type_text", "keyboard"),
    ("key_control", "keyboard"),
    // vision (14)
    ("screenshot", "vision"),
    ("screen_info", "vision"),
    ("screen_highlight", "vision"),
    ("color_at", "vision"),
    ("set_spatial_focus", "vision"),
    ("get_ui_tree", "vision"),
    ("get_focused_element", "vision"),
    ("find_element", "vision"),
    ("find_text_on_screen", "vision"),
    ("find_icon", "vision"),
    ("wait_for_ui_element", "vision"),
    ("invoke_element", "vision"),
    ("screen_record", "vision"),
    ("screen_stream", "vision"),
    // automation (4)
    ("sleep", "automation"),
    ("mouse_move_path", "automation"),
    ("system_command", "automation"),
    ("web_query", "automation"),
    // admin (10)
    ("window_control", "admin"),
    ("get_windows", "admin"),
    ("get_active_window", "admin"),
    ("metrics", "admin"),
    ("get_action_history", "admin"),
    ("replay_action", "admin"),
    ("clear_action_history", "admin"),
    ("plugin_list", "admin"),
    ("plugin_run", "admin"),
    ("plugin_reload", "admin"),
    // clipboard (3)
    ("clipboard_get", "clipboard"),
    ("clipboard_set", "clipboard"),
    ("clipboard_clear", "clipboard"),
];

pub const ALL_TOOL_NAMES: &[&str] = &[
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
    "screen_highlight",
    "color_at",
    "set_spatial_focus",
    "get_ui_tree",
    "get_focused_element",
    "find_element",
    "find_text_on_screen",
    "find_icon",
    "wait_for_ui_element",
    "invoke_element",
    "sleep",
    "mouse_move_path",
    "system_command",
    "web_query",
    "window_control",
    "get_windows",
    "get_active_window",
    "metrics",
    "get_action_history",
    "replay_action",
    "clear_action_history",
    "plugin_list",
    "plugin_run",
    "plugin_reload",
    "clipboard_get",
    "clipboard_set",
    "clipboard_clear",
    "screen_record",
    "screen_stream",
];

/// Tools implemented by a provider backend (per the Tool Summary "Backend"
/// column). Server-core tools (`sleep`, `set_spatial_focus`,
/// `system_command`, `metrics`, `get_action_history`, `replay_action`,
/// `clear_action_history`, `plugin_*`) are excluded — they never produce
/// -32010.
pub fn is_provider_backed(name: &str) -> bool {
    !matches!(
        name,
        "sleep"
            | "set_spatial_focus"
            | "system_command"
            | "metrics"
            | "get_action_history"
            | "replay_action"
            | "clear_action_history"
            | "plugin_list"
            | "plugin_run"
            | "plugin_reload"
    )
}

/// Tools that are consent-gated (docs/TOOLS.md §Destructive-Action Consent):
/// `system_command`, `replay_action`, `clear_action_history`,
/// `clipboard_set`/`clipboard_clear` (they overwrite/drop user clipboard
/// state), and `window_control` only for `action:"close"`.
pub fn is_consent_gated(name: &str, args: &Map<String, Value>) -> bool {
    match name {
        "system_command"
        | "replay_action"
        | "clear_action_history"
        | "clipboard_set"
        | "clipboard_clear" => true,
        "window_control" => args.get("action").and_then(Value::as_str) == Some("close"),
        _ => false,
    }
}

/// Build a `serde_json::Map` from a `json!` object literal.
pub fn args(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        other => panic!("args helper expects a JSON object, got {other}"),
    }
}

/// Dispatch a call through the public tool surface.
pub async fn call(
    name: &str,
    arguments: Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    ultranix_mcp::tools::call_tool(name, arguments, providers).await
}

/// Schema-valid arguments for each of the 40 tools (happy path).
pub fn valid_args(name: &str) -> Map<String, Value> {
    match name {
        "mouse_click" => args(json!({"x": 640, "y": 420, "button": "left"})),
        "mouse_double_click" => args(json!({"x": 512, "y": 300, "button": "middle"})),
        "mouse_move" => args(json!({"x": 10, "y": -20})),
        "mouse_get_position" => args(json!({})),
        "mouse_scroll" => args(json!({"dx": 2, "dy": -3})),
        "mouse_drag" => args(json!({
            "from_x": 0, "from_y": 0, "to_x": 100, "to_y": 100,
            "button": "left", "duration_ms": 0
        })),
        "mouse_button_control" => args(json!({"button": "right", "action": "down"})),
        "type_text" => args(json!({"text": "hello world", "delay_ms": 0})),
        "key_control" => args(json!({
            "key": "Return", "action": "press", "modifiers": ["ctrl", "shift"]
        })),
        "screenshot" => args(json!({"region": {"x": 0, "y": 0, "w": 100, "h": 100}})),
        "screen_info" => args(json!({})),
        "screen_highlight" => args(json!({"x": 0, "y": 0, "w": 50, "h": 50, "duration_ms": 100})),
        "color_at" => args(json!({"x": 0, "y": 0})),
        "set_spatial_focus" => args(json!({"x": 0, "y": 0, "w": 200, "h": 200})),
        "get_ui_tree" => args(json!({"depth": 3})),
        "get_focused_element" => args(json!({})),
        "find_element" => args(json!({"query": "Sign in"})),
        "find_text_on_screen" => args(json!({"text": "Sign in"})),
        "find_icon" => args(json!({"description": "hamburger menu icon"})),
        "wait_for_ui_element" => args(json!({"query": "button", "timeout_ms": 250})),
        "invoke_element" => args(json!({"query": "Sign in", "action": "press"})),
        "sleep" => args(json!({"ms": 1})),
        "mouse_move_path" => args(json!({
            "points": [{"x": 0, "y": 0}, {"x": 5, "y": 5}, {"x": 10, "y": 0}],
            "duration_ms": 0
        })),
        "system_command" => args(json!({"command": "slurp", "args": ["-f", "%x %y %w %h"]})),
        "web_query" => args(json!({"selector": "button.submit"})),
        "window_control" => args(json!({"action": "focus", "window": "0x0"})),
        "get_windows" => args(json!({})),
        "get_active_window" => args(json!({})),
        "metrics" => args(json!({})),
        "get_action_history" => args(json!({"limit": 5})),
        "replay_action" => args(json!({"index": 0})),
        "clear_action_history" => args(json!({})),
        "plugin_list" => args(json!({})),
        "plugin_run" => args(json!({"name": "no-such-plugin"})),
        "plugin_reload" => args(json!({})),
        "clipboard_get" => args(json!({})),
        "clipboard_set" => args(json!({"text": "hi"})),
        "clipboard_clear" => args(json!({})),
        "screen_record" => args(json!({"duration_ms": 100, "interval_ms": 100})),
        "screen_stream" => args(json!({"action": "status"})),
        other => panic!("no valid_args fixture for unknown tool {other}"),
    }
}

/// Schema-invalid arguments for each tool — every entry is a violation the
/// frozen inputSchema must reject with -32602 InvalidParams.
pub fn invalid_args(name: &str) -> Map<String, Value> {
    match name {
        // missing required `x`
        "mouse_click" => args(json!({"y": 420, "button": "left"})),
        // button outside the enum
        "mouse_double_click" => args(json!({"x": 1, "y": 2, "button": "bogus"})),
        // wrong type for `x`
        "mouse_move" => args(json!({"x": "10", "y": 20})),
        // additionalProperties: false
        "mouse_get_position" => args(json!({"bogus": 1})),
        // wrong type (schema-level; the both-zero semantic rule is a
        // separate case in dispatch_mock.rs)
        "mouse_scroll" => args(json!({"dx": "2", "dy": -3})),
        // missing required `to_y`
        "mouse_drag" => args(json!({"from_x": 0, "from_y": 0, "to_x": 1})),
        // action outside the enum
        "mouse_button_control" => args(json!({"button": "left", "action": "hold"})),
        // minLength 1
        "type_text" => args(json!({"text": ""})),
        // missing required `action`
        "key_control" => args(json!({"key": "a"})),
        // region.w below minimum 1
        "screenshot" => args(json!({"region": {"x": 0, "y": 0, "w": 0, "h": 10}})),
        "screen_info" => args(json!({"bogus": 1})),
        // missing required `h`
        "screen_highlight" => args(json!({"x": 0, "y": 0, "w": 10})),
        // missing required `y`
        "color_at" => args(json!({"x": 0})),
        // neither a full rect nor `clear: true` (anyOf fails)
        "set_spatial_focus" => args(json!({})),
        // depth below minimum 1
        "get_ui_tree" => args(json!({"depth": 0})),
        "get_focused_element" => args(json!({"bogus": 1})),
        // query minLength 1
        "find_element" => args(json!({"query": ""})),
        // missing required `text`
        "find_text_on_screen" => args(json!({})),
        // description minLength 1
        "find_icon" => args(json!({"description": ""})),
        // timeout_ms below minimum 250
        "wait_for_ui_element" => args(json!({"query": "x", "timeout_ms": 10})),
        // action outside the enum
        "invoke_element" => args(json!({"query": "x", "action": "bogus"})),
        // ms above maximum 60000
        "sleep" => args(json!({"ms": 60001})),
        // points below minItems 2
        "mouse_move_path" => args(json!({"points": [{"x": 0, "y": 0}]})),
        // command outside the enum
        "system_command" => args(json!({"command": "curl"})),
        // missing required `selector`
        "web_query" => args(json!({})),
        // action outside the enum
        "window_control" => args(json!({"action": "explode"})),
        "get_windows" => args(json!({"bogus": 1})),
        "get_active_window" => args(json!({"bogus": 1})),
        "metrics" => args(json!({"bogus": 1})),
        // limit below minimum 1
        "get_action_history" => args(json!({"limit": 0})),
        // neither selector present (anyOf fails)
        "replay_action" => args(json!({})),
        "clear_action_history" => args(json!({"bogus": 1})),
        "plugin_list" => args(json!({"bogus": 1})),
        // missing required `name`
        "plugin_run" => args(json!({})),
        "plugin_reload" => args(json!({"bogus": 1})),
        "clipboard_get" => args(json!({"bogus": 1})),
        // missing required `text`
        "clipboard_set" => args(json!({})),
        "clipboard_clear" => args(json!({"bogus": 1})),
        // missing required `duration_ms`
        "screen_record" => args(json!({"interval_ms": 100})),
        // action outside the enum
        "screen_stream" => args(json!({"action": "pause"})),
        other => panic!("no invalid_args fixture for unknown tool {other}"),
    }
}

/// Assert a dispatch result is a non-error `CallToolResult`: `Ok` and either
/// `is_error` absent/false, and at least one content item per the envelope
/// contract in docs/TOOLS.md.
pub fn assert_success(res: &Result<CallToolResult, ErrorData>, ctx: &str) {
    match res {
        Ok(r) => {
            assert!(
                r.is_error != Some(true),
                "{ctx}: expected success, got isError result: {r:?}"
            );
            assert!(
                !r.content.is_empty(),
                "{ctx}: success result must carry at least one content item"
            );
        }
        Err(e) => panic!("{ctx}: expected Ok(CallToolResult), got error {e:?}"),
    }
}

/// Serializes tests that mutate or depend on the process-global
/// spatial-focus rect (`set_spatial_focus` state is a static in
/// `tools::vision`, so parallel tests must not interleave a `set` with
/// another test's `screenshot`/`find_*` assertions). Hold the guard for
/// the whole test and leave the rect cleared. Async-aware mutex so the
/// guard can be held across `.await` without tripping
/// `clippy::await_holding_lock`.
pub async fn focus_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static L: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    L.lock().await
}

/// Serializes tests that mutate process env vars — parallel tests in
/// the same binary share one environment, so mutation must hold this
/// lock for the whole scope (see [`ScopedStateDir`]). Async-aware
/// mutex, same rationale as [`focus_lock`].
pub async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static L: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    L.lock().await
}

/// RAII override pointing `ULTRANIX_MCP_STATE_DIR` at a test tempdir —
/// restores the previous value on drop. Always construct under
/// [`env_lock`].
///
/// Why it exists: dispatch-level calls that resolve the *ambient* state
/// root — `screen_record`'s `rec-<ulid>` output dir, the `plugin_*`
/// manifest scan — would otherwise write into / read from the real
/// `~/.ultranix-mcp/` tree (or `/tmp`) during integration tests: the
/// `#[cfg(test)]` `TEST_RECORDING_BASE` seam does not exist in the lib
/// build these tests link against. `preferred_captures_base` resolves
/// through `StateDir::resolve_root`, so the env var is the hermetic
/// seam.
pub struct ScopedStateDir(Option<std::ffi::OsString>);

impl ScopedStateDir {
    /// Set `ULTRANIX_MCP_STATE_DIR` to `dir`, remembering the prior
    /// value for restore on drop.
    pub fn set(dir: &std::path::Path) -> Self {
        let saved = std::env::var_os("ULTRANIX_MCP_STATE_DIR");
        // SAFETY: callers hold env_lock() for the whole scope, so no
        // other thread mutates the environment concurrently.
        unsafe { std::env::set_var("ULTRANIX_MCP_STATE_DIR", dir) };
        Self(saved)
    }
}

impl Drop for ScopedStateDir {
    fn drop(&mut self) {
        // SAFETY: same env_lock scope as construction.
        unsafe {
            match &self.0 {
                Some(v) => std::env::set_var("ULTRANIX_MCP_STATE_DIR", v),
                None => std::env::remove_var("ULTRANIX_MCP_STATE_DIR"),
            }
        }
    }
}

/// Assert a dispatch result is a JSON-RPC error with one of `codes`.
pub fn assert_error_code(res: &Result<CallToolResult, ErrorData>, codes: &[i32], ctx: &str) {
    match res {
        Err(e) => assert!(
            codes.contains(&e.code.0),
            "{ctx}: expected error code in {codes:?}, got {} ({e:?})",
            e.code.0
        ),
        Ok(r) => panic!("{ctx}: expected Err with code {codes:?}, got Ok({r:?})"),
    }
}
