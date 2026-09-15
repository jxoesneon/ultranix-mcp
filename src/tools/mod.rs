//! Tool registry: schemas, categories, dispatch. Canonical catalog lives in
//! docs/TOOLS.md — this module is its compiled mirror (32 tools).

mod admin;
mod automation;
mod keyboard;
mod mouse;
mod vision;

use std::sync::LazyLock;

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode, ErrorData, JsonObject, Tool};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::error::codes;
use crate::providers::Providers;
use crate::traits::{
    BrowserProvider, CaptureProvider, InputProvider, Rect, UIAutomationProvider, VisionProvider,
    WindowInfo, WindowProvider,
};

/// Server-defined codes not yet surfaced in `crate::error::codes`
/// (sanitization lands with Phase 1; element lookup with Phase 2).
const SANITIZATION_REJECTED: i32 = -32006;
const ELEMENT_NOT_FOUND: i32 = -32016;

/// Frozen category → tool-name catalog (docs/TOOLS.md "Tool Summary").
/// Names and membership are part of the stable public contract — do not
/// rename without a spec change.
const CATALOG: &[(&str, &[&str])] = &[
    (
        "mouse",
        &[
            "mouse_click",
            "mouse_double_click",
            "mouse_move",
            "mouse_get_position",
            "mouse_scroll",
            "mouse_drag",
            "mouse_button_control",
        ],
    ),
    ("keyboard", &["type_text", "key_control"]),
    (
        "vision",
        &[
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
        ],
    ),
    (
        "automation",
        &["sleep", "mouse_move_path", "system_command", "web_query"],
    ),
    (
        "admin",
        &[
            "window_control",
            "get_windows",
            "get_active_window",
            "metrics",
            "get_action_history",
            "replay_action",
            "clear_action_history",
        ],
    ),
];

/// Every advertised tool definition, built once (schemas are static).
fn all_tools() -> &'static [Tool] {
    static ALL: LazyLock<Vec<Tool>> = LazyLock::new(|| {
        let mut v = Vec::with_capacity(32);
        v.extend(mouse::tools());
        v.extend(keyboard::tools());
        v.extend(vision::tools());
        v.extend(automation::tools());
        v.extend(admin::tools());
        v
    });
    &ALL
}

/// Category a tool name belongs to, or `None` for unknown names.
fn category_of(name: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find_map(|(cat, names)| names.contains(&name).then_some(*cat))
}

/// All advertised tools, filtered by enabled categories (`None` = all).
pub fn list_tools(categories: Option<&[String]>) -> Vec<Tool> {
    match categories {
        None => all_tools().to_vec(),
        Some(cats) => all_tools()
            .iter()
            .filter(|t| category_of(t.name.as_ref()).is_some_and(|c| cats.iter().any(|s| s == c)))
            .cloned()
            .collect(),
    }
}

/// Dispatch a `tools/call` request into the provider layer.
///
/// Every call — hit or miss — is timed and counted in the process-global
/// metrics registry ([`crate::metrics`]). The secured wrapper
/// [`call_tool_secured`] bypasses this shim (it records metrics itself,
/// including the consent-gate overhead) and adds the audit record.
pub async fn call_tool(
    name: &str,
    args: serde_json::Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let t0 = std::time::Instant::now();
    let result = dispatch(name, &args, providers).await;
    crate::metrics::record_call(name, t0.elapsed(), outcome_of(&result));
    result
}

/// The category-dispatch chain behind [`call_tool`]. Takes `&Map` so the
/// secured wrapper can reuse `args` for consent binding and the audit
/// hash without an extra clone.
async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    if let Some(r) = mouse::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = keyboard::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = vision::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = automation::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = admin::dispatch(name, args, providers).await {
        return r;
    }
    Err(unknown_tool(name))
}

/// `dispatch` for the secured path — identical except the admin leg uses
/// [`admin::dispatch_secured`], so `replay_action` re-enters
/// [`call_tool_secured`] for the recorded call: consent re-challenge,
/// audit record, and metric sample on its own `{caller, tool, args_hash}`
/// binding rather than an ungated Phase-0 replay.
async fn dispatch_secured(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    security: &crate::security::SecurityContext,
    session_id: &str,
    key_id: Option<&str>,
) -> Result<CallToolResult, ErrorData> {
    if let Some(r) = mouse::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = keyboard::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = vision::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = automation::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) =
        admin::dispatch_secured(name, args, providers, security, session_id, key_id).await
    {
        return r;
    }
    Err(unknown_tool(name))
}

/// `-32601 MethodNotFound` for a name no category claimed.
fn unknown_tool(name: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode::METHOD_NOT_FOUND,
        format!("unknown tool: {name}"),
        Some(json!({"kind": "MethodNotFound", "tool": name})),
    )
}

/// Map a dispatch result onto the audit/metrics `outcome` vocabulary:
/// `ok`, `tool_error` (`isError` result), `consent_required`, `error`.
fn outcome_of(result: &Result<CallToolResult, ErrorData>) -> &'static str {
    match result {
        Ok(r) if r.is_error == Some(true) => "tool_error",
        Ok(_) => "ok",
        Err(e) if e.code == ErrorCode(codes::CONSENT_REQUIRED) => "consent_required",
        Err(_) => "error",
    }
}

// ---------------------------------------------------------------------------
// Secured dispatch — consent gate + audit + whitelist-constrained exec.
// ---------------------------------------------------------------------------

/// `-32015 ConsentRequired` — destructive call needs a challenge retry.
fn consent_required(token: &str, expires_in_ms: u64) -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::CONSENT_REQUIRED),
        "consent required: destructive action; retry with consent_token",
        Some(json!({
            "kind": "ConsentRequired",
            "consent_token": token,
            "expires_in_ms": expires_in_ms,
        })),
    )
}

/// Whether `name`+`args` lands in the destructive consent class
/// (docs/TOOLS.md §Destructive-Action Consent).
fn is_destructive(name: &str, args: &Map<String, Value>) -> bool {
    match name {
        "system_command" | "clear_action_history" | "replay_action" => true,
        "window_control" => args.get("action").and_then(Value::as_str) == Some("close"),
        _ => false,
    }
}

/// `tools/call` with the security pipeline applied: consent gate for the
/// destructive class, real whitelist-constrained `system_command` exec,
/// a hash-chained audit record for **every** call (accepted or rejected —
/// SECURITY.md "Audit | Every invocation"), and a
/// `ultranix_mcp_tool_calls_total` / `_duration_seconds` metric sample.
pub async fn call_tool_secured(
    name: &str,
    args: Map<String, Value>,
    providers: &Providers,
    security: &crate::security::SecurityContext,
    session_id: &str,
    key_id: Option<&str>,
) -> Result<CallToolResult, ErrorData> {
    let t0 = std::time::Instant::now();
    let argsv = Value::Object(args.clone());
    let hash = crate::security::consent::args_hash(&argsv);
    let destructive = is_destructive(name, &args);

    // Resolve the execution-time target for target-scoped consent:
    // window_control{close} without `window` binds the *current* active
    // window at challenge time (docs/TOOLS.md — a target change between
    // challenge and retry invalidates the token).
    let resolved_target = if name == "window_control"
        && args.get("action").and_then(Value::as_str) == Some("close")
        && args.get("window").is_none()
    {
        match &providers.window {
            Some(w) => w.active_window().await.ok().flatten().map(|w| w.id),
            None => None,
        }
    } else {
        None
    };

    if destructive && !security.allow_destructive {
        let supplied = args.get("consent_token").and_then(Value::as_str);
        let ok = supplied.is_some_and(|t| {
            security.consent.verify(
                t,
                key_id,
                session_id,
                name,
                &argsv,
                resolved_target.as_deref(),
            )
        });
        if !ok {
            crate::metrics::record_call(name, t0.elapsed(), "consent_required");
            let _ = security.audit.record(
                name,
                &hash,
                "consent_required",
                t0.elapsed().as_millis() as u64,
                crate::security::audit::CallContext {
                    key_id,
                    caller: Some(key_id.unwrap_or(session_id)),
                    consent: None,
                },
            );
            let ch = match resolved_target.as_deref() {
                Some(t) => security
                    .consent
                    .challenge_for_target(key_id, session_id, name, &argsv, t),
                None => security.consent.challenge(key_id, session_id, name, &argsv),
            };
            return Err(consent_required(&ch.token, ch.expires_in_ms));
        }
    }

    let consent_stamp = if destructive {
        Some(if security.allow_destructive {
            "bypassed"
        } else {
            "verified"
        })
    } else {
        None
    };

    let result = if name == "system_command" {
        exec_system_command(&args, security).await
    } else {
        // `dispatch_secured`, not `call_tool`: the metric sample below is
        // recorded with the full pipeline latency — routing through
        // `call_tool` would double-count every secured call — and the
        // admin leg must see the security context so `replay_action`
        // re-enters this same gated+audited path for the recorded call.
        dispatch_secured(name, &args, providers, security, session_id, key_id).await
    };

    // Every invocation — gated or not, ok or error — emits one metric
    // sample and one hash-chained audit record (SECURITY.md "Audit |
    // Every invocation — accepted or rejected").
    let elapsed = t0.elapsed();
    let outcome = outcome_of(&result);
    crate::metrics::record_call(name, elapsed, outcome);
    let _ = security.audit.record(
        name,
        &hash,
        outcome,
        elapsed.as_millis() as u64,
        crate::security::audit::CallContext {
            key_id,
            caller: Some(key_id.unwrap_or(session_id)),
            consent: consent_stamp,
        },
    );

    // Encrypted action history: every replayable invocation appends to
    // the context-scoped store (meta/history tools excluded — replaying
    // them is meaningless and recording them is noise).
    if !admin::NON_REPLAYABLE.contains(&name)
        && let Ok(store) = security.history()
    {
        let _ = store.record(crate::security::history::NewActionRecord {
            tool: name.to_string(),
            args_json: argsv.clone(),
            result_summary: result_summary(&result),
            caller: key_id.unwrap_or(session_id).to_string(),
            duration_ms: elapsed.as_millis() as u64,
            outcome: outcome.to_string(),
        });
    }
    result
}

/// First text block of a tool result (or the error line) — the summary
/// persisted beside each action-history record.
fn result_summary(result: &Result<CallToolResult, ErrorData>) -> String {
    match result {
        Ok(r) => r
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .map(|t| t.text.clone())
            .unwrap_or_else(|| "<non-text result>".into()),
        Err(e) => format!("-{:05} {}", e.code.0, e.message),
    }
}

/// Real `system_command` exec: whitelist validation → pinned absolute
/// binary → spawn, 15 s timeout, 64 KiB stdout/stderr truncation
/// (docs/TOOLS.md contract). Never reaches a shell.
async fn exec_system_command(
    args: &Map<String, Value>,
    security: &crate::security::SecurityContext,
) -> Result<CallToolResult, ErrorData> {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("system_command: missing `command`"))?;
    let cmd_args: Vec<String> = args
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // grim/scrot need a server-supplied output path inside a fresh 0700 dir.
    let capture_dir = if matches!(command, "grim" | "scrot") {
        Some(crate::security::captures::fresh_capture_dir().map_err(|e| {
            ErrorData::new(ErrorCode::INTERNAL_ERROR, format!("capture dir: {e}"), None)
        })?)
    } else {
        None
    };
    let capture_out = capture_dir.as_ref().map(|d| d.join("capture.png"));

    let inv = security
        .pins
        .validate_command(
            command,
            &cmd_args,
            security.x11_active,
            capture_out.as_deref(),
        )
        .map_err(|e| {
            ErrorData::new(
                ErrorCode(codes::ARG_CONSTRAINT_VIOLATION),
                format!("{e}"),
                Some(json!({"kind": "ArgConstraintViolation", "detail": e.to_string()})),
            )
        })?;

    let out = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(&inv.abs_path)
            .args(&inv.argv[1..])
            .output(),
    )
    .await;

    // Unlink the server-supplied capture file after use (unlink-after-use).
    if let Some(d) = &capture_dir {
        let _ = std::fs::remove_dir_all(d);
    }

    match out {
        Err(_) => Ok(json_result(&json!({"timed_out": true}))),
        Ok(Err(e)) => Ok(tool_error(format!("spawn failed: {e}"))),
        Ok(Ok(o)) => Ok(json_result(&json!({
            "exit_code": o.status.code().unwrap_or(-1),
            "stdout": truncate64k(&o.stdout),
            "stderr": truncate64k(&o.stderr),
        }))),
    }
}

fn truncate64k(bytes: &[u8]) -> String {
    const MAX: usize = 64 * 1024;
    let s = String::from_utf8_lossy(bytes);
    if s.len() > MAX {
        s[..MAX].to_string()
    } else {
        s.into_owned()
    }
}

// ---------------------------------------------------------------------------
// Shared helpers used by the category submodules.
// ---------------------------------------------------------------------------

/// Build a `Tool` whose `inputSchema` is derived from param struct `P`
/// (schemars, draft 2020-12, `additionalProperties: false` via
/// `#[serde(deny_unknown_fields)]`).
pub(super) fn tool<P>(name: &'static str, description: &'static str) -> Tool
where
    P: JsonSchema + 'static,
{
    Tool::new(name, description, tool_schema::<P>())
}

/// The generated `inputSchema` for `P`, normalised to the spec shape every
/// tool advertises (`type: "object"`, an object-valued `properties`,
/// `additionalProperties: false`). Tools that need extra keywords (e.g.
/// `anyOf`) patch the returned map before constructing the `Tool`.
pub(super) fn tool_schema<P>() -> JsonObject
where
    P: JsonSchema + 'static,
{
    let mut schema = rmcp::handler::server::tool::schema_for_input::<P>()
        .unwrap_or_else(|e| panic!("invalid input schema: {e}"))
        .as_ref()
        .clone();
    // schemars omits `properties` for field-less structs; the frozen
    // contract advertises it unconditionally.
    schema.entry("properties").or_insert_with(|| json!({}));
    schema
        .entry("additionalProperties")
        .or_insert(Value::Bool(false));
    schema
}

/// Deserialize the `tools/call` arguments object into param struct `P`;
/// schema violations map to `-32602 InvalidParams`.
pub(super) fn parse_args<P>(tool_name: &str, args: &Map<String, Value>) -> Result<P, ErrorData>
where
    P: DeserializeOwned,
{
    serde_json::from_value(Value::Object(args.clone()))
        .map_err(|e| invalid_params(format!("{tool_name}: {e}")))
}

/// `-32602 InvalidParams` with the `data.kind` discriminator.
pub(super) fn invalid_params(message: impl Into<String>) -> ErrorData {
    let message = message.into();
    ErrorData::invalid_params(
        message.clone(),
        Some(json!({"kind": "InvalidParams", "detail": message})),
    )
}

/// `-32010 ProviderUnavailable` — the required backend slot is `None`.
pub(super) fn provider_unavailable(provider: &'static str) -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::PROVIDER_UNAVAILABLE),
        format!("provider unavailable: {provider}"),
        Some(json!({"kind": "ProviderUnavailable", "provider": provider})),
    )
}

/// `-32006 SanitizationRejected` — argument failed input sanitization.
pub(super) fn sanitization_rejected(message: impl Into<String>) -> ErrorData {
    let message = message.into();
    ErrorData::new(
        ErrorCode(SANITIZATION_REJECTED),
        message.clone(),
        Some(json!({"kind": "SanitizationRejected", "detail": message})),
    )
}

/// `-32016 ElementNotFound` — action-targeted element query matched nothing.
pub(super) fn element_not_found(message: impl Into<String>) -> ErrorData {
    let message = message.into();
    ErrorData::new(
        ErrorCode(ELEMENT_NOT_FOUND),
        message.clone(),
        Some(json!({"kind": "ElementNotFound", "detail": message})),
    )
}

/// Successful single-`text`-item result.
pub(super) fn text_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.into())])
}

/// Successful result carrying a JSON document in a single `text` item
/// (the documented wire shape for JSON-returning tools).
pub(super) fn json_result(value: &Value) -> CallToolResult {
    text_result(value.to_string())
}

/// Tool-level error (`isError: true`) — the call was valid but execution
/// failed; the caller sees this message.
pub(super) fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

/// Backend `anyhow` failure → `isError: true` result (never a JSON-RPC error).
pub(super) fn backend_error(err: anyhow::Error) -> CallToolResult {
    tool_error(format!("backend error: {err:#}"))
}

/// Await a provider call inside a `Result<CallToolResult, ErrorData>`
/// handler; on `Err` return an `isError` tool result describing the failure.
macro_rules! backend {
    ($expr:expr) => {
        match $expr {
            ::core::result::Result::Ok(v) => v,
            ::core::result::Result::Err(e) => {
                return ::core::result::Result::Ok($crate::tools::backend_error(e));
            }
        }
    };
}
pub(crate) use backend;

// --- provider slot accessors (None → -32010 ProviderUnavailable) ---

pub(super) fn input_provider(p: &Providers) -> Result<&dyn InputProvider, ErrorData> {
    p.input
        .as_deref()
        .ok_or_else(|| provider_unavailable("InputProvider"))
}

pub(super) fn capture_provider(p: &Providers) -> Result<&dyn CaptureProvider, ErrorData> {
    p.capture
        .as_deref()
        .ok_or_else(|| provider_unavailable("CaptureProvider"))
}

pub(super) fn ui_provider(p: &Providers) -> Result<&dyn UIAutomationProvider, ErrorData> {
    p.ui_automation
        .as_deref()
        .ok_or_else(|| provider_unavailable("UIAutomationProvider"))
}

pub(super) fn window_provider(p: &Providers) -> Result<&dyn WindowProvider, ErrorData> {
    p.window
        .as_deref()
        .ok_or_else(|| provider_unavailable("WindowProvider"))
}

pub(super) fn vision_provider(p: &Providers) -> Result<&dyn VisionProvider, ErrorData> {
    p.vision
        .as_deref()
        .ok_or_else(|| provider_unavailable("VisionProvider"))
}

pub(super) fn browser_provider(p: &Providers) -> Result<&dyn BrowserProvider, ErrorData> {
    p.browser
        .as_deref()
        .ok_or_else(|| provider_unavailable("BrowserProvider"))
}

// --- shared payload shapes ---

/// `{"x","y","w","h"}` for a [`Rect`].
pub(super) fn bounds_json(r: &Rect) -> Value {
    json!({"x": r.x, "y": r.y, "w": r.w, "h": r.h})
}

/// `{"x","y"}` centre of a [`Rect`].
pub(super) fn center_json(r: &Rect) -> Value {
    json!({"x": r.x + r.w / 2, "y": r.y + r.h / 2})
}

/// `get_windows` wire shape for a [`WindowInfo`].
pub(super) fn window_json(w: &WindowInfo) -> Value {
    json!({
        "address": w.id,
        "class": w.class,
        "title": w.title,
        "workspace": {"id": w.workspace, "name": w.workspace.to_string()},
        "at": {"x": w.rect.x, "y": w.rect.y},
        "size": {"w": w.rect.w, "h": w.rect.h},
        "focused": w.focused,
    })
}

/// Base64 (standard alphabet, with padding) — avoids a new dependency for
/// the `image` content blocks returned by capture tools.
pub(super) fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn catalog_has_32_tools() {
        let all = list_tools(None);
        assert_eq!(all.len(), 32, "expected the full 32-tool catalog");
        let total: usize = CATALOG.iter().map(|(_, names)| names.len()).sum();
        assert_eq!(total, 32);
        // every catalog name maps to a built tool, and vice versa
        for t in &all {
            assert!(
                category_of(&t.name).is_some(),
                "uncatalogued tool {}",
                t.name
            );
        }
    }

    #[test]
    fn category_filtering() {
        let mouse = list_tools(Some(&["mouse".to_string()]));
        assert_eq!(mouse.len(), 7);
        let kb_admin = list_tools(Some(&["keyboard".to_string(), "admin".to_string()]));
        assert_eq!(kb_admin.len(), 9);
        let empty = list_tools(Some(&[]));
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn schemas_are_objects() {
        for t in list_tools(None) {
            assert_eq!(
                t.input_schema.get("type").and_then(Value::as_str),
                Some("object"),
                "tool {} inputSchema must be an object",
                t.name
            );
        }
    }

    #[tokio::test]
    async fn unknown_tool_is_method_not_found() {
        let err = call_tool("nope", Map::new(), &Providers::all_mocks())
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn mouse_click_with_mocks() {
        let r = call_tool(
            "mouse_click",
            args(json!({"x": 640, "y": 420})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap();
        assert_eq!(r.is_error, Some(false));
        assert_eq!(text_of(&r), "Clicked left at (640, 420)");
    }

    #[tokio::test]
    async fn missing_provider_is_error_data_32010() {
        let err = call_tool(
            "mouse_click",
            args(json!({"x": 1, "y": 2})),
            &Providers::empty(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, -32010);
        assert!(err.message.contains("InputProvider"));
    }

    #[tokio::test]
    async fn invalid_params_is_error_data_32602() {
        // missing required y
        let err = call_tool(
            "mouse_click",
            args(json!({"x": 1})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // out-of-range sleep
        let err = call_tool("sleep", args(json!({"ms": 60001})), &Providers::all_mocks())
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // both-zero scroll
        let err = call_tool(
            "mouse_scroll",
            args(json!({"dx": 0, "dy": 0})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // extra unknown key
        let err = call_tool(
            "screenshot",
            args(json!({"bogus": true})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn screenshot_returns_text_and_image() {
        let r = call_tool("screenshot", Map::new(), &Providers::all_mocks())
            .await
            .unwrap();
        assert_eq!(r.is_error, Some(false));
        assert_eq!(r.content.len(), 2);
        assert!(r.content[1].as_image().is_some());
    }

    #[tokio::test]
    async fn find_element_not_found_is_success_payload() {
        let r = call_tool(
            "find_element",
            args(json!({"query": "nothing"})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap();
        assert_eq!(r.is_error, Some(false));
        let v: Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["found"], false);
    }

    #[tokio::test]
    async fn system_command_is_validated_stub() {
        let r = call_tool(
            "system_command",
            args(json!({"command": "slurp", "args": ["-f", "%x %y %w %h"]})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap();
        assert_eq!(r.is_error, Some(false));
        // metacharacters are rejected
        let err = call_tool(
            "system_command",
            args(json!({"command": "slurp", "args": ["a;rm -rf /"]})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, -32006);
    }

    #[tokio::test]
    async fn window_control_validates_action_params() {
        // move requires x,y
        let err = call_tool(
            "window_control",
            args(json!({"action": "move"})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // focus on the mock's window works
        let r = call_tool(
            "window_control",
            args(json!({"action": "focus", "window": "mock"})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap();
        assert_eq!(text_of(&r), "focus applied to 0x0 (\"mock-window\")");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_ui_element_times_out_as_success() {
        let r = call_tool(
            "wait_for_ui_element",
            args(json!({"query": "never", "timeout_ms": 500})),
            &Providers::all_mocks(),
        )
        .await
        .unwrap();
        assert_eq!(r.is_error, Some(false));
        let v: Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["timed_out"], true);
    }

    #[test]
    fn base64_roundtrip_shape() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(&[0xFF, 0xFE]), "//4=");
    }

    // --- dispatch instrumentation: metrics + complete audit coverage ---

    fn security_in(dir: &std::path::Path) -> crate::security::SecurityContext {
        crate::security::SecurityContext::new(dir, false, false).expect("security context")
    }

    #[tokio::test]
    async fn secured_dispatch_audits_every_tool_and_verifies_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = security_in(tmp.path());
        let providers = Providers::all_mocks();

        // Non-destructive tools across categories — previously unaudited.
        for (name, a) in [
            ("mouse_click", json!({"x": 1, "y": 2})),
            ("type_text", json!({"text": "hi", "delay_ms": 0})),
            ("get_windows", json!({})),
        ] {
            call_tool_secured(name, args(a), &providers, &sec, "sess-t", None)
                .await
                .unwrap();
        }
        // Destructive call without a token: audited as consent_required.
        let err = call_tool_secured(
            "system_command",
            args(json!({"command": "slurp"})),
            &providers,
            &sec,
            "sess-t",
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::CONSENT_REQUIRED);

        let log_path = tmp.path().join("logs").join("audit.jsonl");
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4, "every call must produce one record");
        let tools: Vec<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["tool"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            tools,
            ["mouse_click", "type_text", "get_windows", "system_command"]
        );
        let last: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(last["outcome"], "consent_required");
        assert_eq!(last["caller"], "sess-t");
        // The mixed-tool chain verifies end-to-end.
        assert!(crate::security::audit::verify_chain_at(&log_path).unwrap());
    }

    #[tokio::test]
    async fn secured_dispatch_records_metrics_for_all_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = security_in(tmp.path());
        let providers = Providers::all_mocks();

        call_tool_secured(
            "screen_info",
            args(json!({})),
            &providers,
            &sec,
            "sess-m",
            None,
        )
        .await
        .unwrap();
        let _ = call_tool_secured(
            "replay_action", // gated → consent_required, still measured
            args(json!({"id": "x"})),
            &providers,
            &sec,
            "sess-m",
            None,
        )
        .await;

        let exp = crate::metrics::exposition();
        assert!(
            exp.contains("ultranix_mcp_tool_calls_total{tool=\"screen_info\",outcome=\"ok\"}"),
            "{exp}"
        );
        assert!(
            exp.contains(
                "ultranix_mcp_tool_calls_total{tool=\"replay_action\",outcome=\"consent_required\"}"
            ),
            "{exp}"
        );
        assert!(
            exp.contains("ultranix_mcp_tool_duration_seconds_count{tool=\"screen_info\"}"),
            "{exp}"
        );
    }

    #[tokio::test]
    async fn audit_records_args_hash_never_raw_args() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = security_in(tmp.path());
        let providers = Providers::all_mocks();

        let secret_args = json!({"text": "s3cr3t-blob", "delay_ms": 0});
        call_tool_secured(
            "type_text",
            args(secret_args.clone()),
            &providers,
            &sec,
            "sess-h",
            None,
        )
        .await
        .unwrap();

        let content = std::fs::read_to_string(tmp.path().join("logs").join("audit.jsonl")).unwrap();
        assert!(
            !content.contains("s3cr3t-blob"),
            "raw argument text must never reach the audit log"
        );
        let line: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(
            line["args_hash"].as_str().unwrap(),
            crate::security::consent::args_hash(&secret_args),
            "args_hash must be the canonical consent-gate hash"
        );
        assert_eq!(line["caller"], "sess-h");
    }

    #[tokio::test]
    async fn unsecured_dispatch_still_records_metrics() {
        call_tool("mouse_get_position", Map::new(), &Providers::all_mocks())
            .await
            .unwrap();
        let exp = crate::metrics::exposition();
        assert!(
            exp.contains(
                "ultranix_mcp_tool_calls_total{tool=\"mouse_get_position\",outcome=\"ok\"}"
            )
        );
    }
}
