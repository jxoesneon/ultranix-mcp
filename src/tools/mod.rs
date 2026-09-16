//! Tool registry: schemas, categories, dispatch. Canonical catalog lives in
//! docs/TOOLS.md — this module is its compiled mirror (40 tools).

mod admin;
mod automation;
mod clipboard;
mod keyboard;
mod mouse;
mod plugin;
mod record;
mod stream;
mod vision;

use std::sync::{Arc, LazyLock};

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
/// (element lookup lands with Phase 2).
const ELEMENT_NOT_FOUND: i32 = -32016;

/// Policy-denial error constructors. The `denial_reason` is recorded in
/// the audit log and returned as `data.denial_reason` so clients can
/// distinguish `--readonly` from per-tool list violations.
fn policy_denied(tool: &str, reason: &str) -> ErrorData {
    let code = if reason == "readonly_mode" {
        codes::READ_ONLY_MODE
    } else {
        codes::NOT_IN_TOOL_LIST
    };
    let kind = if reason == "readonly_mode" {
        "ReadOnlyMode"
    } else {
        "NotInToolList"
    };
    ErrorData::new(
        ErrorCode(code),
        format!("{tool} denied: {reason}"),
        Some(json!({"kind": kind, "denial_reason": reason})),
    )
}

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
            "screen_record",
            "screen_stream",
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
            "plugin_list",
            "plugin_run",
            "plugin_reload",
        ],
    ),
    (
        "clipboard",
        &["clipboard_get", "clipboard_set", "clipboard_clear"],
    ),
];

/// Every advertised tool definition, built once (schemas are static).
fn all_tools() -> &'static [Tool] {
    static ALL: LazyLock<Vec<Tool>> = LazyLock::new(|| {
        let mut v = Vec::with_capacity(40);
        v.extend(mouse::tools());
        v.extend(keyboard::tools());
        v.extend(vision::tools());
        v.extend(automation::tools());
        v.extend(admin::tools());
        v.extend(clipboard::tools());
        v.extend(record::tools());
        v.extend(stream::tools());
        v.extend(plugin::tools());
        v
    });
    &ALL
}

/// All category names in catalog order (`mouse`, `keyboard`, …).
pub fn categories() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().map(|(c, _)| *c)
}

/// Category a tool name belongs to, or `None` for unknown names.
pub(crate) fn category_of(name: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find_map(|(cat, names)| names.contains(&name).then_some(*cat))
}

/// Metric-safe tool label: client-supplied names that aren't in the
/// catalog collapse to `"__unknown__"` — otherwise every arbitrary name
/// would mint a new `tool_calls_total`/`tool_duration_seconds` series
/// (unbounded label cardinality). Returns the catalog's own `&'static`
/// name so the metrics maps can key on `&'static str` without copying.
fn metric_label(name: &str) -> &'static str {
    CATALOG
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .find(|n| *n == name)
        .unwrap_or("__unknown__")
}

/// Resolve the provider name used by a tool from the startup backend registry.
/// Names are capability-specific, so this remains correct when an earlier
/// provider slot failed detection and is absent from `backend_names`. All
/// returned names are `&'static` (provider names and sentinels), so the
/// metric maps never allocate per call.
fn metric_backend(name: &str, providers: &Providers) -> &'static str {
    let candidates: &[&str] = match name {
        "mouse_click"
        | "mouse_double_click"
        | "mouse_move"
        | "mouse_get_position"
        | "mouse_scroll"
        | "mouse_drag"
        | "mouse_button_control"
        | "type_text"
        | "key_control"
        | "mouse_move_path" => &[
            "wlr-virtual-input",
            "uinput",
            "portal-remote-desktop",
            "xdotool",
            "mock-input",
        ],
        "screenshot" | "screen_info" | "color_at" | "screen_record" | "screen_stream" => &[
            "wlr-screencopy",
            "grim",
            "portal-screenshot",
            "scrot",
            "mock-capture",
        ],
        "screen_highlight" => &["wlr-layer-shell", "mock-overlay"],
        "get_ui_tree"
        | "get_focused_element"
        | "find_element"
        | "wait_for_ui_element"
        | "invoke_element" => &["atspi2", "mock-ui-automation"],
        "find_text_on_screen" | "find_icon" => &["onnx", "mock-vision"],
        "web_query" => &["cdp", "mock-browser"],
        "clipboard_get" | "clipboard_set" | "clipboard_clear" => {
            &["wl-clipboard", "xclip", "mock-clipboard"]
        }
        "window_control" | "get_windows" | "get_active_window" => &[
            "hyprctl",
            "sway-ipc",
            "kdotool",
            "wayfire-ipc",
            "riverctl",
            "gnome-shell",
            "wmctrl",
            "mock-window",
        ],
        // These execute entirely in the server even when they inspect or
        // mutate state owned by a provider-backed subsystem.
        _ => return "core",
    };
    providers
        .backend_names
        .iter()
        .copied()
        .find(|backend| candidates.contains(backend))
        .unwrap_or("unknown")
}

fn record_tool_metric(
    name: &str,
    providers: &Providers,
    duration: std::time::Duration,
    outcome: &'static str,
) {
    crate::metrics::record_call_with_backend(
        metric_label(name),
        metric_backend(name, providers),
        duration,
        outcome,
    );
}

/// `-32601 MethodNotFound` for a tool outside the enabled category set —
/// the wire shape docs/API_VERSIONING.md fixes for calls to filtered
/// tools (`data.kind = "CategoryDisabled"`). `None` categories = all
/// enabled; unknown names yield `None` here and fall through to
/// [`unknown_tool`].
pub fn category_gate(name: &str, categories: Option<&[String]>) -> Option<ErrorData> {
    let cats = categories?;
    let cat = category_of(name)?;
    if cats.iter().any(|c| c == cat) {
        return None;
    }
    Some(ErrorData::new(
        ErrorCode::METHOD_NOT_FOUND,
        format!("tool disabled by category filter: {name}"),
        Some(json!({
            "kind": "CategoryDisabled",
            "category": cat,
            "tool": name,
        })),
    ))
}

/// `tools/list` with an optional runtime policy: per-key scoping on HTTP,
/// default role on stdio. When `policy` is `None`, this is exactly
/// [`list_tools`].
pub fn list_tools_for(
    categories: Option<&[String]>,
    policy: Option<&crate::security::policy::Policy>,
    key_id: Option<&str>,
) -> Vec<Tool> {
    let mut tools = list_tools(categories);
    if let Some(policy) = policy {
        let role = policy.resolve(key_id);
        tools.retain(|t| policy.is_tool_allowed(role, &t.name));
    }
    tools
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
    record_tool_metric(name, providers, t0.elapsed(), outcome_of(&result));
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
    if let Some(r) = clipboard::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = record::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = stream::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = plugin::dispatch(name, args, providers).await {
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
    security: SecRef<'_>,
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
    if let Some(r) = clipboard::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = record::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) = stream::dispatch(name, args, providers).await {
        return r;
    }
    if let Some(r) =
        plugin::dispatch_secured(name, args, providers, security, session_id, key_id).await
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

/// Shared-or-borrowed [`crate::security::SecurityContext`] handle accepted
/// by [`call_tool_secured`].
///
/// `UltraNixServer` holds the context in an `Arc`; passing that
/// `&Arc<SecurityContext>` ([`SecRef::Shared`]) lets the hash-chained
/// audit append move onto `tokio::task::spawn_blocking` like the
/// encrypted-history write (EFF-1). A plain `&SecurityContext`
/// ([`SecRef::Borrowed`]) has no `'static` handle to move, so its audit
/// records are appended inline — the record bytes are identical either
/// way; only the executor placement differs.
#[derive(Clone, Copy)]
pub enum SecRef<'a> {
    /// Borrowed context — audit appends run on the current task.
    Borrowed(&'a crate::security::SecurityContext),
    /// `Arc`-shared context — audit appends run on `spawn_blocking`.
    Shared(&'a Arc<crate::security::SecurityContext>),
}

impl<'a> From<&'a crate::security::SecurityContext> for SecRef<'a> {
    fn from(ctx: &'a crate::security::SecurityContext) -> Self {
        Self::Borrowed(ctx)
    }
}

impl<'a> From<&'a Arc<crate::security::SecurityContext>> for SecRef<'a> {
    fn from(ctx: &'a Arc<crate::security::SecurityContext>) -> Self {
        Self::Shared(ctx)
    }
}

impl std::ops::Deref for SecRef<'_> {
    type Target = crate::security::SecurityContext;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(ctx) => ctx,
            Self::Shared(ctx) => ctx,
        }
    }
}

/// `-32015 ConsentRequired` — destructive call needs a challenge retry.
fn consent_required(token: &str, expires_in_ms: u64, tool: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::CONSENT_REQUIRED),
        "consent required: destructive action; retry with consent_token",
        Some(json!({
            "kind": "ConsentRequired",
            "consent_token": token,
            "expires_in_ms": expires_in_ms,
            "tool": tool,
        })),
    )
}

/// Whether `name`+`args` lands in the destructive consent class
/// (docs/TOOLS.md §Destructive-Action Consent).
fn is_destructive(name: &str, args: &Map<String, Value>) -> bool {
    match name {
        "system_command" | "clear_action_history" | "replay_action" => true,
        // Clipboard writes destroy user state (and can plant hostile
        // paste content) — same destructive class as the other mutating
        // tools.
        "clipboard_set" | "clipboard_clear" => true,
        "window_control" => args.get("action").and_then(Value::as_str) == Some("close"),
        _ => false,
    }
}

/// Append one hash-chained audit record. On the [`SecRef::Shared`] path
/// the <1 KiB write (+ day-rollover rotation/prune) runs on
/// `spawn_blocking` like the encrypted-history append (EFF-1); a borrowed
/// context records inline — identical bytes, only the executor placement
/// differs. Errors are swallowed: an audit sink fault must never fail a
/// tool call.
async fn audit_record(
    security: SecRef<'_>,
    tool: &str,
    args_hash: &str,
    outcome: &'static str,
    duration_ms: u64,
    ctx: crate::security::audit::CallContext<'_>,
    denial_reason: Option<&'static str>,
) {
    match security {
        SecRef::Shared(sec) => {
            let sec = Arc::clone(sec);
            let tool = tool.to_string();
            let args_hash = args_hash.to_string();
            let denial_reason = denial_reason.map(str::to_string);
            // CallContext borrows caller strings — own them for the move.
            let key_id = ctx.key_id.map(str::to_string);
            let caller = ctx.caller.map(str::to_string);
            let consent = ctx.consent.map(str::to_string);
            let res = tokio::task::spawn_blocking(move || {
                sec.audit.record(
                    &tool,
                    &args_hash,
                    outcome,
                    duration_ms,
                    crate::security::audit::CallContext {
                        key_id: key_id.as_deref(),
                        caller: caller.as_deref(),
                        consent: consent.as_deref(),
                    },
                    denial_reason.as_deref(),
                )
            })
            .await;
            // Audit faults must not fail the tool call — but a dropped
            // record must not be silent either.
            match res {
                Ok(Err(e)) => tracing::warn!(%e, "audit record failed"),
                Err(e) => tracing::warn!(%e, "audit record task panicked"),
                Ok(Ok(())) => {}
            }
        }
        SecRef::Borrowed(sec) => {
            if let Err(e) =
                sec.audit
                    .record(tool, args_hash, outcome, duration_ms, ctx, denial_reason)
            {
                tracing::warn!(%e, "audit record failed");
            }
        }
    }
}

/// `tools/call` with the security pipeline applied: consent gate for the
/// destructive class, real whitelist-constrained `system_command` exec,
/// a hash-chained audit record for **every** call (accepted or rejected —
/// SECURITY.md "Audit | Every invocation"), and a
/// `ultranix_mcp_tool_calls_total` / `_duration_seconds` metric sample.
///
/// `security` accepts `&SecurityContext` or `&Arc<SecurityContext>` (see
/// [`SecRef`]); the latter moves the audit append off the runtime worker.
pub async fn call_tool_secured<'a>(
    name: &str,
    args: Map<String, Value>,
    providers: &Providers,
    security: impl Into<SecRef<'a>>,
    session_id: &str,
    key_id: Option<&str>,
) -> Result<CallToolResult, ErrorData> {
    let security = security.into();
    let t0 = std::time::Instant::now();
    let mut args = args;
    let argsv = Value::Object(args.clone());
    let hash = crate::security::consent::args_hash(&argsv);
    let destructive = is_destructive(name, &args);

    // Category gate (docs/API_VERSIONING.md "Category Filters"): a tool
    // outside the enabled set is `MethodNotFound` — audited and metered
    // like every other rejected call. Lives here (not in the server
    // handler) so `replay_action`'s re-entry enforces it too.
    if let Some(err) = category_gate(name, security.categories.as_deref()) {
        let elapsed = t0.elapsed();
        record_tool_metric(name, providers, elapsed, "error");
        audit_record(
            security,
            name,
            &hash,
            "error",
            elapsed.as_millis() as u64,
            crate::security::audit::CallContext {
                key_id,
                caller: Some(key_id.unwrap_or(session_id)),
                consent: None,
            },
            None,
        )
        .await;
        return Err(err);
    }

    // Per-caller runtime policy: per-key scoping on HTTP, default role on
    // stdio. Hidden tools are rejected with a policy-specific code and
    // audited as denied.
    let role = security.policy.resolve(key_id);
    if !security.policy.is_tool_allowed(role, name) {
        let elapsed = t0.elapsed();
        let reason =
            if role.readonly && !crate::security::policy::readonly_allowlist().contains(&name) {
                "readonly_mode"
            } else {
                "not_in_tool_list"
            };
        record_tool_metric(name, providers, elapsed, "denied");
        audit_record(
            security,
            name,
            &hash,
            "denied",
            elapsed.as_millis() as u64,
            crate::security::audit::CallContext {
                key_id,
                caller: Some(key_id.unwrap_or(session_id)),
                consent: None,
            },
            Some(reason),
        )
        .await;
        return Err(policy_denied(name, reason));
    }

    // Resolve the execution-time target for target-scoped consent:
    // window_control{close} binds the concrete window id at challenge
    // time — the active window when `window` is absent, the unique
    // selector match when present (docs/TOOLS.md — a target change
    // between challenge and retry invalidates the token).
    let resolved_target = if name == "window_control"
        && args.get("action").and_then(Value::as_str) == Some("close")
    {
        match &providers.window {
            Some(w) => {
                resolve_close_target(w.as_ref(), args.get("window").and_then(Value::as_str)).await
            }
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
            record_tool_metric(name, providers, t0.elapsed(), "consent_required");
            audit_record(
                security,
                name,
                &hash,
                "consent_required",
                t0.elapsed().as_millis() as u64,
                crate::security::audit::CallContext {
                    key_id,
                    caller: Some(key_id.unwrap_or(session_id)),
                    consent: None,
                },
                None,
            )
            .await;
            let ch = match resolved_target.as_deref() {
                Some(t) => security
                    .consent
                    .challenge_for_target(key_id, session_id, name, &argsv, t),
                None => security.consent.challenge(key_id, session_id, name, &argsv),
            };
            return Err(consent_required(&ch.token, ch.expires_in_ms, name));
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

    // Bind execution to the challenged identity (S-6): substituting the
    // resolved window id for the (possibly absent) selector makes the
    // admin leg take its exact-id path, so a selector that would now
    // match a different window — or a focus change since the challenge —
    // cannot redirect the close.
    if let Some(id) = &resolved_target {
        args.insert("window".into(), Value::String(id.clone()));
    }

    let result = if name == "system_command" {
        exec_system_command(&args, &security).await
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
    record_tool_metric(name, providers, elapsed, outcome);
    audit_record(
        security,
        name,
        &hash,
        outcome,
        elapsed.as_millis() as u64,
        crate::security::audit::CallContext {
            key_id,
            caller: Some(key_id.unwrap_or(session_id)),
            consent: consent_stamp,
        },
        None,
    )
    .await;

    // Encrypted action history: every replayable invocation appends to
    // the context-scoped store (meta/history tools excluded — replaying
    // them is meaningless and recording them is noise). The append does
    // blocking file + crypto work, so it runs on `spawn_blocking`
    // instead of a runtime worker (EFF-1).
    if !admin::is_unrecorded(name, &argsv)
        && let Ok(store) = security.history_arc()
    {
        // Strip the spent consent token — the store holds replayable
        // args, and a recorded token is dead weight (replay re-challenges
        // anyway).
        let mut recorded = argsv.clone();
        if let Some(obj) = recorded.as_object_mut() {
            obj.remove("consent_token");
        }
        let rec = crate::security::history::NewActionRecord {
            tool: name.to_string(),
            args_json: recorded,
            result_summary: result_summary(name, &result),
            caller: key_id.unwrap_or(session_id).to_string(),
            duration_ms: elapsed.as_millis() as u64,
            outcome: outcome.to_string(),
        };
        let res = tokio::task::spawn_blocking(move || {
            let res = store.record(rec);
            if res.is_ok() {
                crate::metrics::set_action_history_size(store.len());
            }
            res
        })
        .await;
        match res {
            Ok(Err(e)) => tracing::warn!(%e, "history record failed"),
            Err(e) => tracing::warn!(%e, "history record task panicked"),
            Ok(Ok(_)) => {}
        }
    }
    result
}

/// Concrete window id for a `window_control{close}` consent binding:
/// `None` selector → active window; `Some(sel)` → exact id match, else
/// unique case-insensitive title/class substring (mirrors the admin
/// leg's selector rules). Unresolvable or ambiguous selectors yield
/// `None` — dispatch then reports the real error unbound.
async fn resolve_close_target(
    window: &dyn WindowProvider,
    selector: Option<&str>,
) -> Option<String> {
    // Focused-view-only backend (river): every close targets the focused
    // view, which cannot be identified further — bind the token to the
    // focused selector itself.
    if let Some(fid) = window.focused_view_selector() {
        return match selector {
            None => Some(fid.to_string()),
            Some(sel) => (sel == fid).then(|| fid.to_string()),
        };
    }
    match selector {
        None => window.active_window().await.ok().flatten().map(|w| w.id),
        Some(sel) => {
            let windows = window.list_windows().await.ok()?;
            if let Some(w) = windows.iter().find(|w| w.id == sel) {
                return Some(w.id.clone());
            }
            let needle = sel.to_lowercase();
            let matches: Vec<&WindowInfo> = windows
                .iter()
                .filter(|w| {
                    w.title.to_lowercase().contains(&needle)
                        || w.class.to_lowercase().contains(&needle)
                })
                .collect();
            (matches.len() == 1).then(|| matches[0].id.clone())
        }
    }
}

/// First text block of a tool result (or the error line) — the summary
/// persisted beside each action-history record. `clipboard_get` is
/// special-cased: clipboard contents are secrets-adjacent (password
/// managers copy through the clipboard), so the summary keeps only the
/// MIME type and payload length — never the payload itself, the same
/// threat model as the `type_text`/`clipboard_set` arg redaction.
/// `plugin_run` — and any plugin-exposed dynamic tool — is also
/// special-cased: step payloads (which may come from secret-bearing
/// tools like `clipboard_get`) are never persisted; only the plugin name
/// and step count are recorded. The check is on the *result shape*
/// (`{"plugin": …, "steps_run": …}`), not the dispatch name, so exposed
/// tools are covered without a registry lookup on the record path.
fn result_summary(tool: &str, result: &Result<CallToolResult, ErrorData>) -> String {
    if let Ok(r) = result
        && let Some(v) = r
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .and_then(|t| serde_json::from_str::<Value>(&t.text).ok())
        && v.get("plugin").and_then(Value::as_str).is_some()
        && v.get("steps_run").and_then(Value::as_u64).is_some()
    {
        return format!(
            "plugin={} steps={}",
            v.get("plugin").and_then(Value::as_str).unwrap_or("?"),
            v.get("steps_run").and_then(Value::as_u64).unwrap_or(0)
        );
    }
    if tool == "clipboard_get"
        && let Ok(r) = result
    {
        return r
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .and_then(|t| serde_json::from_str::<Value>(&t.text).ok())
            .map(|v| {
                format!(
                    "mime={} len={}",
                    v.get("mime").and_then(Value::as_str).unwrap_or("?"),
                    v.get("text").and_then(Value::as_str).map_or(0, str::len)
                )
            })
            .unwrap_or_else(|| "<clipboard read>".into());
    }
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
        .map_err(|e| whitelist_error_data(&e))?;

    // Pinned absolute path, scrubbed environment (S-10), kill-on-drop so
    // a timed-out wait still reaps the child, 15 s budget, 4 MiB
    // stdout/stderr capture via `spawn::output_within` (unbounded
    // post-exit buffering removed in v1.2.0). The outer timeout
    // preserves the `{"timed_out": true}` contract; the inner bound is
    // a defensive backstop only.
    let argv: Vec<&str> = inv.argv[1..].iter().map(String::as_str).collect();
    let mut cmd = crate::security::spawn::command(&inv.abs_path, &argv);
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        crate::security::spawn::output_within(&mut cmd, std::time::Duration::from_secs(30)),
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

/// `WhitelistError` → the documented JSON-RPC code + `data.kind`
/// (docs/TOOLS.md error taxonomy): not-whitelisted and argument
/// constraints → `-32003`, path whitelist → `-32004`, sanitization →
/// `-32006`.
fn whitelist_error_data(e: &crate::security::whitelist::WhitelistError) -> ErrorData {
    use crate::security::whitelist::WhitelistError as W;
    let (code, kind) = match e {
        W::Sanitize(_) => (codes::SANITIZATION_REJECTED, "SanitizationRejected"),
        W::Path(_) => (codes::PATH_NOT_WHITELISTED, "PathNotWhitelisted"),
        W::NotWhitelisted(_) => (codes::COMMAND_NOT_WHITELISTED, "CommandNotWhitelisted"),
        W::ArgConstraint { .. } => (codes::ARG_CONSTRAINT_VIOLATION, "ArgConstraintViolation"),
    };
    let detail = e.to_string();
    ErrorData::new(
        ErrorCode(code),
        detail.clone(),
        Some(json!({"kind": kind, "detail": detail})),
    )
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
        ErrorCode(codes::SANITIZATION_REJECTED),
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
    fn catalog_covers_every_built_tool() {
        let all = list_tools(None);
        let total: usize = CATALOG.iter().map(|(_, names)| names.len()).sum();
        assert_eq!(
            all.len(),
            total,
            "every catalog name must map to a built tool"
        );
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
        assert_eq!(kb_admin.len(), 12);
        let clipboard = list_tools(Some(&["clipboard".to_string()]));
        assert_eq!(clipboard.len(), 3);
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

    #[tokio::test]
    async fn secured_dispatch_accepts_arc_context() {
        // `&Arc<SecurityContext>` selects SecRef::Shared — the audit
        // append runs on `spawn_blocking`, awaited before return.
        let tmp = tempfile::tempdir().unwrap();
        let sec = std::sync::Arc::new(security_in(tmp.path()));
        let providers = Providers::all_mocks();

        call_tool_secured(
            "mouse_click",
            args(json!({"x": 1, "y": 2})),
            &providers,
            &sec,
            "sess-arc",
            None,
        )
        .await
        .unwrap();

        let content = std::fs::read_to_string(tmp.path().join("logs").join("audit.jsonl")).unwrap();
        let line: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["tool"], "mouse_click");
        assert_eq!(line["caller"], "sess-arc");
        // A replayable call also refreshed the history-size gauge.
        assert!(crate::metrics::exposition().contains("ultranix_mcp_action_history_size"));
    }

    // --- runtime access-control policy (ADR 0010) ---

    fn policy_sec(
        dir: &std::path::Path,
        f: impl FnOnce(&mut crate::security::policy::Policy),
    ) -> crate::security::SecurityContext {
        let mut sec = security_in(dir);
        let mut p = crate::security::policy::Policy::default();
        f(&mut p);
        sec.set_policy(p);
        sec
    }

    #[test]
    fn readonly_list_tools_shows_only_non_mutating() {
        let p = crate::security::policy::Policy {
            default_role: crate::security::policy::Role {
                readonly: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let names: Vec<String> = list_tools_for(None, Some(&p), None)
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.contains(&"screenshot".to_string()));
        assert!(names.contains(&"get_windows".to_string()));
        assert!(!names.contains(&"type_text".to_string()));
        assert!(!names.contains(&"invoke_element".to_string()));
        assert!(!names.contains(&"clipboard_get".to_string()));
        assert!(!names.contains(&"screen_highlight".to_string()));
        assert!(!names.contains(&"get_action_history".to_string()));
        assert!(!names.contains(&"system_command".to_string()));
        assert_eq!(names.len(), 15);
    }

    #[tokio::test]
    async fn readonly_call_is_denied_and_audited() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = policy_sec(tmp.path(), |p| {
            p.default_role.readonly = true;
        });
        let providers = Providers::all_mocks();
        let err = call_tool_secured(
            "type_text",
            args(json!({"text": "x"})),
            &providers,
            &sec,
            "sess-readonly",
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::READ_ONLY_MODE);
        assert_eq!(err.data.as_ref().unwrap()["denial_reason"], "readonly_mode");
        assert_eq!(err.data.as_ref().unwrap()["kind"], "ReadOnlyMode");

        let content = std::fs::read_to_string(tmp.path().join("logs").join("audit.jsonl")).unwrap();
        let line: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["tool"], "type_text");
        assert_eq!(line["outcome"], "denied");
        assert_eq!(line["denial_reason"], "readonly_mode");
    }

    #[tokio::test]
    async fn allowlist_denies_unlisted_tool() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = policy_sec(tmp.path(), |p| {
            p.default_role.allow_tools = Some(["screenshot".to_string()].into_iter().collect());
        });
        let providers = Providers::all_mocks();
        let err = call_tool_secured(
            "system_command",
            args(json!({"command": "slurp", "args": []})),
            &providers,
            &sec,
            "sess-allow",
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);

        let content = std::fs::read_to_string(tmp.path().join("logs").join("audit.jsonl")).unwrap();
        let line: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["denial_reason"], "not_in_tool_list");
    }

    #[tokio::test]
    async fn denylist_overrides_category_and_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = policy_sec(tmp.path(), |p| {
            p.default_role.deny_tools.insert("screenshot".to_string());
        });
        let providers = Providers::all_mocks();
        let err = call_tool_secured(
            "screenshot",
            args(json!({})),
            &providers,
            &sec,
            "sess-deny",
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }

    #[tokio::test]
    async fn per_key_scope_applies_to_call_tool() {
        let tmp = tempfile::tempdir().unwrap();
        let sec = policy_sec(tmp.path(), |p| {
            p.roles.insert(
                "analyst".to_string(),
                crate::security::policy::Role {
                    allow_tools: Some(
                        ["screenshot".to_string(), "get_windows".to_string()]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            );
            p.keys.insert("key-1".to_string(), "analyst".to_string());
        });
        let providers = Providers::all_mocks();
        // key-1 is scoped to the analyst role — type_text is denied.
        let err = call_tool_secured(
            "type_text",
            args(json!({"text": "x"})),
            &providers,
            &sec,
            "sess-keyed",
            Some("key-1"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
        // The mapped role still permits its own tools.
        call_tool_secured(
            "screenshot",
            args(json!({})),
            &providers,
            &sec,
            "sess-keyed",
            Some("key-1"),
        )
        .await
        .unwrap();
        // An unknown key falls back to the default role (all allowed).
        call_tool_secured(
            "type_text",
            args(json!({"text": "x"})),
            &providers,
            &sec,
            "sess-other",
            Some("unknown-key"),
        )
        .await
        .unwrap();
    }
}
