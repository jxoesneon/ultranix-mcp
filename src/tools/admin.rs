//! Admin & observability tools (10) - `WindowProvider` for windowing;
//! history tools run on the AES-256-GCM [`HistoryStore`]; `metrics`
//! serves the live Prometheus exposition.

use rmcp::model::{CallToolResult, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    SecRef, backend, backend_error, invalid_params, json_result, parse_args, text_result, tool,
    tool_error, tool_schema, window_json, window_provider,
};
use crate::providers::Providers;
use crate::security::history::{ActionRecord, HistoryStore};
use crate::traits::{Rect, WindowInfo, WindowProvider};

/// `-32014 HistoryError` - encrypted history store fault (docs/TOOLS.md
/// error taxonomy; not yet surfaced in `crate::error::codes`).
const HISTORY_ERROR: i32 = -32014;

/// History tools that can never be replayed (recursion + no-op guards,
/// docs/TOOLS.md `replay_action`).
pub(super) const NON_REPLAYABLE: &[&str] = &[
    "metrics",
    "get_action_history",
    "replay_action",
    "clear_action_history",
    // Meta plugin tools: read-only catalog/rescan operations - nothing
    // to replay, and recording them is noise. `plugin_run` IS recorded
    // (it's a real action) and replays only when its params redaction
    // leaves nothing to hide.
    "plugin_list",
    "plugin_reload",
    // Lifecycle, not an action: replaying `screen_stream{start}` would
    // spawn a background capture task - the record is kept (audit/
    // history still apply) but replay is refused.
    "screen_stream",
];

/// Tools never *recorded* to action history at all - replaying them is
/// meaningless and recording them is noise. `screen_stream` is NOT here:
/// its lifecycle events (`start`/`stop`) are recorded, while the
/// polling actions are filtered by [`is_unrecorded`] below.
pub(super) const UNRECORDED: &[&str] = &[
    "metrics",
    "get_action_history",
    "replay_action",
    "clear_action_history",
    "plugin_list",
    "plugin_reload",
];

/// Whether a call is appended to action history. Whole-tool
/// suppressions live in [`UNRECORDED`]; `screen_stream`'s polling
/// actions (`status`/`latest`) are additionally suppressed - they are
/// per-frame reads that would flood the bounded store - while `start`
/// and `stop` are lifecycle events worth keeping (and refusing to
/// replay via [`NON_REPLAYABLE`]).
pub(super) fn is_unrecorded(name: &str, args: &Value) -> bool {
    if UNRECORDED.contains(&name) {
        return true;
    }
    name == "screen_stream"
        && matches!(
            args.get("action").and_then(Value::as_str),
            Some("status") | Some("latest")
        )
}

/// `-32014` with the `data.kind` discriminator - store faults (decrypt,
/// key, or filesystem) the caller sees.
fn history_error(err: anyhow::Error) -> ErrorData {
    let detail = format!("{err:#}");
    ErrorData::new(
        ErrorCode(HISTORY_ERROR),
        format!("history error: {detail}"),
        Some(json!({"kind": "HistoryError", "detail": detail})),
    )
}

/// Resolve the encrypted store for this call: on the secured path the
/// store is scoped to the `SecurityContext`'s own state root (keeps
/// tests and isolated contexts hermetic); unsecured callers fall back to
/// the process-wide ambient-root store. Open/init faults map to `-32014`.
fn store<'a>(secured: &'a Option<Secured<'a>>) -> Result<&'a HistoryStore, ErrorData> {
    if let Some(s) = secured {
        return s.security.history().map_err(history_error);
    }
    HistoryStore::shared().map_err(history_error)
}

/// A store handle that can move into `tokio::task::spawn_blocking`
/// (`Send + 'static`): `&'static` for the ambient shared store, `Arc`
/// for the context-scoped one
/// ([`crate::security::SecurityContext::history_arc`] exists for exactly
/// this - EFF-1). Used by `clear_action_history`, whose wipe does real
/// file work; the read paths above keep their `&HistoryStore` borrows.
enum StoreHandle {
    /// The process-wide shared store - already `'static`.
    Ambient(&'static HistoryStore),
    /// Context-scoped store held by `Arc`.
    Scoped(std::sync::Arc<HistoryStore>),
}

impl std::ops::Deref for StoreHandle {
    type Target = HistoryStore;
    fn deref(&self) -> &HistoryStore {
        match self {
            Self::Ambient(s) => s,
            Self::Scoped(a) => a,
        }
    }
}

/// [`store`] for the blocking wipe path - returns the movable handle.
fn store_handle(secured: &Option<Secured<'_>>) -> Result<StoreHandle, ErrorData> {
    if let Some(s) = secured {
        return s
            .security
            .history_arc()
            .map(StoreHandle::Scoped)
            .map_err(history_error);
    }
    HistoryStore::shared()
        .map(StoreHandle::Ambient)
        .map_err(history_error)
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WindowAction {
    Focus,
    Move,
    Resize,
    Minimize,
    Close,
}

impl WindowAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Focus => "focus",
            Self::Move => "move",
            Self::Resize => "resize",
            Self::Minimize => "minimize",
            Self::Close => "close",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WindowControlParams {
    /// Window operation to apply
    action: WindowAction,
    /// Hyprland address ("0x...") or unique title/class substring;
    /// omit for the active window. On focused-view-only backends (river)
    /// `"focused"` - or omitting the selector - addresses the focused
    /// view directly.
    window: Option<String>,
    /// Target x (move only)
    x: Option<i32>,
    /// Target y (move only)
    y: Option<i32>,
    /// Target width (resize only)
    w: Option<i32>,
    /// Target height (resize only)
    h: Option<i32>,
    /// Relative x delta (move only; focused-view backends such as river)
    dx: Option<i32>,
    /// Relative y delta (move only; focused-view backends such as river)
    dy: Option<i32>,
    /// Relative width delta (resize only; focused-view backends such as river)
    dw: Option<i32>,
    /// Relative height delta (resize only; focused-view backends such as river)
    dh: Option<i32>,
    /// Challenge token from a prior -32015 ConsentRequired response
    /// (close only)
    consent_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HistoryParams {
    /// Maximum records to return, newest-first
    #[serde(default = "default_history_limit")]
    #[schemars(range(min = 1, max = 1000))]
    limit: u32,
    /// Case-insensitive substring filter on the recorded tool name
    /// (e.g. "mouse" matches mouse_click, mouse_drag, ...)
    action: Option<String>,
}

fn default_history_limit() -> u32 {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReplayParams {
    /// History index from get_action_history
    index: Option<u64>,
    /// Record ULID (exactly 26 chars)
    id: Option<String>,
    /// Challenge token from a prior -32015 ConsentRequired response for this
    /// exact call
    consent_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClearHistoryParams {
    /// Challenge token from a prior -32015 ConsentRequired response
    consent_token: Option<String>,
}

fn replay_tool() -> Tool {
    let mut schema = tool_schema::<ReplayParams>();
    schema.insert(
        "anyOf".into(),
        json!([
            {"required": ["index"], "not": {"required": ["id"]}},
            {"required": ["id"], "not": {"required": ["index"]}},
        ]),
    );
    Tool::new(
        "replay_action",
        "Re-execute a recorded action by ULID `id` or `index` (exactly one selector; consent-gated).",
        schema,
    )
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<WindowControlParams>(
            "window_control",
            "Focus, move, resize, minimise, or close a window via compositor dispatchers.",
        ),
        tool::<NoParams>("get_windows", "List all managed windows."),
        tool::<NoParams>(
            "get_active_window",
            "Return the focused window, or {\"focused\": null} when nothing is focused.",
        ),
        tool::<NoParams>(
            "metrics",
            "Return the Prometheus text exposition served at GET /metrics on :3010.",
        ),
        tool::<HistoryParams>(
            "get_action_history",
            "Read the encrypted action history, newest-first; `action` filters to tool names containing it.",
        ),
        replay_tool(),
        tool::<ClearHistoryParams>(
            "clear_action_history",
            "Securely wipe history.json and reset the in-memory index (consent-gated).",
        ),
    ]
}

/// Borrowed security pipeline for the secured dispatch path - lets
/// `replay_action` pass the recorded call back through `call_tool_secured`
/// (consent re-challenge, audit, real `system_command` exec) instead of the
/// Phase-0 ungated dispatch.
#[derive(Clone, Copy)]
struct Secured<'a> {
    /// [`SecRef`] (not a bare `&SecurityContext`) so a replay re-entering
    /// `call_tool_secured` keeps the `Arc` shared handle and its
    /// `spawn_blocking` audit path.
    security: SecRef<'a>,
    session_id: &'a str,
    key_id: Option<&'a str>,
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    dispatch_ctx(name, args, providers, None).await
}

/// Secured variant for `call_tool_secured` (via `super::dispatch_secured`):
/// identical to [`dispatch`] but `replay_action` re-enters the full
/// security pipeline for the recorded call, so replaying a destructive
/// action re-challenges the consent gate on its own
/// `{caller, tool, args_hash}` binding (docs/TOOLS.md).
pub(super) async fn dispatch_secured(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    security: SecRef<'_>,
    session_id: &str,
    key_id: Option<&str>,
) -> Option<Result<CallToolResult, ErrorData>> {
    dispatch_ctx(
        name,
        args,
        providers,
        Some(Secured {
            security,
            session_id,
            key_id,
        }),
    )
    .await
}

async fn dispatch_ctx(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "window_control" => window_control(args, providers).await,
        "get_windows" => get_windows(args, providers).await,
        "get_active_window" => get_active_window(args, providers).await,
        "metrics" => metrics(args).await,
        "get_action_history" => match store(&secured) {
            Ok(s) => get_action_history(args, s).await,
            Err(e) => Err(e),
        },
        "replay_action" => match store(&secured) {
            Ok(s) => replay_action(args, providers, s, secured).await,
            Err(e) => Err(e),
        },
        "clear_action_history" => match store_handle(&secured) {
            Ok(s) => clear_action_history(args, s).await,
            Err(e) => Err(e),
        },
        _ => return None,
    })
}

/// Resolve the `window` selector: `None` -> active window; `Some(s)` -> exact
/// address match, else unique case-insensitive title/class substring.
/// Backend faults surface as `isError` results; bad selectors as
/// `InvalidParams`.
async fn resolve_window(
    window: &dyn WindowProvider,
    selector: Option<&str>,
) -> Result<WindowInfo, ResolveWindowError> {
    let Some(selector) = selector else {
        return window
            .active_window()
            .await
            .map_err(ResolveWindowError::Backend)?
            .ok_or(ResolveWindowError::NoActive);
    };
    let windows = window
        .list_windows()
        .await
        .map_err(ResolveWindowError::Backend)?;
    if let Some(w) = windows.iter().find(|w| w.id == selector) {
        return Ok(w.clone());
    }
    let needle = selector.to_lowercase();
    let matches: Vec<WindowInfo> = windows
        .into_iter()
        .filter(|w| {
            w.title.to_lowercase().contains(&needle) || w.class.to_lowercase().contains(&needle)
        })
        .collect();
    match matches.len() {
        0 => Err(ResolveWindowError::NoMatch(selector.to_string())),
        1 => Ok(matches.into_iter().next().expect("len checked")),
        n => Err(ResolveWindowError::Ambiguous {
            selector: selector.to_string(),
            candidates: matches.iter().map(|w| w.id.clone()).collect(),
            count: n,
        }),
    }
}

enum ResolveWindowError {
    Backend(anyhow::Error),
    NoActive,
    NoMatch(String),
    Ambiguous {
        selector: String,
        candidates: Vec<String>,
        count: usize,
    },
}

/// Synthetic `WindowInfo` for focused-view-only backends (river): the
/// compositor can act on the focused view but cannot report its
/// title/class/geometry - the fields are deliberately marked rather
/// than fabricated.
fn focused_view_info() -> WindowInfo {
    WindowInfo {
        id: "focused".into(),
        title: "(focused view)".into(),
        class: String::new(),
        workspace: -1,
        rect: Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        },
        focused: true,
        floating: None,
        fullscreen: None,
        pid: None,
        monitor: None,
    }
}

async fn window_control(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: WindowControlParams = parse_args("window_control", args)?;
    let deltas = [p.dx, p.dy, p.dw, p.dh].into_iter().flatten().count();
    // Per-action parameter rules (docs/TOOLS.md): move needs x,y or
    // dx,dy (relative deltas, focused-view backends); resize needs w,h
    // or dw,dh; the other actions take no geometry at all.
    match p.action {
        WindowAction::Move => match (p.x, p.y, p.dx, p.dy) {
            (Some(_), Some(_), None, None) | (None, None, Some(_), Some(_)) => {}
            _ => {
                return Err(invalid_params(
                    "window_control: move requires x and y, or dx and dy",
                ));
            }
        },
        WindowAction::Resize => match (p.w, p.h, p.dw, p.dh) {
            (Some(w), Some(h), None, None) if w >= 1 && h >= 1 => {}
            (None, None, Some(_), Some(_)) => {}
            _ => {
                return Err(invalid_params(
                    "window_control: resize requires w and h (both >= 1), or dw and dh",
                ));
            }
        },
        _ => {
            if deltas > 0 {
                return Err(invalid_params(
                    "window_control: dx/dy/dw/dh apply only to move/resize",
                ));
            }
        }
    }
    let window = window_provider(providers)?;
    if deltas > 0 && window.focused_view_selector().is_none() {
        return Err(invalid_params(
            "window_control: dx/dy/dw/dh relative deltas are only valid on focused-view backends (river)",
        ));
    }
    // Focused-view-only backends (river) cannot enumerate or identify
    // windows, so the literal `"focused"` selector - and, on such a
    // backend, an omitted selector - address the focused view directly.
    let target = match (window.focused_view_selector(), p.window.as_deref()) {
        (Some(_), None) => focused_view_info(),
        (Some(fid), Some(sel)) if sel == fid => focused_view_info(),
        _ => match resolve_window(window, p.window.as_deref()).await {
            Ok(w) => w,
            Err(ResolveWindowError::Backend(e)) => return Ok(backend_error(e)),
            Err(ResolveWindowError::NoActive) => {
                return Ok(tool_error("window_control: no active window"));
            }
            Err(ResolveWindowError::NoMatch(sel)) => {
                return Err(invalid_params(format!(
                    "window_control: no window matches '{sel}'"
                )));
            }
            Err(ResolveWindowError::Ambiguous {
                selector,
                candidates,
                count,
            }) => {
                return Err(invalid_params(format!(
                    "window_control: ambiguous window '{selector}' - {count} candidates: {}",
                    candidates.join(", ")
                )));
            }
        },
    };
    let mut dispatch_args = match p.action {
        WindowAction::Move if p.dx.is_some() => json!({"dx": p.dx, "dy": p.dy}),
        WindowAction::Move => json!({"x": p.x, "y": p.y}),
        WindowAction::Resize if p.dw.is_some() => json!({"dw": p.dw, "dh": p.dh}),
        WindowAction::Resize => json!({"w": p.w, "h": p.h}),
        _ => json!({}),
    };
    // Snapshot-id guards: providers whose ids come from a fresh
    // enumeration (`wlr-toplevel-N`) verify these against the new
    // snapshot before acting - a reordered list can never retarget the
    // op onto a different window. Other backends ignore unknown keys.
    if target.id.starts_with("wlr-toplevel-") {
        dispatch_args["expect_title"] = json!(target.title);
        dispatch_args["expect_class"] = json!(target.class);
    }
    // `close` consent is enforced upstream by `call_tool_secured`
    // (challenge + resolved-target binding); the token is already spent
    // by the time dispatch reaches this leg.
    let _ = &p.consent_token;
    backend!(
        window
            .dispatch(p.action.as_str(), &target.id, &dispatch_args)
            .await
    );
    Ok(text_result(format!(
        "{} applied to {} (\"{}\")",
        p.action.as_str(),
        target.id,
        target.title
    )))
}

/// Whether the recorded arguments contain a redacted placeholder
/// (`"<redacted:N chars>"`, written by the history store for
/// `type_text.text`) - such records can never be replayed faithfully.
fn args_contain_redacted(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with("<redacted:"),
        Value::Array(a) => a.iter().any(args_contain_redacted),
        Value::Object(o) => o.values().any(args_contain_redacted),
        _ => false,
    }
}

/// `get_windows` wire shape: `window_json` plus `floating`,
/// `fullscreen`, `pid`, `monitor` (docs/TOOLS.md `get_windows`).
/// `null` when the backend can't report the field.
fn window_json_full(w: &WindowInfo) -> Value {
    let mut v = window_json(w);
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "floating".into(),
            w.floating.map(Value::from).unwrap_or(Value::Null),
        );
        o.insert(
            "fullscreen".into(),
            w.fullscreen.map(Value::from).unwrap_or(Value::Null),
        );
        o.insert("pid".into(), w.pid.map(Value::from).unwrap_or(Value::Null));
        o.insert(
            "monitor".into(),
            w.monitor.map(Value::from).unwrap_or(Value::Null),
        );
    }
    v
}

async fn get_windows(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("get_windows", args)?;
    let window = window_provider(providers)?;
    let windows = backend!(window.list_windows().await);
    Ok(json_result(&Value::Array(
        windows.iter().map(window_json_full).collect(),
    )))
}

async fn get_active_window(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("get_active_window", args)?;
    let window = window_provider(providers)?;
    let active = backend!(window.active_window().await);
    let out = match active {
        Some(w) => window_json_full(&w),
        None => json!({"focused": null}),
    };
    Ok(json_result(&out))
}

async fn metrics(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("metrics", args)?;
    Ok(text_result(crate::metrics::exposition()))
}

/// Wire shape of one history entry in `get_action_history` output
/// (docs/TOOLS.md). `args` carries the raw recorded arguments verbatim -
/// history exists for replay, and it is encrypted at rest.
fn record_json(r: &ActionRecord) -> Value {
    json!({
        "id": r.id,
        "index": r.index,
        "timestamp": r.ts,
        "tool": r.tool,
        "args": r.args_json,
        "success": r.outcome == "ok",
        "duration_ms": r.duration_ms,
        "result_summary": r.result_summary,
        "caller": r.caller,
        "outcome": r.outcome,
    })
}

async fn get_action_history(
    args: &Map<String, Value>,
    store: &HistoryStore,
) -> Result<CallToolResult, ErrorData> {
    let p: HistoryParams = parse_args("get_action_history", args)?;
    if !(1..=1000).contains(&p.limit) {
        return Err(invalid_params(
            "get_action_history: limit must be between 1 and 1000",
        ));
    }
    let needle = p.action.as_deref().map(str::to_lowercase);
    // When filtering, read the full retained window first so the limit
    // applies to *matching* records, not the newest `limit` prefix -
    // `list_filtered` filters inside the lock and clones only matches.
    let actions: Vec<Value> = match needle.as_deref() {
        Some(n) => store
            .list_filtered(n, p.limit as usize)
            .iter()
            .map(record_json)
            .collect(),
        None => store
            .list(p.limit as usize)
            .iter()
            .map(record_json)
            .collect(),
    };
    Ok(json_result(&json!({
        "count": actions.len(),
        "actions": actions,
    })))
}

async fn replay_action(
    args: &Map<String, Value>,
    providers: &Providers,
    store: &HistoryStore,
    secured: Option<Secured<'_>>,
) -> Result<CallToolResult, ErrorData> {
    let p: ReplayParams = parse_args("replay_action", args)?;
    // Exactly one selector is required.
    if p.index.is_some() == p.id.is_some() {
        return Err(invalid_params(
            "replay_action: provide exactly one of `index` or `id`",
        ));
    }
    if let Some(id) = &p.id
        && id.parse::<ulid::Ulid>().is_err()
    {
        return Err(invalid_params(
            "replay_action: id must be a 26-char ULID (Crockford Base32)",
        ));
    }
    let _ = &p.consent_token;
    let rec = match (p.index, p.id.as_deref()) {
        (Some(i), None) => store.get_by_index(i),
        (None, Some(id)) => store.get_by_id(id),
        _ => unreachable!("exactly-one selector enforced above"),
    }
    .ok_or_else(|| invalid_params("replay_action: no history record matches the selector"))?;
    if NON_REPLAYABLE.contains(&rec.tool.as_str()) {
        return Err(invalid_params(format!(
            "replay_action: {} is not replayable",
            rec.tool
        )));
    }
    if args_contain_redacted(&rec.args_json) {
        return Err(invalid_params(
            "replay_action: record is redacted - secret arguments were never \
             stored, so the call cannot be faithfully replayed",
        ));
    }
    let rec_args = rec.args_json.as_object().cloned().unwrap_or_default();
    // The replayed call goes back through dispatch. On the secured path it
    // re-enters `call_tool_secured`, so a destructive recorded action
    // re-challenges the consent gate on its own binding and is audited -
    // the consent granted to `replay_action` never covers the replayed
    // call (docs/TOOLS.md).
    // Boxed re-dispatch: replay -> dispatch -> replay is an async recursion
    // cycle - the indirection keeps the future sized (E0733).
    let inner = match secured {
        Some(s) => {
            Box::pin(super::call_tool_secured(
                &rec.tool,
                rec_args,
                providers,
                s.security,
                s.session_id,
                s.key_id,
            ))
            .await
        }
        None => Box::pin(super::call_tool(&rec.tool, rec_args, providers)).await,
    };
    match inner {
        // The replayed tool's own JSON-RPC error surfaces directly
        // (docs/TOOLS.md: "plus any error the replayed tool itself raises").
        Err(e) => Err(e),
        Ok(r) => {
            let mut out = json_result(&json!({
                "replayed": rec.tool,
                "id": rec.id,
                "result": serde_json::to_value(&r.content).unwrap_or(Value::Null),
            }));
            if r.is_error == Some(true) {
                out.is_error = Some(true);
            }
            Ok(out)
        }
    }
}

async fn clear_action_history(
    args: &Map<String, Value>,
    store: StoreHandle,
) -> Result<CallToolResult, ErrorData> {
    let p: ClearHistoryParams = parse_args("clear_action_history", args)?;
    let _ = &p.consent_token;
    // Overwrite-then-delete + index reset is blocking file work - move
    // it onto `spawn_blocking` like the secured record path (EFF-1).
    let removed = tokio::task::spawn_blocking(move || store.clear())
        .await
        .map_err(|e| history_error(anyhow::anyhow!("history clear task: {e}")))?
        .map_err(history_error)?;
    crate::metrics::set_action_history_size(0);
    Ok(text_result(format!(
        "Action history cleared ({removed} records removed)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;
    use crate::security::history::NewActionRecord;

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

    fn tmp_store() -> (tempfile::TempDir, HistoryStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    fn record(store: &HistoryStore, tool: &str, args: Value) -> ActionRecord {
        store
            .record(NewActionRecord {
                tool: tool.to_string(),
                args_json: args,
                result_summary: format!("{tool} summary"),
                caller: "test-session".to_string(),
                duration_ms: 3,
                outcome: "ok".to_string(),
            })
            .unwrap()
    }

    fn providers() -> Providers {
        Providers::empty()
    }

    const INVALID_PARAMS: i32 = -32602;
    const CONSENT_REQUIRED: i32 = -32015;
    const SESSION: &str = "test-session-1";

    #[tokio::test]
    async fn history_lists_newest_first_in_wire_shape() {
        let (_tmp, store) = tmp_store();
        let a = record(&store, "mouse_click", json!({"x": 1, "y": 2}));
        let b = record(&store, "sleep", json!({"ms": 0}));

        let res = get_action_history(&args(json!({"limit": 10})), &store)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["count"], 2);
        let actions = body["actions"].as_array().unwrap();
        // Newest first.
        assert_eq!(actions[0]["id"], b.id);
        assert_eq!(actions[1]["id"], a.id);
        // Wire shape (docs/TOOLS.md).
        let first = &actions[0];
        assert_eq!(first["index"], 1);
        assert_eq!(first["tool"], "sleep");
        assert_eq!(first["args"], json!({"ms": 0}));
        assert_eq!(first["success"], true);
        assert_eq!(first["duration_ms"], 3);
        assert_eq!(first["result_summary"], "sleep summary");
        chrono::DateTime::parse_from_rfc3339(first["timestamp"].as_str().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn history_limit_bounds_enforced() {
        let (_tmp, store) = tmp_store();
        for bad in [json!({"limit": 0}), json!({"limit": 1001})] {
            let err = get_action_history(&args(bad), &store).await.unwrap_err();
            assert_eq!(err.code.0, INVALID_PARAMS);
        }
        // Default limit works.
        let res = get_action_history(&args(json!({})), &store).await.unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["count"], 0);
    }

    #[tokio::test]
    async fn replay_by_index_reexecutes_and_envelopes() {
        let (_tmp, store) = tmp_store();
        let rec = record(&store, "sleep", json!({"ms": 0}));

        let res = replay_action(&args(json!({"index": 0})), &providers(), &store, None)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["replayed"], "sleep");
        assert_eq!(body["id"], rec.id);
        let result = body["result"].as_array().unwrap();
        assert!(
            result[0]["text"].as_str().unwrap().contains("Slept"),
            "inner result must carry the replayed call's content: {body}"
        );
    }

    #[tokio::test]
    async fn replay_by_id_resolves() {
        let (_tmp, store) = tmp_store();
        let rec = record(&store, "sleep", json!({"ms": 0}));

        let res = replay_action(&args(json!({"id": rec.id})), &providers(), &store, None)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["replayed"], "sleep");
        assert_eq!(body["id"], rec.id);
    }

    #[tokio::test]
    async fn replay_selector_validation() {
        let (_tmp, store) = tmp_store();
        let p = providers();
        // both selectors
        let err = replay_action(
            &args(json!({"index": 0, "id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12"})),
            &p,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // neither selector
        let err = replay_action(&args(json!({})), &p, &store, None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // id wrong length
        let err = replay_action(&args(json!({"id": "tooshort"})), &p, &store, None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // unknown index / unknown id
        let err = replay_action(&args(json!({"index": 7})), &p, &store, None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        let err = replay_action(
            &args(json!({"id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12"})),
            &p,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn replay_refuses_non_replayable_tools() {
        let (_tmp, store) = tmp_store();
        for tool in NON_REPLAYABLE {
            let rec = record(&store, tool, json!({}));
            let err = replay_action(&args(json!({"id": rec.id})), &providers(), &store, None)
                .await
                .unwrap_err();
            assert_eq!(err.code.0, INVALID_PARAMS, "{tool} must not replay");
        }
    }

    #[tokio::test]
    async fn history_action_filter_is_case_insensitive_substring() {
        let (_tmp, store) = tmp_store();
        record(&store, "mouse_click", json!({"x": 1, "y": 2}));
        record(&store, "mouse_drag", json!({"from_x": 0}));
        record(&store, "type_text", json!({"text": "secret"}));

        // Substring match - "mouse" selects both mouse_* records.
        let res = get_action_history(&args(json!({"action": "MOUSE"})), &store)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["count"], 2);
        let tools: Vec<&str> = body["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["tool"].as_str().unwrap())
            .collect();
        assert_eq!(tools, ["mouse_drag", "mouse_click"]);

        // Non-matching filter -> empty result, still a success.
        let res = get_action_history(&args(json!({"action": "zzz"})), &store)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["count"], 0);

        // Filter composes with `limit`.
        let res = get_action_history(&args(json!({"action": "mouse", "limit": 1})), &store)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["count"], 1);
        assert_eq!(body["actions"][0]["tool"], "mouse_drag");
    }

    #[tokio::test]
    async fn replay_rejects_malformed_ulid() {
        let (_tmp, store) = tmp_store();
        let p = providers();
        for bad in [
            "tooshort",
            // Right length, wrong alphabet ('!' is not Crockford Base32).
            "!!!!!!!!!!!!!!!!!!!!!!!!!!",
            // Right length, but I/L/O/U are excluded from Crockford Base32.
            "ILOU1LOU1LOU1LOU1LOU1LOU12",
        ] {
            let err = replay_action(&args(json!({"id": bad})), &p, &store, None)
                .await
                .unwrap_err();
            assert_eq!(err.code.0, INVALID_PARAMS, "{bad} must be rejected");
        }
    }

    #[tokio::test]
    async fn replay_refuses_redacted_records() {
        let (_tmp, store) = tmp_store();
        // `type_text` args are redacted at record time by the store.
        let rec = record(
            &store,
            "type_text",
            json!({"text": "s3cret", "delay_ms": 0}),
        );
        assert_eq!(
            rec.args_json["text"], "<redacted:6 chars>",
            "store must have redacted the fixture"
        );
        let err = replay_action(&args(json!({"id": rec.id})), &providers(), &store, None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        assert!(err.message.contains("redacted"));
    }

    #[tokio::test]
    async fn replay_of_destructive_action_rechallenges_consent() {
        let (_tmp, store) = tmp_store();
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let rec_args = json!({"command": "slurp", "args": ["-f", "%x"]});
        record(&store, "system_command", rec_args.clone());

        let secured = Secured {
            security: SecRef::Borrowed(&sec),
            session_id: SESSION,
            key_id: None,
        };
        let err = replay_action(
            &args(json!({"index": 0})),
            &providers(),
            &store,
            Some(secured),
        )
        .await
        .unwrap_err();
        // -32015 ConsentRequired carrying a challenge bound to the
        // *replayed* call - the replay's own consent is not inherited.
        assert_eq!(err.code.0, CONSENT_REQUIRED);
        let token = err.data.unwrap()["consent_token"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            sec.consent
                .verify(&token, None, SESSION, "system_command", &rec_args, None,)
        );
    }

    #[tokio::test]
    async fn replay_non_destructive_through_secured_path_executes() {
        let (_tmp, store) = tmp_store();
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        record(&store, "sleep", json!({"ms": 0}));

        let secured = Secured {
            security: SecRef::Borrowed(&sec),
            session_id: SESSION,
            key_id: None,
        };
        let res = replay_action(
            &args(json!({"index": 0})),
            &providers(),
            &store,
            Some(secured),
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["replayed"], "sleep");
    }

    #[tokio::test]
    async fn replay_and_clear_rechallenge_at_the_secured_gate() {
        // End-to-end through call_tool_secured: the destructive class is
        // challenged before dispatch ever reaches the store.
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let p = providers();

        for (name, a) in [
            ("replay_action", json!({"index": 0})),
            ("clear_action_history", json!({})),
        ] {
            let err =
                super::super::call_tool_secured(name, args(a.clone()), &p, &sec, SESSION, None)
                    .await
                    .unwrap_err();
            assert_eq!(err.code.0, CONSENT_REQUIRED, "{name} must challenge");
            let token = err.data.unwrap()["consent_token"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(
                sec.consent.verify(&token, None, SESSION, name, &a, None),
                "{name} token must bind to its own tool+args"
            );
        }
    }

    #[tokio::test]
    async fn clear_reports_count_and_wipes_file() {
        let (_tmp, store) = tmp_store();
        // `clear` moves onto `spawn_blocking` - the store must ride in an
        // `Arc` (production passes the context-scoped `history_arc()`).
        let store = std::sync::Arc::new(store);
        record(&store, "sleep", json!({"ms": 0}));
        record(&store, "sleep", json!({"ms": 1}));
        let path = store.path().to_path_buf();

        let res = clear_action_history(&args(json!({})), StoreHandle::Scoped(store.clone()))
            .await
            .unwrap();
        assert_eq!(text_of(&res), "Action history cleared (2 records removed)");
        assert!(store.is_empty());
        assert!(!path.exists());
        // The gauge is reset to 0 alongside the wipe.
        assert!(crate::metrics::exposition().contains("ultranix_mcp_action_history_size"));

        // Idempotent: a second clear reports zero.
        let res = clear_action_history(&args(json!({})), StoreHandle::Scoped(store.clone()))
            .await
            .unwrap();
        assert_eq!(text_of(&res), "Action history cleared (0 records removed)");
    }
}
