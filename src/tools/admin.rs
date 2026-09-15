//! Admin & observability tools (7) — `WindowProvider` for windowing;
//! history tools run on the AES-256-GCM [`HistoryStore`]; `metrics` stays a
//! server-core stub until the Phase-4 exporter lands.

use rmcp::model::{CallToolResult, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, backend_error, invalid_params, json_result, parse_args, text_result, tool, tool_error,
    tool_schema, window_json, window_provider,
};
use crate::providers::Providers;
use crate::security::SecurityContext;
use crate::security::history::{ActionRecord, HistoryStore};
use crate::traits::{WindowInfo, WindowProvider};

/// `-32014 HistoryError` — encrypted history store fault (docs/TOOLS.md
/// error taxonomy; not yet surfaced in `crate::error::codes`).
const HISTORY_ERROR: i32 = -32014;

/// History tools that can never be replayed (recursion + no-op guards,
/// docs/TOOLS.md `replay_action`).
pub(super) const NON_REPLAYABLE: &[&str] = &[
    "metrics",
    "get_action_history",
    "replay_action",
    "clear_action_history",
];

/// `-32014` with the `data.kind` discriminator — store faults (decrypt,
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
    /// Hyprland address ("0x…") or unique title/class substring;
    /// omit for the active window
    window: Option<String>,
    /// Target x (move only)
    x: Option<i32>,
    /// Target y (move only)
    y: Option<i32>,
    /// Target width (resize only)
    w: Option<i32>,
    /// Target height (resize only)
    h: Option<i32>,
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
            "Read the encrypted action history, newest-first.",
        ),
        replay_tool(),
        tool::<ClearHistoryParams>(
            "clear_action_history",
            "Securely wipe history.json and reset the in-memory index (consent-gated).",
        ),
    ]
}

/// Borrowed security pipeline for the secured dispatch path — lets
/// `replay_action` pass the recorded call back through `call_tool_secured`
/// (consent re-challenge, audit, real `system_command` exec) instead of the
/// Phase-0 ungated dispatch.
#[derive(Clone, Copy)]
struct Secured<'a> {
    security: &'a SecurityContext,
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
    security: &SecurityContext,
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
        "clear_action_history" => match store(&secured) {
            Ok(s) => clear_action_history(args, s).await,
            Err(e) => Err(e),
        },
        _ => return None,
    })
}

/// Resolve the `window` selector: `None` → active window; `Some(s)` → exact
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

async fn window_control(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: WindowControlParams = parse_args("window_control", args)?;
    // Per-action parameter rules (docs/TOOLS.md): move needs x,y; resize
    // needs w,h; the other actions ignore geometry.
    match p.action {
        WindowAction::Move => {
            if p.x.is_none() || p.y.is_none() {
                return Err(invalid_params("window_control: move requires x and y"));
            }
        }
        WindowAction::Resize => match (p.w, p.h) {
            (Some(w), Some(h)) if w >= 1 && h >= 1 => {}
            _ => {
                return Err(invalid_params(
                    "window_control: resize requires w and h (both >= 1)",
                ));
            }
        },
        _ => {}
    }
    let window = window_provider(providers)?;
    let target = match resolve_window(window, p.window.as_deref()).await {
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
                "window_control: ambiguous window '{selector}' — {count} candidates: {}",
                candidates.join(", ")
            )));
        }
    };
    let dispatch_args = match p.action {
        WindowAction::Move => json!({"x": p.x, "y": p.y}),
        WindowAction::Resize => json!({"w": p.w, "h": p.h}),
        _ => json!({}),
    };
    // `close` is consent-gated in the spec; the consent challenge is Phase 1,
    // so consent_token is accepted but not yet verified.
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

async fn get_windows(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("get_windows", args)?;
    let window = window_provider(providers)?;
    let windows = backend!(window.list_windows().await);
    Ok(json_result(&Value::Array(
        windows.iter().map(window_json).collect(),
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
        Some(w) => window_json(&w),
        None => json!({"focused": null}),
    };
    Ok(json_result(&out))
}

async fn metrics(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("metrics", args)?;
    Ok(text_result(crate::metrics::exposition()))
}

/// Wire shape of one history entry in `get_action_history` output
/// (docs/TOOLS.md). `args` carries the raw recorded arguments verbatim —
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
    let actions: Vec<Value> = store
        .list(p.limit as usize)
        .iter()
        .map(record_json)
        .collect();
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
        && id.chars().count() != 26
    {
        return Err(invalid_params("replay_action: id must be a 26-char ULID"));
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
    let rec_args = rec.args_json.as_object().cloned().unwrap_or_default();
    // The replayed call goes back through dispatch. On the secured path it
    // re-enters `call_tool_secured`, so a destructive recorded action
    // re-challenges the consent gate on its own binding and is audited —
    // the consent granted to `replay_action` never covers the replayed
    // call (docs/TOOLS.md).
    // Boxed re-dispatch: replay → dispatch → replay is an async recursion
    // cycle — the indirection keeps the future sized (E0733).
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
    store: &HistoryStore,
) -> Result<CallToolResult, ErrorData> {
    let p: ClearHistoryParams = parse_args("clear_action_history", args)?;
    let _ = &p.consent_token;
    let removed = store.clear().map_err(history_error)?;
    Ok(text_result(format!(
        "Action history cleared ({removed} records removed)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn replay_of_destructive_action_rechallenges_consent() {
        let (_tmp, store) = tmp_store();
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let rec_args = json!({"command": "slurp", "args": ["-f", "%x"]});
        record(&store, "system_command", rec_args.clone());

        let secured = Secured {
            security: &sec,
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
        // *replayed* call — the replay's own consent is not inherited.
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
            security: &sec,
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
        record(&store, "sleep", json!({"ms": 0}));
        record(&store, "sleep", json!({"ms": 1}));
        let path = store.path().to_path_buf();

        let res = clear_action_history(&args(json!({})), &store)
            .await
            .unwrap();
        assert_eq!(text_of(&res), "Action history cleared (2 records removed)");
        assert!(store.is_empty());
        assert!(!path.exists());

        // Idempotent: a second clear reports zero.
        let res = clear_action_history(&args(json!({})), &store)
            .await
            .unwrap();
        assert_eq!(text_of(&res), "Action history cleared (0 records removed)");
    }
}
