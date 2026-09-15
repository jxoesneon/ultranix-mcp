//! Admin & observability tools (7) — `WindowProvider` for windowing;
//! history/metrics are server-core stubs until Phase 4.

use rmcp::model::{CallToolResult, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, backend_error, invalid_params, json_result, parse_args, text_result, tool, tool_error,
    tool_schema, window_json, window_provider,
};
use crate::providers::Providers;
use crate::traits::{WindowInfo, WindowProvider};

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
    /// (close only; the consent gate itself lands in Phase 1)
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
    /// exact call (accepted; the consent gate itself lands in Phase 1)
    consent_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClearHistoryParams {
    /// Challenge token from a prior -32015 ConsentRequired response
    /// (accepted; the consent gate itself lands in Phase 1)
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

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "window_control" => window_control(args, providers).await,
        "get_windows" => get_windows(args, providers).await,
        "get_active_window" => get_active_window(args, providers).await,
        "metrics" => metrics(args).await,
        "get_action_history" => get_action_history(args).await,
        "replay_action" => replay_action(args).await,
        "clear_action_history" => clear_action_history(args).await,
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
    // Phase 0: instrumentation lands with Phase 4 — emit the canonical
    // metric set header so stdio callers can parse the exposition format.
    Ok(text_result(
        "# phase-0 stub: metrics are not yet collected\n\
         # HELP ultranix_mcp_tool_calls_total Tool call count by outcome\n\
         # TYPE ultranix_mcp_tool_calls_total counter\n\
         # HELP ultranix_mcp_tool_duration_seconds Per-tool execution latency\n\
         # TYPE ultranix_mcp_tool_duration_seconds histogram\n\
         # HELP ultranix_mcp_rate_limit_rejections_total Rate-limit rejections by category\n\
         # TYPE ultranix_mcp_rate_limit_rejections_total counter\n\
         # HELP ultranix_mcp_active_sessions Live sessions by transport\n\
         # TYPE ultranix_mcp_active_sessions gauge\n\
         ultranix_mcp_active_sessions{transport=\"stdio\"} 0\n",
    ))
}

async fn get_action_history(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: HistoryParams = parse_args("get_action_history", args)?;
    if !(1..=1000).contains(&p.limit) {
        return Err(invalid_params(
            "get_action_history: limit must be between 1 and 1000",
        ));
    }
    // Phase 0: the AES-256-GCM history store lands in Phase 4.
    Ok(json_result(&json!({
        "count": 0,
        "actions": [],
        "phase0_stub": true,
    })))
}

async fn replay_action(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
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
    Ok(json_result(&json!({
        "phase0_stub": true,
        "replayed": false,
        "index": p.index,
        "id": p.id,
        "note": "replay_action is a Phase-0 stub: the encrypted history store lands in Phase 4",
    })))
}

async fn clear_action_history(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: ClearHistoryParams = parse_args("clear_action_history", args)?;
    let _ = &p.consent_token;
    Ok(text_result(
        "Action history cleared (0 records removed) [phase-0 stub]",
    ))
}
