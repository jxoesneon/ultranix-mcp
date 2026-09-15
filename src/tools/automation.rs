//! Automation tools (4) — timing, pointer paths, arg-constrained exec,
//! and the CDP browser bridge.

use std::time::Duration;

use rmcp::model::{CallToolResult, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, browser_provider, input_provider, invalid_params, json_result, parse_args,
    sanitization_rejected, text_result, tool,
};
use crate::providers::Providers;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SleepParams {
    /// Milliseconds to block this call (other sessions are not blocked)
    #[schemars(range(min = 0, max = 60000))]
    ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PathPoint {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct MovePathParams {
    /// Polyline waypoints (2..=256)
    #[schemars(length(min = 2, max = 256))]
    points: Vec<PathPoint>,
    /// Total traversal time in milliseconds; 0 jumps straight through
    #[serde(default = "default_path_ms")]
    #[schemars(range(min = 0, max = 30000))]
    duration_ms: u64,
}

fn default_path_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum CommandName {
    Grim,
    Slurp,
    Hyprctl,
    Scrot,
    Xdotool,
    Wmctrl,
}

impl CommandName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Grim => "grim",
            Self::Slurp => "slurp",
            Self::Hyprctl => "hyprctl",
            Self::Scrot => "scrot",
            Self::Xdotool => "xdotool",
            Self::Wmctrl => "wmctrl",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SystemCommandParams {
    /// Allowed binary to execute (resolved to a pinned absolute path at startup)
    command: CommandName,
    /// Arguments passed verbatim (no shell expansion); validated against the
    /// per-binary constraints in docs/TOOLS.md
    #[serde(default)]
    #[schemars(length(max = 16))]
    args: Vec<String>,
    /// Challenge token from a prior -32015 ConsentRequired response for this
    /// exact call (accepted; the consent gate itself lands in Phase 1)
    consent_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WebQueryParams {
    /// CSS selector, e.g. "button.submit", "#main h1"
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<SleepParams>(
            "sleep",
            "Block the call for `ms` milliseconds (tokio timer; other sessions are not blocked).",
        ),
        tool::<MovePathParams>(
            "mouse_move_path",
            "Move the pointer through a polyline of points over duration_ms (a hover, not a drag).",
        ),
        tool::<SystemCommandParams>(
            "system_command",
            "Execute a binary from the fixed, arg-constrained command set (consent-gated).",
        ),
        tool::<WebQueryParams>(
            "web_query",
            "Evaluate a CSS selector in the browser attached via CDP at 127.0.0.1:9222.",
        ),
    ]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "sleep" => sleep(args).await,
        "mouse_move_path" => mouse_move_path(args, providers).await,
        "system_command" => system_command(args).await,
        "web_query" => web_query(args, providers).await,
        _ => return None,
    })
}

async fn sleep(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: SleepParams = parse_args("sleep", args)?;
    if p.ms > 60_000 {
        return Err(invalid_params(
            "sleep: ms must be between 0 and 60000 (chain calls for longer waits)",
        ));
    }
    tokio::time::sleep(Duration::from_millis(p.ms)).await;
    Ok(text_result(format!("Slept {} ms", p.ms)))
}

async fn mouse_move_path(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: MovePathParams = parse_args("mouse_move_path", args)?;
    if p.points.len() < 2 || p.points.len() > 256 {
        return Err(invalid_params(
            "mouse_move_path: points must contain 2..=256 entries",
        ));
    }
    if p.duration_ms > 30_000 {
        return Err(invalid_params(
            "mouse_move_path: duration_ms must be between 0 and 30000",
        ));
    }
    let input = input_provider(providers)?;
    let pts: Vec<(i32, i32)> = p.points.iter().map(|pt| (pt.x, pt.y)).collect();

    // Evenly-timed interpolation along the polyline's arc length.
    let seg_len: Vec<f64> = pts
        .windows(2)
        .map(|w| {
            let dx = f64::from(w[1].0 - w[0].0);
            let dy = f64::from(w[1].1 - w[0].1);
            (dx * dx + dy * dy).sqrt()
        })
        .collect();
    let total_len: f64 = seg_len.iter().sum();
    let steps = ((p.duration_ms / 16) as usize).clamp(1, 512);
    let step_delay = Duration::from_millis(p.duration_ms / steps as u64);

    backend!(input.mouse_move(pts[0].0, pts[0].1).await);
    for i in 1..=steps {
        // Position at arc-length fraction i/steps along the polyline.
        let (mut x, mut y) = *pts.last().expect("non-empty points");
        if total_len > 0.0 {
            let mut remaining = total_len * (i as f64 / steps as f64);
            for (s, &len) in seg_len.iter().enumerate() {
                if len <= 0.0 {
                    continue;
                }
                if remaining <= len {
                    let t = remaining / len;
                    x = pts[s].0 + ((pts[s + 1].0 - pts[s].0) as f64 * t).round() as i32;
                    y = pts[s].1 + ((pts[s + 1].1 - pts[s].1) as f64 * t).round() as i32;
                    break;
                }
                remaining -= len;
            }
        }
        backend!(input.mouse_move(x, y).await);
        if i < steps {
            tokio::time::sleep(step_delay).await;
        }
    }
    Ok(text_result(format!(
        "Moved along {}-point path in {}ms",
        pts.len(),
        p.duration_ms
    )))
}

/// Shell metacharacters denied in `system_command` args (docs/TOOLS.md
/// `-32006 SanitizationRejected`).
fn arg_has_metachars(arg: &str) -> bool {
    arg.chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '`' | '\0' | '\n' | '\r'))
        || arg.contains("$(")
}

async fn system_command(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: SystemCommandParams = parse_args("system_command", args)?;
    if p.args.len() > 16 {
        return Err(invalid_params("system_command: at most 16 args"));
    }
    for a in &p.args {
        if a.chars().count() > 512 {
            return Err(invalid_params(
                "system_command: each arg must be <= 512 chars",
            ));
        }
        if arg_has_metachars(a) {
            return Err(sanitization_rejected(format!(
                "system_command: arg {a:?} contains shell metacharacters"
            )));
        }
    }
    // Phase 0: the arg-constrained exec and the consent challenge land in
    // Phase 1 — validate the shape, then report a deterministic stub.
    let _ = &p.consent_token;
    Ok(json_result(&json!({
        "phase0_stub": true,
        "executed": false,
        "command": p.command.as_str(),
        "args": p.args,
        "note": "system_command is a Phase-0 stub: validated but not executed",
    })))
}

async fn web_query(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: WebQueryParams = parse_args("web_query", args)?;
    if p.selector.is_empty() || p.selector.chars().count() > 1024 {
        return Err(invalid_params("web_query: selector must be 1..=1024 chars"));
    }
    if p.selector.to_lowercase().contains("javascript:")
        || p.selector.chars().any(|c| c.is_control())
    {
        return Err(sanitization_rejected(
            "web_query: selector containing 'javascript:' or control bytes is rejected",
        ));
    }
    let browser = browser_provider(providers)?;
    backend!(browser.ensure_ready().await);
    let mut result = backend!(browser.query_selector(&p.selector).await);
    // Normalise to the documented {found, element?} envelope: providers may
    // return a raw {"matches": [...]} payload in Phase 0.
    if let Some(obj) = result.as_object_mut()
        && !obj.contains_key("found")
    {
        let found = obj
            .get("matches")
            .and_then(Value::as_array)
            .is_some_and(|m| !m.is_empty());
        obj.insert("found".into(), Value::Bool(found));
    }
    Ok(json_result(&result))
}
