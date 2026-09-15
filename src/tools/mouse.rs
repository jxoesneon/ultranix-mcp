//! Mouse tools (7) — all backed by `InputProvider`.
//! Coordinates are Hyprland logical layout-space integers.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use rmcp::model::{CallToolResult, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, backend_error, input_provider, invalid_params, json_result, parse_args,
    provider_unavailable, text_result, tool,
};
use crate::providers::Providers;

/// Session button-state tracker for `mouse_button_control`
/// (docs/TOOLS.md: "the server tracks button state per session").
/// Process-global — dispatch carries no session handle yet, so the held
/// set is shared across callers. `mouse_click`/`mouse_drag` are transient
/// down+up sequences and do not enter the set.
static HELD_BUTTONS: LazyLock<Mutex<HashSet<MouseButton>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn button_is_held(button: MouseButton) -> bool {
    HELD_BUTTONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&button)
}

fn set_button_held(button: MouseButton, held: bool) {
    let mut set = HELD_BUTTONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if held {
        set.insert(button);
    } else {
        set.remove(&button);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum MouseButton {
    #[default]
    Left,
    Right,
    Middle,
}

impl MouseButton {
    fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Middle => "middle",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClickParams {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
    /// Button to click
    #[serde(default)]
    button: MouseButton,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct MoveParams {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScrollParams {
    /// Horizontal wheel steps; positive scrolls right, negative left
    #[serde(default)]
    dx: i32,
    /// Vertical wheel steps; positive scrolls down, negative up
    #[serde(default)]
    dy: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DragParams {
    /// Start x in logical layout space
    from_x: i32,
    /// Start y in logical layout space
    from_y: i32,
    /// End x in logical layout space
    to_x: i32,
    /// End y in logical layout space
    to_y: i32,
    /// Button to drag with
    #[serde(default)]
    button: MouseButton,
    /// Interpolation time in ms; 0 performs an instant drag
    #[serde(default = "default_drag_ms")]
    #[schemars(range(min = 0, max = 10000))]
    duration_ms: u64,
}

fn default_drag_ms() -> u64 {
    250
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ButtonAction {
    Down,
    Up,
}

impl ButtonAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Up => "up",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ButtonControlParams {
    /// Button to hold or release
    button: MouseButton,
    /// `down` presses and holds; `up` releases
    action: ButtonAction,
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<ClickParams>(
            "mouse_click",
            "Move the pointer to (x, y) and click a button.",
        ),
        tool::<ClickParams>(
            "mouse_double_click",
            "Move to (x, y) and double-click within the compositor's click interval.",
        ),
        tool::<MoveParams>(
            "mouse_move",
            "Move the pointer without pressing buttons (hover).",
        ),
        tool::<NoParams>(
            "mouse_get_position",
            "Report the current pointer position in logical layout coordinates.",
        ),
        tool::<ScrollParams>(
            "mouse_scroll",
            "Emit scroll-wheel deltas at the current pointer position.",
        ),
        tool::<DragParams>(
            "mouse_drag",
            "Press a button at (from_x, from_y), move to (to_x, to_y) over duration_ms, then release.",
        ),
        tool::<ButtonControlParams>(
            "mouse_button_control",
            "Hold or release a mouse button without moving (building block for custom gestures).",
        ),
    ]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "mouse_click" => mouse_click(args, providers).await,
        "mouse_double_click" => mouse_double_click(args, providers).await,
        "mouse_move" => mouse_move(args, providers).await,
        "mouse_get_position" => mouse_get_position(args, providers).await,
        "mouse_scroll" => mouse_scroll(args, providers).await,
        "mouse_drag" => mouse_drag(args, providers).await,
        "mouse_button_control" => mouse_button_control(args, providers).await,
        _ => return None,
    })
}

async fn mouse_click(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ClickParams = parse_args("mouse_click", args)?;
    let input = input_provider(providers)?;
    backend!(input.mouse_click(p.x, p.y, p.button.as_str()).await);
    Ok(text_result(format!(
        "Clicked {} at ({}, {})",
        p.button.as_str(),
        p.x,
        p.y
    )))
}

async fn mouse_double_click(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ClickParams = parse_args("mouse_double_click", args)?;
    let input = input_provider(providers)?;
    // The trait has no double-click primitive; two rapid clicks on the same
    // point fall inside the compositor's click interval.
    backend!(input.mouse_click(p.x, p.y, p.button.as_str()).await);
    backend!(input.mouse_click(p.x, p.y, p.button.as_str()).await);
    Ok(text_result(format!(
        "Double-clicked {} at ({}, {})",
        p.button.as_str(),
        p.x,
        p.y
    )))
}

async fn mouse_move(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: MoveParams = parse_args("mouse_move", args)?;
    let input = input_provider(providers)?;
    backend!(input.mouse_move(p.x, p.y).await);
    Ok(text_result(format!("Pointer moved to ({}, {})", p.x, p.y)))
}

async fn mouse_get_position(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("mouse_get_position", args)?;
    // Pointer position is a compositor query, not an injection — prefer the
    // input backend's read channel, fall back to the capture backend's.
    let (x, y) = if let Some(input) = providers.input.as_deref() {
        backend!(input.cursor_position().await)
    } else if let Some(capture) = providers.capture.as_deref() {
        backend!(capture.cursor_position().await)
    } else {
        return Err(provider_unavailable("InputProvider"));
    };
    // `display` (output under the pointer) is resolved by real backends in
    // Phase 1; null is spec-valid ("between outputs").
    Ok(json_result(
        &json!({"x": x, "y": y, "display": Value::Null}),
    ))
}

async fn mouse_scroll(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ScrollParams = parse_args("mouse_scroll", args)?;
    if p.dx == 0 && p.dy == 0 {
        return Err(invalid_params(
            "mouse_scroll: at least one of dx, dy must be non-zero",
        ));
    }
    let input = input_provider(providers)?;
    backend!(input.scroll(p.dx as f64, p.dy as f64).await);
    Ok(text_result(format!("Scrolled dx={} dy={}", p.dx, p.dy)))
}

async fn mouse_drag(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: DragParams = parse_args("mouse_drag", args)?;
    if p.duration_ms > 10_000 {
        return Err(invalid_params(
            "mouse_drag: duration_ms must be between 0 and 10000",
        ));
    }
    let input = input_provider(providers)?;
    backend!(input.mouse_move(p.from_x, p.from_y).await);
    backend!(input.mouse_button(p.button.as_str(), true).await);

    let steps = (p.duration_ms / 16).clamp(1, 64) as u32;
    let step_delay = Duration::from_millis(p.duration_ms / steps as u64);
    let mut move_err = None;
    for i in 1..=steps {
        let t = f64::from(i) / f64::from(steps);
        let x = p.from_x as f64 + (p.to_x - p.from_x) as f64 * t;
        let y = p.from_y as f64 + (p.to_y - p.from_y) as f64 * t;
        if let Err(e) = input.mouse_move(x.round() as i32, y.round() as i32).await {
            move_err = Some(e);
            break;
        }
        if i < steps {
            tokio::time::sleep(step_delay).await;
        }
    }
    // Always release the button before reporting — a stuck-down button is
    // worse than a failed drag.
    let release = input.mouse_button(p.button.as_str(), false).await;
    if let Some(e) = move_err {
        return Ok(backend_error(e));
    }
    backend!(release);
    Ok(text_result(format!(
        "Dragged {} from ({}, {}) to ({}, {}) in {}ms",
        p.button.as_str(),
        p.from_x,
        p.from_y,
        p.to_x,
        p.to_y,
        p.duration_ms
    )))
}

async fn mouse_button_control(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ButtonControlParams = parse_args("mouse_button_control", args)?;
    let down = matches!(p.action, ButtonAction::Down);
    let held = button_is_held(p.button);
    // Spec: "releasing an unpressed button is a no-op success" — and the
    // symmetric press of an already-held button is equally a no-op: the
    // requested end state already holds, so no event is injected.
    if down == held {
        return Ok(text_result(format!(
            "{} button {}",
            p.button.as_str(),
            p.action.as_str()
        )));
    }
    let input = input_provider(providers)?;
    backend!(input.mouse_button(p.button.as_str(), down).await);
    // Only a successful injection mutates the tracked state.
    set_button_held(p.button, down);
    Ok(text_result(format!(
        "{} button {}",
        p.button.as_str(),
        p.action.as_str()
    )))
}
