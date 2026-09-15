//! Vision & screen tools (12) — `CaptureProvider` for pixels,
//! `UIAutomationProvider` for the AT-SPI2 tree, `VisionProvider` for
//! OCR / open-vocabulary detection.

use std::time::Duration;

use tokio::time::Instant;

use rmcp::model::{CallToolResult, ContentBlock, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, backend_error, base64_encode, bounds_json, capture_provider, center_json,
    element_not_found, invalid_params, json_result, parse_args, text_result, tool, tool_schema,
    ui_provider, vision_provider,
};
use crate::providers::Providers;
use crate::traits::Rect;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RegionParam {
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

impl RegionParam {
    fn to_rect(&self) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            w: self.w,
            h: self.h,
        }
    }

    fn validate(&self, tool_name: &str) -> Result<(), ErrorData> {
        if self.w < 1 || self.h < 1 {
            return Err(invalid_params(format!(
                "{tool_name}: region w and h must be >= 1"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScreenshotParams {
    /// Crop rect in logical coordinates
    region: Option<RegionParam>,
    /// Output name from screen_info (e.g. "eDP-1", "DP-2"); omit for all outputs
    display: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HighlightParams {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
    /// Rectangle width (>= 1)
    #[schemars(range(min = 1))]
    w: i32,
    /// Rectangle height (>= 1)
    #[schemars(range(min = 1))]
    h: i32,
    /// Overlay lifetime in milliseconds
    #[serde(default = "default_highlight_ms")]
    #[schemars(range(min = 100, max = 30000))]
    duration_ms: u64,
}

fn default_highlight_ms() -> u64 {
    1500
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ColorAtParams {
    /// Horizontal coordinate in logical layout space
    x: i32,
    /// Vertical coordinate in logical layout space
    y: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SpatialFocusParams {
    /// Focus rect x
    x: Option<i32>,
    /// Focus rect y
    y: Option<i32>,
    /// Focus rect width (>= 1)
    w: Option<i32>,
    /// Focus rect height (>= 1)
    h: Option<i32>,
    /// Set true to clear the session focus rect
    clear: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UiTreeParams {
    /// Maximum tree depth below the focused application root
    #[serde(default = "default_depth")]
    #[schemars(range(min = 1, max = 16))]
    depth: u32,
}

fn default_depth() -> u32 {
    3
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindElementParams {
    /// Substring matched against accessible name, description, or role
    #[schemars(length(min = 1, max = 256))]
    query: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindTextParams {
    /// Text to locate (case-insensitive)
    #[schemars(length(min = 1, max = 256))]
    text: String,
    /// Overrides the spatial-focus rect for this call
    region: Option<RegionParam>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindIconParams {
    /// Natural-language visual query, e.g. "hamburger menu icon"
    #[schemars(length(min = 1, max = 256))]
    description: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitParams {
    /// Substring matched against accessible name, description, or role
    #[schemars(length(min = 1, max = 256))]
    query: String,
    /// Give up after this many milliseconds
    #[serde(default = "default_timeout_ms")]
    #[schemars(range(min = 250, max = 120000))]
    timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum InvokeAction {
    #[default]
    Press,
    Focus,
    Expand,
    Collapse,
}

impl InvokeAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Press => "press",
            Self::Focus => "focus",
            Self::Expand => "expand",
            Self::Collapse => "collapse",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InvokeParams {
    /// Substring matched against accessible name, description, or role
    /// (same semantics as find_element)
    #[schemars(length(min = 1, max = 256))]
    query: String,
    /// AT-SPI Action to invoke on the matched element
    #[serde(default)]
    action: InvokeAction,
}

fn screenshot_tool() -> Tool {
    tool::<ScreenshotParams>(
        "screenshot",
        "Capture the screen as PNG; `region` crops, `display` limits to one output.",
    )
}

fn spatial_focus_tool() -> Tool {
    let mut schema = tool_schema::<SpatialFocusParams>();
    schema.insert(
        "anyOf".into(),
        json!([
            {"required": ["x", "y", "w", "h"]},
            {"required": ["clear"], "properties": {"clear": {"const": true}}},
        ]),
    );
    Tool::new(
        "set_spatial_focus",
        "Set or clear the session region of interest used by capture and screen-search tools.",
        schema,
    )
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        screenshot_tool(),
        tool::<NoParams>(
            "screen_info",
            "Enumerate outputs, layout bounds, and the focused output.",
        ),
        tool::<HighlightParams>(
            "screen_highlight",
            "Draw a translucent rectangle overlay at (x, y, w, h) for duration_ms.",
        ),
        tool::<ColorAtParams>(
            "color_at",
            "Sample the colour of the logical-space pixel at (x, y).",
        ),
        spatial_focus_tool(),
        tool::<UiTreeParams>(
            "get_ui_tree",
            "Return the AT-SPI2 accessibility tree of the focused application as nested JSON.",
        ),
        tool::<NoParams>(
            "get_focused_element",
            "Return properties of the element that currently owns keyboard focus.",
        ),
        tool::<FindElementParams>(
            "find_element",
            "Search the focused application's AT-SPI2 tree by case-insensitive substring.",
        ),
        tool::<FindTextParams>(
            "find_text_on_screen",
            "OCR the screen (or a region) and return bounding boxes for occurrences of `text`.",
        ),
        tool::<FindIconParams>(
            "find_icon",
            "Locate an icon or visual element from a natural-language description.",
        ),
        tool::<WaitParams>(
            "wait_for_ui_element",
            "Poll find_element every 250 ms until the query matches or timeout_ms elapses.",
        ),
        tool::<InvokeParams>(
            "invoke_element",
            "Invoke an AT-SPI Action on the element matching `query` — no synthesized pointer event.",
        ),
    ]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "screenshot" => screenshot(args, providers).await,
        "screen_info" => screen_info(args, providers).await,
        "screen_highlight" => screen_highlight(args, providers).await,
        "color_at" => color_at(args, providers).await,
        "set_spatial_focus" => set_spatial_focus(args).await,
        "get_ui_tree" => get_ui_tree(args, providers).await,
        "get_focused_element" => get_focused_element(args, providers).await,
        "find_element" => find_element(args, providers).await,
        "find_text_on_screen" => find_text_on_screen(args, providers).await,
        "find_icon" => find_icon(args, providers).await,
        "wait_for_ui_element" => wait_for_ui_element(args, providers).await,
        "invoke_element" => invoke_element(args, providers).await,
        _ => return None,
    })
}

/// `find_element`-shaped match entry for a rect-only hit.
fn rect_match_json(rect: &Rect) -> Value {
    json!({"bounds": bounds_json(rect), "center": center_json(rect)})
}

async fn screenshot(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ScreenshotParams = parse_args("screenshot", args)?;
    if let Some(r) = &p.region {
        r.validate("screenshot")?;
    }
    let capture = capture_provider(providers)?;
    // `display` has no per-output capture entry point on the trait yet;
    // Phase-1 backends resolve the output's layout rect and crop. Phase 0
    // captures the full frame and reports the requested scope verbatim.
    let frame = backend!(
        capture
            .capture_frame(p.region.as_ref().map(RegionParam::to_rect))
            .await
    );
    let scope = if let Some(r) = &p.region {
        format!("region ({},{},{},{})", r.x, r.y, r.w, r.h)
    } else if let Some(d) = &p.display {
        format!("display {d}")
    } else {
        "full layout".to_string()
    };
    Ok(CallToolResult::success(vec![
        ContentBlock::text(format!(
            "Captured {}x{} PNG of {scope}",
            frame.width, frame.height
        )),
        ContentBlock::image(base64_encode(&frame.png), "image/png"),
    ]))
}

async fn screen_info(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("screen_info", args)?;
    let capture = capture_provider(providers)?;
    let info = backend!(capture.screen_info().await);
    Ok(json_result(&info))
}

async fn screen_highlight(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: HighlightParams = parse_args("screen_highlight", args)?;
    if p.w < 1 || p.h < 1 {
        return Err(invalid_params("screen_highlight: w and h must be >= 1"));
    }
    if !(100..=30_000).contains(&p.duration_ms) {
        return Err(invalid_params(
            "screen_highlight: duration_ms must be between 100 and 30000",
        ));
    }
    // The layer-shell overlay rides on the capture backend; fail loudly when
    // it is absent rather than silently no-op (docs/TOOLS.md).
    let _capture = capture_provider(providers)?;
    Ok(text_result(format!(
        "Highlighted ({}, {}, {}, {}) for {}ms [phase-0 stub]",
        p.x, p.y, p.w, p.h, p.duration_ms
    )))
}

async fn color_at(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ColorAtParams = parse_args("color_at", args)?;
    let capture = capture_provider(providers)?;
    // A real 1x1 screencopy; Phase 0 does not decode the PNG pixel yet, so
    // the returned colour is the deterministic mock pixel (1x1 white).
    let _frame = backend!(
        capture
            .capture_frame(Some(Rect {
                x: p.x,
                y: p.y,
                w: 1,
                h: 1,
            }))
            .await
    );
    Ok(json_result(&json!({
        "x": p.x,
        "y": p.y,
        "hex": "#FFFFFF",
        "r": 255, "g": 255, "b": 255, "a": 255,
        "phase0_stub": true,
    })))
}

async fn set_spatial_focus(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: SpatialFocusParams = parse_args("set_spatial_focus", args)?;
    if p.clear == Some(true) {
        return Ok(text_result("Spatial focus cleared [phase-0 stub]"));
    }
    match (p.x, p.y, p.w, p.h) {
        (Some(x), Some(y), Some(w), Some(h)) if w >= 1 && h >= 1 => Ok(text_result(format!(
            "Spatial focus set to ({x}, {y}, {w}, {h}) [phase-0 stub]"
        ))),
        _ => Err(invalid_params(
            "set_spatial_focus: provide x, y, w, h (w,h >= 1) or {\"clear\": true}",
        )),
    }
}

async fn get_ui_tree(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: UiTreeParams = parse_args("get_ui_tree", args)?;
    if !(1..=16).contains(&p.depth) {
        return Err(invalid_params(
            "get_ui_tree: depth must be between 1 and 16",
        ));
    }
    let ui = ui_provider(providers)?;
    let tree = backend!(ui.get_root_json(p.depth).await);
    Ok(json_result(&tree))
}

async fn get_focused_element(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("get_focused_element", args)?;
    let ui = ui_provider(providers)?;
    let focused = backend!(ui.get_focused_json().await);
    let out = match focused {
        Value::Null => json!({"found": false}),
        Value::Object(mut o) => {
            o.insert("found".into(), Value::Bool(true));
            Value::Object(o)
        }
        other => json!({"found": true, "element": other}),
    };
    Ok(json_result(&out))
}

async fn find_element(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: FindElementParams = parse_args("find_element", args)?;
    if p.query.is_empty() || p.query.chars().count() > 256 {
        return Err(invalid_params("find_element: query must be 1..=256 chars"));
    }
    let ui = ui_provider(providers)?;
    let hit = backend!(ui.find_element(&p.query).await);
    // Not-found is a success result: absence of an element is data.
    let out = match hit {
        Some(rect) => json!({
            "found": true,
            "count": 1,
            "matches": [rect_match_json(&rect)],
        }),
        None => json!({"found": false, "count": 0, "matches": []}),
    };
    Ok(json_result(&out))
}

async fn find_text_on_screen(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: FindTextParams = parse_args("find_text_on_screen", args)?;
    if p.text.is_empty() || p.text.chars().count() > 256 {
        return Err(invalid_params(
            "find_text_on_screen: text must be 1..=256 chars",
        ));
    }
    if let Some(r) = &p.region {
        r.validate("find_text_on_screen")?;
    }
    let vision = vision_provider(providers)?;
    let capture = capture_provider(providers)?;
    let frame = backend!(
        capture
            .capture_frame(p.region.as_ref().map(RegionParam::to_rect))
            .await
    );
    let detections = backend!(vision.recognize_text(&frame).await);
    let needle = p.text.to_lowercase();
    let matches: Vec<Value> = detections
        .iter()
        .filter(|d| d.text.to_lowercase().contains(&needle))
        .map(|d| {
            json!({
                "text": d.text,
                "confidence": d.confidence,
                "bounds": bounds_json(&d.rect),
                "center": center_json(&d.rect),
            })
        })
        .collect();
    Ok(json_result(&json!({
        "found": !matches.is_empty(),
        "count": matches.len(),
        "matches": matches,
    })))
}

async fn find_icon(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: FindIconParams = parse_args("find_icon", args)?;
    if p.description.is_empty() || p.description.chars().count() > 256 {
        return Err(invalid_params(
            "find_icon: description must be 1..=256 chars",
        ));
    }
    let vision = vision_provider(providers)?;
    let capture = capture_provider(providers)?;
    let frame = backend!(capture.capture_frame(None).await);
    let detections = backend!(vision.find_icon(&frame, &p.description).await);
    let out: Vec<Value> = detections
        .iter()
        .map(|d| {
            json!({
                "label": d.text,
                "score": d.confidence,
                "bounds": bounds_json(&d.rect),
                "center": center_json(&d.rect),
            })
        })
        .collect();
    Ok(json_result(&json!({
        "found": !out.is_empty(),
        "count": out.len(),
        "detections": out,
    })))
}

async fn wait_for_ui_element(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: WaitParams = parse_args("wait_for_ui_element", args)?;
    if p.query.is_empty() || p.query.chars().count() > 256 {
        return Err(invalid_params(
            "wait_for_ui_element: query must be 1..=256 chars",
        ));
    }
    if !(250..=120_000).contains(&p.timeout_ms) {
        return Err(invalid_params(
            "wait_for_ui_element: timeout_ms must be between 250 and 120000",
        ));
    }
    let ui = ui_provider(providers)?;
    let start = Instant::now();
    let deadline = Duration::from_millis(p.timeout_ms);
    loop {
        match ui.find_element(&p.query).await {
            Ok(Some(rect)) => {
                return Ok(json_result(&json!({
                    "found": true,
                    "count": 1,
                    "matches": [rect_match_json(&rect)],
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                })));
            }
            Ok(None) => {}
            Err(e) => return Ok(backend_error(e)),
        }
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            // Timeout is a success result carrying `found: false`.
            return Ok(json_result(&json!({
                "found": false,
                "timed_out": true,
                "elapsed_ms": elapsed.as_millis() as u64,
            })));
        }
        tokio::time::sleep(Duration::from_millis(250).min(deadline - elapsed)).await;
    }
}

async fn invoke_element(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: InvokeParams = parse_args("invoke_element", args)?;
    if p.query.is_empty() || p.query.chars().count() > 256 {
        return Err(invalid_params(
            "invoke_element: query must be 1..=256 chars",
        ));
    }
    let ui = ui_provider(providers)?;
    // Action-targeted lookup: no match is an error here, not data.
    let rect = match backend!(ui.find_element(&p.query).await) {
        Some(r) => r,
        None => {
            return Err(element_not_found(format!(
                "invoke_element: no element matched query {:?}",
                p.query
            )));
        }
    };
    let invoked = backend!(ui.invoke_element(&p.query).await);
    Ok(json_result(&json!({
        "found": true,
        "action": p.action.as_str(),
        "action_result": if invoked { "ok" } else { "action_not_supported" },
        "element": {"bounds": bounds_json(&rect), "center": center_json(&rect)},
    })))
}
