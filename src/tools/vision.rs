//! Vision & screen tools (12) — `CaptureProvider` for pixels,
//! `UIAutomationProvider` for the AT-SPI2 tree, `VisionProvider` for
//! OCR / open-vocabulary detection.

use std::sync::RwLock;
use std::time::Duration;

use image::GenericImageView;
use tokio::time::Instant;

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, backend_error, base64_encode, bounds_json, capture_provider, center_json,
    element_not_found, invalid_params, json_result, parse_args, text_result, tool, tool_error,
    tool_schema, ui_provider, vision_provider,
};
use crate::providers::Providers;
use crate::traits::Rect;

/// Session spatial-focus rect installed by `set_spatial_focus`
/// (docs/TOOLS.md §Spatial Focus). Process-global: the dispatch layer
/// carries no session handle yet, so the rect is shared by every caller
/// until `{"clear": true}` or process end.
static SPATIAL_FOCUS: RwLock<Option<Rect>> = RwLock::new(None);

/// The active spatial-focus rect, if one is installed. Poisoned locks
/// degrade to the inner value — a stale focus read is never fatal.
fn focus_rect() -> Option<Rect> {
    *SPATIAL_FOCUS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn set_focus_rect(rect: Option<Rect>) {
    *SPATIAL_FOCUS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = rect;
}

/// Cheap rect-overlap test used to scope OCR/icon hits to a region.
fn rects_intersect(a: &Rect, b: &Rect) -> bool {
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
}

/// Shift a frame-local detection rect into logical layout space by the
/// captured region's origin (a cropped frame's (0,0) is `scope.x/scope.y`).
fn offset_into_scope(r: &Rect, scope: &Rect) -> Rect {
    Rect {
        x: r.x + scope.x,
        y: r.y + scope.y,
        ..*r
    }
}

/// `(name, bounds)` for every output in a `screen_info` payload. Accepts
/// the shapes the backends emit: a bare hyprctl monitor array,
/// `{"monitors": […]}` (mock/portal), and `{"outputs": […]}` (wlr
/// fallback). Missing `x`/`y` default to `0`; `width`/`height` (hyprctl
/// spelling) or `w`/`h` are accepted. Entries without a name or a
/// positive size are skipped.
fn output_rects(info: &Value) -> Vec<(String, Rect)> {
    let empty: &[Value] = &[];
    let items: &[Value] = if let Some(arr) = info.as_array() {
        arr
    } else {
        info.get("monitors")
            .or_else(|| info.get("outputs"))
            .and_then(Value::as_array)
            .map_or(empty, Vec::as_slice)
    };
    items
        .iter()
        .filter_map(|m| {
            let name = m.get("name")?.as_str()?.to_string();
            let w = m
                .get("width")
                .or_else(|| m.get("w"))
                .and_then(Value::as_i64)? as i32;
            let h = m
                .get("height")
                .or_else(|| m.get("h"))
                .and_then(Value::as_i64)? as i32;
            let x = m.get("x").and_then(Value::as_i64).unwrap_or(0) as i32;
            let y = m.get("y").and_then(Value::as_i64).unwrap_or(0) as i32;
            (w > 0 && h > 0).then_some((name, Rect { x, y, w, h }))
        })
        .collect()
}

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
        "Set or clear the session region of interest: while set, `screenshot` without \
         an explicit `region` captures the focus rect and `find_text_on_screen` / \
         `find_icon` narrow capture and results to it.",
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
            "Draw a translucent rectangle overlay at (x, y, w, h) for duration_ms. \
             Overlay drawing is not yet implemented: the call validates its arguments \
             then returns ProviderUnavailable until a layer-shell backend lands.",
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
            "OCR the screen (or a region) and return bounding boxes for occurrences of `text`. \
             An explicit `region` wins; otherwise the spatial-focus rect narrows the search.",
        ),
        tool::<FindIconParams>(
            "find_icon",
            "Locate an icon or visual element from a natural-language description; \
             the spatial-focus rect narrows the search when set.",
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

/// Resolve `screenshot`'s `display` name to the output's layout rect via
/// `screen_info`. Unknown names are `-32602`; a backend that cannot report
/// output geometry at all gets an honest `isError` (no per-output capture).
async fn display_region(
    capture: &dyn crate::traits::CaptureProvider,
    display: &str,
) -> Result<Rect, DisplayResolve> {
    let info = capture
        .screen_info()
        .await
        .map_err(DisplayResolve::Backend)?;
    let outputs = output_rects(&info);
    if outputs.is_empty() {
        return Err(DisplayResolve::Unsupported);
    }
    outputs
        .iter()
        .find(|(name, _)| name == display)
        .map(|(_, r)| *r)
        .ok_or_else(|| {
            DisplayResolve::Unknown(outputs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>())
        })
}

enum DisplayResolve {
    Backend(anyhow::Error),
    Unsupported,
    Unknown(Vec<String>),
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
    // Scope precedence: explicit `region` > `display` > spatial focus >
    // full layout (docs/TOOLS.md §Spatial Focus). `display` is resolved to
    // the output's layout rect and captured as a region — the capture
    // trait has no per-output entry point.
    let (region, scope) = if let Some(r) = &p.region {
        (
            Some(r.to_rect()),
            format!("region ({},{},{},{})", r.x, r.y, r.w, r.h),
        )
    } else if let Some(d) = &p.display {
        let rect = match display_region(capture, d).await {
            Ok(r) => r,
            Err(DisplayResolve::Backend(e)) => return Ok(backend_error(e)),
            Err(DisplayResolve::Unsupported) => {
                return Ok(tool_error(
                    "screenshot: per-output capture not supported by this backend \
                     (screen_info reported no output geometry)",
                ));
            }
            Err(DisplayResolve::Unknown(known)) => {
                return Err(invalid_params(format!(
                    "screenshot: unknown display {d:?} (known outputs: {})",
                    known.join(", ")
                )));
            }
        };
        (Some(rect), format!("display {d}"))
    } else if let Some(f) = focus_rect() {
        (
            Some(f),
            format!("spatial focus ({},{},{},{})", f.x, f.y, f.w, f.h),
        )
    } else {
        (None, "full layout".to_string())
    };
    let frame = backend!(capture.capture_frame(region).await);
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
    // No overlay backend exists in the provider registry yet — per spec a
    // no-op success is NOT returned; the call fails loudly with -32010
    // (TOOLS.md: `screen_highlight` errors include ProviderUnavailable for a
    // compositor lacking layer-shell; here the overlay provider itself is
    // absent). The capture-slot check stays first so a backend-less
    // registry still reports its more fundamental gap.
    let _capture = capture_provider(providers)?;
    Err(ErrorData::new(
        ErrorCode(crate::error::codes::PROVIDER_UNAVAILABLE),
        format!(
            "provider unavailable: OverlayProvider — no layer-shell highlight backend \
             is implemented; nothing was drawn at ({}, {}, {}, {})",
            p.x, p.y, p.w, p.h
        ),
        Some(json!({
            "kind": "ProviderUnavailable",
            "provider": "OverlayProvider",
            "detail": "screen_highlight overlay drawing is not yet implemented",
        })),
    ))
}

async fn color_at(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ColorAtParams = parse_args("color_at", args)?;
    let capture = capture_provider(providers)?;
    // Bounds-check against the output layout when the backend can report
    // it (spec: "point outside layout bounds" → InvalidParams). A backend
    // that cannot enumerate outputs simply skips the check — the screencopy
    // itself will fail loudly if the point is unreadable.
    if let Ok(info) = capture.screen_info().await {
        let outputs: Vec<Rect> = output_rects(&info).into_iter().map(|(_, r)| r).collect();
        if !outputs.is_empty()
            && !outputs
                .iter()
                .any(|r| p.x >= r.x && p.x < r.x + r.w && p.y >= r.y && p.y < r.y + r.h)
        {
            return Err(invalid_params(format!(
                "color_at: ({}, {}) is outside the layout bounds",
                p.x, p.y
            )));
        }
    }
    // Real 1x1 screencopy at the point, decoded to RGBA.
    let frame = backend!(
        capture
            .capture_frame(Some(Rect {
                x: p.x,
                y: p.y,
                w: 1,
                h: 1,
            }))
            .await
    );
    let img = match image::load_from_memory(&frame.png) {
        Ok(i) => i,
        Err(e) => {
            return Ok(tool_error(format!(
                "color_at: failed to decode captured frame: {e}"
            )));
        }
    };
    // A 1x1 logical region can come back larger on HiDPI outputs — sample
    // the centre of whatever was captured.
    let px = img.get_pixel(img.width() / 2, img.height() / 2);
    let [r, g, b, a] = px.0;
    Ok(json_result(&json!({
        "x": p.x,
        "y": p.y,
        "hex": format!("#{r:02X}{g:02X}{b:02X}"),
        "r": r, "g": g, "b": b, "a": a,
    })))
}

async fn set_spatial_focus(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    let p: SpatialFocusParams = parse_args("set_spatial_focus", args)?;
    if p.clear == Some(true) {
        set_focus_rect(None);
        return Ok(text_result("Spatial focus cleared"));
    }
    match (p.x, p.y, p.w, p.h) {
        (Some(x), Some(y), Some(w), Some(h)) if w >= 1 && h >= 1 => {
            set_focus_rect(Some(Rect { x, y, w, h }));
            Ok(text_result(format!(
                "Spatial focus set to ({x}, {y}, {w}, {h})"
            )))
        }
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
    // Spatial focus deliberately does NOT apply here — the spec exempts
    // AT-SPI tree tools (they operate on the accessibility tree, not
    // pixels; docs/TOOLS.md §Spatial Focus).
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
    // Scope: an explicit `region` always wins; otherwise the spatial-focus
    // rect restricts both capture and reported hits (§Spatial Focus).
    let scope = p
        .region
        .as_ref()
        .map(RegionParam::to_rect)
        .or_else(focus_rect);
    let frame = backend!(capture.capture_frame(scope).await);
    let detections = backend!(vision.recognize_text(&frame).await);
    let needle = p.text.to_lowercase();
    let matches: Vec<Value> = detections
        .iter()
        .filter(|d| d.text.to_lowercase().contains(&needle))
        .filter_map(|d| {
            // Detections arrive in frame-local coordinates: shift them by
            // the captured region's origin into layout space and keep hits
            // that intersect the scope.
            let rect = match scope {
                Some(s) => {
                    let r = offset_into_scope(&d.rect, &s);
                    rects_intersect(&r, &s).then_some(r)?
                }
                None => d.rect,
            };
            Some(json!({
                "text": d.text,
                "confidence": d.confidence,
                "bounds": bounds_json(&rect),
                "center": center_json(&rect),
            }))
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
    // The spatial-focus rect restricts capture and reported detections
    // (§Spatial Focus).
    let scope = focus_rect();
    let frame = backend!(capture.capture_frame(scope).await);
    let detections = backend!(vision.find_icon(&frame, &p.description).await);
    let out: Vec<Value> = detections
        .iter()
        .filter_map(|d| {
            let rect = match scope {
                Some(s) => {
                    let r = offset_into_scope(&d.rect, &s);
                    rects_intersect(&r, &s).then_some(r)?
                }
                None => d.rect,
            };
            Some(json!({
                "label": d.text,
                "score": d.confidence,
                "bounds": bounds_json(&rect),
                "center": center_json(&rect),
            }))
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
    // The requested action name goes through to the provider: backends
    // enumerate the AT-SPI Action interface and invoke the matching named
    // action ("press"/"activate"…); a backend without named-action support
    // reports `action_not_supported` rather than silently pressing.
    let invoked = backend!(ui.invoke_element_action(&p.query, p.action.as_str()).await);
    Ok(json_result(&json!({
        "found": true,
        "action": p.action.as_str(),
        "action_result": if invoked { "ok" } else { "action_not_supported" },
        "element": {"bounds": bounds_json(&rect), "center": center_json(&rect)},
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_rects_accepts_every_backend_shape() {
        // hyprctl: bare array, width/height spelling.
        let hypr = json!([
            {"name": "eDP-1", "x": 0, "y": 0, "width": 1920, "height": 1080},
            {"name": "DP-2", "x": 1920, "y": -30, "width": 2560, "height": 1440},
        ]);
        let got = output_rects(&hypr);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[1].1,
            Rect {
                x: 1920,
                y: -30,
                w: 2560,
                h: 1440
            }
        );

        // wlr fallback: {"outputs": […]}.
        let wlr = json!({"backend": "wlr-screencopy", "outputs": [
            {"name": "WL-1", "x": 0, "y": 0, "width": 1280, "height": 800}
        ]});
        assert_eq!(output_rects(&wlr)[0].0, "WL-1");

        // mock/portal: {"monitors": […]}, missing x/y → 0.
        let mock = json!({"monitors": [{"name": "mock", "width": 1920, "height": 1080}]});
        assert_eq!(
            output_rects(&mock)[0].1,
            Rect {
                x: 0,
                y: 0,
                w: 1920,
                h: 1080
            }
        );

        // Unusable shapes yield an empty inventory (→ "unsupported" arm).
        for bad in [json!({}), json!({"monitors": "x"}), json!([{"width": 1}])] {
            assert!(output_rects(&bad).is_empty());
        }
    }

    #[test]
    fn rects_intersect_edges() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        };
        let inside = Rect {
            x: 5,
            y: 5,
            w: 2,
            h: 2,
        };
        let edge = Rect {
            x: 9,
            y: 0,
            w: 4,
            h: 4,
        };
        let outside = Rect {
            x: 10,
            y: 0,
            w: 4,
            h: 4,
        };
        assert!(rects_intersect(&a, &inside));
        assert!(rects_intersect(&a, &edge));
        assert!(!rects_intersect(&a, &outside)); // touching ≠ intersecting
    }

    #[test]
    fn offset_into_scope_shifts_origin() {
        let local = Rect {
            x: 5,
            y: 6,
            w: 7,
            h: 8,
        };
        let scope = Rect {
            x: 100,
            y: 200,
            w: 50,
            h: 50,
        };
        assert_eq!(
            offset_into_scope(&local, &scope),
            Rect {
                x: 105,
                y: 206,
                w: 7,
                h: 8
            }
        );
    }
}
