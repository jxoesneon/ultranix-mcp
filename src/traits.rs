//! Provider traits — the dependency-injection contract every backend
//! implements. Mirrors the sibling `ultrawin-mcp` pattern: each provider is
//! held as `Option<Arc<dyn Trait>>`, fully mockable in tests, and tools
//! degrade to typed `ProviderUnavailable` errors when a backend is `None`.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A screen-space rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// A captured frame, encoded as PNG bytes (callers base64-encode for MCP).
#[derive(Debug, Clone)]
pub struct Frame {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// A single detected word/icon from the vision pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub text: String,
    pub rect: Rect,
    pub confidence: f32,
}

/// One match from [`UIAutomationProvider::find_elements`]: whatever
/// accessibility metadata the backend can supply plus the bounding rect.
/// `name`/`role` are `""` and `states` empty when the backend reports
/// geometry only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElementMatch {
    pub name: String,
    pub role: String,
    pub states: Vec<String>,
    pub bounds: Rect,
}

/// A window record returned by [`WindowProvider`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    /// Compositor address/identifier (e.g. Hyprland `address`).
    pub id: String,
    pub title: String,
    pub class: String,
    pub workspace: i32,
    pub rect: Rect,
    pub focused: bool,
    /// Floating (vs tiled) state — `None` when the backend can't report it.
    pub floating: Option<bool>,
    /// Fullscreen state — `None` when the backend can't report it.
    pub fullscreen: Option<bool>,
    /// Owning process id — `None` when the backend can't report it.
    pub pid: Option<i64>,
    /// Monitor/output index or id — `None` when the backend can't report it.
    pub monitor: Option<i64>,
}

/// Screen capture (wlr-screencopy / portal / X11).
#[async_trait]
pub trait CaptureProvider: Send + Sync {
    /// Capture the full compositor output, or `region` when given.
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame>;
    /// Current pointer position, if the backend can report it.
    async fn cursor_position(&self) -> Result<(i32, i32)>;
    /// Monitor/output inventory as compositor-native JSON.
    async fn screen_info(&self) -> Result<Value>;
}

/// Input injection (wlr virtual pointer/keyboard, uinput, portal, X11).
#[async_trait]
pub trait InputProvider: Send + Sync {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()>;
    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()>;
    async fn mouse_button(&self, button: &str, down: bool) -> Result<()>;
    async fn scroll(&self, dx: f64, dy: f64) -> Result<()>;
    async fn key_event(&self, key: &str, down: bool) -> Result<()>;
    async fn type_text(&self, text: &str) -> Result<()>;
    /// Current pointer position per the input backend (may differ from
    /// `CaptureProvider::cursor_position` on compositors exposing both).
    async fn cursor_position(&self) -> Result<(i32, i32)>;
}

/// Accessibility tree (AT-SPI2).
#[async_trait]
pub trait UIAutomationProvider: Send + Sync {
    /// Serialized a11y tree from the root, to `depth` levels.
    async fn get_root_json(&self, depth: u32) -> Result<Value>;
    /// Serialized a11y subtree for the currently focused element.
    async fn get_focused_json(&self) -> Result<Value>;
    /// Find an element matching `query` (role/name/text). Returns its
    /// bounding rect when found.
    async fn find_element(&self, query: &str) -> Result<Option<Rect>>;
    /// All matches for `query`, capped at `limit`, in tree order. The
    /// default impl wraps [`find_element`](Self::find_element) into a
    /// single-element vec with empty `name`/`role`/`states`; backends
    /// that can enumerate multiple hits (AT-SPI) override it.
    async fn find_elements(&self, query: &str, limit: usize) -> Result<Vec<ElementMatch>> {
        let Some(bounds) = self.find_element(query).await? else {
            return Ok(Vec::new());
        };
        Ok(if limit == 0 {
            Vec::new()
        } else {
            vec![ElementMatch {
                name: String::new(),
                role: String::new(),
                states: Vec::new(),
                bounds,
            }]
        })
    }
    /// Invoke the element's default action (AT-SPI `Action` interface).
    async fn invoke_element(&self, query: &str) -> Result<bool>;
    /// Invoke a *named* action on the matched element — the
    /// `invoke_element` `action` enum: `"press"`, `"focus"`, `"expand"`,
    /// `"collapse"` (docs/TOOLS.md). Backends that can enumerate the AT-SPI
    /// `Action` interface's action names should override; the default maps
    /// `"press"`/`"activate"` onto the element's default action and reports
    /// every other name as unsupported (`Ok(false)`).
    async fn invoke_element_action(&self, query: &str, action: &str) -> Result<bool> {
        match action {
            "press" | "activate" => self.invoke_element(query).await,
            _ => Ok(false),
        }
    }
}

/// Window management via compositor IPC (hyprctl first, then fallbacks).
#[async_trait]
pub trait WindowProvider: Send + Sync {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>>;
    async fn active_window(&self) -> Result<Option<WindowInfo>>;
    /// Backend-native window op: `focus|move|resize|minimize|close`.
    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()>;
    /// Selector token that addresses the *focused view* directly,
    /// bypassing `list_windows`/`active_window` resolution — for
    /// compositors (river) that can act on the focused view but cannot
    /// enumerate or identify it. `None` (default) means selectors always
    /// resolve through the window list.
    fn focused_view_selector(&self) -> Option<&'static str> {
        None
    }
}

/// OCR + icon detection (ONNX Runtime).
#[async_trait]
pub trait VisionProvider: Send + Sync {
    /// OCR over a frame: detected words with bounding boxes.
    async fn recognize_text(&self, frame: &Frame) -> Result<Vec<Detection>>;
    /// Locate UI icons matching a natural-language description.
    async fn find_icon(&self, frame: &Frame, description: &str) -> Result<Vec<Detection>>;
}

/// On-screen highlight overlay (wlr-layer-shell).
#[async_trait]
pub trait OverlayProvider: Send + Sync {
    /// Draw a translucent rectangle over `rect` for `duration_ms`, then
    /// remove it. Purely visual — implementations must not affect
    /// capture or input.
    async fn highlight(&self, rect: Rect, duration_ms: u64) -> Result<()>;
}

/// Browser bridge (Chrome DevTools Protocol, loopback :9222).
#[async_trait]
pub trait BrowserProvider: Send + Sync {
    /// Evaluate a CSS-selector query in the active tab; returns matched
    /// elements as JSON.
    async fn query_selector(&self, selector: &str) -> Result<Value>;
    /// Ensure the CDP endpoint is reachable (lazy connect).
    async fn ensure_ready(&self) -> Result<()>;
}

/// Clipboard access (wl-clipboard on Wayland, xclip/xsel on X11).
///
/// The contract is text-first: reads surface UTF-8 text only — binary
/// payloads are never moved through the provider boundary (a clipboard
/// can carry arbitrary secrets; the tool layer is not a file bridge).
#[async_trait]
pub trait ClipboardProvider: Send + Sync {
    /// Current clipboard text, or `None` when the clipboard is empty or
    /// offers no text MIME type.
    async fn get_text(&self) -> Result<Option<String>>;
    /// Overwrite the clipboard with `text`.
    async fn set_text(&self, text: &str) -> Result<()>;
    /// Drop the selection entirely — subsequent reads report empty.
    async fn clear(&self) -> Result<()>;
    /// MIME types the clipboard owner currently offers (empty when the
    /// clipboard is empty).
    async fn list_mimes(&self) -> Result<Vec<String>>;
}
