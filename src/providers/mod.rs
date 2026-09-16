//! Provider registry — the `Option<Arc<dyn Trait>>` injection point.
//! Backends register themselves at startup; `None` slots make tools
//! degrade to `-32010 ProviderUnavailable` instead of failing silently.

// Per-backend feature gates (Cargo.toml `[features]`): disabling a group
// compiles out its provider modules; the detect ladder still plans the
// backend but construction yields `None` → honest ProviderUnavailable.
#[cfg(feature = "a11y")]
pub mod atspi;
#[cfg(feature = "browser")]
pub mod cdp_browser;
pub mod clipboard;
pub(crate) mod common;
#[cfg(feature = "a11y")]
pub mod gnome_window;
pub mod grim_capture;
pub mod hyprctl;
pub mod kdotool_window;
pub mod mock;
#[cfg(feature = "vision")]
pub mod onnx_vision;
#[cfg(feature = "wayland")]
pub mod overlay;
#[cfg(feature = "a11y")]
pub mod portal_capture;
#[cfg(feature = "a11y")]
pub mod portal_input;
pub mod river_window;
pub mod sway_window;
#[cfg(feature = "uinput")]
pub mod uinput_input;
pub mod wayfire_window;
#[cfg(feature = "wayland")]
pub mod wlr_capture;
#[cfg(feature = "wayland")]
pub mod wlr_input;
pub mod x11_capture;
pub mod x11_input;
pub mod x11_window;

use std::sync::Arc;

use crate::traits::{
    BrowserProvider, CaptureProvider, ClipboardProvider, InputProvider, OverlayProvider,
    UIAutomationProvider, VisionProvider, WindowProvider,
};

/// Every injectable backend, one slot per capability.
#[derive(Default)]
pub struct Providers {
    pub capture: Option<Arc<dyn CaptureProvider>>,
    pub input: Option<Arc<dyn InputProvider>>,
    pub ui_automation: Option<Arc<dyn UIAutomationProvider>>,
    pub window: Option<Arc<dyn WindowProvider>>,
    pub vision: Option<Arc<dyn VisionProvider>>,
    pub browser: Option<Arc<dyn BrowserProvider>>,
    /// Visual overlay (`screen_highlight`) — layer-shell or equivalent.
    pub overlay: Option<Arc<dyn OverlayProvider>>,
    /// Clipboard backend (`clipboard_*` tools) — wl-clipboard or xclip.
    pub clipboard: Option<Arc<dyn ClipboardProvider>>,
    /// Backend names that actually initialised (e.g. `"wlr-screencopy"`,
    /// `"atspi2"`) — surfaced in `capabilities.ultranix.providers`.
    pub backend_names: Vec<&'static str>,
}

impl Providers {
    /// Registry populated entirely with mocks (Phase 0 / tests).
    pub fn all_mocks() -> Self {
        Self {
            capture: Some(Arc::new(mock::MockCapture)),
            input: Some(Arc::new(mock::MockInput)),
            ui_automation: Some(Arc::new(mock::MockUiAutomation)),
            window: Some(Arc::new(mock::MockWindow)),
            vision: Some(Arc::new(mock::MockVision)),
            browser: Some(Arc::new(mock::MockBrowser)),
            overlay: Some(Arc::new(mock::MockOverlay)),
            clipboard: Some(Arc::new(mock::MockClipboard)),
            backend_names: vec![
                "mock-capture",
                "mock-input",
                "mock-ui-automation",
                "mock-window",
                "mock-vision",
                "mock-browser",
                "mock-overlay",
                "mock-clipboard",
            ],
        }
    }

    /// Empty registry — every tool reports `ProviderUnavailable`.
    pub fn empty() -> Self {
        Self::default()
    }
}
