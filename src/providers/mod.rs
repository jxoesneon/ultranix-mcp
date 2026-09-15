//! Provider registry — the `Option<Arc<dyn Trait>>` injection point.
//! Backends register themselves at startup; `None` slots make tools
//! degrade to `-32010 ProviderUnavailable` instead of failing silently.

pub mod atspi;
pub mod grim_capture;
pub mod hyprctl;
pub mod mock;
pub mod uinput_input;
pub mod wlr_capture;
pub mod wlr_input;

use std::sync::Arc;

use crate::traits::{
    BrowserProvider, CaptureProvider, InputProvider, UIAutomationProvider, VisionProvider,
    WindowProvider,
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
        }
    }

    /// Empty registry — every tool reports `ProviderUnavailable`.
    pub fn empty() -> Self {
        Self::default()
    }
}
