//! Session probing and the provider fallback ladder.
//!
//! Three layers, in increasing order of side effects:
//!
//! 1. [`SessionInfo`] — pure snapshot of the session environment
//!    (`XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`,
//!    `HYPRLAND_INSTANCE_SIGNATURE`, `WAYLAND_DISPLAY`, `DISPLAY`).
//! 2. [`plan_backends`] — pure function mapping a `SessionInfo` onto the
//!    ordered candidate list for each provider slot. This is the part the
//!    unit tests exercise across the env matrix.
//! 3. [`detect_providers`] — walks each ladder, calls each backend's
//!    `pub fn new() -> Option<Self>` runtime availability check, and
//!    registers (with `tracing::info!`) the first one that says yes.
//!
//! Live rungs: `providers::wlr_capture`, `providers::grim_capture`,
//! `providers::hyprctl`, `providers::wlr_input` and
//! `providers::uinput_input` are all wired below. Each backend's
//! `pub fn new() -> Option<Self>` performs its own runtime availability
//! probe (protocol advertisement, `/dev/uinput` writability, IPC socket),
//! so a missing backend simply falls through to the next rung.

use std::sync::Arc;

use crate::providers::Providers;
use crate::traits::{
    BrowserProvider, CaptureProvider, InputProvider, UIAutomationProvider, VisionProvider,
    WindowProvider,
};

/// Session class derived from `XDG_SESSION_TYPE`, with display-variable
/// inference when that variable is unset or non-committal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Wayland,
    X11,
    /// tty / ssh / container — no display to automate.
    Headless,
}

/// Snapshot of the session environment the fallback ladder keys off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_type: SessionType,
    /// Raw `XDG_CURRENT_DESKTOP` value (e.g. `"Hyprland"`, `"GNOME"`,
    /// `"sway:wlroots"`). `None` when unset or empty.
    pub desktop: Option<String>,
    /// `HYPRLAND_INSTANCE_SIGNATURE` is present and non-empty — the
    /// authoritative Hyprland signal (also gates the hyprctl window
    /// backend, whose IPC socket lives under `$XDG_RUNTIME_DIR/hypr/<sig>`).
    pub is_hyprland: bool,
    /// `WAYLAND_DISPLAY` (e.g. `"wayland-1"`), `None` when unset/empty.
    pub wayland_display: Option<String>,
    /// `DISPLAY` (e.g. `":0"`), `None` when unset/empty.
    pub display: Option<String>,
}

impl SessionInfo {
    /// Snapshot the real process environment.
    pub fn detect() -> Self {
        Self::from_env(|key| std::env::var(key).ok())
    }

    /// Build from an arbitrary env lookup — the unit-testable core.
    /// Empty-string values are treated as unset throughout: a var that is
    /// exported but empty carries no usable signal.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let non_empty = |key: &str| get(key).filter(|v| !v.is_empty());

        let raw_type = non_empty("XDG_SESSION_TYPE");
        let wayland_display = non_empty("WAYLAND_DISPLAY");
        let display = non_empty("DISPLAY");

        let session_type = match raw_type.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("wayland") => SessionType::Wayland,
            Some("x11") => SessionType::X11,
            // "tty", "unspecified", unset: infer from display vars before
            // declaring the session headless — e.g. a Wayland session
            // entered via `dbus-run-session` may lack XDG_SESSION_TYPE.
            _ if wayland_display.is_some() => SessionType::Wayland,
            _ if display.is_some() => SessionType::X11,
            _ => SessionType::Headless,
        };

        Self {
            session_type,
            desktop: non_empty("XDG_CURRENT_DESKTOP"),
            is_hyprland: non_empty("HYPRLAND_INSTANCE_SIGNATURE").is_some(),
            wayland_display,
            display,
        }
    }

    /// Case-insensitive substring check against `XDG_CURRENT_DESKTOP`
    /// (handles compound values like `"sway:wlroots"` / `"GNOME;Unity"`).
    pub fn desktop_contains(&self, needle: &str) -> bool {
        self.desktop.as_deref().is_some_and(|d| {
            d.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
    }
}

/// Ordered candidates for the capture slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// wlr-screencopy-unstable-v1 (wayland-rs protocol backend).
    Wlr,
    /// `grim`/`slurp` subprocess fallback for wlroots compositors.
    Grim,
    /// XDG `org.freedesktop.portal.Screenshot` — universal last resort.
    Portal,
}

/// Ordered candidates for the input slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputBackend {
    /// wlr-virtual-pointer + virtual-keyboard (compositor-native).
    Wlr,
    /// `/dev/uinput` kernel-level injection — display-agnostic fallback.
    UInput,
    /// XDG `org.freedesktop.portal.RemoteDesktop` — universal last resort.
    Portal,
}

/// Ordered candidates for the window-management slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowBackend {
    /// `hyprctl` IPC (`$XDG_RUNTIME_DIR/hypr/$HIS/.socket.sock`).
    Hyprctl,
}

/// Ordered candidates for the UI-automation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAutomationBackend {
    /// AT-SPI2 accessibility bus (`org.a11y.Bus` on the session bus).
    Atspi,
}

/// Ordered candidates for the vision slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionBackend {
    /// Local ONNX inference (`ort`): OCR + OWL-ViT, models fetched
    /// on first use into the state dir.
    Onnx,
}

/// Ordered candidates for the browser slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserBackend {
    /// Chrome DevTools Protocol bridge on `127.0.0.1:9222`.
    Cdp,
}

/// The ordered ladders [`detect_providers`] walks, resolved from session
/// info alone. Pure and unit-testable — no syscalls, no constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionPlan {
    pub capture: Vec<CaptureBackend>,
    pub input: Vec<InputBackend>,
    pub window: Vec<WindowBackend>,
    pub ui_automation: Vec<UiAutomationBackend>,
    pub vision: Vec<VisionBackend>,
    pub browser: Vec<BrowserBackend>,
}

/// Map a session snapshot onto the per-slot fallback ladders.
///
/// Ladder policy (per spec):
/// - capture: `Wlr → Grim → Portal → None` (wlr rungs are Wayland-only;
///   the portal rung also candidated on X11 — it's session-agnostic)
/// - input: `Wlr → UInput → Portal → None` (Wayland prefers
///   compositor-native injection; uinput and the portal are
///   display-agnostic so they also candidated on X11)
/// - window: `Hyprctl → None` (Hyprland sessions only)
/// - ui_automation: `Atspi → None` on any non-headless session — the
///   accessibility bus is compositor-agnostic (Wayland and X11 alike)
/// - vision: `Onnx → None` on any non-headless session — frames come
///   from the capture slot, which is empty headless anyway
/// - browser: `Cdp → None` on any non-headless session — the loopback
///   probe is cheap and no-op when nothing listens on :9222
/// - headless: every ladder is empty — there is no display to automate.
pub fn plan_backends(session: &SessionInfo) -> DetectionPlan {
    let capture = match session.session_type {
        SessionType::Wayland => vec![
            CaptureBackend::Wlr,
            CaptureBackend::Grim,
            CaptureBackend::Portal,
        ],
        SessionType::X11 => vec![CaptureBackend::Portal],
        SessionType::Headless => vec![],
    };

    let input = match session.session_type {
        SessionType::Wayland => vec![
            InputBackend::Wlr,
            InputBackend::UInput,
            InputBackend::Portal,
        ],
        SessionType::X11 => vec![InputBackend::UInput, InputBackend::Portal],
        SessionType::Headless => vec![],
    };

    let window = if session.is_hyprland {
        vec![WindowBackend::Hyprctl]
    } else {
        vec![]
    };

    let ui_automation = match session.session_type {
        SessionType::Wayland | SessionType::X11 => vec![UiAutomationBackend::Atspi],
        SessionType::Headless => vec![],
    };

    let vision = match session.session_type {
        SessionType::Wayland | SessionType::X11 => vec![VisionBackend::Onnx],
        SessionType::Headless => vec![],
    };

    let browser = match session.session_type {
        SessionType::Wayland | SessionType::X11 => vec![BrowserBackend::Cdp],
        SessionType::Headless => vec![],
    };

    DetectionPlan {
        capture,
        input,
        window,
        ui_automation,
        vision,
        browser,
    }
}

/// Detect the session environment and walk each fallback ladder.
///
/// For every slot, candidates are tried in order; the first backend whose
/// constructor reports itself usable is registered and logged via
/// `tracing::info!`. Slots with no working candidate stay `None`.
pub fn detect_providers(session: &SessionInfo) -> Providers {
    tracing::info!(
        session_type = ?session.session_type,
        desktop = session.desktop.as_deref().unwrap_or("<unset>"),
        is_hyprland = session.is_hyprland,
        wayland_display = session.wayland_display.as_deref().unwrap_or("<unset>"),
        display = session.display.as_deref().unwrap_or("<unset>"),
        "session probed"
    );

    let plan = plan_backends(session);

    let providers = Providers {
        capture: detect_capture(&plan.capture),
        input: detect_input(&plan.input),
        window: detect_window(&plan.window),
        ui_automation: detect_ui_automation(&plan.ui_automation),
        vision: detect_vision(&plan.vision),
        browser: detect_browser(&plan.browser),
    };

    tracing::info!(
        capture = providers.capture.is_some(),
        input = providers.input.is_some(),
        window = providers.window.is_some(),
        ui_automation = providers.ui_automation.is_some(),
        vision = providers.vision.is_some(),
        browser = providers.browser.is_some(),
        "provider detection complete"
    );

    providers
}

/// Walk the capture ladder: `Wlr → Grim → None`.
fn detect_capture(candidates: &[CaptureBackend]) -> Option<Arc<dyn CaptureProvider>> {
    for &candidate in candidates {
        match candidate {
            CaptureBackend::Wlr => {
                if let Some(p) = crate::providers::wlr_capture::WlrCapture::new() {
                    tracing::info!(backend = "wlr-screencopy", "capture provider registered");
                    return Some(Arc::new(p));
                }
            }
            CaptureBackend::Grim => {
                if let Some(p) = crate::providers::grim_capture::GrimCapture::new() {
                    tracing::info!(backend = "grim", "capture provider registered");
                    return Some(Arc::new(p));
                }
            }
            CaptureBackend::Portal => {
                if let Some(p) = crate::providers::portal_capture::PortalCapture::new() {
                    tracing::info!(backend = "portal-screenshot", "capture provider registered");
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("capture: no backend registered");
    None
}

/// Walk the input ladder: `Wlr → UInput → None`.
fn detect_input(candidates: &[InputBackend]) -> Option<Arc<dyn InputProvider>> {
    for &candidate in candidates {
        match candidate {
            InputBackend::Wlr => {
                if let Some(p) = crate::providers::wlr_input::WlrInput::new() {
                    tracing::info!(backend = "wlr-virtual-input", "input provider registered");
                    return Some(Arc::new(p));
                }
            }
            InputBackend::UInput => {
                if let Some(p) = crate::providers::uinput_input::UinputInput::new() {
                    tracing::info!(backend = "uinput", "input provider registered");
                    return Some(Arc::new(p));
                }
            }
            InputBackend::Portal => {
                if let Some(p) = crate::providers::portal_input::PortalInput::new() {
                    tracing::info!(
                        backend = "portal-remote-desktop",
                        "input provider registered"
                    );
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("input: no backend registered");
    None
}

/// Walk the window ladder: `Hyprctl → None`.
fn detect_window(candidates: &[WindowBackend]) -> Option<Arc<dyn WindowProvider>> {
    for &candidate in candidates {
        match candidate {
            WindowBackend::Hyprctl => {
                if let Some(p) = crate::providers::hyprctl::HyprctlWindow::new() {
                    tracing::info!(backend = "hyprctl", "window provider registered");
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("window: no backend registered");
    None
}

fn detect_ui_automation(
    candidates: &[UiAutomationBackend],
) -> Option<Arc<dyn UIAutomationProvider>> {
    for &candidate in candidates {
        match candidate {
            UiAutomationBackend::Atspi => {
                if let Some(p) = crate::providers::atspi::AtspiUi::new() {
                    tracing::info!(backend = "atspi2", "ui-automation provider registered");
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("ui_automation: no backend registered");
    None
}

fn detect_vision(candidates: &[VisionBackend]) -> Option<Arc<dyn VisionProvider>> {
    for &candidate in candidates {
        match candidate {
            VisionBackend::Onnx => {
                if let Some(p) = crate::providers::onnx_vision::OnnxVision::new() {
                    tracing::info!(backend = "onnx", "vision provider registered");
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("vision: no backend registered");
    None
}

fn detect_browser(candidates: &[BrowserBackend]) -> Option<Arc<dyn BrowserProvider>> {
    for &candidate in candidates {
        match candidate {
            BrowserBackend::Cdp => {
                if let Some(p) = crate::providers::cdp_browser::CdpBrowser::new() {
                    tracing::info!(backend = "cdp", "browser provider registered");
                    return Some(Arc::new(p));
                }
            }
        }
    }
    tracing::debug!("browser: no backend registered");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake environment lookup over a fixed key/value set.
    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn hyprland_wayland_session() {
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "Hyprland"),
            ("HYPRLAND_INSTANCE_SIGNATURE", "deadbeef_1700000000"),
            ("WAYLAND_DISPLAY", "wayland-1"),
            ("DISPLAY", ":1"),
        ]));
        assert_eq!(s.session_type, SessionType::Wayland);
        assert!(s.is_hyprland);
        assert_eq!(s.desktop.as_deref(), Some("Hyprland"));
        assert_eq!(s.wayland_display.as_deref(), Some("wayland-1"));
        assert_eq!(s.display.as_deref(), Some(":1"));
        assert!(s.desktop_contains("hyprland"));

        let plan = plan_backends(&s);
        assert_eq!(
            plan.capture,
            vec![
                CaptureBackend::Wlr,
                CaptureBackend::Grim,
                CaptureBackend::Portal,
            ]
        );
        assert_eq!(
            plan.input,
            vec![
                InputBackend::Wlr,
                InputBackend::UInput,
                InputBackend::Portal,
            ]
        );
        assert_eq!(plan.window, vec![WindowBackend::Hyprctl]);
    }

    #[test]
    fn generic_wayland_session_has_no_window_backend() {
        // GNOME/sway: capture + input ladders apply, but there is no
        // hyprctl IPC so the window slot has no candidates.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "GNOME"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]));
        assert_eq!(s.session_type, SessionType::Wayland);
        assert!(!s.is_hyprland);
        assert!(s.desktop_contains("gnome"));
        assert!(!s.desktop_contains("kde"));

        let plan = plan_backends(&s);
        assert_eq!(
            plan.capture,
            vec![
                CaptureBackend::Wlr,
                CaptureBackend::Grim,
                CaptureBackend::Portal,
            ]
        );
        assert_eq!(
            plan.input,
            vec![
                InputBackend::Wlr,
                InputBackend::UInput,
                InputBackend::Portal,
            ]
        );
        assert!(plan.window.is_empty());
    }

    #[test]
    fn x11_session() {
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "x11"),
            ("XDG_CURRENT_DESKTOP", "XFCE"),
            ("DISPLAY", ":0"),
        ]));
        assert_eq!(s.session_type, SessionType::X11);
        assert!(!s.is_hyprland);

        let plan = plan_backends(&s);
        // No X11-native capture backend — the portal rung is
        // session-agnostic and the only candidate.
        assert_eq!(plan.capture, vec![CaptureBackend::Portal]);
        // uinput is display-agnostic — a legitimate X11 candidate,
        // with the portal behind it.
        assert_eq!(plan.input, vec![InputBackend::UInput, InputBackend::Portal]);
        assert!(plan.window.is_empty());
    }

    #[test]
    fn headless_session() {
        let s = SessionInfo::from_env(fake_env(&[]));
        assert_eq!(s.session_type, SessionType::Headless);
        assert!(!s.is_hyprland);
        assert_eq!(s.desktop, None);
        assert_eq!(s.wayland_display, None);
        assert_eq!(s.display, None);
        assert!(!s.desktop_contains("anything"));

        let plan = plan_backends(&s);
        assert!(plan.capture.is_empty());
        assert!(plan.input.is_empty());
        assert!(plan.window.is_empty());
    }

    #[test]
    fn tty_session_type_is_headless() {
        let s = SessionInfo::from_env(fake_env(&[("XDG_SESSION_TYPE", "tty")]));
        assert_eq!(s.session_type, SessionType::Headless);
    }

    #[test]
    fn session_type_inferred_from_wayland_display() {
        // No XDG_SESSION_TYPE (e.g. dbus-run-session) but a live Wayland
        // socket name — still a Wayland session.
        let s = SessionInfo::from_env(fake_env(&[("WAYLAND_DISPLAY", "wayland-0")]));
        assert_eq!(s.session_type, SessionType::Wayland);
    }

    #[test]
    fn session_type_inferred_from_display() {
        let s = SessionInfo::from_env(fake_env(&[("DISPLAY", ":0")]));
        assert_eq!(s.session_type, SessionType::X11);
    }

    #[test]
    fn wayland_display_wins_over_display_when_type_unset() {
        let s = SessionInfo::from_env(fake_env(&[
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("DISPLAY", ":0"),
        ]));
        assert_eq!(s.session_type, SessionType::Wayland);
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", ""),
            ("XDG_CURRENT_DESKTOP", ""),
            ("HYPRLAND_INSTANCE_SIGNATURE", ""),
            ("WAYLAND_DISPLAY", ""),
            ("DISPLAY", ":0"),
        ]));
        assert_eq!(s.session_type, SessionType::X11);
        assert!(!s.is_hyprland);
        assert_eq!(s.desktop, None);
        assert_eq!(s.wayland_display, None);
    }

    #[test]
    fn session_type_value_is_case_insensitive() {
        let s = SessionInfo::from_env(fake_env(&[("XDG_SESSION_TYPE", "Wayland")]));
        assert_eq!(s.session_type, SessionType::Wayland);
    }

    #[test]
    fn hyprland_requires_signature_not_just_desktop() {
        // XDG_CURRENT_DESKTOP=Hyprland without the instance signature
        // (e.g. stale env in a nested session) must not gate hyprctl on.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "Hyprland"),
        ]));
        assert!(!s.is_hyprland);
        assert!(plan_backends(&s).window.is_empty());
    }

    #[test]
    fn detect_from_real_env_does_not_panic() {
        let _ = SessionInfo::detect();
    }

    #[test]
    fn detect_providers_headless_yields_empty_registry() {
        // Headless: no candidates on any ladder, so every slot is None —
        // guaranteed regardless of which provider modules are gated in.
        let s = SessionInfo::from_env(fake_env(&[]));
        let providers = detect_providers(&s);
        assert!(providers.capture.is_none());
        assert!(providers.input.is_none());
        assert!(providers.window.is_none());
        assert!(providers.ui_automation.is_none());
        assert!(providers.vision.is_none());
        assert!(providers.browser.is_none());
    }
}
