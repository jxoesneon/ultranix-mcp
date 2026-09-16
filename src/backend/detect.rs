//! Session probing and the provider fallback ladder.
//!
//! Three layers, in increasing order of side effects:
//!
//! 1. [`SessionInfo`] — pure snapshot of the session environment
//!    (`XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`,
//!    `HYPRLAND_INSTANCE_SIGNATURE`, `SWAYSOCK`, `WAYFIRE_SOCKET`,
//!    `KDE_SESSION_VERSION`, `WAYLAND_DISPLAY`, `DISPLAY`), reduced to a
//!    [`SessionKind`] compositor family plus a [`SessionType`]
//!    transport.
//! 2. [`plan_backends`] — pure function mapping a `SessionInfo` onto the
//!    ordered candidate list for each provider slot. This is the part the
//!    unit tests exercise across the env matrix.
//! 3. [`detect_providers`] — walks each ladder, calls each backend's
//!    `pub fn new() -> Option<Self>` runtime availability check, and
//!    registers (with `tracing::info!`) the first one that says yes.
//!
//! Live rungs: `providers::wlr_capture`, `providers::grim_capture`,
//! `providers::hyprctl`, `providers::sway_window`,
//! `providers::kdotool_window`, `providers::wlr_input` and
//! `providers::uinput_input` are all wired below. Each backend's
//! `pub fn new() -> Option<Self>` performs its own runtime availability
//! probe (protocol advertisement, `/dev/uinput` writability, IPC socket,
//! session marker + binary pin), so a missing backend simply falls
//! through to the next rung.
//!
//! Compositor coverage (v1.2.0): the wlroots family — Hyprland, sway,
//! Wayfire, river — routes to the `wlr-*` capture/input rungs and the
//! layer-shell overlay; KDE and GNOME route to the portal rungs they
//! actually implement. Since v1.4.0 every compositor also has a window
//! rung — `wayfire-ipc` on Wayfire, focused-view-only `riverctl` on
//! river, `gnome-shell` (Window Calls extension) on GNOME. See
//! [`plan_backends`] for the per-slot policy.

use std::sync::Arc;

use crate::providers::Providers;
use crate::traits::{
    BrowserProvider, CaptureProvider, ClipboardProvider, InputProvider, OverlayProvider,
    UIAutomationProvider, VisionProvider, WindowProvider,
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

/// Compositor/desktop family the session signature resolves to —
/// orthogonal to [`SessionType`] (a Plasma X11 session is still
/// [`SessionKind::Kde`]). Detection precedence is signature-first:
/// `HYPRLAND_INSTANCE_SIGNATURE` → `SWAYSOCK`/`sway` →
/// `WAYFIRE_SOCKET`/`Wayfire` → `river` → `KDE_SESSION_VERSION`/`KDE` →
/// `GNOME`. Everything else is [`SessionKind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// `HYPRLAND_INSTANCE_SIGNATURE` present — the signature is
    /// authoritative; `XDG_CURRENT_DESKTOP=Hyprland` alone is not
    /// (stale env in a nested session must not gate hyprctl on).
    Hyprland,
    /// `SWAYSOCK` present, or `XDG_CURRENT_DESKTOP` contains `sway`.
    Sway,
    /// `WAYFIRE_SOCKET` present, or `XDG_CURRENT_DESKTOP` contains
    /// `Wayfire`.
    Wayfire,
    /// `XDG_CURRENT_DESKTOP` contains `river`.
    River,
    /// `KDE_SESSION_VERSION` present, or `XDG_CURRENT_DESKTOP` contains
    /// `KDE`/`Plasma`.
    Kde,
    /// `XDG_CURRENT_DESKTOP` contains `GNOME`.
    Gnome,
    /// Any session matching no known compositor signature — most
    /// unknown Wayland desktops are wlroots-based (niri, labwc, …), so
    /// the ladders keep the wlr-first rungs with probe fallthrough.
    Other,
}

impl SessionKind {
    /// wlroots-family compositors — the `wlr-screencopy`,
    /// `wlr-virtual-input` and `wlr-layer-shell` rungs all probe
    /// successfully only on these.
    pub fn is_wlroots(&self) -> bool {
        matches!(
            self,
            Self::Hyprland | Self::Sway | Self::Wayfire | Self::River
        )
    }
}

/// Snapshot of the session environment the fallback ladder keys off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_type: SessionType,
    /// Resolved compositor family (see [`SessionKind`]).
    pub kind: SessionKind,
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

        let desktop = non_empty("XDG_CURRENT_DESKTOP");
        let dhas = |needle: &str| {
            desktop.as_deref().is_some_and(|d| {
                d.to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
        };
        let is_hyprland = non_empty("HYPRLAND_INSTANCE_SIGNATURE").is_some();
        let kind = if is_hyprland {
            SessionKind::Hyprland
        } else if non_empty("SWAYSOCK").is_some() || dhas("sway") {
            SessionKind::Sway
        } else if non_empty("WAYFIRE_SOCKET").is_some() || dhas("wayfire") {
            SessionKind::Wayfire
        } else if dhas("river") {
            SessionKind::River
        } else if non_empty("KDE_SESSION_VERSION").is_some() || dhas("kde") || dhas("plasma") {
            SessionKind::Kde
        } else if dhas("gnome") {
            SessionKind::Gnome
        } else {
            SessionKind::Other
        };

        Self {
            session_type,
            kind,
            desktop,
            is_hyprland,
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

    /// Wayland transport (`XDG_SESSION_TYPE=wayland` or inferred).
    pub fn is_wayland(&self) -> bool {
        self.session_type == SessionType::Wayland
    }

    /// X11 transport (`XDG_SESSION_TYPE=x11` or inferred).
    pub fn is_x11(&self) -> bool {
        self.session_type == SessionType::X11
    }

    /// wlroots-family session — Hyprland, sway, Wayfire, river. These
    /// route to the `wlr-*` capture/input rungs and the layer-shell
    /// overlay; KDE/GNOME do not.
    pub fn is_wlroots(&self) -> bool {
        self.kind.is_wlroots()
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
    /// `scrot` subprocess — X11-native capture.
    Scrot,
}

/// Ordered candidates for the input slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputBackend {
    /// wlr-virtual-pointer + virtual-keyboard (compositor-native).
    Wlr,
    /// `xdotool` subprocess — X11-native injection.
    Xdotool,
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
    /// sway IPC direct to `$SWAYSOCK` — `providers::sway_window`.
    SwayIpc,
    /// `kdotool` subprocess — KWin window management on Wayland *and*
    /// X11 (KDE rung). `providers::kdotool_window`, backend name
    /// `"kdotool"`; drops out when the pin or KDE session marker is
    /// absent.
    Kdotool,
    /// Wayfire `ipc` plugin socket (`$WAYFIRE_SOCKET`), length-prefixed
    /// JSON. `providers::wayfire_window`, backend name `"wayfire-ipc"`.
    WayfireIpc,
    /// `riverctl` subprocess — river focused-view ops (no list IPC
    /// exists). `providers::river_window`, backend name `"riverctl"`;
    /// drops out when the pin or `XDG_CURRENT_DESKTOP=river` marker is
    /// absent.
    Riverctl,
    /// GNOME Shell "Window Calls" extension over the session D-Bus
    /// (`org.gnome.Shell.Extensions.Windows`). `providers::gnome_window`,
    /// backend name `"gnome-shell"`; drops out when the extension is not
    /// installed.
    GnomeShell,
    /// `wmctrl` + `xdotool` — X11 EWMH window management.
    Wmctrl,
}

/// Ordered candidates for the visual-overlay slot (`screen_highlight`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayBackend {
    /// `zwlr_layer_shell_v1` — short-lived translucent overlay surface.
    WlrLayerShell,
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

/// Ordered candidates for the clipboard slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardBackend {
    /// `wl-copy`/`wl-paste` (wl-clipboard) — Wayland-native clipboard.
    WlClipboard,
    /// `xclip` (+ `xsel` for clear) — X11 and XWayland clipboard.
    Xclip,
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
    pub overlay: Vec<OverlayBackend>,
    pub clipboard: Vec<ClipboardBackend>,
}

/// Map a session snapshot onto the per-slot fallback ladders.
///
/// Ladder policy (per spec):
/// - capture: `Wlr → Grim → Portal → None` on wlroots and unknown
///   Wayland sessions; `Portal → None` on KDE/GNOME Wayland (they
///   implement neither wlr-screencopy nor grim-compatible protocols, so
///   probing those rungs could never succeed — the portal is the real
///   mechanism); `Scrot → Portal → None` on X11.
/// - input: `Wlr → UInput → Portal → None` on wlroots and unknown
///   Wayland; `Portal → None` on KDE/GNOME Wayland;
///   `Xdotool → UInput → Portal → None` on X11 (X11-native first —
///   uinput needs the udev rule).
/// - window: `Hyprctl → None` on Hyprland; `SwayIpc → None` on sway;
///   `WayfireIpc → None` on Wayfire (`$WAYFIRE_SOCKET`, `ipc`/`ipc-rules`
///   plugins — drops out when the socket is absent); `Riverctl → None`
///   on river (focused-view-only rung: no list IPC — `get_windows`/
///   `get_active_window` fail honestly, `window_control` reaches the
///   focused view); `Kdotool → None` on KDE Wayland; `Kdotool → Wmctrl →
///   None` on KDE X11 (`kdotool` drives KWin on both transports and drops
///   out when the pin or session marker is absent, but a Plasma X11
///   session always has EWMH `wmctrl` behind it); `GnomeShell → None` on
///   GNOME Wayland and `GnomeShell → Wmctrl → None` on GNOME X11 (the
///   Window Calls extension — `org.gnome.Shell.Eval` stays deliberately
///   unused); `Wmctrl → None` on other X11 sessions.
/// - overlay: `WlrLayerShell → None` on wlroots and unknown Wayland
///   (the layer-shell protocol has no X11 analogue and no KDE/GNOME
///   implementation — those sessions get an honest empty ladder).
/// - ui_automation: `Atspi → None` on any non-headless session — the
///   accessibility bus is compositor-agnostic (Wayland and X11 alike).
/// - vision: `Onnx → None` on any non-headless session — frames come
///   from the capture slot, which is empty headless anyway.
/// - browser: `Cdp → None` on any non-headless session — the loopback
///   probe is cheap and no-op when nothing listens on :9222.
/// - clipboard: `WlClipboard → Xclip → None` on Wayland (the X11 helpers
///   still serve the selection through XWayland); `Xclip → None` on X11.
/// - headless: every ladder is empty — there is no display to automate.
pub fn plan_backends(session: &SessionInfo) -> DetectionPlan {
    // KDE/GNOME Wayland sessions are portal-native for capture, input
    // and overlay — see the ladder policy above.
    let portal_desktop =
        session.is_wayland() && matches!(session.kind, SessionKind::Kde | SessionKind::Gnome);

    let capture = match session.session_type {
        SessionType::Wayland if portal_desktop => vec![CaptureBackend::Portal],
        SessionType::Wayland => vec![
            CaptureBackend::Wlr,
            CaptureBackend::Grim,
            CaptureBackend::Portal,
        ],
        SessionType::X11 => vec![CaptureBackend::Scrot, CaptureBackend::Portal],
        SessionType::Headless => vec![],
    };

    let input = match session.session_type {
        SessionType::Wayland if portal_desktop => vec![InputBackend::Portal],
        SessionType::Wayland => vec![
            InputBackend::Wlr,
            InputBackend::UInput,
            InputBackend::Portal,
        ],
        SessionType::X11 => vec![
            InputBackend::Xdotool,
            InputBackend::UInput,
            InputBackend::Portal,
        ],
        SessionType::Headless => vec![],
    };

    let window = match session.kind {
        SessionKind::Hyprland => vec![WindowBackend::Hyprctl],
        SessionKind::Sway => vec![WindowBackend::SwayIpc],
        // Wayfire's `ipc` plugin exposes `list-views` + view methods over
        // `$WAYFIRE_SOCKET`; river gets focused-view ops via `riverctl`
        // (no list/active IPC exists — those calls error honestly).
        SessionKind::Wayfire => vec![WindowBackend::WayfireIpc],
        SessionKind::River => vec![WindowBackend::Riverctl],
        SessionKind::Kde if session.is_wayland() => vec![WindowBackend::Kdotool],
        // Plasma X11: kdotool is still the KWin-native rung, but a
        // session without the pin/marker is not window-less — EWMH
        // `wmctrl` manages X11 clients under KWin.
        SessionKind::Kde if session.is_x11() => {
            vec![WindowBackend::Kdotool, WindowBackend::Wmctrl]
        }
        // GNOME: the "Window Calls" Shell extension is the only real
        // window IPC; on X11 sessions EWMH stays the fallback rung.
        SessionKind::Gnome if session.is_wayland() => vec![WindowBackend::GnomeShell],
        SessionKind::Gnome if session.is_x11() => {
            vec![WindowBackend::GnomeShell, WindowBackend::Wmctrl]
        }
        SessionKind::Other if session.is_x11() => vec![WindowBackend::Wmctrl],
        SessionKind::Kde | SessionKind::Gnome | SessionKind::Other => vec![],
    };

    let overlay = match session.session_type {
        SessionType::Wayland if !portal_desktop => vec![OverlayBackend::WlrLayerShell],
        SessionType::Wayland | SessionType::X11 | SessionType::Headless => vec![],
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

    let clipboard = match session.session_type {
        SessionType::Wayland => vec![ClipboardBackend::WlClipboard, ClipboardBackend::Xclip],
        SessionType::X11 => vec![ClipboardBackend::Xclip],
        SessionType::Headless => vec![],
    };

    DetectionPlan {
        capture,
        input,
        window,
        ui_automation,
        vision,
        browser,
        overlay,
        clipboard,
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
        session_kind = ?session.kind,
        desktop = session.desktop.as_deref().unwrap_or("<unset>"),
        is_hyprland = session.is_hyprland,
        is_wlroots = session.is_wlroots(),
        wayland_display = session.wayland_display.as_deref().unwrap_or("<unset>"),
        display = session.display.as_deref().unwrap_or("<unset>"),
        "session probed"
    );

    let plan = plan_backends(session);

    let mut backend_names = Vec::new();
    let capture = detect_capture(&plan.capture);
    if let Some((_, name)) = &capture {
        backend_names.push(*name);
    }
    let input = detect_input(&plan.input);
    if let Some((_, name)) = &input {
        backend_names.push(*name);
    }
    let window = detect_window(&plan.window);
    if let Some((_, name)) = &window {
        backend_names.push(*name);
    }
    let ui_automation = detect_ui_automation(&plan.ui_automation);
    if let Some((_, name)) = &ui_automation {
        backend_names.push(*name);
    }
    let vision = detect_vision(&plan.vision);
    if let Some((_, name)) = &vision {
        backend_names.push(*name);
    }
    let browser = detect_browser(&plan.browser);
    if let Some((_, name)) = &browser {
        backend_names.push(*name);
    }
    let overlay = detect_overlay(&plan.overlay);
    if let Some((_, name)) = &overlay {
        backend_names.push(*name);
    }
    let clipboard = detect_clipboard(&plan.clipboard);
    if let Some((_, name)) = &clipboard {
        backend_names.push(*name);
    }

    let providers = Providers {
        capture: capture.map(|(p, _)| p),
        input: input.map(|(p, _)| p),
        window: window.map(|(p, _)| p),
        ui_automation: ui_automation.map(|(p, _)| p),
        vision: vision.map(|(p, _)| p),
        browser: browser.map(|(p, _)| p),
        overlay: overlay.map(|(p, _)| p),
        clipboard: clipboard.map(|(p, _)| p),
        backend_names,
    };

    tracing::info!(
        capture = providers.capture.is_some(),
        input = providers.input.is_some(),
        window = providers.window.is_some(),
        ui_automation = providers.ui_automation.is_some(),
        vision = providers.vision.is_some(),
        browser = providers.browser.is_some(),
        overlay = providers.overlay.is_some(),
        clipboard = providers.clipboard.is_some(),
        "provider detection complete"
    );

    providers
}

/// Walk the capture ladder: `Wlr → Grim → None`.
fn detect_capture(
    candidates: &[CaptureBackend],
) -> Option<(Arc<dyn CaptureProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            CaptureBackend::Wlr => {
                #[cfg(feature = "wayland")]
                if let Some(p) = crate::providers::wlr_capture::WlrCapture::new() {
                    tracing::info!(backend = "wlr-screencopy", "capture provider registered");
                    return Some((Arc::new(p), "wlr-screencopy"));
                }
            }
            CaptureBackend::Grim => {
                if let Some(p) = crate::providers::grim_capture::GrimCapture::new() {
                    tracing::info!(backend = "grim", "capture provider registered");
                    return Some((Arc::new(p), "grim"));
                }
            }
            CaptureBackend::Portal => {
                #[cfg(feature = "a11y")]
                if let Some(p) = crate::providers::portal_capture::PortalCapture::new() {
                    tracing::info!(backend = "portal-screenshot", "capture provider registered");
                    return Some((Arc::new(p), "portal-screenshot"));
                }
            }
            CaptureBackend::Scrot => {
                if let Some(p) = crate::providers::x11_capture::X11Capture::new() {
                    tracing::info!(backend = "scrot", "capture provider registered");
                    return Some((Arc::new(p), "scrot"));
                }
            }
        }
    }
    tracing::debug!("capture: no backend registered");
    None
}

/// Walk the input ladder: `Wlr → UInput → None`.
fn detect_input(candidates: &[InputBackend]) -> Option<(Arc<dyn InputProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            InputBackend::Wlr =>
            {
                #[cfg(feature = "wayland")]
                if let Some(p) = crate::providers::wlr_input::WlrInput::new() {
                    tracing::info!(backend = "wlr-virtual-input", "input provider registered");
                    return Some((Arc::new(p), "wlr-virtual-input"));
                }
            }
            InputBackend::UInput => {
                #[cfg(feature = "uinput")]
                if let Some(p) = crate::providers::uinput_input::UinputInput::new() {
                    tracing::info!(backend = "uinput", "input provider registered");
                    return Some((Arc::new(p), "uinput"));
                }
            }
            InputBackend::Portal => {
                #[cfg(feature = "a11y")]
                if let Some(p) = crate::providers::portal_input::PortalInput::new() {
                    tracing::info!(
                        backend = "portal-remote-desktop",
                        "input provider registered"
                    );
                    return Some((Arc::new(p), "portal-remote-desktop"));
                }
            }
            InputBackend::Xdotool => {
                if let Some(p) = crate::providers::x11_input::X11Input::new() {
                    tracing::info!(backend = "xdotool", "input provider registered");
                    return Some((Arc::new(p), "xdotool"));
                }
            }
        }
    }
    tracing::debug!("input: no backend registered");
    None
}

/// Walk the window ladder: `Hyprctl → None` on Hyprland, `SwayIpc →
/// None` on sway, `Kdotool → None` on KDE Wayland (`Kdotool → Wmctrl →
/// None` on KDE X11), `WayfireIpc → None` on Wayfire, `Riverctl → None`
/// on river, `GnomeShell → None` on GNOME Wayland (`GnomeShell → Wmctrl
/// → None` on GNOME X11), `Wmctrl → None` on other X11 sessions.
fn detect_window(candidates: &[WindowBackend]) -> Option<(Arc<dyn WindowProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            WindowBackend::Hyprctl => {
                if let Some(p) = crate::providers::hyprctl::HyprctlWindow::new() {
                    tracing::info!(backend = "hyprctl", "window provider registered");
                    return Some((Arc::new(p), "hyprctl"));
                }
            }
            WindowBackend::SwayIpc => {
                if let Some(p) = crate::providers::sway_window::SwayWindow::new() {
                    tracing::info!(backend = "sway-ipc", "window provider registered");
                    return Some((Arc::new(p), "sway-ipc"));
                }
            }
            WindowBackend::Kdotool => {
                if let Some(p) = crate::providers::kdotool_window::KdotoolWindow::new() {
                    tracing::info!(backend = "kdotool", "window provider registered");
                    return Some((Arc::new(p), "kdotool"));
                }
            }
            WindowBackend::WayfireIpc => {
                if let Some(p) = crate::providers::wayfire_window::WayfireWindow::new() {
                    tracing::info!(backend = "wayfire-ipc", "window provider registered");
                    return Some((Arc::new(p), "wayfire-ipc"));
                }
            }
            WindowBackend::Riverctl => {
                if let Some(p) = crate::providers::river_window::RiverWindow::new() {
                    tracing::info!(backend = "riverctl", "window provider registered");
                    return Some((Arc::new(p), "riverctl"));
                }
            }
            WindowBackend::GnomeShell => {
                #[cfg(feature = "a11y")]
                if let Some(p) = crate::providers::gnome_window::GnomeShellWindow::new() {
                    tracing::info!(backend = "gnome-shell", "window provider registered");
                    return Some((Arc::new(p), "gnome-shell"));
                }
            }
            WindowBackend::Wmctrl => {
                if let Some(p) = crate::providers::x11_window::X11Window::new() {
                    tracing::info!(backend = "wmctrl", "window provider registered");
                    return Some((Arc::new(p), "wmctrl"));
                }
            }
        }
    }
    tracing::debug!("window: no backend registered");
    None
}

fn detect_ui_automation(
    candidates: &[UiAutomationBackend],
) -> Option<(Arc<dyn UIAutomationProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            UiAutomationBackend::Atspi =>
            {
                #[cfg(feature = "a11y")]
                if let Some(p) = crate::providers::atspi::AtspiUi::new() {
                    tracing::info!(backend = "atspi2", "ui-automation provider registered");
                    return Some((Arc::new(p), "atspi2"));
                }
            }
        }
    }
    tracing::debug!("ui_automation: no backend registered");
    None
}

fn detect_vision(candidates: &[VisionBackend]) -> Option<(Arc<dyn VisionProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            VisionBackend::Onnx => {
                #[cfg(feature = "vision")]
                if let Some(p) = crate::providers::onnx_vision::OnnxVision::new() {
                    tracing::info!(backend = "onnx", "vision provider registered");
                    return Some((Arc::new(p), "onnx"));
                }
            }
        }
    }
    tracing::debug!("vision: no backend registered");
    None
}

fn detect_browser(
    candidates: &[BrowserBackend],
) -> Option<(Arc<dyn BrowserProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            BrowserBackend::Cdp => {
                #[cfg(feature = "browser")]
                if let Some(p) = crate::providers::cdp_browser::CdpBrowser::new() {
                    tracing::info!(backend = "cdp", "browser provider registered");
                    return Some((Arc::new(p), "cdp"));
                }
            }
        }
    }
    tracing::debug!("browser: no backend registered");
    None
}

fn detect_overlay(
    candidates: &[OverlayBackend],
) -> Option<(Arc<dyn OverlayProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            OverlayBackend::WlrLayerShell => {
                #[cfg(feature = "wayland")]
                if let Some(p) = crate::providers::overlay::Overlay::new() {
                    tracing::info!(backend = "wlr-layer-shell", "overlay provider registered");
                    return Some((Arc::new(p), "wlr-layer-shell"));
                }
            }
        }
    }
    tracing::debug!("overlay: no backend registered");
    None
}

/// Walk the clipboard ladder: `WlClipboard → Xclip → None` on Wayland,
/// `Xclip → None` on X11.
fn detect_clipboard(
    candidates: &[ClipboardBackend],
) -> Option<(Arc<dyn ClipboardProvider>, &'static str)> {
    for &candidate in candidates {
        match candidate {
            ClipboardBackend::WlClipboard => {
                if let Some(p) = crate::providers::clipboard::WlClipboard::new() {
                    tracing::info!(backend = "wl-clipboard", "clipboard provider registered");
                    return Some((Arc::new(p), "wl-clipboard"));
                }
            }
            ClipboardBackend::Xclip => {
                if let Some(p) = crate::providers::clipboard::XclipClipboard::new() {
                    tracing::info!(backend = "xclip", "clipboard provider registered");
                    return Some((Arc::new(p), "xclip"));
                }
            }
        }
    }
    tracing::debug!("clipboard: no backend registered");
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
        assert_eq!(plan.overlay, vec![OverlayBackend::WlrLayerShell]);
    }

    #[test]
    fn generic_wayland_session_has_no_window_backend() {
        // An unrecognized Wayland desktop (labwc/niri/cosmic/…): the
        // wlr-first capture + input ladders apply — most unknown
        // compositors are wlroots-based, and probe fallthrough is cheap —
        // but the window slot has no candidates.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "LabWC"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]));
        assert_eq!(s.session_type, SessionType::Wayland);
        assert_eq!(s.kind, SessionKind::Other);
        assert!(s.is_wayland());
        assert!(!s.is_x11());
        assert!(!s.is_hyprland);
        assert!(!s.is_wlroots());
        assert!(s.desktop_contains("labwc"));
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
        assert_eq!(plan.overlay, vec![OverlayBackend::WlrLayerShell]);
    }

    #[test]
    fn sway_session_via_sock_and_desktop() {
        for env in [
            // SWAYSOCK alone is authoritative — sway exports it to the
            // whole session.
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("SWAYSOCK", "/run/user/1000/sway-ipc.1000.1234.sock"),
                ("WAYLAND_DISPLAY", "wayland-1"),
            ]),
            // Desktop name alone (e.g. socket var stripped by a nested
            // launcher) still resolves the kind.
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "sway"),
                ("WAYLAND_DISPLAY", "wayland-1"),
            ]),
        ] {
            let s = SessionInfo::from_env(env);
            assert_eq!(s.kind, SessionKind::Sway);
            assert!(s.is_wlroots());
            assert!(!s.is_hyprland);

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
            assert_eq!(plan.window, vec![WindowBackend::SwayIpc]);
            assert_eq!(plan.overlay, vec![OverlayBackend::WlrLayerShell]);
        }
    }

    #[test]
    fn wayfire_session_gets_ipc_window_rung() {
        for env in [
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "Wayfire"),
                ("WAYFIRE_SOCKET", "/tmp/wayfire-wayland-1.socket"),
                ("WAYLAND_DISPLAY", "wayland-1"),
            ]),
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "Wayfire"),
                ("WAYLAND_DISPLAY", "wayland-1"),
            ]),
        ] {
            let s = SessionInfo::from_env(env);
            assert_eq!(s.kind, SessionKind::Wayfire);
            assert!(s.is_wlroots());

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
            // Wayfire's `ipc` plugin exposes `list-views` + view ops over
            // `$WAYFIRE_SOCKET` — a real window rung.
            assert_eq!(plan.window, vec![WindowBackend::WayfireIpc]);
            assert_eq!(plan.overlay, vec![OverlayBackend::WlrLayerShell]);
        }
    }

    #[test]
    fn river_session_gets_riverctl_window_rung() {
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "river"),
            ("WAYLAND_DISPLAY", "wayland-1"),
        ]));
        assert_eq!(s.kind, SessionKind::River);
        assert!(s.is_wlroots());

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
        // riverctl manages the *focused* view — a partial rung; list/
        // active window calls error honestly at the provider.
        assert_eq!(plan.window, vec![WindowBackend::Riverctl]);
        assert_eq!(plan.overlay, vec![OverlayBackend::WlrLayerShell]);
    }

    #[test]
    fn kde_session_routes_portal_and_kdotool() {
        for env in [
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "KDE"),
                ("KDE_SESSION_VERSION", "6"),
                ("WAYLAND_DISPLAY", "wayland-0"),
            ]),
            // Session-version marker alone resolves the kind.
            fake_env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("KDE_SESSION_VERSION", "5"),
                ("WAYLAND_DISPLAY", "wayland-0"),
            ]),
        ] {
            let s = SessionInfo::from_env(env);
            assert_eq!(s.kind, SessionKind::Kde);
            assert!(!s.is_wlroots());

            let plan = plan_backends(&s);
            // Portal is the only real capture/input mechanism on KWin.
            assert_eq!(plan.capture, vec![CaptureBackend::Portal]);
            assert_eq!(plan.input, vec![InputBackend::Portal]);
            // kdotool drives KWin on Wayland and X11 alike; the rung
            // drops out at detect time when the pin or the KDE session
            // marker is absent. On Wayland there is no EWMH behind it —
            // the single-rung ladder is honest (the KDE-X11 case below
            // adds `wmctrl`).
            assert_eq!(plan.window, vec![WindowBackend::Kdotool]);
            // No layer-shell on KWin → honest empty overlay.
            assert!(plan.overlay.is_empty());
        }
    }

    #[test]
    fn kde_x11_keeps_kdotool_window_rung() {
        // Plasma X11: X11-native capture/input ladders, and kdotool is
        // still the first window rung (it drives KWin on both
        // transports) — with EWMH `wmctrl` behind it so a session
        // lacking the pin/marker is not left window-less.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "x11"),
            ("XDG_CURRENT_DESKTOP", "KDE"),
            ("KDE_SESSION_VERSION", "5"),
            ("DISPLAY", ":0"),
        ]));
        assert_eq!(s.session_type, SessionType::X11);
        assert!(s.is_x11());
        assert_eq!(s.kind, SessionKind::Kde);

        let plan = plan_backends(&s);
        assert_eq!(
            plan.capture,
            vec![CaptureBackend::Scrot, CaptureBackend::Portal]
        );
        assert_eq!(
            plan.window,
            vec![WindowBackend::Kdotool, WindowBackend::Wmctrl]
        );
        assert!(plan.overlay.is_empty());
    }

    #[test]
    fn gnome_session_routes_portal_and_shell_extension() {
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "GNOME"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]));
        assert_eq!(s.kind, SessionKind::Gnome);
        assert!(!s.is_wlroots());

        let plan = plan_backends(&s);
        assert_eq!(plan.capture, vec![CaptureBackend::Portal]);
        assert_eq!(plan.input, vec![InputBackend::Portal]);
        // The "Window Calls" Shell extension is the window rung —
        // gnome-shell `Eval` stays deliberately unused (arbitrary-JS).
        assert_eq!(plan.window, vec![WindowBackend::GnomeShell]);
        assert!(plan.overlay.is_empty());
    }

    #[test]
    fn clipboard_ladder_follows_session_transport() {
        // Wayland: wl-clipboard first, the X11 helpers behind it — they
        // still serve the selection through XWayland.
        let wl = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ]));
        assert_eq!(
            plan_backends(&wl).clipboard,
            vec![ClipboardBackend::WlClipboard, ClipboardBackend::Xclip]
        );

        // X11: xclip only — no Wayland selection exists to serve.
        let x = SessionInfo::from_env(fake_env(&[("XDG_SESSION_TYPE", "x11"), ("DISPLAY", ":0")]));
        assert_eq!(plan_backends(&x).clipboard, vec![ClipboardBackend::Xclip]);

        // Headless: no display → no clipboard.
        let h = SessionInfo::from_env(fake_env(&[]));
        assert!(plan_backends(&h).clipboard.is_empty());
    }

    #[test]
    fn is_wlroots_covers_all_four_compositors() {
        let wlroots = [
            fake_env(&[("HYPRLAND_INSTANCE_SIGNATURE", "sig_1")]),
            fake_env(&[("SWAYSOCK", "/tmp/sway.sock")]),
            fake_env(&[("XDG_CURRENT_DESKTOP", "Wayfire")]),
            fake_env(&[("XDG_CURRENT_DESKTOP", "river")]),
        ];
        for env in wlroots {
            assert!(SessionInfo::from_env(env).is_wlroots());
        }
        let not_wlroots = [
            fake_env(&[("XDG_CURRENT_DESKTOP", "KDE")]),
            fake_env(&[("XDG_CURRENT_DESKTOP", "GNOME")]),
            fake_env(&[("XDG_CURRENT_DESKTOP", "XFCE")]),
            fake_env(&[]),
        ];
        for env in not_wlroots {
            assert!(!SessionInfo::from_env(env).is_wlroots());
        }
    }

    #[test]
    fn kind_detection_precedence() {
        // Signature beats desktop name; SWAYSOCK beats a stale desktop.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("HYPRLAND_INSTANCE_SIGNATURE", "sig_1"),
            ("XDG_CURRENT_DESKTOP", "sway:Hyprland"),
            ("SWAYSOCK", "/tmp/sway.sock"),
        ]));
        assert_eq!(s.kind, SessionKind::Hyprland);

        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("SWAYSOCK", "/tmp/sway.sock"),
            ("XDG_CURRENT_DESKTOP", "GNOME"),
        ]));
        assert_eq!(s.kind, SessionKind::Sway);
    }

    #[test]
    fn headless_kde_env_does_not_emit_kdotool() {
        // Stale desktop vars on a tty must not produce a window rung —
        // headless keeps every ladder empty except the signature-gated
        // compositor rungs whose IPC socket is itself the proof of life.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "tty"),
            ("XDG_CURRENT_DESKTOP", "KDE"),
            ("KDE_SESSION_VERSION", "5"),
        ]));
        assert_eq!(s.session_type, SessionType::Headless);
        assert_eq!(s.kind, SessionKind::Kde);
        let plan = plan_backends(&s);
        assert!(plan.capture.is_empty());
        assert!(plan.input.is_empty());
        assert!(plan.window.is_empty());
        assert!(plan.overlay.is_empty());
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
        // X11-native `scrot` first, the portal behind it.
        assert_eq!(
            plan.capture,
            vec![CaptureBackend::Scrot, CaptureBackend::Portal]
        );
        // X11-native `xdotool` first, then the display-agnostic rungs.
        assert_eq!(
            plan.input,
            vec![
                InputBackend::Xdotool,
                InputBackend::UInput,
                InputBackend::Portal,
            ]
        );
        // EWMH window management via `wmctrl`.
        assert_eq!(plan.window, vec![WindowBackend::Wmctrl]);
        // No layer-shell protocol on X11.
        assert!(plan.overlay.is_empty());
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
        assert!(plan.overlay.is_empty());
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
    fn session_wide_slots_follow_display_presence() {
        // ui_automation / vision / browser ride along on any session
        // with a display — they are compositor-agnostic.
        let wl = SessionInfo::from_env(fake_env(&[("WAYLAND_DISPLAY", "wayland-0")]));
        let plan = plan_backends(&wl);
        assert_eq!(plan.ui_automation, vec![UiAutomationBackend::Atspi]);
        assert_eq!(plan.vision, vec![VisionBackend::Onnx]);
        assert_eq!(plan.browser, vec![BrowserBackend::Cdp]);

        let x = SessionInfo::from_env(fake_env(&[("DISPLAY", ":0")]));
        let plan = plan_backends(&x);
        assert_eq!(plan.ui_automation, vec![UiAutomationBackend::Atspi]);
        assert_eq!(plan.vision, vec![VisionBackend::Onnx]);
        assert_eq!(plan.browser, vec![BrowserBackend::Cdp]);

        // Headless: nothing to automate → all three slots empty.
        let h = SessionInfo::from_env(fake_env(&[]));
        let plan = plan_backends(&h);
        assert!(plan.ui_automation.is_empty());
        assert!(plan.vision.is_empty());
        assert!(plan.browser.is_empty());
    }

    #[test]
    fn hyprland_signature_wins_even_on_x11_typed_session() {
        // A session that reports `x11` but carries the instance
        // signature (e.g. Xwayland-only display var) still gets the
        // hyprctl window backend — the signature check precedes the
        // X11 fallback.
        let s = SessionInfo::from_env(fake_env(&[
            ("XDG_SESSION_TYPE", "x11"),
            ("HYPRLAND_INSTANCE_SIGNATURE", "deadbeef_1700000000"),
            ("DISPLAY", ":0"),
        ]));
        assert!(s.is_hyprland);
        assert_eq!(plan_backends(&s).window, vec![WindowBackend::Hyprctl]);
    }

    #[test]
    fn kdotool_rung_yields_none_outside_kde_session() {
        // Construction path: with no KDE session markers the provider
        // refuses to construct even if the `kdotool` pin could resolve —
        // the rung falls through to an honest `None`.
        // SAFETY: test-only env mutation, restored before returning —
        // the same pattern the provider gate tests use.
        let saved_v = std::env::var_os("KDE_SESSION_VERSION");
        let saved_d = std::env::var_os("XDG_CURRENT_DESKTOP");
        unsafe {
            std::env::remove_var("KDE_SESSION_VERSION");
            std::env::remove_var("XDG_CURRENT_DESKTOP");
        }
        assert!(detect_window(&[WindowBackend::Kdotool]).is_none());
        if let Some(v) = saved_v {
            unsafe { std::env::set_var("KDE_SESSION_VERSION", v) };
        }
        if let Some(v) = saved_d {
            unsafe { std::env::set_var("XDG_CURRENT_DESKTOP", v) };
        }
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
