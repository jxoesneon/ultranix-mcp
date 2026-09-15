//! XDG Desktop Portal `RemoteDesktop` input backend — the last-resort
//! rung of the input fallback ladder (`wlr-virtual` → `/dev/uinput` →
//! portal → `xdotool`; ADR 0004, ARCHITECTURE.md §5).
//!
//! This is the only input path that works on compositors with neither
//! `zwlr_virtual_pointer_manager_v1`/`virtual-keyboard-unstable-v1` nor a
//! writable `/dev/uinput` — GNOME, KDE Plasma, COSMIC — at the price of a
//! **consent dialog**.
//!
//! ## Session lifecycle
//!
//! [`PortalInput::new`] is a *probe only*: it checks that
//! `org.freedesktop.portal.Desktop` is owned on the session bus and
//! returns. The session is established lazily on the first input call and
//! cached in the struct (`Mutex<Option<Session>>`):
//!
//! ```text
//! CreateSession ──► Response{session_handle}
//! SelectDevices(types = pointer|keyboard)
//! SelectSources(types = monitor)              — v2+ only, best-effort
//! Start("", {}) ──► Response{devices, streams?}
//! ```
//!
//! Every method answers via a `Response` signal on a per-call request
//! object (see `portal_capture::await_response`); `Start` is the call
//! that raises the consent dialog. If a `Notify*` call fails later
//! (session revoked, portal restarted) the session is dropped and
//! **re-established once** — a `user-cancelled` failure on the retry
//! propagates without a third attempt.
//!
//! ## Consent behavior per backend
//!
//! - `persist_mode`/`restore_token` are **deliberately never sent and
//!   never stored**: a persisted restore credential would let a later
//!   process re-establish a RemoteDesktop session with no fresh consent
//!   prompt (THREAT_MODEL.md §4.2). Every session — including the
//!   one-shot re-establishment after a `Notify*` failure — consents
//!   afresh through `Start`.
//! - `xdg-desktop-portal-gnome` / `-kde`: `Start` shows a dialog asking
//!   which screen to share *and* grants the device set.
//! - `xdg-desktop-portal-hyprland` / `-wlr`: consent is typically a
//!   one-shot prompt.
//! - Version-1 backends get the same plain non-persisted sessions — the
//!   dialog appears once per process (and again if the session must be
//!   rebuilt).
//!
//! ## Absolute pointer motion and streams
//!
//! `NotifyPointerMotionAbsolute` addresses a *stream* (PipeWire node id).
//! When the session selected sources (v2 `SelectSources`), the granted
//! stream's `position`/`size` map global coordinates into stream-local
//! space — this is what GNOME/KDE need. Input-only sessions (v1, or a
//! backend that skipped `SelectSources`) get no streams; we then pass
//! [`NO_STREAM`] (`u32::MAX`) with global coordinates, which the wlr/
//! hyprland family treats as whole-session space. A backend that rejects
//! it answers with a D-Bus error → one reconnect attempt → surfaced as
//! `InputInjectionFailed`.
//!
//! ## What is deliberately not done
//!
//! - **No PipeWire consumer**: granted streams carry live pixels we never
//!   read. `SelectSources` exists solely to obtain output geometry for
//!   absolute positioning; the video fd is dropped, unopened.
//! - **No `NotifyKeyboardKeysym`/text input**: keys go out as evdev
//!   keycodes resolved against the fixed US-layout table shared with
//!   `uinput_input` (portal sessions have no keymap channel).
//! - **No clipboard/touch devices**: `types = pointer|keyboard` only.
//!
//! SAFETY: unit tests never create a session — `CreateSession`/`Start`
//! raise GUI consent dialogs on the live desktop. Tests cover the pure
//! mapping/parsing halves only.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use atspi::zbus::{self, proxy::Builder, proxy::CacheProperties, zvariant};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::traits::InputProvider;

use super::portal_capture::{
    Options, PORTAL_BUS_NAME, PORTAL_DESKTOP_PATH, await_response, get_string, get_u32,
    new_handle_token, portal_call, portal_name_owned, response_stream,
};

/// `org.freedesktop.portal.RemoteDesktop` interface on the portal object.
const REMOTE_DESKTOP_IFACE: &str = "org.freedesktop.portal.RemoteDesktop";

/// `SelectDevices` `types` bitmask: keyboard(1) | pointer(2). (4 would be
/// touchscreen — unused.)
const DEVICE_TYPES: u32 = 0b011;

/// `SelectSources` `types` bitmask: monitor(1) only.
const SOURCE_MONITOR: u32 = 1;

/// `cursor_mode`: hidden(1) — we never composite a cursor into the stream
/// (the stream itself is never consumed).
const CURSOR_HIDDEN: u32 = 1;

/// `stream` argument for `NotifyPointerMotionAbsolute` when the session
/// granted no sources: `u32::MAX`, the whole-session convention used by
/// the wlr/hyprland portal family.
const NO_STREAM: u32 = u32::MAX;

/// evdev axis selector for `NotifyPointerAxisDiscrete`: 0 = vertical,
/// 1 = horizontal.
const AXIS_VERTICAL: u32 = 0;
const AXIS_HORIZONTAL: u32 = 1;

/// Borrowed-session future used by [`PortalInput::with_session`].
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// XDG portal `RemoteDesktop` backend for [`InputProvider`].
pub struct PortalInput {
    /// Session bus, bound to the ambient runtime on first use.
    conn: tokio::sync::OnceCell<zbus::Connection>,
    /// Live portal session; `None` until first call and after a failed
    /// call tore it down (reconnect-once in [`Self::with_session`]).
    session: tokio::sync::Mutex<Option<Session>>,
    /// Bookkeeping that survives session reconnects: last emitted
    /// absolute position (cursor fallback) and sub-detent wheel
    /// remainders.
    pointer: Mutex<PointerState>,
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction — the `cursor_position` fallback (S-1).
    hyprctl: Option<PathBuf>,
}

/// Compile-time contract: `InputProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PortalInput>();
};

/// A live `RemoteDesktop` session on the portal object.
struct Session {
    /// `org.freedesktop.portal.RemoteDesktop` proxy (methods are invoked
    /// with the session handle as their first argument).
    proxy: zbus::Proxy<'static>,
    /// Object path of the `org.freedesktop.portal.Session` object.
    path: OwnedObjectPath,
    /// Streams granted by `Start` — empty for input-only sessions.
    streams: Vec<Stream>,
}

/// One granted source stream: PipeWire node id + logical desktop rect
/// (`position`/`size` dict entries, portal v2+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stream {
    node_id: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

#[derive(Default)]
struct PointerState {
    last_pos: Option<(i32, i32)>,
    wheel_acc: f64,
    hwheel_acc: f64,
}

// ---------------------------------------------------------------------------
// Options builders (pure — unit-tested)
// ---------------------------------------------------------------------------

fn base_options(token: String) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(token));
    o
}

fn create_session_options(handle_token: String, session_token: String) -> Options {
    let mut o = base_options(handle_token);
    o.insert("session_handle_token", Value::new(session_token));
    o
}

/// `SelectDevices` options — never carries `persist_mode` or
/// `restore_token`: restore credentials are not requested, stored, or
/// replayed, so every `Start` re-consents (module docs).
fn select_devices_options(handle_token: String) -> Options {
    let mut o = base_options(handle_token);
    o.insert("types", Value::new(DEVICE_TYPES));
    o
}

fn select_sources_options(handle_token: String) -> Options {
    let mut o = base_options(handle_token);
    o.insert("types", Value::new(SOURCE_MONITOR));
    o.insert("multiple", Value::new(false));
    o.insert("cursor_mode", Value::new(CURSOR_HIDDEN));
    o
}

fn empty_options() -> Options {
    Options::new()
}

// ---------------------------------------------------------------------------
// Response parsing (pure halves)
// ---------------------------------------------------------------------------

/// `session_handle` from a `CreateSession` response: spec type `s`, but
/// accept `o` too (some backends return an object path variant).
fn session_path_from(results: &HashMap<String, OwnedValue>) -> Result<OwnedObjectPath> {
    if let Ok(s) = get_string(results, "session_handle") {
        return OwnedObjectPath::try_from(s).context("session_handle is not an object path");
    }
    let v = results
        .get("session_handle")
        .ok_or_else(|| anyhow!("CreateSession response missing session_handle"))?;
    OwnedObjectPath::try_from(v.try_clone().context("clone session_handle")?)
        .context("session_handle is neither s nor o")
}

/// One stream entry (`{node_id: u, position: (ii), size: (ii), …}`) of
/// the `aa{sv}` `streams` result.
fn parse_stream(dict: &HashMap<String, OwnedValue>) -> Option<Stream> {
    let node_id = u32::try_from(dict.get("node_id")?).ok()?;
    let (x, y) = pair_i32(dict.get("position")).unwrap_or((0, 0));
    let (w, h) = pair_i32(dict.get("size")).unwrap_or((0, 0));
    Some(Stream {
        node_id,
        x,
        y,
        w,
        h,
    })
}

/// `(ii)`/`(uu)` variant → integer pair, via `Structure` fields.
fn pair_i32(v: Option<&OwnedValue>) -> Option<(i32, i32)> {
    let st: &zvariant::Structure = v?.try_into().ok()?;
    let f = st.fields();
    if f.len() < 2 {
        return None;
    }
    let a = i32::try_from(&f[0]).ok()?;
    let b = i32::try_from(&f[1]).ok()?;
    Some((a, b))
}

/// Parse the `streams` entry of a `Start` response (absent for
/// input-only sessions).
fn parse_streams(results: &HashMap<String, OwnedValue>) -> Vec<Stream> {
    let dicts = results
        .get("streams")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<HashMap<String, OwnedValue>>::try_from(v).ok())
        .unwrap_or_default();
    dicts.iter().filter_map(parse_stream).collect()
}

/// Map global `(x, y)` into `stream`'s PipeWire node id + stream-local
/// coordinates. With no streams: [`NO_STREAM`] + global coords (see
/// module docs). With streams: the stream whose rect contains the point,
/// else the first stream with the point clamped into it.
fn absolute_target(streams: &[Stream], x: i32, y: i32) -> (u32, f64, f64) {
    let Some(first) = streams.first() else {
        return (NO_STREAM, f64::from(x), f64::from(y));
    };
    let s = streams
        .iter()
        .find(|s| s.w > 0 && s.h > 0 && x >= s.x && y >= s.y && x < s.x + s.w && y < s.y + s.h)
        .unwrap_or(first);
    // Streams without geometry report (0,0,0,0) — identity mapping.
    if s.w <= 0 || s.h <= 0 {
        return (s.node_id, f64::from(x), f64::from(y));
    }
    (
        s.node_id,
        f64::from((x - s.x).clamp(0, s.w - 1)),
        f64::from((y - s.y).clamp(0, s.h - 1)),
    )
}

// ---------------------------------------------------------------------------
// Key/button tables — parity with uinput_input.rs (canonical copy).
// Duplicated here because the portal rung is display-protocol agnostic
// exactly like uinput: no keymap channel, fixed US-layout evdev codes.
// ---------------------------------------------------------------------------

/// Normalize a key/button name: lowercase, drop `_`, `-` and spaces.
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A resolved key: evdev keycode plus whether `Shift` must be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyBinding {
    code: u16,
    shifted: bool,
}

const KEY_LEFTSHIFT: i32 = 42;

/// evdev button code for a button name (`linux/input-event-codes.h`).
fn button_code(name: &str) -> Option<i32> {
    Some(match normalize_name(name).as_str() {
        "left" | "lmb" => 0x110,     // BTN_LEFT
        "right" | "rmb" => 0x111,    // BTN_RIGHT
        "middle" | "mmb" => 0x112,   // BTN_MIDDLE
        "side" | "thumb" => 0x113,   // BTN_SIDE
        "extra" | "thumb2" => 0x114, // BTN_EXTRA
        "forward" | "fwd" => 0x115,  // BTN_FORWARD
        "back" => 0x116,             // BTN_BACK
        "task" => 0x117,             // BTN_TASK
        _ => return None,
    })
}

/// evdev code for a letter key, `'a'..='z'`.
fn letter_code(c: char) -> u16 {
    match c {
        'q' => 16,
        'w' => 17,
        'e' => 18,
        'r' => 19,
        't' => 20,
        'y' => 21,
        'u' => 22,
        'i' => 23,
        'o' => 24,
        'p' => 25,
        'a' => 30,
        's' => 31,
        'd' => 32,
        'f' => 33,
        'g' => 34,
        'h' => 35,
        'j' => 36,
        'k' => 37,
        'l' => 38,
        'z' => 44,
        'x' => 45,
        'c' => 46,
        'v' => 47,
        'b' => 48,
        'n' => 49,
        'm' => 50,
        _ => unreachable!("letter_code called with non-letter"),
    }
}

/// evdev code for a row digit `'0'..='9'`.
fn digit_code(c: char) -> u16 {
    match c {
        '0' => 11,
        '1'..='9' => 1 + (c as u16 - '0' as u16), // KEY_1 = 2
        _ => unreachable!("digit_code called with non-digit"),
    }
}

/// Multi-character key names → evdev codes (input normalized already).
fn named_key_code(n: &str) -> Option<u16> {
    Some(match n {
        "esc" | "escape" => 1,                                   // KEY_ESC
        "backspace" | "bksp" | "bs" => 14,                       // KEY_BACKSPACE
        "tab" => 15,                                             // KEY_TAB
        "enter" | "return" | "ret" | "newline" => 28,            // KEY_ENTER
        "ctrl" | "control" | "ctl" | "lctrl" | "leftctrl" => 29, // KEY_LEFTCTRL
        "shift" | "lshift" | "leftshift" => 42,                  // KEY_LEFTSHIFT
        "rshift" | "rightshift" => 54,                           // KEY_RIGHTSHIFT
        "kpasterisk" | "kpmultiply" | "multiply" => 55,          // KEY_KPASTERISK
        "alt" | "lalt" | "leftalt" => 56,                        // KEY_LEFTALT
        "space" | "spc" | "spacebar" => 57,                      // KEY_SPACE
        "caps" | "capslock" => 58,                               // KEY_CAPSLOCK
        "numlock" => 69,                                         // KEY_NUMLOCK
        "scrolllock" => 70,                                      // KEY_SCROLLLOCK
        "kpminus" | "kpsubtract" | "subtract" => 74,             // KEY_KPMINUS
        "kpplus" | "kpadd" | "add" => 78,                        // KEY_KPPLUS
        "kpdot" | "kpdecimal" | "kpperiod" => 83,                // KEY_KPDOT
        "kpenter" | "numpadenter" => 96,                         // KEY_KPENTER
        "rctrl" | "rightctrl" => 97,                             // KEY_RIGHTCTRL
        "kpslash" | "kpdivide" | "divide" => 98,                 // KEY_KPSLASH
        "printscreen" | "prtsc" | "sysrq" | "print" => 99,       // KEY_SYSRQ
        "ralt" | "rightalt" | "altgr" => 100,                    // KEY_RIGHTALT
        "home" => 102,                                           // KEY_HOME
        "up" | "uparrow" | "arrowup" => 103,                     // KEY_UP
        "pageup" | "pgup" => 104,                                // KEY_PAGEUP
        "left" | "leftarrow" | "arrowleft" => 105,               // KEY_LEFT
        "right" | "rightarrow" | "arrowright" => 106,            // KEY_RIGHT
        "end" => 107,                                            // KEY_END
        "down" | "downarrow" | "arrowdown" => 108,               // KEY_DOWN
        "pagedown" | "pgdown" | "pgdn" => 109,                   // KEY_PAGEDOWN
        "insert" | "ins" => 110,                                 // KEY_INSERT
        "delete" | "del" => 111,                                 // KEY_DELETE
        "mute" | "audiomute" => 113,                             // KEY_MUTE
        "volumedown" | "voldown" | "audiolowervolume" => 114,    // KEY_VOLUMEDOWN
        "volumeup" | "volup" | "audioraisevolume" => 115,        // KEY_VOLUMEUP
        "power" => 116,                                          // KEY_POWER
        "kpequal" => 117,                                        // KEY_KPEQUAL
        "pause" | "break" => 119,                                // KEY_PAUSE
        "kpcomma" => 121,                                        // KEY_KPCOMMA
        "super" | "win" | "cmd" | "meta" | "lsuper" | "leftsuper" | "lmeta" | "leftmeta" => 125, // KEY_LEFTMETA
        "rsuper" | "rightsuper" | "rmeta" | "rightmeta" => 126, // KEY_RIGHTMETA
        "compose" => 127,                                       // KEY_COMPOSE
        "menu" | "appmenu" | "apps" => 139,                     // KEY_MENU
        "browserback" | "acback" => 158,                        // KEY_BACK
        "browserforward" | "acforward" => 159,                  // KEY_FORWARD
        "nextsong" | "nexttrack" | "audionext" => 163,          // KEY_NEXTSONG
        "playpause" | "play" | "audioplay" => 164,              // KEY_PLAYPAUSE
        "previoussong" | "prevtrack" | "audioprev" => 165,      // KEY_PREVIOUSSONG
        "stopcd" | "mediastop" => 166,                          // KEY_STOPCD
        "homepage" | "www" | "browser" => 172,                  // KEY_HOMEPAGE
        "refresh" | "reload" => 173,                            // KEY_REFRESH
        "search" => 217,                                        // KEY_SEARCH
        "kp0" | "numpad0" => 82,
        "kp1" | "numpad1" => 79,
        "kp2" | "numpad2" => 80,
        "kp3" | "numpad3" => 81,
        "kp4" | "numpad4" => 75,
        "kp5" | "numpad5" => 76,
        "kp6" | "numpad6" => 77,
        "kp7" | "numpad7" => 71,
        "kp8" | "numpad8" => 72,
        "kp9" | "numpad9" => 73,
        "kpleftparen" => 179,  // KEY_KPLEFTPAREN
        "kprightparen" => 180, // KEY_KPRIGHTPAREN
        _ => return None,
    })
}

/// `F1`–`F24` → KEY_F1(59)..F10(68), F11(87), F12(88), F13(183)..F24(194).
fn fn_key_code(n: &str) -> Option<u16> {
    let f: u16 = n.strip_prefix('f')?.parse().ok()?;
    Some(match f {
        1..=10 => 58 + f,
        11 | 12 => 76 + f,
        13..=24 => 170 + f,
        _ => return None,
    })
}

/// KeyBinding for a literal character on a US-layout assumption;
/// `\n`/`\r` → Enter, `\t` → Tab, non-ASCII has no binding.
fn char_binding(c: char) -> Option<KeyBinding> {
    let (code, shifted) = match c {
        'a'..='z' => (letter_code(c), false),
        'A'..='Z' => (letter_code(c.to_ascii_lowercase()), true),
        '0'..='9' => (digit_code(c), false),
        '\n' | '\r' => (28, false), // KEY_ENTER
        '\t' => (15, false),        // KEY_TAB
        ' ' => (57, false),         // KEY_SPACE
        '-' => (12, false),
        '_' => (12, true), // KEY_MINUS
        '=' => (13, false),
        '+' => (13, true), // KEY_EQUAL
        '[' => (26, false),
        '{' => (26, true), // KEY_LEFTBRACE
        ']' => (27, false),
        '}' => (27, true), // KEY_RIGHTBRACE
        ';' => (39, false),
        ':' => (39, true), // KEY_SEMICOLON
        '\'' => (40, false),
        '"' => (40, true), // KEY_APOSTROPHE
        '`' => (41, false),
        '~' => (41, true), // KEY_GRAVE
        '\\' => (43, false),
        '|' => (43, true), // KEY_BACKSLASH
        ',' => (51, false),
        '<' => (51, true), // KEY_COMMA
        '.' => (52, false),
        '>' => (52, true), // KEY_DOT
        '/' => (53, false),
        '?' => (53, true), // KEY_SLASH
        '!' => (2, true),
        '@' => (3, true),
        '#' => (4, true),
        '$' => (5, true),
        '%' => (6, true),
        '^' => (7, true),
        '&' => (8, true),
        '*' => (9, true),
        '(' => (10, true),
        ')' => (11, true),
        _ => return None,
    };
    Some(KeyBinding { code, shifted })
}

/// Resolve a key name to a binding: single chars carry case/shift state,
/// multi-char names hit the normalized table then the F-key range.
fn key_binding(name: &str) -> Option<KeyBinding> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if let Some(b) = char_binding(c) {
            return Some(b);
        }
    }
    let n = normalize_name(name);
    named_key_code(&n)
        .or_else(|| fn_key_code(&n))
        .map(|code| KeyBinding {
            code,
            shifted: false,
        })
}

/// Split a wheel delta into whole detents, carrying the sub-detent
/// remainder across calls via `acc`.
fn detents(delta: f64, acc: &mut f64) -> i32 {
    *acc += delta;
    let steps = acc.round() as i32;
    *acc -= f64::from(steps);
    steps
}

// ---------------------------------------------------------------------------
// hyprctl cursor fallback (no portal read channel exists)
// ---------------------------------------------------------------------------

fn parse_cursorpos(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        let x = v.get("x")?.as_i64()?;
        let y = v.get("y")?.as_i64()?;
        return Some((x as i32, y as i32));
    }
    let (xs, ys) = t.split_once(',')?;
    Some((xs.trim().parse().ok()?, ys.trim().parse().ok()?))
}

/// Pinned `hyprctl -j cursorpos`, scrubbed env, bounded wait.
async fn hyprctl_cursorpos(bin: &Path) -> Result<(i32, i32)> {
    let mut cmd = crate::security::spawn::command(bin, &["-j", "cursorpos"]);
    let out =
        crate::security::spawn::output_within(&mut cmd, crate::security::spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("run hyprctl cursorpos")?;
    if !out.status.success() {
        bail!("hyprctl cursorpos exited {}", out.status);
    }
    parse_cursorpos(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| anyhow!("unparseable hyprctl cursorpos output"))
}

// ---------------------------------------------------------------------------
// PortalInput
// ---------------------------------------------------------------------------

impl PortalInput {
    /// Probe only: `Some` when the session bus is up and
    /// `org.freedesktop.portal.Desktop` is owned. No portal method is
    /// invoked — the session (and its consent dialog) starts lazily on
    /// the first input call.
    pub fn new() -> Option<Self> {
        if !portal_name_owned() {
            tracing::debug!("portal input: org.freedesktop.portal.Desktop not owned");
            return None;
        }
        Some(Self {
            conn: tokio::sync::OnceCell::new(),
            session: tokio::sync::Mutex::new(None),
            pointer: Mutex::new(PointerState::default()),
            hyprctl: crate::security::whitelist::resolve_binaries()
                .get("hyprctl")
                .map(Path::to_path_buf),
        })
    }

    async fn conn(&self) -> Result<&zbus::Connection> {
        self.conn
            .get_or_try_init(|| async {
                portal_call(zbus::Connection::session())
                    .await
                    .context("session bus connect failed")
            })
            .await
    }

    /// Run `op` against the live session, establishing it on demand. On
    /// op failure the session is dropped and rebuilt **once** — covering
    /// revoked sessions and portal restarts without an error loop. The
    /// session mutex serializes every call, so one consent flow is ever
    /// in flight.
    async fn with_session<F, R>(&self, op: F) -> Result<R>
    where
        F: for<'s> Fn(&'s Session) -> BoxFut<'s, R>,
    {
        let conn = self.conn().await?;
        let mut guard = self.session.lock().await;
        if guard.is_none() {
            *guard = Some(self.start_session(conn).await?);
        }
        let session = guard.as_ref().expect("session just established");
        match op(session).await {
            Ok(v) => Ok(v),
            Err(first) => {
                tracing::warn!(
                    "portal input session call failed ({first:#}); re-establishing once"
                );
                *guard = None;
                let session = self.start_session(conn).await?;
                let result = op(&session).await;
                *guard = Some(session);
                result
            }
        }
    }

    /// Interface `version` property (v2 adds `SelectSources`). Tries the
    /// modern `version` name then the legacy `AvailableVersion`;
    /// unreadable/timed-out → `1` (conservative).
    async fn interface_version(proxy: &zbus::Proxy<'_>) -> u32 {
        if let Ok(v) = portal_call(proxy.get_property::<u32>("version")).await {
            return v;
        }
        portal_call(proxy.get_property::<u32>("AvailableVersion"))
            .await
            .unwrap_or(1)
    }

    /// `CreateSession → SelectDevices → SelectSources? → Start` — see
    /// module docs for the consent story. `Start` is where the consent
    /// dialog lives; it is re-run on every establishment — no
    /// `persist_mode`/`restore_token` is ever sent or stored.
    async fn start_session(&self, conn: &zbus::Connection) -> Result<Session> {
        let proxy = portal_call(
            Builder::<zbus::Proxy>::new(conn)
                .destination(PORTAL_BUS_NAME)
                .map_err(|e| anyhow!("portal proxy destination: {e}"))?
                .path(PORTAL_DESKTOP_PATH)
                .map_err(|e| anyhow!("portal proxy path: {e}"))?
                .interface(REMOTE_DESKTOP_IFACE)
                .map_err(|e| anyhow!("portal proxy interface: {e}"))?
                .cache_properties(CacheProperties::No)
                .build(),
        )
        .await
        .context("build RemoteDesktop proxy")?;

        // One signal subscription covers every request in the handshake
        // (each is matched on its returned request path).
        let mut responses = response_stream(conn).await?;

        // SelectSources exists at interface version ≥ 2.
        let has_sources = Self::interface_version(&proxy).await >= 2;

        // CreateSession(a{sv}) → request → Response{session_handle}
        let opts = create_session_options(new_handle_token(), new_handle_token());
        let req: OwnedObjectPath = portal_call(proxy.call("CreateSession", &(&opts,)))
            .await
            .context("portal CreateSession call")?;
        let results = await_response(&mut responses, &req).await?;
        let session_path = session_path_from(&results)?;

        // SelectDevices(o, a{sv}) — pointer + keyboard.
        let opts = select_devices_options(new_handle_token());
        let req: OwnedObjectPath =
            portal_call(proxy.call("SelectDevices", &(&session_path, &opts)))
                .await
                .context("portal SelectDevices call")?;
        await_response(&mut responses, &req).await?;

        // SelectSources(o, a{sv}) — v2+, best-effort. One monitor source
        // gives `Start` a stream whose geometry anchors absolute pointer
        // motion (GNOME/KDE require it). Backends without source support
        // keep running streamless.
        if has_sources {
            let opts = select_sources_options(new_handle_token());
            match portal_call(
                proxy.call::<_, _, OwnedObjectPath>("SelectSources", &(&session_path, &opts)),
            )
            .await
            {
                Ok(req) => {
                    if let Err(e) = await_response(&mut responses, &req).await {
                        tracing::warn!(
                            "portal SelectSources declined ({e:#}); continuing streamless"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "portal SelectSources call failed ({e:#}); continuing streamless"
                    );
                }
            }
        }

        // Start(o, s parent_window, a{sv}) — this is where the consent
        // dialog lives; may block until the user answers. A
        // `restore_token` in the response is deliberately ignored —
        // persistence is off by policy (module docs).
        let opts = base_options(new_handle_token());
        let req: OwnedObjectPath = portal_call(proxy.call("Start", &(&session_path, "", &opts)))
            .await
            .context("portal Start call")?;
        let results = await_response(&mut responses, &req).await?;

        let granted = get_u32(&results, "devices").unwrap_or(0);
        let streams = parse_streams(&results);
        tracing::info!(
            devices = granted,
            streams = streams.len(),
            has_sources,
            "portal remote-desktop session started"
        );
        Ok(Session {
            proxy,
            path: session_path,
            streams,
        })
    }

    /// `NotifyPointerMotionAbsolute(o, a{sv}, u stream, d x, d y)`.
    async fn move_to(&self, x: i32, y: i32) -> Result<()> {
        let (px, py) = (x.max(0), y.max(0));
        self.with_session(|s| {
            let (node, lx, ly) = absolute_target(&s.streams, px, py);
            Box::pin(async move {
                portal_call(s.proxy.call::<_, _, ()>(
                    "NotifyPointerMotionAbsolute",
                    &(&s.path, &empty_options(), node, lx, ly),
                ))
                .await
                .context("portal NotifyPointerMotionAbsolute")
            })
        })
        .await?;
        self.pointer.lock().expect("portal_input poisoned").last_pos = Some((px, py));
        Ok(())
    }

    /// `NotifyPointerButton(o, a{sv}, i button, u state)`.
    async fn emit_button(&self, code: i32, down: bool) -> Result<()> {
        self.with_session(|s| {
            Box::pin(async move {
                portal_call(s.proxy.call::<_, _, ()>(
                    "NotifyPointerButton",
                    &(&s.path, &empty_options(), code, u32::from(down)),
                ))
                .await
                .context("portal NotifyPointerButton")
            })
        })
        .await
    }

    /// Press or release one key binding; a level-1 (shifted) binding
    /// wraps the key in a `KEY_LEFTSHIFT` hold (US-layout table, parity
    /// with `uinput_input::emit_key`).
    async fn emit_key(&self, binding: KeyBinding, down: bool) -> Result<()> {
        self.with_session(|s| {
            Box::pin(async move {
                if binding.shifted {
                    if down {
                        notify_keycode(s, KEY_LEFTSHIFT, true).await?;
                        notify_keycode(s, i32::from(binding.code), true).await?;
                    } else {
                        notify_keycode(s, i32::from(binding.code), false).await?;
                        notify_keycode(s, KEY_LEFTSHIFT, false).await?;
                    }
                } else {
                    notify_keycode(s, i32::from(binding.code), down).await?;
                }
                Ok(())
            })
        })
        .await
    }
}

/// `NotifyKeyboardKeycode(o, a{sv}, i keycode, u state)` — one press or
/// release of `code` on `s`.
async fn notify_keycode(s: &Session, code: i32, down: bool) -> Result<()> {
    portal_call(s.proxy.call::<_, _, ()>(
        "NotifyKeyboardKeycode",
        &(&s.path, &empty_options(), code, u32::from(down)),
    ))
    .await
    .context("portal NotifyKeyboardKeycode")
}

// ---------------------------------------------------------------------------
// InputProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl InputProvider for PortalInput {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()> {
        self.move_to(x, y).await
    }

    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()> {
        // Validate before moving — a bad name never repositions the
        // pointer (same ordering as wlr_input/uinput_input).
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        self.move_to(x, y).await?;
        self.emit_button(code, true).await?;
        self.emit_button(code, false).await
    }

    async fn mouse_button(&self, button: &str, down: bool) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        self.emit_button(code, down).await
    }

    /// `dx`/`dy` are wheel steps; positive scrolls right/down —
    /// `NotifyPointerAxisDiscrete` shares that sign convention (unlike
    /// evdev `REL_WHEEL`), so no inversion is needed. Sub-detent
    /// remainders accumulate across calls.
    async fn scroll(&self, dx: f64, dy: f64) -> Result<()> {
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let (v, h) = {
            let mut p = self.pointer.lock().expect("portal_input poisoned");
            (
                detents(dy, &mut p.wheel_acc),
                detents(dx, &mut p.hwheel_acc),
            )
        };
        if v != 0 {
            self.with_session(|s| {
                Box::pin(async move {
                    portal_call(s.proxy.call::<_, _, ()>(
                        "NotifyPointerAxisDiscrete",
                        &(&s.path, &empty_options(), AXIS_VERTICAL, v),
                    ))
                    .await
                    .context("portal NotifyPointerAxisDiscrete")
                })
            })
            .await?;
        }
        if h != 0 {
            self.with_session(|s| {
                Box::pin(async move {
                    portal_call(s.proxy.call::<_, _, ()>(
                        "NotifyPointerAxisDiscrete",
                        &(&s.path, &empty_options(), AXIS_HORIZONTAL, h),
                    ))
                    .await
                    .context("portal NotifyPointerAxisDiscrete")
                })
            })
            .await?;
        }
        Ok(())
    }

    async fn key_event(&self, key: &str, down: bool) -> Result<()> {
        let binding = key_binding(key).ok_or_else(|| anyhow!("unknown key name {key:?}"))?;
        self.emit_key(binding, down).await
    }

    /// Resolve every character *before* emitting, so an unbindable char
    /// can never leave a half-typed prefix behind (parity with
    /// `uinput_input::type_text`).
    async fn type_text(&self, text: &str) -> Result<()> {
        let mut seq = Vec::with_capacity(text.len());
        for c in text.chars() {
            seq.push(char_binding(c).ok_or_else(|| anyhow!("no evdev key binding for {c:?}"))?);
        }
        for b in seq {
            self.emit_key(b, true).await?;
            self.emit_key(b, false).await?;
        }
        Ok(())
    }

    /// No portal read channel: live `hyprctl cursorpos` first, then the
    /// last absolute position this provider emitted.
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        if let Some(bin) = &self.hyprctl
            && let Ok(pos) = hyprctl_cursorpos(bin).await
        {
            return Ok(pos);
        }
        self.pointer
            .lock()
            .expect("portal_input poisoned")
            .last_pos
            .ok_or_else(|| anyhow!("cursor position unknown (portal input has no read channel)"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: no test in this module opens a portal session or calls a
// portal method — `CreateSession`/`Start` raise GUI consent dialogs on a
// live desktop. Covered: key/button tables, option builders, response
// parsing, stream mapping, wheel detents, and the read-only
// name-ownership probe.

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(v: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(v.into()).unwrap()
    }

    // ---- tables -------------------------------------------------------

    #[test]
    fn button_code_maps_mouse_buttons() {
        assert_eq!(button_code("left"), Some(0x110));
        assert_eq!(button_code("right"), Some(0x111));
        assert_eq!(button_code("middle"), Some(0x112));
        assert_eq!(button_code("LEFT"), Some(0x110));
        assert_eq!(button_code("back"), Some(0x116));
        assert_eq!(button_code("forward"), Some(0x115));
        assert_eq!(button_code("side"), Some(0x113));
        assert_eq!(button_code("primary"), None);
        assert_eq!(button_code(""), None);
    }

    #[test]
    fn named_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("enter"), Some(28));
        assert_eq!(code("escape"), Some(1));
        assert_eq!(code("ctrl"), Some(29));
        assert_eq!(code("rightctrl"), Some(97));
        assert_eq!(code("super"), Some(125));
        assert_eq!(code("pageup"), Some(104));
        assert_eq!(code("Page_Up"), Some(104));
        assert_eq!(code("delete"), Some(111));
        assert_eq!(code("f1"), Some(59));
        assert_eq!(code("F12"), Some(88));
        assert_eq!(code("f25"), None);
        assert_eq!(code("definitely-not-a-key"), None);
        assert_eq!(code(""), None);
    }

    #[test]
    fn single_chars_carry_shift_state() {
        assert_eq!(
            key_binding("A"),
            Some(KeyBinding {
                code: 30,
                shifted: true
            })
        );
        assert_eq!(
            key_binding("a"),
            Some(KeyBinding {
                code: 30,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("!"),
            Some(KeyBinding {
                code: 2,
                shifted: true
            })
        );
        assert_eq!(
            char_binding('\n'),
            Some(KeyBinding {
                code: 28,
                shifted: false
            })
        );
        assert_eq!(char_binding('é'), None);
    }

    #[test]
    fn detents_carry_sub_step_remainder() {
        let mut acc = 0.0;
        assert_eq!(detents(0.4, &mut acc), 0);
        assert_eq!(detents(0.4, &mut acc), 1);
        assert_eq!(detents(-3.0, &mut acc), -3);
    }

    // ---- options builders ----------------------------------------------

    #[test]
    fn create_session_options_carry_both_tokens() {
        let o = create_session_options("h".into(), "s".into());
        assert!(matches!(o["handle_token"], Value::Str(_)));
        assert!(matches!(o["session_handle_token"], Value::Str(_)));
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn select_devices_options_pointer_keyboard() {
        let o = select_devices_options("h".into());
        assert!(matches!(o["types"], Value::U32(3)));
        // Restore credentials are never requested: every `Start`
        // re-consents (module docs — no persist_mode, no restore_token).
        assert!(!o.contains_key("persist_mode"));
        assert!(!o.contains_key("restore_token"));
    }

    #[test]
    fn select_sources_options_monitor_only() {
        let o = select_sources_options("h".into());
        assert!(matches!(o["types"], Value::U32(1)));
        assert!(matches!(o["multiple"], Value::Bool(false)));
        assert!(matches!(o["cursor_mode"], Value::U32(1)));
        assert!(!o.contains_key("persist_mode"));
        assert!(!o.contains_key("restore_token"));
    }

    // ---- response parsing -----------------------------------------------

    #[test]
    fn session_path_from_s_and_o() {
        let mut r: HashMap<String, OwnedValue> = HashMap::new();
        r.insert(
            "session_handle".into(),
            owned("/org/freedesktop/portal/desktop/session/1_2/tok"),
        );
        let p = session_path_from(&r).unwrap();
        assert_eq!(
            p.as_str(),
            "/org/freedesktop/portal/desktop/session/1_2/tok"
        );

        r.insert(
            "session_handle".into(),
            owned(
                zvariant::ObjectPath::try_from("/org/freedesktop/portal/desktop/session/1_2/tok")
                    .unwrap(),
            ),
        );
        assert!(session_path_from(&r).is_ok());

        assert!(session_path_from(&HashMap::new()).is_err());
        let mut bad: HashMap<String, OwnedValue> = HashMap::new();
        bad.insert("session_handle".into(), owned(42u32));
        assert!(session_path_from(&bad).is_err());
    }

    #[test]
    fn parse_streams_reads_geometry() {
        // One stream dict as the portal sends it: node_id u, position
        // (ii), size (ii).
        let mut s: HashMap<String, OwnedValue> = HashMap::new();
        s.insert("node_id".into(), owned(55u32));
        s.insert(
            "position".into(),
            owned(zvariant::Structure::from((1920i32, 0i32))),
        );
        s.insert(
            "size".into(),
            owned(zvariant::Structure::from((2560i32, 1440i32))),
        );
        let mut results: HashMap<String, OwnedValue> = HashMap::new();
        results.insert("streams".into(), owned(vec![s]));

        let streams = parse_streams(&results);
        assert_eq!(streams.len(), 1);
        assert_eq!(
            streams[0],
            Stream {
                node_id: 55,
                x: 1920,
                y: 0,
                w: 2560,
                h: 1440
            }
        );

        // Missing/empty → none.
        assert!(parse_streams(&HashMap::new()).is_empty());
    }

    // ---- stream → coordinate mapping ------------------------------------

    #[test]
    fn absolute_target_without_streams_uses_no_stream() {
        let (node, x, y) = absolute_target(&[], 640, 480);
        assert_eq!(node, NO_STREAM);
        assert_eq!((x, y), (640.0, 480.0));
    }

    #[test]
    fn absolute_target_maps_into_containing_stream() {
        let streams = vec![
            Stream {
                node_id: 10,
                x: 0,
                y: 0,
                w: 1920,
                h: 1080,
            },
            Stream {
                node_id: 11,
                x: 1920,
                y: 0,
                w: 2560,
                h: 1440,
            },
        ];
        // Point on the second output → stream-local coords.
        let (node, x, y) = absolute_target(&streams, 2000, 100);
        assert_eq!(node, 11);
        assert_eq!((x, y), (80.0, 100.0));
        // Point on the first output.
        let (node, x, y) = absolute_target(&streams, 5, 5);
        assert_eq!(node, 10);
        assert_eq!((x, y), (5.0, 5.0));
        // Point outside all → first stream, clamped.
        let (node, x, y) = absolute_target(&streams, 9000, 9000);
        assert_eq!(node, 10);
        assert_eq!((x, y), (1919.0, 1079.0));
    }

    #[test]
    fn absolute_target_streamless_geometry_is_identity() {
        // Backend reports a node id but no position/size (0,0,0,0):
        // coordinates pass through unchanged.
        let streams = vec![Stream {
            node_id: 7,
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }];
        let (node, x, y) = absolute_target(&streams, 123, 456);
        assert_eq!(node, 7);
        assert_eq!((x, y), (123.0, 456.0));
    }

    // ---- cursor / probe ---------------------------------------------------

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1,\"y\":2}"), Some((1, 2)));
        assert_eq!(parse_cursorpos("3, 4"), Some((3, 4)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn new_probe_is_bounded_and_pure() {
        // Only session-bus NameHasOwner — no session, no dialog.
        let _ = PortalInput::new();
    }

    #[test]
    #[ignore = "requires a live session bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    fn live_probe_matches_name_owner() {
        if std::env::var("ULTRANIX_MCP_LIVE_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        // Probe only — deliberately NOT calling any InputProvider method:
        // the first call would trigger Start → GUI consent dialog.
        let p = PortalInput::new();
        tracing::info!("portal input probe: {:?}", p.is_some());
    }
}
