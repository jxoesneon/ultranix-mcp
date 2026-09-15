//! Kernel-level input injection via `/dev/uinput` — rung two of the input
//! fallback ladder (wlr virtual input → uinput → portal).
//!
//! Unlike [`super::wlr_input`], this backend is display-protocol agnostic:
//! the virtual device it creates injects `input_event`s straight into the
//! kernel input layer, so it works under Wayland, X11 and even the
//! framebuffer console. The trade-off is that there is no compositor-side
//! context — no keymap, no read channel for the cursor, and no output
//! layout. Specifically:
//!
//! - `mouse_move` is *absolute*: `EV_ABS`/`ABS_X`/`ABS_Y` are registered at
//!   device-creation time with range `0..=width` / `0..=height`, and
//!   libinput/compositors map that rectangle onto the desktop. Bounds come
//!   from `ULTRANIX_SCREEN_SIZE` (`"WxH"`), else
//!   `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT`, else
//!   `hyprctl -j monitors` (best effort), else `1920x1080`.
//!   [`UinputInput::with_screen_size`] forces the bounds explicitly.
//! - `type_text`/`key_event` resolve names and characters against a fixed
//!   evdev (US-layout) code table — there is no xkb keymap at this level.
//!   Characters without a binding fail *before* any event is emitted, so a
//!   bad string can never leave a half-typed prefix behind.
//! - `cursor_position` tries `hyprctl` first (live on Hyprland), then falls
//!   back to the last absolute position this provider emitted.
//!
//! ## Permissions
//!
//! `/dev/uinput` is `root:root 0660` on most distributions. The supported
//! setup is a dedicated group via `99-ultranix-mcp-uinput.rules`:
//!
//! ```text
//! # /etc/udev/rules.d/99-ultranix-mcp-uinput.rules
//! SUBSYSTEM=="misc", KERNEL=="uinput", ACTION=="add", \
//!   MODE="0660", GROUP="ultranix-input", TAG+="uaccess"
//! ```
//!
//! Never grant `GROUP="input"`: that group can *read* every real input
//! device (`/dev/input/event*`), which turns the daemon into a keylogger.
//!
//! SAFETY: unit tests in this module never call [`UinputInput::new`],
//! [`UinputInput::with_screen_size`] or `create_device` — creating a real
//! uinput device injects kernel-level input on the host desktop. Tests
//! cover only the pure mapping/parsing functions and the writability
//! probe, which opens but never creates a device.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use uinput::event::{self, Event, Keyboard};

use crate::traits::InputProvider;

/// Path of the kernel uinput control node.
const UINPUT_PATH: &str = "/dev/uinput";

/// Combined screen-size env var (`"1920x1080"`); per-axis
/// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT` are the fallback.
const ENV_SCREEN_SIZE: &str = "ULTRANIX_SCREEN_SIZE";
const ENV_SCREEN_W: &str = "ULTRANIX_SCREEN_WIDTH";
const ENV_SCREEN_H: &str = "ULTRANIX_SCREEN_HEIGHT";

/// Last-resort ABS range when nothing can report the real desktop extent.
const DEFAULT_SCREEN: (i32, i32) = (1920, 1080);

// evdev event types / axis / key codes, from linux/input-event-codes.h.
// Emitted through `Device::write` (doc-hidden but public) because the
// crate's typed `send()` API cannot express arbitrary event codes.
const EV_KEY: i32 = 0x01;
const EV_REL: i32 = 0x02;
const EV_ABS: i32 = 0x03;

const ABS_X: i32 = 0x00;
const ABS_Y: i32 = 0x01;
const REL_HWHEEL: i32 = 0x06;
const REL_WHEEL: i32 = 0x08;

const KEY_LEFTSHIFT: i32 = 42;

/// `/dev/uinput` virtual input backend.
///
/// One virtual device behind a mutex (`Device` methods take `&mut self`);
/// the provider is `Send + Sync` and safe to share behind
/// `Arc<dyn InputProvider>`. Dropping the device issues `UI_DEV_DESTROY`,
/// removing the kernel node.
pub struct UinputInput {
    inner: Arc<Mutex<Inner>>,
}

/// Compile-time contract: `InputProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UinputInput>();
};

/// Everything behind the lock: the device plus per-provider bookkeeping
/// (uinput gives no read channel, so we track what we emitted).
struct Inner {
    device: uinput::Device,
    /// ABS range registered at creation; `mouse_move` clamps into it.
    width: i32,
    height: i32,
    /// Last absolute position emitted — `cursor_position` fallback.
    last_pos: Option<(i32, i32)>,
    /// Sub-detent wheel remainders, so repeated fractional scrolls of
    /// e.g. 0.4 steps still accumulate into whole `REL_WHEEL` detents.
    wheel_acc: f64,
    hwheel_acc: f64,
}

/// A resolved key: evdev keycode plus whether `Shift` must be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyBinding {
    code: u16,
    shifted: bool,
}

// ---------------------------------------------------------------------------
// Name → code mappings (parity with wlr_input's alias set, resolved to
// raw evdev codes instead of keysyms since no keymap exists here)
// ---------------------------------------------------------------------------

/// Normalize a key/button name: lowercase, drop `_`, `-` and spaces, so
/// `"Page_Up"`, `"page-up"` and `"pgup"` all reach the same arm.
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// evdev button code for a button name (`linux/input-event-codes.h`).
/// Same table as `wlr_input`: `InputProvider` callers pass
/// "left" | "right" | "middle"; the extras cover navigation buttons.
fn button_code(name: &str) -> Option<u16> {
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

/// evdev code for a letter key, `'a'..='z'` (QWERTY-ordered codes).
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

/// Multi-character key names → evdev codes. Input is already normalized
/// (lowercase, separators stripped). Covers `wlr_input`'s alias table plus
/// keypad/media keys that exist as real keycodes.
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
        // No KEY_HYPER exists in evdev; wlr's "hyper" alias has no
        // counterpart here (Hyper_L is unbound on stock keymaps anyway).
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

/// KeyBinding for a literal character, on a US-layout keymap assumption
/// (uinput has no keymap; this mirrors the stock `us` evdev layout).
/// `\n`/`\r` → Enter, `\t` → Tab; non-ASCII has no binding.
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

/// Resolve a key name to a binding. Single characters go through
/// [`char_binding`] first so case carries shift state (`"A"` → Shift+a,
/// matching `wlr_input`'s level-1 keysym handling); multi-character names
/// hit the normalized table, then the F-key range.
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
/// remainder in `acc` so repeated small scrolls still accumulate.
fn detents(delta: f64, acc: &mut f64) -> i32 {
    *acc += delta;
    let steps = acc.round() as i32;
    *acc -= f64::from(steps);
    steps
}

// ---------------------------------------------------------------------------
// Screen-size resolution
// ---------------------------------------------------------------------------

/// Parse `"WxH"` (also `"W,H"`) into positive pixel dimensions.
fn parse_screen_size(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    let (w, h) = t
        .split_once(['x', 'X', ','])
        .map(|(w, h)| (w.trim(), h.trim()))?;
    let (w, h) = (w.parse().ok()?, h.parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

/// Screen bounds from `ULTRANIX_SCREEN_SIZE`, else the per-axis
/// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT` pair.
fn screen_size_from_env(get: impl Fn(&str) -> Option<String>) -> Option<(i32, i32)> {
    if let Some(wh) = get(ENV_SCREEN_SIZE).and_then(|v| parse_screen_size(&v)) {
        return Some(wh);
    }
    let w: i32 = get(ENV_SCREEN_W)?.trim().parse().ok()?;
    let h: i32 = get(ENV_SCREEN_H)?.trim().parse().ok()?;
    (w > 0 && h > 0).then_some((w, h))
}

/// Bounding box of `hyprctl -j monitors` output (position + logical size).
fn parse_monitors(bytes: &[u8]) -> Option<(i32, i32)> {
    let arr = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .as_array()?
        .clone();
    let (mut w, mut h) = (0i64, 0i64);
    for m in &arr {
        let (Some(x), Some(y), Some(mw), Some(mh)) = (
            m.get("x").and_then(|v| v.as_i64()),
            m.get("y").and_then(|v| v.as_i64()),
            m.get("width").and_then(|v| v.as_i64()),
            m.get("height").and_then(|v| v.as_i64()),
        ) else {
            continue;
        };
        w = w.max(x + mw);
        h = h.max(y + mh);
    }
    (w > 0 && h > 0).then_some((w as i32, h as i32))
}

/// Best-effort desktop extent via `hyprctl -j monitors` (sync; used only
/// at construction time). `None` off Hyprland.
fn hyprctl_screen_size() -> Option<(i32, i32)> {
    let out = std::process::Command::new("hyprctl")
        .args(["-j", "monitors"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_monitors(&out.stdout)
}

// ---------------------------------------------------------------------------
// Device creation / probe
// ---------------------------------------------------------------------------

/// Returns true when `path` can be opened `O_WRONLY`. Opening the uinput
/// control node for write does NOT create a device — `UI_DEV_CREATE`
/// happens only in [`create_device`].
fn uinput_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// Open `path` and create the virtual device: every keyboard key
/// (`Keyboard::All` sets `EV_KEY` + all `KEY_*` bits), the mouse buttons,
/// `REL_X`/`REL_Y`/`REL_WHEEL`/`REL_HWHEEL`, and `ABS_X`/`ABS_Y` bounded
/// to `0..=width`/`0..=height` for absolute pointer moves.
fn create_device(path: &Path, width: i32, height: i32) -> Result<uinput::Device> {
    use event::{absolute, controller, relative};

    let mut builder = uinput::open(path)
        .context("open uinput")?
        .name("ultranix-mcp virtual input")
        .context("uinput set name")?
        .bus(0x06) // BUS_VIRTUAL — honest provenance for a uinput device
        .vendor(0x0001)
        .product(0x0001)
        .version(1);

    let events = [
        Event::Keyboard(Keyboard::All),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Left)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Right)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Middle)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Side)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Extra)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Forward)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Back)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Task)),
        Event::Relative(relative::Relative::Position(relative::Position::X)),
        Event::Relative(relative::Relative::Position(relative::Position::Y)),
        Event::Relative(relative::Relative::Wheel(relative::Wheel::Vertical)),
        Event::Relative(relative::Relative::Wheel(relative::Wheel::Horizontal)),
    ];
    for ev in events {
        builder = builder.event(ev).context("uinput register event")?;
    }

    // Absolute axes take their range from the *previously* registered
    // event — min()/max() apply to `self.abs`, so they must immediately
    // follow each absolute `event()` call.
    builder = builder
        .event(absolute::Absolute::Position(absolute::Position::X))
        .context("uinput register ABS_X")?
        .min(0)
        .max(width);
    builder = builder
        .event(absolute::Absolute::Position(absolute::Position::Y))
        .context("uinput register ABS_Y")?
        .min(0)
        .max(height);

    builder.create().context("uinput create device")
}

impl UinputInput {
    /// Probe `/dev/uinput` (writable `O_WRONLY`) and create the virtual
    /// device. Returns `None` when the node is missing or not writable —
    /// i.e. no `ultranix-input` group membership / udev rule.
    ///
    /// Screen bounds for the ABS range come from `ULTRANIX_SCREEN_SIZE`,
    /// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT`,
    /// `hyprctl -j monitors`, then a 1920x1080 default.
    pub fn new() -> Option<Self> {
        let (w, h) = screen_size_from_env(|k| std::env::var(k).ok())
            .or_else(hyprctl_screen_size)
            .unwrap_or(DEFAULT_SCREEN);
        Self::open(Path::new(UINPUT_PATH), w, h)
    }

    /// Like [`Self::new`] but with an explicit ABS range — for callers
    /// that already know the desktop extent (e.g. `wlr_input` output
    /// layout or a `grim`/`xdpyinfo` measurement upstream).
    pub fn with_screen_size(width: i32, height: i32) -> Option<Self> {
        Self::open(Path::new(UINPUT_PATH), width, height)
    }

    /// Shared constructor: probe writability first (cheap, never creates
    /// a device), then build. Any failure is a debug-level `None`, not a
    /// hard error — this is a fallback rung.
    fn open(path: &Path, width: i32, height: i32) -> Option<Self> {
        if !uinput_writable(path) {
            tracing::debug!(path = %path.display(), "uinput: node not writable, backend unavailable");
            return None;
        }
        if width <= 0 || height <= 0 {
            tracing::debug!(
                width,
                height,
                "uinput: invalid screen bounds, backend unavailable"
            );
            return None;
        }
        match create_device(path, width, height) {
            Ok(device) => Some(Self {
                inner: Arc::new(Mutex::new(Inner {
                    device,
                    width,
                    height,
                    last_pos: None,
                    wheel_acc: 0.0,
                    hwheel_acc: 0.0,
                })),
            }),
            Err(e) => {
                tracing::debug!("uinput backend unavailable: {e:#}");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking device plumbing
// ---------------------------------------------------------------------------

impl Inner {
    /// Write one `input_event` (kind/code/value) to the device fd.
    fn emit(&mut self, kind: i32, code: i32, value: i32) -> Result<()> {
        self.device
            .write(kind, code, value)
            .context("uinput write event")
    }

    /// `EV_SYN`/`SYN_REPORT` — flush the buffered frame.
    fn sync(&mut self) -> Result<()> {
        self.device.synchronize().context("uinput synchronize")
    }

    fn move_to(&mut self, x: i32, y: i32) -> Result<()> {
        let px = x.clamp(0, self.width);
        let py = y.clamp(0, self.height);
        self.emit(EV_ABS, ABS_X, px)?;
        self.emit(EV_ABS, ABS_Y, py)?;
        self.sync()?;
        self.last_pos = Some((px, py));
        Ok(())
    }

    fn emit_button(&mut self, button: &str, down: bool) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        self.emit(EV_KEY, i32::from(code), i32::from(down))?;
        self.sync()
    }

    /// Validate the button *before* moving so a bad name never repositions
    /// the pointer (same ordering as `wlr_input::click`).
    fn click(&mut self, x: i32, y: i32, button: &str) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        let px = x.clamp(0, self.width);
        let py = y.clamp(0, self.height);
        self.emit(EV_ABS, ABS_X, px)?;
        self.emit(EV_ABS, ABS_Y, py)?;
        self.emit(EV_KEY, i32::from(code), 1)?;
        self.emit(EV_KEY, i32::from(code), 0)?;
        self.sync()?;
        self.last_pos = Some((px, py));
        Ok(())
    }

    /// `dx`/`dy` are wheel steps; positive scrolls right / down.
    ///
    /// Sign convention: wl_pointer axis positive = down/right, while
    /// evdev `REL_WHEEL` positive = up (wheel away from user) — so
    /// vertical is inverted. `REL_HWHEEL` positive = right already.
    /// Sub-detent remainders carry across calls via `detents`.
    fn scroll(&mut self, dx: f64, dy: f64) -> Result<()> {
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let wheel = detents(-dy, &mut self.wheel_acc);
        let hwheel = detents(dx, &mut self.hwheel_acc);
        if wheel != 0 {
            self.emit(EV_REL, REL_WHEEL, wheel)?;
        }
        if hwheel != 0 {
            self.emit(EV_REL, REL_HWHEEL, hwheel)?;
        }
        self.sync()
    }

    /// Press or release one key binding; a level-1 (shifted) binding wraps
    /// the key in a `KEY_LEFTSHIFT` hold, mirroring `wlr_input`.
    fn emit_key(&mut self, binding: KeyBinding, down: bool) -> Result<()> {
        if binding.shifted {
            if down {
                self.emit(EV_KEY, KEY_LEFTSHIFT, 1)?;
                self.emit(EV_KEY, i32::from(binding.code), 1)?;
            } else {
                self.emit(EV_KEY, i32::from(binding.code), 0)?;
                self.emit(EV_KEY, KEY_LEFTSHIFT, 0)?;
            }
        } else {
            self.emit(EV_KEY, i32::from(binding.code), i32::from(down))?;
        }
        self.sync()
    }

    fn key_event(&mut self, key: &str, down: bool) -> Result<()> {
        let binding = key_binding(key).ok_or_else(|| anyhow!("unknown key name {key:?}"))?;
        self.emit_key(binding, down)
    }

    /// Type a literal string. Every character is resolved to a binding
    /// *before* any event is emitted, so an unsupported character can
    /// never leave a half-typed string behind.
    fn type_text(&mut self, text: &str) -> Result<()> {
        let mut seq = Vec::with_capacity(text.len());
        for c in text.chars() {
            seq.push(char_binding(c).ok_or_else(|| anyhow!("no evdev key binding for {c:?}"))?);
        }
        for b in seq {
            if b.shifted {
                self.emit(EV_KEY, KEY_LEFTSHIFT, 1)?;
                self.emit(EV_KEY, i32::from(b.code), 1)?;
                self.emit(EV_KEY, i32::from(b.code), 0)?;
                self.emit(EV_KEY, KEY_LEFTSHIFT, 0)?;
            } else {
                self.emit(EV_KEY, i32::from(b.code), 1)?;
                self.emit(EV_KEY, i32::from(b.code), 0)?;
            }
        }
        self.sync()
    }
}

// ---------------------------------------------------------------------------
// hyprctl helpers (duplicated from wlr_input — the uinput rung may be
// live on X11 where no cursor read channel exists at all)
// ---------------------------------------------------------------------------

/// Parse `hyprctl cursorpos` output — modern JSON `{"x":N,"y":M}` or the
/// legacy `x, y` pair.
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

async fn hyprctl_cursorpos() -> Result<(i32, i32)> {
    let out = tokio::process::Command::new("hyprctl")
        .args(["-j", "cursorpos"])
        .output()
        .await
        .context("run hyprctl cursorpos")?;
    if !out.status.success() {
        bail!("hyprctl cursorpos exited {}", out.status);
    }
    parse_cursorpos(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| anyhow!("unparseable hyprctl cursorpos output"))
}

// ---------------------------------------------------------------------------
// InputProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl InputProvider for UinputInput {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").move_to(x, y))
            .await
            .context("uinput input task")?
    }

    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("uinput poisoned").click(x, y, &button)
        })
        .await
        .context("uinput input task")?
    }

    async fn mouse_button(&self, button: &str, down: bool) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("uinput poisoned")
                .emit_button(&button, down)
        })
        .await
        .context("uinput input task")?
    }

    async fn scroll(&self, dx: f64, dy: f64) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").scroll(dx, dy))
            .await
            .context("uinput input task")?
    }

    async fn key_event(&self, key: &str, down: bool) -> Result<()> {
        let key = key.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("uinput poisoned").key_event(&key, down)
        })
        .await
        .context("uinput input task")?
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        let text = text.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").type_text(&text))
            .await
            .context("uinput input task")?
    }

    /// uinput has no read channel: prefer live `hyprctl cursorpos`, else
    /// the last absolute position this provider emitted, else an error.
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        if let Ok(pos) = hyprctl_cursorpos().await {
            return Ok(pos);
        }
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("uinput poisoned")
                .last_pos
                .ok_or_else(|| anyhow!("cursor position unknown (uinput has no read channel)"))
        })
        .await
        .context("uinput input task")?
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: these tests are structurally incapable of injecting input —
// none of them call `new()`, `with_screen_size()` or `create_device()`,
// and `uinput_writable`/`open` only ever *open* a path (never
// `UI_DEV_CREATE`). The `open` tests point at paths that cannot be a
// uinput node (a missing path, a directory), so no device is ever
// created even on a fully-permissioned host.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_code_maps_mouse_buttons() {
        assert_eq!(button_code("left"), Some(0x110));
        assert_eq!(button_code("right"), Some(0x111));
        assert_eq!(button_code("middle"), Some(0x112));
        assert_eq!(button_code("LEFT"), Some(0x110)); // case-insensitive
        assert_eq!(button_code("back"), Some(0x116));
        assert_eq!(button_code("forward"), Some(0x115));
        assert_eq!(button_code("side"), Some(0x113));
        assert_eq!(button_code("extra"), Some(0x114));
    }

    #[test]
    fn button_code_rejects_unknown() {
        assert_eq!(button_code("primary"), None);
        assert_eq!(button_code(""), None);
    }

    #[test]
    fn named_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("enter"), Some(28));
        assert_eq!(code("ret"), Some(28));
        assert_eq!(code("escape"), Some(1));
        assert_eq!(code("esc"), Some(1));
        assert_eq!(code("ctrl"), Some(29));
        assert_eq!(code("rightctrl"), Some(97));
        assert_eq!(code("shift"), Some(42));
        assert_eq!(code("altgr"), Some(100));
        assert_eq!(code("super"), Some(125));
        assert_eq!(code("tab"), Some(15));
        assert_eq!(code("pageup"), Some(104));
        assert_eq!(code("Page_Up"), Some(104)); // normalized
        assert_eq!(code("pgdn"), Some(109));
        assert_eq!(code("delete"), Some(111));
        assert_eq!(code("printscreen"), Some(99));
        assert_eq!(code("pause"), Some(119));
        assert_eq!(code("menu"), Some(139));
        assert_eq!(code("compose"), Some(127));
    }

    #[test]
    fn fn_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("f1"), Some(59));
        assert_eq!(code("F5"), Some(63)); // case-insensitive
        assert_eq!(code("f10"), Some(68));
        assert_eq!(code("f11"), Some(87));
        assert_eq!(code("f12"), Some(88));
        assert_eq!(code("f13"), Some(183));
        assert_eq!(code("f24"), Some(194));
        assert_eq!(code("f25"), None);
        assert_eq!(code("f0"), None);
    }

    #[test]
    fn keypad_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("kp5"), Some(76));
        assert_eq!(code("KP_5"), Some(76)); // normalized
        assert_eq!(code("numpad0"), Some(82));
        assert_eq!(code("kpenter"), Some(96));
        assert_eq!(code("kpslash"), Some(98));
        assert_eq!(code("kpminus"), Some(74));
        assert_eq!(code("numlock"), Some(69));
    }

    #[test]
    fn single_chars_carry_shift_state() {
        // Parity with wlr_input's level-1 keysym handling: "A" must
        // produce Shift+a, not a bare "a".
        assert_eq!(
            key_binding("a"),
            Some(KeyBinding {
                code: 30,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("A"),
            Some(KeyBinding {
                code: 30,
                shifted: true
            })
        );
        assert_eq!(
            key_binding(";"),
            Some(KeyBinding {
                code: 39,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("1"),
            Some(KeyBinding {
                code: 2,
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
    }

    #[test]
    fn key_binding_rejects_garbage() {
        assert_eq!(key_binding("definitely-not-a-key"), None);
        assert_eq!(key_binding(""), None);
        assert_eq!(key_binding("hyper"), None); // no KEY_HYPER in evdev
        assert_eq!(key_binding("é"), None); // non-ASCII, no keymap
    }

    #[test]
    fn char_binding_maps_ascii() {
        let b = |c: char| char_binding(c);
        assert_eq!(
            b('\n'),
            Some(KeyBinding {
                code: 28,
                shifted: false
            })
        );
        assert_eq!(
            b('\r'),
            Some(KeyBinding {
                code: 28,
                shifted: false
            })
        );
        assert_eq!(
            b('\t'),
            Some(KeyBinding {
                code: 15,
                shifted: false
            })
        );
        assert_eq!(
            b(' '),
            Some(KeyBinding {
                code: 57,
                shifted: false
            })
        );
        assert_eq!(
            b('z'),
            Some(KeyBinding {
                code: 44,
                shifted: false
            })
        );
        assert_eq!(
            b('Z'),
            Some(KeyBinding {
                code: 44,
                shifted: true
            })
        );
        assert_eq!(
            b('~'),
            Some(KeyBinding {
                code: 41,
                shifted: true
            })
        );
        assert_eq!(
            b(')'),
            Some(KeyBinding {
                code: 11,
                shifted: true
            })
        );
        assert_eq!(
            b('/'),
            Some(KeyBinding {
                code: 53,
                shifted: false
            })
        );
        assert_eq!(
            b('?'),
            Some(KeyBinding {
                code: 53,
                shifted: true
            })
        );
        assert_eq!(b('é'), None);
        assert_eq!(b('←'), None);
    }

    #[test]
    fn detents_carry_sub_step_remainder() {
        let mut acc = 0.0;
        assert_eq!(detents(0.4, &mut acc), 0);
        assert_eq!(detents(0.4, &mut acc), 1); // 0.8 → one detent
        assert_eq!(detents(0.4, &mut acc), 0); // 0.2 left
        assert_eq!(detents(-3.0, &mut acc), -3);
        assert_eq!(detents(2.5, &mut acc), 3); // rounds to nearest
    }

    #[test]
    fn parse_screen_size_accepts_common_forms() {
        assert_eq!(parse_screen_size("1920x1080"), Some((1920, 1080)));
        assert_eq!(parse_screen_size("3840X2160"), Some((3840, 2160)));
        assert_eq!(parse_screen_size("1024,768"), Some((1024, 768)));
        assert_eq!(parse_screen_size(" 2560 x 1440 "), Some((2560, 1440)));
        assert_eq!(parse_screen_size("garbage"), None);
        assert_eq!(parse_screen_size("1920x"), None);
        assert_eq!(parse_screen_size("0x1080"), None);
        assert_eq!(parse_screen_size("-1x10"), None);
    }

    #[test]
    fn screen_size_from_env_prefers_combined_then_pair() {
        let env = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            move |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };
        assert_eq!(
            screen_size_from_env(env(&[("ULTRANIX_SCREEN_SIZE", "3440x1440")])),
            Some((3440, 1440))
        );
        assert_eq!(
            screen_size_from_env(env(&[
                ("ULTRANIX_SCREEN_WIDTH", "2560"),
                ("ULTRANIX_SCREEN_HEIGHT", "1440"),
            ])),
            Some((2560, 1440))
        );
        // Combined wins over the per-axis pair.
        assert_eq!(
            screen_size_from_env(env(&[
                ("ULTRANIX_SCREEN_SIZE", "1920x1080"),
                ("ULTRANIX_SCREEN_WIDTH", "9999"),
                ("ULTRANIX_SCREEN_HEIGHT", "9999"),
            ])),
            Some((1920, 1080))
        );
        assert_eq!(screen_size_from_env(env(&[])), None);
        assert_eq!(
            screen_size_from_env(env(&[("ULTRANIX_SCREEN_SIZE", "bogus")])),
            None
        );
    }

    #[test]
    fn parse_monitors_takes_layout_bounding_box() {
        let json = br#"[
            {"x":0,"y":0,"width":1920,"height":1080},
            {"x":1920,"y":-300,"width":2560,"height":1440}
        ]"#;
        assert_eq!(parse_monitors(json), Some((4480, 1140)));
        assert_eq!(parse_monitors(b"[]"), None);
        assert_eq!(parse_monitors(b"not json"), None);
    }

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn uinput_writable_probe() {
        // Missing node → not writable.
        assert!(!uinput_writable(Path::new(
            "/dev/ultranix-nonexistent-uinput-node"
        )));
        // A directory can never be opened O_WRONLY (EISDIR) — reliable
        // even when tests run as root.
        assert!(!uinput_writable(Path::new("/tmp")));
        // A plain writable file opens fine (it is never created into a
        // device — this probe only tests open() success).
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(uinput_writable(f.path()));
    }

    #[test]
    fn open_returns_none_for_unwritable_paths() {
        // Exits through the early-probe path: `create_device` is never
        // reached, so no kernel device can be created.
        assert!(UinputInput::open(Path::new("/dev/ultranix-nonexistent"), 1920, 1080).is_none());
        assert!(UinputInput::open(Path::new("/tmp"), 1920, 1080).is_none());
    }
}
