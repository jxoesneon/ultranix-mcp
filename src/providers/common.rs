//! Shared provider helpers - the single home for code the provider
//! backends used to carry as private copies.
//!
//! Two families live here:
//!
//! - **`hyprctl` degraded-read helpers**(`parse_cursorpos`,
//!   [`hyprctl_cursorpos`], [`hyprctl_monitors`], [`hyprctl_screen_size`]):
//!   backends without their own read channel (uinput, portal, grim) reuse
//!   Hyprland's IPC for cursor position / monitor inventory. The binary is
//!   always the canonicalized path pinned by
//!   [`crate::security::whitelist`] at construction and spawned under the
//!   scrubbed env + timeouts of [`crate::security::spawn`].
//! - **evdev key/button table**([`key_binding`], [`char_binding`],
//!   [`button_code`], [`detents`], ...): the fixed US-layout code table
//!   shared by `uinput_input` and `portal_input` - both rungs are
//!   display-protocol agnostic with no keymap channel, so names and
//!   characters resolve to raw evdev codes.
//!
//! Also shared: [`OutputInfo`] (the `wl_output` geometry record used by
//! the two in-process Wayland backends) and the `ULTRANIX_SCREEN_*`
//! screen-size parsers ([`parse_screen_size`], [`screen_size_from_env`],
//! [`parse_monitors_extent`]).

// Every consumer of this module is feature-gated (`wayland`, `uinput`,
// `a11y`, `vision`), so under `--no-default-features` nothing uses it -
// dead-code warnings there are feature-shape artifacts, not real drift.
#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

// ---------------------------------------------------------------------------
// hyprctl helpers
// ---------------------------------------------------------------------------

/// Parse `hyprctl cursorpos` output - modern JSON `{"x":N,"y":M}` or the
/// legacy `x, y` pair.
pub(crate) fn parse_cursorpos(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        let x = v.get("x")?.as_i64()?;
        let y = v.get("y")?.as_i64()?;
        return Some((x as i32, y as i32));
    }
    let (xs, ys) = t.split_once(',')?;
    Some((xs.trim().parse().ok()?, ys.trim().parse().ok()?))
}

/// Pinned `hyprctl -j cursorpos`, scrubbed env, bounded wait.
pub(crate) async fn hyprctl_cursorpos(bin: &Path) -> Result<(i32, i32)> {
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

/// Pinned `hyprctl -j monitors`, scrubbed env, bounded wait. Returns the
/// raw compositor JSON array (per-monitor records).
pub(crate) async fn hyprctl_monitors(bin: &Path) -> Result<Value> {
    let mut cmd = crate::security::spawn::command(bin, &["-j", "monitors"]);
    let out =
        crate::security::spawn::output_within(&mut cmd, crate::security::spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("run hyprctl monitors")?;
    if !out.status.success() {
        bail!("hyprctl monitors exited {}", out.status);
    }
    serde_json::from_slice(&out.stdout).context("parse hyprctl monitors JSON")
}

/// Best-effort desktop extent via `hyprctl -j monitors` (blocking; used
/// only at provider construction). `None` off Hyprland - `bin` is the
/// pinned whitelisted path under a scrubbed env, and the wait is bounded
/// so a wedged helper cannot stall provider detection.
pub(crate) fn hyprctl_screen_size(bin: &Path) -> Option<(i32, i32)> {
    let mut cmd = crate::security::spawn::std_command(bin, &["-j", "monitors"]);
    let out = crate::security::spawn::std_output_within(
        &mut cmd,
        crate::security::spawn::SUBPROCESS_TIMEOUT,
    )?;
    if !out.status.success() {
        return None;
    }
    parse_monitors_extent(&out.stdout)
}

// ---------------------------------------------------------------------------
// Screen-size parsing
// ---------------------------------------------------------------------------

/// Combined screen-size env var (`"1920x1080"`); per-axis
/// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT` are the fallback.
pub(crate) const ENV_SCREEN_SIZE: &str = "ULTRANIX_SCREEN_SIZE";
pub(crate) const ENV_SCREEN_W: &str = "ULTRANIX_SCREEN_WIDTH";
pub(crate) const ENV_SCREEN_H: &str = "ULTRANIX_SCREEN_HEIGHT";

/// Parse `"WxH"` (also `"W,H"`) into positive pixel dimensions.
pub(crate) fn parse_screen_size(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    let (w, h) = t
        .split_once(['x', 'X', ','])
        .map(|(w, h)| (w.trim(), h.trim()))?;
    let (w, h) = (w.parse().ok()?, h.parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

/// Screen bounds from `ULTRANIX_SCREEN_SIZE`, else the per-axis
/// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT` pair. The getter
/// indirection keeps this testable without touching process env.
pub(crate) fn screen_size_from_env(get: impl Fn(&str) -> Option<String>) -> Option<(i32, i32)> {
    if let Some(wh) = get(ENV_SCREEN_SIZE).and_then(|v| parse_screen_size(&v)) {
        return Some(wh);
    }
    let w: i32 = get(ENV_SCREEN_W)?.trim().parse().ok()?;
    let h: i32 = get(ENV_SCREEN_H)?.trim().parse().ok()?;
    (w > 0 && h > 0).then_some((w, h))
}

/// Bounding box of `hyprctl -j monitors` output (position + logical size).
pub(crate) fn parse_monitors_extent(bytes: &[u8]) -> Option<(i32, i32)> {
    let arr = serde_json::from_slice::<Value>(bytes)
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

// ---------------------------------------------------------------------------
// wl_output geometry record
// ---------------------------------------------------------------------------

/// Accumulated `wl_output` geometry - the full field set of
/// `wlr_capture` (name/make/model/refresh/scale are unused by
/// `wlr_input`, which only needs the layout rect).
#[derive(Clone, Default)]
pub(crate) struct OutputInfo {
    pub(crate) name: String,
    pub(crate) make: String,
    pub(crate) model: String,
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) width: i32,
    pub(crate) height: i32,
    pub(crate) refresh_millihz: i32,
    pub(crate) scale: i32,
}

// ---------------------------------------------------------------------------
// evdev key/button table (fixed US layout - no keymap channel exists on
// the uinput / portal rungs; wlr_input resolves keysyms instead)
// ---------------------------------------------------------------------------

/// `KEY_LEFTSHIFT`, held around shifted [`KeyBinding`]s.
pub(crate) const KEY_LEFTSHIFT: i32 = 42;

/// A resolved key: evdev keycode plus whether `Shift` must be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyBinding {
    pub(crate) code: u16,
    pub(crate) shifted: bool,
}

/// Normalize a key/button name: lowercase, drop `_`, `-` and spaces, so
/// `"Page_Up"`, `"page-up"` and `"pgup"` all reach the same arm.
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// evdev button code for a button name (`linux/input-event-codes.h`).
/// `InputProvider` callers pass `"left"` | `"right"` | `"middle"`; the
/// extras cover navigation buttons.
pub(crate) fn button_code(name: &str) -> Option<u16> {
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

/// Multi-character key names -> evdev codes. Input is already normalized
/// (lowercase, separators stripped). Covers `wlr_input`'s alias set plus
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

/// `F1`-`F24` -> KEY_F1(59)..F10(68), F11(87), F12(88), F13(183)..F24(194).
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
/// (no keymap exists at this level; this mirrors the stock `us` evdev
/// layout). `\n`/`\r` -> Enter, `\t` -> Tab; non-ASCII has no binding.
pub(crate) fn char_binding(c: char) -> Option<KeyBinding> {
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
/// [`char_binding`] first so case carries shift state (`"A"` -> Shift+a,
/// matching `wlr_input`'s level-1 keysym handling); multi-character names
/// hit the normalized table, then the F-key range.
pub(crate) fn key_binding(name: &str) -> Option<KeyBinding> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next())
        && let Some(b) = char_binding(c)
    {
        return Some(b);
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
pub(crate) fn detents(delta: f64, acc: &mut f64) -> i32 {
    *acc += delta;
    let steps = acc.round() as i32;
    *acc -= f64::from(steps);
    steps
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
        // JSON takes precedence when it parses; negative coords pass through.
        assert_eq!(parse_cursorpos("{\"x\":-5,\"y\":2}"), Some((-5, 2)));
        assert_eq!(parse_cursorpos("  7,8  "), Some((7, 8)));
        assert_eq!(parse_cursorpos(""), None);
        assert_eq!(parse_cursorpos("1,2,3"), None);
        // JSON without x/y falls back to the pair form, which then fails.
        assert_eq!(parse_cursorpos("{\"a\":1}"), None);
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
    fn parse_monitors_extent_takes_layout_bounding_box() {
        let json = br#"[
            {"x":0,"y":0,"width":1920,"height":1080},
            {"x":1920,"y":-300,"width":2560,"height":1440}
        ]"#;
        assert_eq!(parse_monitors_extent(json), Some((4480, 1140)));
        assert_eq!(parse_monitors_extent(b"[]"), None);
        assert_eq!(parse_monitors_extent(b"not json"), None);
        // Entries missing a field are skipped.
        let partial = br#"[{"x":0,"y":0,"width":800}, {"x":0,"y":0,"width":640,"height":480}]"#;
        assert_eq!(parse_monitors_extent(partial), Some((640, 480)));
    }

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
        assert_eq!(button_code("task"), Some(0x117));
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
        assert_eq!(b('\u{2190}'), None);
    }

    #[test]
    fn detents_carry_sub_step_remainder() {
        let mut acc = 0.0;
        assert_eq!(detents(0.4, &mut acc), 0);
        assert_eq!(detents(0.4, &mut acc), 1); // 0.8 -> one detent
        assert_eq!(detents(0.4, &mut acc), 0); // 0.2 left
        assert_eq!(detents(-3.0, &mut acc), -3);
        assert_eq!(detents(2.5, &mut acc), 3); // rounds to nearest
    }
}
