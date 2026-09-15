//! X11-native input injection via the pinned `xdotool` binary — the X11
//! rung of the input fallback ladder (`InputBackend::Xdotool`), live only
//! when [`X11Input::new`] sees a non-empty `DISPLAY`.
//!
//! Every action is one `xdotool` invocation under the scrubbed
//! environment + per-spawn timeout of [`crate::security::spawn`], with
//! the binary path canonicalized by [`crate::security::whitelist`] at
//! construction — a `PATH` hijack after construction cannot substitute a
//! trojan, and a wedged child cannot hang a call. No shell is involved:
//! every argument is a separate argv entry, so key names and typed text
//! can never be reinterpreted as syntax.
//!
//! Mapping notes:
//!
//! - `key_event` maps `down`/`up` to `xdotool keydown`/`keyup`, *not*
//!   `xdotool key` — the tools layer holds modifiers across calls (e.g.
//!   `key_event("Control_L", true)` … `key_event("c", …)` …
//!   `key_event("Control_L", false)`), so press/release must be
//!   expressible independently. A `+`-joined chord (`"ctrl+alt+t"`)
//!   resolves each part and passes them all to one invocation; `up`
//!   releases in reverse order.
//! - `mouse_click(x, y, b)` is a single `xdotool mousemove x y click N`
//!   — one spawn, so the pointer can never be observed mid-flight. The
//!   trait has no double-click primitive; the `mouse_double_click` tool
//!   already composes two `mouse_click` calls inside the click interval
//!   (`xdotool click --repeat 2` remains the equivalent native form).
//! - `scroll(dx, dy)` emits wheel buttons 4/5/6/7 (up/down/left/right)
//!   with `click --repeat`, carrying sub-detent remainders across calls
//!   like [`super::uinput_input`]'s `wheel_acc`.
//! - `type_text` uses `xdotool type --delay 0 -- <text>` — the `--`
//!   end-of-options marker keeps a leading `-` in the payload from being
//!   parsed as a flag.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;

use crate::security::{spawn, whitelist};
use crate::traits::InputProvider;

/// `xdotool`-driven input injection, X11-only.
pub struct X11Input {
    xdotool: PathBuf,
    /// Sub-detent wheel remainders `(vertical, horizontal)` so repeated
    /// fractional scrolls of e.g. 0.4 steps still accumulate into whole
    /// `click 4|5|6|7` detents (mirrors `uinput_input::Inner`).
    wheel_acc: Mutex<(f64, f64)>,
}

/// Compile-time contract: `InputProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<X11Input>();
};

/// Session gate shared by the X11 backends: a non-empty `DISPLAY`.
fn x11_display() -> Option<()> {
    let d = std::env::var_os("DISPLAY")?;
    (!d.is_empty()).then_some(())
}

/// Pinned `<bin> <args>` → stdout bytes; non-zero exit is an error.
/// (Sibling copies live in `x11_capture.rs` / `x11_window.rs`.)
async fn run(bin: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = spawn::command(bin, args);
    let out = spawn::output_within(&mut cmd, spawn::SUBPROCESS_TIMEOUT)
        .await
        .with_context(|| format!("spawn {}", bin.display()))?;
    if !out.status.success() {
        bail!("{} {:?} exited {}", bin.display(), args, out.status);
    }
    Ok(out.stdout)
}

/// Same as [`run`] when only the exit status matters.
async fn run_ok(bin: &Path, args: &[&str]) -> Result<()> {
    run(bin, args).await.map(|_| ())
}

impl X11Input {
    /// Available iff `DISPLAY` is set (non-empty) and `xdotool` was
    /// pinned on `PATH` at construction.
    pub fn new() -> Option<Self> {
        x11_display()?;
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the
    /// `DISPLAY` session gate — the testable seam: hermetic tests resolve
    /// a fresh `PinnedBins` over a tempdir `PATH` and exercise the real
    /// spawn paths without mutating process env.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            xdotool: pins.get("xdotool")?.to_path_buf(),
            wheel_acc: Mutex::new((0.0, 0.0)),
        })
    }
}

/// X11 button number for a button name. `InputProvider` callers pass
/// "left" | "right" | "middle"; the extras cover navigation buttons
/// (X11 numbering: 4–7 are the wheel and are never used here — scroll
/// emits them directly).
fn button_number(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "left" | "lmb" => "1",
        "middle" | "mmb" => "2",
        "right" | "rmb" => "3",
        "back" | "side" | "thumb" => "8",
        "forward" | "fwd" | "extra" | "thumb2" => "9",
        _ => return None,
    })
}

/// Normalize a key name: lowercase, drop `_`, `-` and spaces, so
/// `"Page_Up"`, `"page-up"` and `"pgup"` all reach the same arm
/// (same normalization as `uinput_input`).
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Friendly/compact key names → canonical X keysym names `xdotool`
/// understands. The caller-visible contract is XKB keysym names
/// (`tools::keyboard` passes `Control_L`, `Shift_L`, `Return`, `F5`,
/// `Left`, single characters); this table covers the common aliases the
/// other input backends also accept.
fn key_alias(n: &str) -> Option<&'static str> {
    Some(match n {
        "ctrl" | "control" | "ctl" | "lctrl" | "leftctrl" => "Control_L",
        "rctrl" | "rightctrl" => "Control_R",
        "shift" | "lshift" | "leftshift" => "Shift_L",
        "rshift" | "rightshift" => "Shift_R",
        "alt" | "lalt" | "leftalt" => "Alt_L",
        "ralt" | "rightalt" | "altgr" => "ISO_Level3_Shift",
        "super" | "win" | "cmd" | "meta" | "lsuper" | "leftsuper" | "lmeta" | "leftmeta" => {
            "Super_L"
        }
        "rsuper" | "rightsuper" | "rmeta" | "rightmeta" => "Super_R",
        "hyper" => "Hyper_L",
        "enter" | "return" | "ret" | "newline" => "Return",
        "esc" | "escape" => "Escape",
        "backspace" | "bksp" | "bs" => "BackSpace",
        "tab" => "Tab",
        "space" | "spc" | "spacebar" => "space",
        "caps" | "capslock" => "Caps_Lock",
        "numlock" => "Num_Lock",
        "scrolllock" => "Scroll_Lock",
        "printscreen" | "prtsc" | "sysrq" | "print" => "Print",
        "pause" | "break" => "Pause",
        "delete" | "del" => "Delete",
        "insert" | "ins" => "Insert",
        "home" => "Home",
        "end" => "End",
        "pageup" | "pgup" => "Page_Up",
        "pagedown" | "pgdown" | "pgdn" => "Page_Down",
        "up" | "uparrow" | "arrowup" => "Up",
        "down" | "downarrow" | "arrowdown" => "Down",
        "left" | "leftarrow" | "arrowleft" => "Left",
        "right" | "rightarrow" | "arrowright" => "Right",
        "menu" | "appmenu" | "apps" => "Menu",
        _ => return None,
    })
}

/// Resolve one key name to the spelling passed to `xdotool
/// keydown`/`keyup`. Order: alias table → `F1`–`F24` → literal single
/// character → already-canonical keysym spelling (forwarded to
/// `XStringToKeysym`; a bogus name makes `xdotool` exit non-zero, which
/// surfaces as a normal backend error).
fn xdotool_key_name(name: &str) -> Option<String> {
    if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let n = normalize_name(name);
    if let Some(sym) = key_alias(&n) {
        return Some(sym.to_string());
    }
    if let Some(rest) = n.strip_prefix('f')
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_digit())
    {
        // f<digits> spells an F-key — only F1..=F24 exist; anything
        // outside the range is a bad name, not a passthrough keysym.
        let f: u32 = rest.parse().ok()?;
        return (1..=24).contains(&f).then(|| format!("F{f}"));
    }
    if name.chars().count() == 1 {
        return Some(name.to_string());
    }
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Some(name.to_string());
    }
    None
}

/// Split a wheel delta into whole detents, carrying the sub-detent
/// remainder in `acc` so repeated small scrolls still accumulate (same
/// algorithm as `super::common::detents`; kept private so this module
/// stays self-contained).
fn detents(delta: f64, acc: &mut f64) -> i32 {
    *acc += delta;
    let steps = acc.round() as i32;
    *acc -= f64::from(steps);
    steps
}

/// `NAME=value` line in `--shell` output → integer value. Kept in sync
/// with the sibling copy in `x11_capture.rs`.
fn shell_var_i64(s: &str, key: &str) -> Option<i64> {
    for line in s.lines() {
        if let Some(v) = line
            .trim()
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return v.trim().parse().ok();
        }
    }
    None
}

/// `xdotool getmouselocation --shell` output → `(x, y)`.
fn parse_getmouselocation(s: &str) -> Option<(i32, i32)> {
    Some((shell_var_i64(s, "X")? as i32, shell_var_i64(s, "Y")? as i32))
}

#[async_trait]
impl InputProvider for X11Input {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()> {
        let (xs, ys) = (x.to_string(), y.to_string());
        run_ok(&self.xdotool, &["mousemove", &xs, &ys]).await
    }

    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()> {
        // Validate before moving so a bad button name never repositions
        // the pointer (same ordering as `wlr_input::click`).
        let n = button_number(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        let (xs, ys) = (x.to_string(), y.to_string());
        run_ok(&self.xdotool, &["mousemove", &xs, &ys, "click", n]).await
    }

    async fn mouse_button(&self, button: &str, down: bool) -> Result<()> {
        let n = button_number(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        run_ok(
            &self.xdotool,
            &[if down { "mousedown" } else { "mouseup" }, n],
        )
        .await
    }

    /// `dx`/`dy` are wheel steps; positive scrolls right / down. X11
    /// wheel buttons: 4 up, 5 down, 6 left, 7 right — `click --repeat N`
    /// emits N detents.
    async fn scroll(&self, dx: f64, dy: f64) -> Result<()> {
        if !dx.is_finite() || !dy.is_finite() {
            bail!("x11 scroll: non-finite delta");
        }
        let (v, h) = {
            let mut acc = self
                .wheel_acc
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (detents(dy, &mut acc.0), detents(dx, &mut acc.1))
        };
        for (button, steps) in [
            (if v >= 0 { "5" } else { "4" }, v.unsigned_abs()),
            (if h >= 0 { "7" } else { "6" }, h.unsigned_abs()),
        ] {
            if steps == 0 {
                continue;
            }
            let n = steps.to_string();
            run_ok(&self.xdotool, &["click", "--repeat", &n, button]).await?;
        }
        Ok(())
    }

    async fn key_event(&self, key: &str, down: bool) -> Result<()> {
        // Resolve every chord member before spawning — a bad name can
        // never leave a half-held modifier behind.
        let mut names = Vec::new();
        for part in key.split('+') {
            let resolved =
                xdotool_key_name(part).ok_or_else(|| anyhow!("unknown key name {part:?}"))?;
            names.push(resolved);
        }
        if !down {
            names.reverse(); // release a chord in reverse press order
        }
        let mut argv: Vec<&str> = Vec::with_capacity(names.len() + 1);
        argv.push(if down { "keydown" } else { "keyup" });
        argv.extend(names.iter().map(String::as_str));
        run_ok(&self.xdotool, &argv).await
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        run_ok(&self.xdotool, &["type", "--delay", "0", "--", text]).await
    }

    /// `xdotool getmouselocation --shell` → `X=`/`Y=` pair.
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        let stdout = run(&self.xdotool, &["getmouselocation", "--shell"]).await?;
        parse_getmouselocation(&String::from_utf8_lossy(&stdout))
            .ok_or_else(|| anyhow!("unparseable xdotool getmouselocation output"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: the hermetic tests spawn only the fake `xdotool` written into a
// tempdir — `with_pins` + `PinnedBins::resolve_in` never consults the
// real `PATH`, so no test can inject input on a live display. The single
// `new()` test removes `DISPLAY` first, exiting through the early-`None`
// path before any spawn.

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write `body` as an executable named `name` inside `dir`.
    fn write_exe(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    /// Fake `xdotool`: appends its argv to `<dir>/xdotool.log` (one line
    /// per spawn, so tests can assert the exact command surface) and
    /// answers the query subcommands with canned `--shell` output.
    fn xdotool_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             echo \"$@\" >> \"$d/xdotool.log\"\n\
             if [ -f \"$d/fail\" ]; then echo 'simulated xdotool failure' >&2; exit 1; fi\n\
             case \"$1\" in\n\
             getmouselocation) printf 'X=11\\nY=22\\nSCREEN=0\\nWINDOW=1\\n';;\n\
             getdisplaygeometry) printf 'WIDTH=1920\\nHEIGHT=1080\\n';;\n\
             getactivewindow) echo 90177548;;\n\
             esac\n\
             exit 0\n",
            d = dir.display()
        )
    }

    fn log(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("xdotool.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    // ---- pure mapping --------------------------------------------------

    #[test]
    fn button_number_maps_buttons() {
        assert_eq!(button_number("left"), Some("1"));
        assert_eq!(button_number("middle"), Some("2"));
        assert_eq!(button_number("right"), Some("3"));
        assert_eq!(button_number("RIGHT"), Some("3")); // case-insensitive
        assert_eq!(button_number("back"), Some("8"));
        assert_eq!(button_number("forward"), Some("9"));
        assert_eq!(button_number("bogus"), None);
    }

    #[test]
    fn xdotool_key_name_aliases_and_canonical() {
        assert_eq!(xdotool_key_name("ctrl").as_deref(), Some("Control_L"));
        assert_eq!(xdotool_key_name("ret").as_deref(), Some("Return"));
        assert_eq!(xdotool_key_name("pgup").as_deref(), Some("Page_Up"));
        assert_eq!(xdotool_key_name("super").as_deref(), Some("Super_L"));
        // Canonical keysym spellings pass through untouched.
        assert_eq!(xdotool_key_name("Control_L").as_deref(), Some("Control_L"));
        assert_eq!(xdotool_key_name("KP_5").as_deref(), Some("KP_5"));
        assert_eq!(
            xdotool_key_name("XF86AudioMute").as_deref(),
            Some("XF86AudioMute")
        );
        // F-keys normalize.
        assert_eq!(xdotool_key_name("f5").as_deref(), Some("F5"));
        assert_eq!(xdotool_key_name("F24").as_deref(), Some("F24"));
        assert_eq!(xdotool_key_name("f25"), None);
        // Literal characters pass through.
        assert_eq!(xdotool_key_name("a").as_deref(), Some("a"));
        assert_eq!(xdotool_key_name(";").as_deref(), Some(";"));
        // Rejected shapes.
        assert_eq!(xdotool_key_name(""), None);
        assert_eq!(xdotool_key_name("with space"), None);
        assert_eq!(xdotool_key_name("bad;char"), None);
    }

    #[test]
    fn detents_accumulate_fractional_scrolls() {
        let mut acc = 0.0;
        assert_eq!(detents(0.4, &mut acc), 0);
        assert_eq!(detents(0.4, &mut acc), 1); // 0.8 → 1 detent
        assert_eq!(detents(-0.6, &mut acc), -1);
        assert_eq!(detents(0.0, &mut acc), 0);
    }

    #[test]
    fn parse_getmouselocation_shell() {
        assert_eq!(
            parse_getmouselocation("X=1017\nY=664\nSCREEN=0\n"),
            Some((1017, 664))
        );
        assert_eq!(parse_getmouselocation("X=1"), None);
        assert_eq!(parse_getmouselocation("garbage"), None);
    }

    // ---- construction probe ---------------------------------------------

    #[test]
    fn with_pins_requires_xdotool() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(X11Input::with_pins(&pins).is_none());

        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).expect("xdotool pin resolves");
        assert!(input.xdotool.is_absolute());
    }

    #[test]
    fn new_is_none_without_display() {
        // SAFETY: test-only env mutation, restored before returning. See
        // the sibling note in `x11_capture.rs`.
        let saved = std::env::var_os("DISPLAY");
        unsafe { std::env::remove_var("DISPLAY") };
        assert!(X11Input::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("DISPLAY", v) };
        }
    }

    // ---- hermetic spawn paths (fake xdotool logs its argv) --------------

    #[tokio::test]
    async fn mouse_ops_spawn_expected_argv() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).unwrap();

        input.mouse_move(10, 20).await.unwrap();
        input.mouse_click(1, 2, "left").await.unwrap();
        input.mouse_button("right", true).await.unwrap();
        input.mouse_button("right", false).await.unwrap();

        assert_eq!(
            log(dir.path()),
            vec![
                "mousemove 10 20",
                "mousemove 1 2 click 1",
                "mousedown 3",
                "mouseup 3",
            ]
        );
    }

    #[tokio::test]
    async fn scroll_emits_wheel_buttons_with_repeat() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).unwrap();

        input.scroll(0.0, -3.0).await.unwrap(); // up → button 4
        input.scroll(0.0, 2.0).await.unwrap(); // down → button 5
        input.scroll(-1.0, 0.0).await.unwrap(); // left → button 6
        input.scroll(4.0, 0.0).await.unwrap(); // right → button 7
        input.scroll(0.0, 0.0).await.unwrap(); // no-op: no spawn

        assert_eq!(
            log(dir.path()),
            vec![
                "click --repeat 3 4",
                "click --repeat 2 5",
                "click --repeat 1 6",
                "click --repeat 4 7",
            ]
        );
    }

    #[tokio::test]
    async fn key_event_maps_to_keydown_keyup() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).unwrap();

        // The tools layer's ctrl+shift+t sequence, verbatim.
        input.key_event("Control_L", true).await.unwrap();
        input.key_event("Shift_L", true).await.unwrap();
        input.key_event("t", true).await.unwrap();
        input.key_event("t", false).await.unwrap();
        input.key_event("Shift_L", false).await.unwrap();
        input.key_event("Control_L", false).await.unwrap();
        // A `+` chord in one call presses all parts; release reverses.
        input.key_event("ctrl+alt+t", true).await.unwrap();
        input.key_event("ctrl+alt+t", false).await.unwrap();

        assert_eq!(
            log(dir.path()),
            vec![
                "keydown Control_L",
                "keydown Shift_L",
                "keydown t",
                "keyup t",
                "keyup Shift_L",
                "keyup Control_L",
                "keydown Control_L Alt_L t",
                "keyup t Alt_L Control_L",
            ]
        );

        // A bad name fails before any spawn — the log is unchanged.
        let before = log(dir.path());
        assert!(input.key_event("bad;name", true).await.is_err());
        assert_eq!(log(dir.path()), before);
    }

    #[tokio::test]
    async fn type_text_uses_end_of_options_marker() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).unwrap();

        input.type_text("hello world").await.unwrap();
        input.type_text("-leading-dash").await.unwrap();
        input.type_text("").await.unwrap(); // no spawn

        assert_eq!(
            log(dir.path()),
            vec![
                "type --delay 0 -- hello world",
                "type --delay 0 -- -leading-dash",
            ]
        );
    }

    #[tokio::test]
    async fn cursor_position_reads_getmouselocation() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xdotool", &xdotool_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let input = X11Input::with_pins(&pins).unwrap();

        assert_eq!(input.cursor_position().await.unwrap(), (11, 22));

        // Non-zero helper exit surfaces as an error.
        std::fs::write(dir.path().join("fail"), "").unwrap();
        assert!(input.cursor_position().await.is_err());
    }
}
