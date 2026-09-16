//! X11-native `WindowProvider` — `wmctrl` (EWMH window list, activate,
//! close, move/resize) plus `xdotool` (active-window id, minimize, pid)
//! and `xprop` (`_NET_WM_STATE` → fullscreen). The X11 rung of the window
//! fallback ladder (`WindowBackend::Wmctrl`), live only when
//! [`X11Window::new`] sees a non-empty `DISPLAY`.
//!
//! Every helper is a canonicalized absolute path pinned by
//! [`crate::security::whitelist`] at construction and spawned under the
//! scrubbed environment + per-spawn timeout of
//! [`crate::security::spawn`]. No shell is involved — window ids pass
//! straight through argv, and [`valid_window_id`] still restricts them
//! to `0x`-hex / decimal shapes so a malformed id fails before any
//! spawn.
//!
//! Listing details:
//!
//! - `wmctrl -lG` gives `id desktop x y w h host title` (bundled short
//!   flags keep the field layout fixed: geometry always follows the
//!   desktop column). `class` comes from a separate `wmctrl -lx` pass —
//!   with `-x` alone the WM_CLASS column always sits right after the
//!   desktop column regardless of the `-G`/`-x` field-order interaction,
//!   which has differed across wmctrl builds. `wmctrl -lp` adds `pid`
//!   the same way. Both enrichment passes are best-effort: a failed
//!   helper degrades the field, never the listing.
//! - `fullscreen` comes from `xprop -id <id> _NET_WM_STATE` per window
//!   when `xprop` is pinned (it is in [`whitelist::WHITELIST`] for
//!   provider use but has no `validate_command` arm — never invocable
//!   through `system_command`). When absent the field reports `None`.
//! - `floating`/`monitor` have no portable EWMH readout → always `None`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::security::{spawn, whitelist};
use crate::traits::{Rect, WindowInfo, WindowProvider};

/// EWMH window management via `wmctrl` + `xdotool` (+ optional `xprop`).
pub struct X11Window {
    wmctrl: PathBuf,
    /// Pinned `xdotool` — active-window id, `windowminimize`,
    /// `getwindowname` fallback. Optional at construction; the methods
    /// that need it error clearly when it was absent at pin time.
    xdotool: Option<PathBuf>,
    /// Pinned `xprop` — `_NET_WM_STATE` fullscreen detection and the
    /// `_NET_ACTIVE_WINDOW` fallback for the active id (see module docs).
    xprop: Option<PathBuf>,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<X11Window>();
};

/// Session gate shared by the X11 backends: a non-empty `DISPLAY`.
fn x11_display() -> Option<()> {
    let d = std::env::var_os("DISPLAY")?;
    (!d.is_empty()).then_some(())
}

/// Pinned `<bin> <args>` → stdout bytes; non-zero exit is an error.
/// (Sibling copies live in `x11_capture.rs` / `x11_input.rs`.)
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

/// [`run`] for argv built as `Vec<String>` (dispatch paths).
async fn run_argv(bin: &Path, args: &[String]) -> Result<()> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    run(bin, &argv).await.map(|_| ())
}

impl X11Window {
    /// Available iff `DISPLAY` is set (non-empty) and `wmctrl` was pinned
    /// on `PATH` at construction. `xdotool`/`xprop` are optional extras.
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
            wmctrl: pins.get("wmctrl")?.to_path_buf(),
            xdotool: pins.get("xdotool").map(Path::to_path_buf),
            xprop: pins.get("xprop").map(Path::to_path_buf),
        })
    }

    /// Hex `0x%08x` id of `_NET_ACTIVE_WINDOW`, best-effort: `xdotool
    /// getactivewindow` (decimal stdout) first, `xprop -root
    /// _NET_ACTIVE_WINDOW` when xdotool is absent or failed.
    async fn active_window_id(&self) -> Option<String> {
        if let Some(xdotool) = &self.xdotool
            && let Ok(out) = run(xdotool, &["getactivewindow"]).await
            && let Ok(dec) = String::from_utf8_lossy(&out).trim().parse::<u64>()
        {
            return Some(format!("0x{dec:08x}"));
        }
        if let Some(xprop) = &self.xprop
            && let Ok(out) = run(xprop, &["-root", "_NET_ACTIVE_WINDOW"]).await
        {
            return parse_xprop_active_window(&String::from_utf8_lossy(&out));
        }
        None
    }

    /// `xprop -id <id> _NET_WM_STATE` → `Some(is_fullscreen)`; `None`
    /// when the property read itself fails (dead window, helper error).
    async fn window_fullscreen(&self, id: &str) -> Option<bool> {
        let xprop = self.xprop.as_ref()?;
        let out = run(xprop, &["-id", id, "_NET_WM_STATE"]).await.ok()?;
        let text = String::from_utf8_lossy(&out);
        // `_NET_WM_STATE(ATOM) = …` on success, "not found" otherwise —
        // both mean "read succeeded", the atom list is just empty.
        if text.contains("_NET_WM_STATE") {
            Some(text.contains("_NET_WM_STATE_FULLSCREEN"))
        } else {
            None
        }
    }

    /// Best-effort enrichment of a `wmctrl -lG` listing: `class` via
    /// `wmctrl -lx`, `pid` via `wmctrl -lp`, `focused` via the active
    /// window id, `fullscreen` via `xprop` when pinned.
    async fn enrich(&self, windows: &mut [WindowInfo]) {
        if let Ok(out) = run(&self.wmctrl, &["-lx"]).await {
            let classes = parse_wmctrl_third_field(&String::from_utf8_lossy(&out));
            for w in windows.iter_mut() {
                if let Some(class) = classes.get(&w.id) {
                    w.class = class.clone();
                }
            }
        }
        if let Ok(out) = run(&self.wmctrl, &["-lp"]).await {
            let pids = parse_wmctrl_third_field(&String::from_utf8_lossy(&out));
            for w in windows.iter_mut() {
                // wmctrl prints 0 when the WM has no _NET_WM_PID — treat
                // non-positive as "unknown", not as pid 0 (the kernel's
                // scheduler placeholder, never an X11 client).
                w.pid = pids
                    .get(&w.id)
                    .and_then(|p| p.parse::<i64>().ok())
                    .filter(|&p| p > 0);
            }
        }
        if let Some(active) = self.active_window_id().await {
            for w in windows.iter_mut() {
                w.focused = w.id == active;
            }
        }
        if self.xprop.is_some() {
            for w in windows.iter_mut() {
                w.fullscreen = self.window_fullscreen(&w.id).await;
            }
        }
    }

    /// `xdotool getwindowname <id>` — title for windows absent from the
    /// EWMH client list (override-redirect panels, docks).
    async fn window_name(&self, id: &str) -> Option<String> {
        let out = run(self.xdotool.as_ref()?, &["getwindowname", id])
            .await
            .ok()?;
        let title = String::from_utf8_lossy(&out).trim().to_string();
        Some(title)
    }
}

#[async_trait]
impl WindowProvider for X11Window {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        let out = run(&self.wmctrl, &["-lG"]).await?;
        let mut windows = parse_wmctrl_list(&String::from_utf8_lossy(&out));
        self.enrich(&mut windows).await;
        Ok(windows)
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        if self.xdotool.is_none() && self.xprop.is_none() {
            bail!("x11: no active-window helper pinned (xdotool/xprop)");
        }
        let Some(id) = self.active_window_id().await else {
            return Ok(None); // helper answered, but nothing is focused
        };
        if let Some(mut w) = self.list_windows().await?.into_iter().find(|w| w.id == id) {
            w.focused = true;
            return Ok(Some(w));
        }
        // Not in the EWMH client list — a minimal record is still more
        // useful than dropping the window entirely.
        Ok(Some(WindowInfo {
            title: self.window_name(&id).await.unwrap_or_default(),
            id,
            class: String::new(),
            workspace: -1,
            rect: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            focused: true,
            floating: None,
            fullscreen: None,
            pid: None,
            monitor: None,
        }))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        if !valid_window_id(window_id) {
            bail!("x11: invalid window id '{window_id}'");
        }
        match dispatch_argv(action, window_id, args)? {
            DispatchCmd::Wmctrl(argv) => run_argv(&self.wmctrl, &argv).await,
            DispatchCmd::Xdotool(argv) => {
                let xdotool = self
                    .xdotool
                    .as_ref()
                    .ok_or_else(|| anyhow!("xdotool not on PATH at pin time"))?;
                run_argv(xdotool, &argv).await
            }
        }
    }
}

/// Which pinned helper carries a dispatch.
enum DispatchCmd {
    Wmctrl(Vec<String>),
    Xdotool(Vec<String>),
}

/// Window ids arrive as `0x<hex>` (wmctrl-style) or bare decimals —
/// restrict to those shapes so a malformed id fails before any spawn.
fn valid_window_id(id: &str) -> bool {
    if let Some(hex) = id.strip_prefix("0x").or_else(|| id.strip_prefix("0X")) {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        !id.is_empty() && id.chars().all(|c| c.is_ascii_digit())
    }
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// Build the argv for a `dispatch` action. Fixed mapping only — there is
/// no path from this function to `wmctrl`'s session-mutating options
/// (`-o`, `-n`, `-s` desktop switches, …) or `xdotool`'s exec primitives.
fn dispatch_argv(action: &str, id: &str, args: &Value) -> Result<DispatchCmd> {
    Ok(match action {
        // `-i` = interpret the window argument as a numeric window id.
        "focus" => DispatchCmd::Wmctrl(vec!["-i".into(), "-a".into(), id.into()]),
        "close" => DispatchCmd::Wmctrl(vec!["-i".into(), "-c".into(), id.into()]),
        "minimize" => DispatchCmd::Xdotool(vec!["windowminimize".into(), id.into()]),
        "move" | "resize" => {
            // `wmctrl -e gravity,X,Y,W,H` — `-1` keeps the current value,
            // gravity 0 is the EWMH default.
            let mut geom: [String; 4] = std::array::from_fn(|_| "-1".to_string());
            if action == "move" {
                let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) else {
                    bail!("x11: move requires x,y")
                };
                geom[0] = x.to_string();
                geom[1] = y.to_string();
            } else {
                let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) else {
                    bail!("x11: resize requires w,h")
                };
                if w < 1 || h < 1 {
                    bail!("x11: resize requires w,h >= 1");
                }
                geom[2] = w.to_string();
                geom[3] = h.to_string();
            }
            DispatchCmd::Wmctrl(vec![
                "-i".into(),
                "-r".into(),
                id.into(),
                "-e".into(),
                format!("0,{}", geom.join(",")),
            ])
        }
        other => bail!("x11: unsupported dispatch action '{other}'"),
    })
}

/// `wmctrl -lG` → window list (base fields only; enrichment is layered
/// on by [`X11Window::enrich`]). Line shape:
/// `id desktop x y w h host title…` — the host is column 7, everything
/// after it is the title.
fn parse_wmctrl_list(text: &str) -> Vec<WindowInfo> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 7 || !f[0].starts_with("0x") {
                return None;
            }
            Some(WindowInfo {
                id: f[0].to_string(),
                workspace: f[1].parse().ok()?,
                rect: Rect {
                    x: f[2].parse().ok()?,
                    y: f[3].parse().ok()?,
                    w: f[4].parse().ok()?,
                    h: f[5].parse().ok()?,
                },
                title: if f.len() > 7 {
                    f[7..].join(" ")
                } else {
                    String::new()
                },
                class: String::new(),
                focused: false,
                floating: None,
                fullscreen: None,
                pid: None,
                monitor: None,
            })
        })
        .collect()
}

/// `wmctrl -lx`/`-lp` → window id → the third column (`WM_CLASS` /
/// `_NET_WM_PID`). With exactly one extra flag the column position is
/// fixed regardless of the `-G`/`-x` field-order question (see module
/// docs).
fn parse_wmctrl_third_field(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 || !f[0].starts_with("0x") {
                return None;
            }
            Some((f[0].to_string(), f[2].to_string()))
        })
        .collect()
}

/// `xprop -root _NET_ACTIVE_WINDOW` → `Some("0x%08x")`. Output looks
/// like `_NET_ACTIVE_WINDOW(WINDOW): window id # 0x560000c`; `0x0` /
/// "not found" mean nothing is focused.
fn parse_xprop_active_window(s: &str) -> Option<String> {
    let hash = s.find('#')?;
    let tok = s[hash + 1..].split_whitespace().next()?;
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
    let v = u64::from_str_radix(hex, 16).ok()?;
    (v != 0).then(|| format!("0x{v:08x}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    /// Write `body` as an executable named `name` inside `dir`.
    fn write_exe(dir: &Path, name: &str, body: &str) {
        use std::io::Write;
        let path = dir.join(name);
        // Write a sibling temp file then rename: `File::create` on a path
        // that a still-running child exec'd earlier fails ETXTBSY, while a
        // rename over a busy executable is atomic and allowed.
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
    }

    /// Shape mirrors a live `wmctrl -lG` capture.
    const WMCTRL_LG: &str = "\
0x05600007  0 10   45   625  745   testhost  devin: onboarding
0x0560000c  1 645  45   625  745   testhost  devin: planning
0x02800003 -1 0    0    1920 24    testhost  panel
";

    /// `wmctrl -lx` — WM_CLASS sits in the third column.
    const WMCTRL_LX: &str = "\
0x05600007  0 kitty.kitty              testhost  devin: onboarding
0x0560000c  1 kitty.kitty              testhost  devin: planning
0x02800003 -1 plasmashell.plasmashell  testhost  panel
";

    /// `wmctrl -lp` — pid sits in the third column (0 = unknown).
    const WMCTRL_LP: &str = "\
0x05600007  0 37381  testhost  devin: onboarding
0x0560000c  1 37382  testhost  devin: planning
0x02800003 -1 0      testhost  panel
";

    /// Fake `wmctrl`: `-lG`/`-lx`/`-lp` print fixture files when present
    /// (falling back to the compiled-in constants); anything else is a
    /// dispatch and gets logged to `<dir>/wmctrl.log`.
    fn wmctrl_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             case \"$1\" in\n\
             -lG|-lx|-lp)\n\
               f=\"$d/reply-${{1#-}}\"\n\
               if [ -f \"$f\" ]; then exec cat \"$f\"; fi\n\
               exec cat \"$d/list-${{1#-}}\";;\n\
             *)\n\
               echo \"$@\" >> \"$d/wmctrl.log\";;\n\
             esac\n\
             exit 0\n",
            d = dir.display()
        )
    }

    /// Fake `xdotool`: `getactivewindow` → decimal id of 0x0560000c;
    /// `getwindowname`/`getwindowpid` → canned values; everything else is
    /// logged to `<dir>/xdotool.log`.
    fn xdotool_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             echo \"$@\" >> \"$d/xdotool.log\"\n\
             case \"$1\" in\n\
             getactivewindow) echo 90177548;;\n\
             getwindowname) echo 'fake window title';;\n\
             getwindowpid) echo 4242;;\n\
             esac\n\
             exit 0\n",
            d = dir.display()
        )
    }

    fn wmctrl_log(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("wmctrl.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn xdotool_log(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("xdotool.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// A fake-bin dir with `wmctrl` + `xdotool` and the list fixtures.
    fn fake_wm(dir: &Path) {
        write_exe(dir, "wmctrl", &wmctrl_script(dir));
        write_exe(dir, "xdotool", &xdotool_script(dir));
        std::fs::write(dir.join("list-lG"), WMCTRL_LG).unwrap();
        std::fs::write(dir.join("list-lx"), WMCTRL_LX).unwrap();
        std::fs::write(dir.join("list-lp"), WMCTRL_LP).unwrap();
    }

    // ---- pure parsing ---------------------------------------------------

    #[test]
    fn parses_wmctrl_lg_into_window_info() {
        let w = parse_wmctrl_list(WMCTRL_LG);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0].id, "0x05600007");
        assert_eq!(w[0].title, "devin: onboarding");
        assert_eq!(w[0].workspace, 0);
        assert_eq!(
            w[0].rect,
            Rect {
                x: 10,
                y: 45,
                w: 625,
                h: 745
            }
        );
        // -1 desktop = sticky window.
        assert_eq!(w[2].workspace, -1);
        assert!(!w.iter().any(|x| x.focused));
    }

    #[test]
    fn wmctrl_list_skips_malformed_lines() {
        let text = "0x1 not-a-desktop 0 0 1 1 host t\n\
                    garbage\n\
                    0x2 0 0 0 100\n\
                    0x3 0 0 0 100 100 host\n";
        let w = parse_wmctrl_list(text);
        // The no-host line is malformed (skipped); the last line is
        // short-but-valid — host present, title empty.
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].id, "0x3");
        assert_eq!(w[0].title, "");
    }

    #[test]
    fn parse_wmctrl_third_field_maps_ids() {
        let classes = parse_wmctrl_third_field(WMCTRL_LX);
        assert_eq!(classes["0x05600007"], "kitty.kitty");
        let pids = parse_wmctrl_third_field(WMCTRL_LP);
        assert_eq!(pids["0x0560000c"], "37382");
    }

    #[test]
    fn parse_xprop_active_window_id() {
        assert_eq!(
            parse_xprop_active_window("_NET_ACTIVE_WINDOW(WINDOW): window id # 0x560000c"),
            Some("0x0560000c".to_string())
        );
        assert_eq!(
            parse_xprop_active_window("_NET_ACTIVE_WINDOW: not found."),
            None
        );
        assert_eq!(
            parse_xprop_active_window("_NET_ACTIVE_WINDOW(WINDOW): window id # 0x0"),
            None
        );
    }

    #[test]
    fn valid_window_id_shapes() {
        assert!(valid_window_id("0x05600007"));
        assert!(valid_window_id("0X05600007"));
        assert!(valid_window_id("90177548"));
        for bad in ["", "0x", "0xZZ", "0x1; rm -rf /", "0x1\nfoo", "win 1"] {
            assert!(!valid_window_id(bad), "id {bad:?} must be rejected");
        }
    }

    #[test]
    fn dispatch_maps_all_actions() {
        let id = "0x0560000c";
        let cases: Vec<(&str, Value, Vec<&str>)> = vec![
            ("focus", json!({}), vec!["-i", "-a", id]),
            ("close", json!({}), vec!["-i", "-c", id]),
            (
                "move",
                json!({"x": 100, "y": 200}),
                vec!["-i", "-r", id, "-e", "0,100,200,-1,-1"],
            ),
            (
                "resize",
                json!({"w": 800, "h": 600}),
                vec!["-i", "-r", id, "-e", "0,-1,-1,800,600"],
            ),
        ];
        for (action, args, want) in cases {
            match dispatch_argv(action, id, &args).unwrap() {
                DispatchCmd::Wmctrl(argv) => {
                    assert_eq!(
                        argv,
                        want.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        "{action}"
                    );
                }
                DispatchCmd::Xdotool(_) => panic!("{action} must route to wmctrl"),
            }
        }
        match dispatch_argv("minimize", id, &json!({})).unwrap() {
            DispatchCmd::Xdotool(argv) => {
                assert_eq!(argv, vec!["windowminimize".to_string(), id.to_string()]);
            }
            DispatchCmd::Wmctrl(_) => panic!("minimize must route to xdotool"),
        }
    }

    #[test]
    fn dispatch_requires_geometry() {
        let id = "0x0560000c";
        assert!(dispatch_argv("move", id, &json!({})).is_err());
        assert!(dispatch_argv("move", id, &json!({"x": 1})).is_err());
        assert!(dispatch_argv("resize", id, &json!({"w": 0, "h": 0})).is_err());
        assert!(dispatch_argv("resize", id, &json!({})).is_err());
        assert!(dispatch_argv("explode", id, &json!({})).is_err());
    }

    // ---- construction probe -----------------------------------------------

    #[test]
    fn with_pins_requires_wmctrl() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(X11Window::with_pins(&pins).is_none());

        fake_wm(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).expect("wmctrl pin resolves");
        assert!(w.wmctrl.is_absolute());
    }

    #[test]
    fn new_is_none_without_display() {
        // SAFETY: test-only env mutation, restored before returning. See
        // the sibling note in `x11_capture.rs`.
        let saved = std::env::var_os("DISPLAY");
        unsafe { std::env::remove_var("DISPLAY") };
        assert!(X11Window::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("DISPLAY", v) };
        }
    }

    // ---- hermetic spawn paths (fake wmctrl/xdotool via resolve_in) --------

    #[tokio::test]
    async fn list_windows_parses_and_enriches() {
        let dir = tempfile::tempdir().unwrap();
        fake_wm(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).unwrap();

        let windows = w.list_windows().await.unwrap();
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].class, "kitty.kitty");
        assert_eq!(windows[0].pid, Some(37381));
        assert_eq!(windows[2].pid, None); // wmctrl reported 0
        // getactivewindow → 90177548 = 0x0560000c → the planning window.
        assert!(windows[1].focused);
        assert!(!windows[0].focused);
        // xprop absent from the tempdir PATH → fullscreen stays None.
        assert!(windows.iter().all(|x| x.fullscreen.is_none()));
        assert!(
            windows
                .iter()
                .all(|x| x.floating.is_none() && x.monitor.is_none())
        );
    }

    #[tokio::test]
    async fn active_window_matches_wmctrl_listing() {
        let dir = tempfile::tempdir().unwrap();
        fake_wm(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).unwrap();

        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, "0x0560000c");
        assert_eq!(active.title, "devin: planning");
        assert!(active.focused);
        assert_eq!(active.pid, Some(37382));

        // An id absent from the EWMH list → minimal record via
        // getwindowname rather than a dropped window.
        std::fs::write(dir.path().join("list-lG"), "").unwrap();
        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, "0x0560000c");
        assert_eq!(active.title, "fake window title");
        assert!(active.focused);
    }

    #[tokio::test]
    async fn active_window_none_when_helpers_say_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "wmctrl", &wmctrl_script(dir.path()));
        write_exe(
            dir.path(),
            "xdotool",
            "#!/bin/sh\nexit 1\n", // getactivewindow fails
        );
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).unwrap();
        assert!(w.active_window().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dispatch_routes_to_wmctrl_and_xdotool() {
        let dir = tempfile::tempdir().unwrap();
        fake_wm(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).unwrap();

        w.dispatch("focus", "0x0560000c", &json!({})).await.unwrap();
        w.dispatch("close", "0x0560000c", &json!({})).await.unwrap();
        w.dispatch("move", "0x0560000c", &json!({"x": 1, "y": 2}))
            .await
            .unwrap();
        w.dispatch("resize", "0x0560000c", &json!({"w": 3, "h": 4}))
            .await
            .unwrap();
        w.dispatch("minimize", "0x0560000c", &json!({}))
            .await
            .unwrap();

        assert_eq!(
            wmctrl_log(dir.path()),
            vec![
                "-i -a 0x0560000c",
                "-i -c 0x0560000c",
                "-i -r 0x0560000c -e 0,1,2,-1,-1",
                "-i -r 0x0560000c -e 0,-1,-1,3,4",
            ]
        );
        // `getactivewindow` also logs to xdotool.log — filter it out.
        let xdotool_lines: Vec<String> = xdotool_log(dir.path())
            .into_iter()
            .filter(|l| !l.starts_with("getactivewindow"))
            .collect();
        assert_eq!(xdotool_lines, vec!["windowminimize 0x0560000c"]);

        // A malformed id fails before any spawn.
        let n = wmctrl_log(dir.path()).len();
        assert!(w.dispatch("focus", "bogus id", &json!({})).await.is_err());
        assert_eq!(wmctrl_log(dir.path()).len(), n);
    }

    #[tokio::test]
    async fn dispatch_minimize_errors_without_xdotool() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "wmctrl", &wmctrl_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = X11Window::with_pins(&pins).unwrap();
        let err = w
            .dispatch("minimize", "0x0560000c", &json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("xdotool not on PATH"), "{err}");
    }
}
