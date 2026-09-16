//! KDE `WindowProvider` - `kdotool`, the xdotool clone for KWin. The KDE
//! rung of the window fallback ladder ([`WindowBackend::Kdotool`]), live
//! on both Wayland and X11 Plasma sessions: kdotool drives KWin through
//! its scripting API (each invocation generates a KWin script, loads it
//! over `org.kde.KWin` D-Bus, runs it, and deletes it), so the transport
//! is compositor-native on either display protocol.
//!
//! Every spawn is the canonicalized absolute path pinned by
//! [`crate::security::whitelist`] at construction, under the scrubbed
//! environment + per-spawn timeout of [`crate::security::spawn`]. No
//! shell is involved - window ids pass straight through argv, and
//! [`valid_window_id`] restricts them to the braced-UUID shape so a
//! malformed id fails before any spawn.
//!
//! Listing and query semantics:
//!
//! - Window ids are KWin `internalId`s - `{xxxxxxxx-...}` UUIDs, printed
//!   braced. They are **not**X11 window ids even on X11 sessions, and
//!   `%N`/`%@` stack references are meaningless across invocations
//!   (each spawn is a fresh script with an empty stack), so only the
//!   braced shape is accepted back from callers.
//! - `list_windows` = `search ""` (empty regex matches every managed
//!   window - panels/OSDs included, like `wmctrl -l`'s sticky/desktop
//!   entries) + `getactivewindow` for `focused`. Per-window fields come
//!   from one chained spawn per window - `getwindowname`,
//!   `getwindowclassname`, `getwindowgeometry`, `getwindowpid`,
//!   `get_desktop_for_window` - each getter emits exactly one result
//!   line (`"null"` when KWin has no value), so the block parses
//!   positionally around the `Window {id}` marker `getwindowgeometry`
//!   prints. A failed or empty describe degrades the window's fields,
//!   never the listing (mirroring `x11_window`'s enrichment).
//! - `workspace` is the window's x11 desktop number; KWin
//!   `onAllDesktops` windows report `null` -> `-1`, the same "sticky"
//!   convention `wmctrl` uses.
//! - `floating`/`fullscreen`/`monitor` have no kdotool readout -> `None`.
//!   `pid` is best-effort (`w.pid` is `null` for clients that don't
//!   report it, and non-positive pids are never real clients).
//!
//! Dispatch mapping (closed set - the `kwinscript` arbitrary-JS
//! primitive, `set_desktop`, `windowstate`, and every other verb are
//! unreachable through [`WindowProvider::dispatch`]):
//!
//! - `focus` -> `windowactivate` (KWin switches desktop when needed -
//!   that is KWin's focus semantic).
//! - `move` -> `windowmove <x> <y>`; `dx,dy` -> `windowmove --relative`.
//! - `resize` -> `windowsize <w> <h>` (absolute only - kdotool has no
//!   relative-resize form, so `dw,dh` fails honestly).
//! - `minimize` -> `windowminimize` (KWin's real minimized state, unlike
//!   sway's scratchpad approximation).
//! - `close` -> `windowclose`.
//!
//! [`WindowBackend::Kdotool`]: crate::backend::detect::WindowBackend::Kdotool

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::security::{spawn, whitelist};
use crate::traits::{Rect, WindowInfo, WindowProvider};

/// KWin window management via the `kdotool` CLI.
pub struct KdotoolWindow {
    /// Pinned `kdotool` - every query and dispatch spawns it.
    kdotool: PathBuf,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<KdotoolWindow>();
};

/// Session gate: a live KDE/Plasma session marker - `KDE_SESSION_VERSION`
/// (the authoritative signal, matching `SessionKind::Kde`) or an
/// `XDG_CURRENT_DESKTOP` containing kde/plasma. The window ladder only
/// reaches this provider on KDE sessions; the check is the last-resort
/// guard for direct [`KdotoolWindow::new`] callers.
fn kde_session() -> Option<()> {
    if std::env::var_os("KDE_SESSION_VERSION").is_some_and(|v| !v.is_empty()) {
        return Some(());
    }
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .ok()?
        .to_ascii_lowercase();
    (desktop.contains("kde") || desktop.contains("plasma")).then_some(())
}

/// Pinned `<bin> <args>` -> stdout bytes; non-zero exit is an error.
/// (Sibling copies live in `x11_window.rs` / `clipboard.rs`.)
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

/// Per-window fields gathered in one chained `kdotool` invocation -
/// see [`KdotoolWindow::describe`].
#[derive(Debug, Default)]
struct Describe {
    title: String,
    class: String,
    rect: Option<Rect>,
    pid: Option<i64>,
    /// x11 desktop number; `None` = onAllDesktops/unparseable -> `-1`.
    desktop: Option<i32>,
}

impl KdotoolWindow {
    /// Available iff a KDE session marker is present and `kdotool` was
    /// pinned on `PATH` at construction.
    pub fn new() -> Option<Self> {
        kde_session()?;
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the KDE
    /// session gate - the testable seam: hermetic tests resolve a fresh
    /// `PinnedBins` over a tempdir `PATH` and exercise the real spawn
    /// paths without mutating process env.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            kdotool: pins.get("kdotool")?.to_path_buf(),
        })
    }

    /// `getactivewindow` -> the focused `internalId`, or `None` when
    /// nothing is focused or the helper failed.
    async fn active_window_id(&self) -> Option<String> {
        let out = run(&self.kdotool, &["getactivewindow"]).await.ok()?;
        parse_id_list(&String::from_utf8_lossy(&out))
            .into_iter()
            .next()
    }

    /// One chained spawn gathering a window's title, class, geometry,
    /// pid and desktop - five `output_result` getters against the same
    /// script run, so the block is a consistent snapshot. `None` when
    /// the invocation fails or the window vanished before answering
    /// (the id loop finds no match -> empty stdout).
    async fn describe(&self, id: &str) -> Option<Describe> {
        let out = run(
            &self.kdotool,
            &[
                "getwindowname",
                id,
                "getwindowclassname",
                id,
                "getwindowgeometry",
                id,
                "getwindowpid",
                id,
                "get_desktop_for_window",
                id,
            ],
        )
        .await
        .ok()?;
        parse_describe(&String::from_utf8_lossy(&out))
    }
}

#[async_trait]
impl WindowProvider for KdotoolWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        let out = run(&self.kdotool, &["search", ""]).await?;
        let ids = parse_id_list(&String::from_utf8_lossy(&out));
        let active = self.active_window_id().await;
        // Each describe is an independent spawn - run them concurrently;
        // join_all preserves id order, and a failed describe still
        // degrades that window's fields rather than failing the listing.
        let describes =
            futures_util::future::join_all(ids.iter().map(|id| self.describe(id))).await;
        Ok(ids
            .into_iter()
            .zip(describes)
            .map(|(id, d)| window_info(&id, d.as_ref(), active.as_deref() == Some(id.as_str())))
            .collect())
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        let Some(id) = self.active_window_id().await else {
            return Ok(None); // helper answered, but nothing is focused
        };
        let d = self.describe(&id).await;
        // A vanished/unanswerable active window still gets a minimal
        // record rather than being dropped - same contract as
        // `x11_window`'s fallback for ids absent from the EWMH list.
        Ok(Some(window_info(&id, d.as_ref(), true)))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        if !valid_window_id(window_id) {
            bail!("kdotool: invalid window id '{window_id}'");
        }
        run_argv(&self.kdotool, &dispatch_argv(action, window_id, args)?).await
    }
}

/// Describe -> [`WindowInfo`]. Unreported fields keep their honest
/// defaults (zero rect, `workspace = -1`, `None` extras).
fn window_info(id: &str, d: Option<&Describe>, focused: bool) -> WindowInfo {
    let (title, class, rect, pid, desktop) = match d {
        Some(d) => (
            d.title.clone(),
            d.class.clone(),
            d.rect.unwrap_or(Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            }),
            d.pid,
            d.desktop.unwrap_or(-1),
        ),
        None => (
            String::new(),
            String::new(),
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            None,
            -1,
        ),
    };
    WindowInfo {
        id: id.to_string(),
        title,
        class,
        workspace: desktop,
        rect,
        focused,
        floating: None,
        fullscreen: None,
        pid,
        monitor: None,
    }
}

/// kdotool window ids are KWin `internalId`s - `{xxxxxxxx-...}` UUIDs
/// printed braced. Restricting to that exact shape keeps a malformed id
/// (or a `%N`/`%@` stack reference, meaningless across invocations)
/// from ever reaching a spawn.
fn valid_window_id(id: &str) -> bool {
    let Some(inner) = id.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// `search`/`getactivewindow` stdout -> braced window ids, one per line.
/// Non-id lines (shouldn't occur) are dropped defensively.
fn parse_id_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| valid_window_id(l))
        .map(str::to_string)
        .collect()
}

/// Chained describe output -> [`Describe`]. Layout (one line per
/// `output_result` call):
///
/// ```text
/// <caption - possibly multi-line>
/// <resourceClass>
/// Window {id}
///   Position: x,y
///   Geometry: wxh
/// <pid or "null">
/// <desktop number or "null">
/// ```
///
/// The `Window {id}` marker `getwindowgeometry` emits anchors the
/// block: everything above it is name (all but the last line) + class
/// (the last line), which keeps a newline-carrying caption intact;
/// pid/desktop are the two lines after the geometry pair. `None` when
/// the marker is absent (window vanished -> empty stdout).
fn parse_describe(text: &str) -> Option<Describe> {
    let lines: Vec<&str> = text.lines().collect();
    let wpos = lines
        .iter()
        .position(|l| l.trim_start().starts_with("Window "))?;
    let class = wpos
        .checked_sub(1)
        .map(|i| lines[i].to_string())
        .unwrap_or_default();
    let title = if wpos >= 2 {
        lines[..wpos - 1].join("\n")
    } else {
        String::new()
    };
    let rect = match (lines.get(wpos + 1), lines.get(wpos + 2)) {
        (Some(p), Some(g)) => {
            let (x, y) = parse_position(p)?;
            let (w, h) = parse_geometry(g)?;
            Some(Rect { x, y, w, h })
        }
        _ => None,
    };
    let pid = lines
        .get(wpos + 3)
        .and_then(|l| l.trim().parse::<i64>().ok())
        // pid 0 is the kernel's scheduler placeholder, never a client.
        .filter(|&p| p > 0);
    let desktop = lines
        .get(wpos + 4)
        .and_then(|l| l.trim().parse::<i32>().ok());
    Some(Describe {
        title,
        class,
        rect,
        pid,
        desktop,
    })
}

/// `  Position: x,y` -> (x, y). Negative coords pass through; a trailing
/// `(screen: N)`-style suffix (xdotool's shape, defensive) is dropped.
fn parse_position(line: &str) -> Option<(i32, i32)> {
    let rest = line.split_once("Position:")?.1.trim();
    let (x, y) = rest.split_once(',')?;
    let y = y.split_whitespace().next()?;
    Some((x.trim().parse().ok()?, y.parse().ok()?))
}

/// `  Geometry: WxH` -> (w, h).
fn parse_geometry(line: &str) -> Option<(i32, i32)> {
    let rest = line.split_once("Geometry:")?.1.trim();
    let (w, h) = rest.split_whitespace().next()?.split_once(['x', 'X'])?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// Build the argv for a `dispatch` action. Fixed mapping only - there is
/// no path from this function to `kwinscript` (arbitrary KWin
/// JavaScript), `set_desktop`, `windowstate`, `--shortcut`, or any other
/// kdotool verb.
fn dispatch_argv(action: &str, id: &str, args: &Value) -> Result<Vec<String>> {
    Ok(match action {
        "focus" => vec!["windowactivate".into(), id.into()],
        "close" => vec!["windowclose".into(), id.into()],
        "minimize" => vec!["windowminimize".into(), id.into()],
        "move" => {
            if let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) {
                vec!["windowmove".into(), id.into(), x.to_string(), y.to_string()]
            } else if let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) {
                vec![
                    "windowmove".into(),
                    "--relative".into(),
                    id.into(),
                    dx.to_string(),
                    dy.to_string(),
                ]
            } else {
                bail!("kdotool: move requires x,y (or dx,dy)")
            }
        }
        "resize" => {
            let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) else {
                bail!("kdotool: resize requires w,h")
            };
            if w < 1 || h < 1 {
                bail!("kdotool: resize requires w,h >= 1")
            }
            vec!["windowsize".into(), id.into(), w.to_string(), h.to_string()]
        }
        other => bail!("kdotool: unsupported dispatch action '{other}'"),
    })
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

    const ID1: &str = "{a1a1a1a1-0000-0000-0000-000000000001}";
    const ID2: &str = "{b2b2b2b2-0000-0000-0000-000000000002}";
    const ID3: &str = "{c3c3c3c3-0000-0000-0000-000000000003}";

    /// Shape mirrors a live `kdotool search ""` capture - one braced
    /// `internalId` per line.
    const SEARCH_OUT: &str = "\
{a1a1a1a1-0000-0000-0000-000000000001}
{b2b2b2b2-0000-0000-0000-000000000002}
{c3c3c3c3-0000-0000-0000-000000000003}
";

    /// Fake `kdotool`: logs every invocation to `<dir>/kdotool.log`,
    /// serves `search`/`getactivewindow` from fixture files, and answers
    /// the chained per-window getters from `<getter>-{id}` fixtures -
    /// emitting `null` (real kdotool's no-value line) when a fixture is
    /// absent. Dispatch verbs fall through to the log with exit 0.
    fn kdotool_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             echo \"$@\" >> \"$d/kdotool.log\"\n\
             getter=''\n\
             for a in \"$@\"; do\n\
             \tcase \"$a\" in\n\
             \t\tsearch) cat \"$d/search.out\"; exit 0;;\n\
             \t\tgetactivewindow) cat \"$d/active.out\"; exit 0;;\n\
             \t\tgetwindowname|getwindowclassname|getwindowgeometry|getwindowpid|get_desktop_for_window)\n\
             \t\t\tgetter=\"$a\";;\n\
             \t\t\\{{*\\}})\n\
             \t\t\tcase \"$getter\" in\n\
             \t\t\t\tgetwindowname|getwindowclassname) cat \"$d/$getter-$a\" 2>/dev/null || echo '';;\n\
             \t\t\t\tgetwindowgeometry) cat \"$d/$getter-$a\";;\n\
             \t\t\t\t*) cat \"$d/$getter-$a\" 2>/dev/null || echo 'null';;\n\
             \t\t\tesac;;\n\
             \tesac\n\
             done\n\
             exit 0\n",
            d = dir.display()
        )
    }

    fn kdotool_log(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("kdotool.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// A fake-bin dir with `kdotool` plus the fixtures for a three-
    /// window session whose active window is `ID2`.
    fn fake_kde(dir: &Path) {
        write_exe(dir, "kdotool", &kdotool_script(dir));
        std::fs::write(dir.join("search.out"), SEARCH_OUT).unwrap();
        std::fs::write(dir.join("active.out"), format!("{ID2}\n")).unwrap();

        std::fs::write(
            dir.join(format!("getwindowname-{ID1}")),
            "notes: onboarding\n",
        )
        .unwrap();
        std::fs::write(dir.join(format!("getwindowclassname-{ID1}")), "kitty\n").unwrap();
        std::fs::write(
            dir.join(format!("getwindowgeometry-{ID1}")),
            format!("Window {ID1}\n  Position: 10,45\n  Geometry: 625x745\n"),
        )
        .unwrap();
        std::fs::write(dir.join(format!("getwindowpid-{ID1}")), "37381\n").unwrap();
        std::fs::write(dir.join(format!("get_desktop_for_window-{ID1}")), "1\n").unwrap();

        std::fs::write(
            dir.join(format!("getwindowname-{ID2}")),
            "notes: planning\n",
        )
        .unwrap();
        std::fs::write(dir.join(format!("getwindowclassname-{ID2}")), "kitty\n").unwrap();
        std::fs::write(
            dir.join(format!("getwindowgeometry-{ID2}")),
            format!("Window {ID2}\n  Position: -5,100\n  Geometry: 800x600\n"),
        )
        .unwrap();
        std::fs::write(dir.join(format!("getwindowpid-{ID2}")), "37382\n").unwrap();
        std::fs::write(dir.join(format!("get_desktop_for_window-{ID2}")), "2\n").unwrap();

        // Panel: onAllDesktops -> desktop fixture absent (fake emits
        // "null"), no pid fixture either -> "null".
        std::fs::write(dir.join(format!("getwindowname-{ID3}")), "panel\n").unwrap();
        std::fs::write(
            dir.join(format!("getwindowclassname-{ID3}")),
            "plasmashell\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("getwindowgeometry-{ID3}")),
            format!("Window {ID3}\n  Position: 0,0\n  Geometry: 1920x24\n"),
        )
        .unwrap();
    }

    // ---- pure parsing ---------------------------------------------------

    #[test]
    fn parse_id_list_accepts_only_braced_uuids() {
        let ids = parse_id_list(SEARCH_OUT);
        assert_eq!(ids, vec![ID1, ID2, ID3]);
        // Non-id lines are dropped, not parsed.
        assert!(parse_id_list("%1\n%@\n{zzz}\ngarbage\n{}\n").is_empty());
    }

    #[test]
    fn valid_window_id_shapes() {
        assert!(valid_window_id(ID1));
        assert!(valid_window_id("{DEADBEEF-1234}"));
        for bad in [
            "",
            "{}",
            "{zzz}",
            "{a1}; rm -rf /",
            "{a1}\nfoo",
            "%1",
            "%@",
            "a1a1a1a1-0000-0000-0000-000000000001", // unbraced is not an id
            "0x05600007",
            "90177548",
        ] {
            assert!(!valid_window_id(bad), "id {bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_describe_full_block() {
        let text = "notes: onboarding\nkitty\nWindow {a1}\n  Position: 10,45\n  Geometry: 625x745\n37381\n2\n";
        let d = parse_describe(text).unwrap();
        assert_eq!(d.title, "notes: onboarding");
        assert_eq!(d.class, "kitty");
        assert_eq!(
            d.rect,
            Some(Rect {
                x: 10,
                y: 45,
                w: 625,
                h: 745
            })
        );
        assert_eq!(d.pid, Some(37381));
        assert_eq!(d.desktop, Some(2));
    }

    #[test]
    fn parse_describe_null_fields() {
        // onAllDesktops + unreported pid - kdotool prints "null".
        let text =
            "panel\nplasmashell\nWindow {a1}\n  Position: 0,0\n  Geometry: 1920x24\nnull\nnull\n";
        let d = parse_describe(text).unwrap();
        assert_eq!(d.title, "panel");
        assert_eq!(d.pid, None);
        assert_eq!(d.desktop, None);
    }

    #[test]
    fn parse_describe_negative_position_and_empty_caption() {
        // An empty caption still occupies its line (kdotool emits a
        // result line per getter).
        let text = "\nsomeclass\nWindow {a1}\n  Position: -12,-3\n  Geometry: 1x1\n0\n-2\n";
        let d = parse_describe(text).unwrap();
        assert_eq!(d.title, "");
        assert_eq!(d.class, "someclass");
        assert_eq!(d.rect.unwrap().x, -12);
        assert_eq!(d.pid, None); // pid 0 is never a client
        assert_eq!(d.desktop, Some(-2)); // negative desktops pass through
    }

    #[test]
    fn parse_describe_multiline_caption_stays_intact() {
        // A newline in the caption shifts the name block - the Window
        // marker still anchors class/rect/pid/desktop correctly.
        let text =
            "line one\nline two\ncls\nWindow {a1}\n  Position: 1,2\n  Geometry: 3x4\nnull\n1\n";
        let d = parse_describe(text).unwrap();
        assert_eq!(d.title, "line one\nline two");
        assert_eq!(d.class, "cls");
        assert_eq!(d.rect.unwrap().w, 3);
    }

    #[test]
    fn parse_describe_rejects_missing_marker_and_bad_geometry() {
        // A vanished window yields empty stdout -> no marker -> None.
        assert!(parse_describe("").is_none());
        assert!(parse_describe("just a title\n").is_none());
        // Marker present but the geometry pair is broken -> None (the
        // describe fails as a unit rather than half-parsing).
        assert!(parse_describe("t\nc\nWindow {a1}\n  Position: x,y\n  Geometry: 3x4\n").is_none());
    }

    #[test]
    fn parse_position_and_geometry_lines() {
        assert_eq!(parse_position("  Position: 10,45"), Some((10, 45)));
        assert_eq!(parse_position("  Position: -5,100"), Some((-5, 100)));
        // xdotool-style trailing "(screen: N)" is tolerated.
        assert_eq!(parse_position("Position: 1,2 (screen: 0)"), Some((1, 2)));
        assert_eq!(parse_geometry("  Geometry: 625x745"), Some((625, 745)));
        assert_eq!(parse_geometry("Geometry: 1x1"), Some((1, 1)));
        assert_eq!(parse_position("Geometry: 3x4"), None);
        assert_eq!(parse_position("Position: x,y"), None);
        assert_eq!(parse_geometry("Geometry: axb"), None);
    }

    // ---- dispatch argv ----------------------------------------------------

    #[test]
    fn dispatch_maps_all_actions() {
        let cases: Vec<(&str, Value, Vec<&str>)> = vec![
            ("focus", json!({}), vec!["windowactivate", ID2]),
            ("close", json!({}), vec!["windowclose", ID2]),
            ("minimize", json!({}), vec!["windowminimize", ID2]),
            (
                "move",
                json!({"x": 100, "y": 200}),
                vec!["windowmove", ID2, "100", "200"],
            ),
            (
                "move",
                json!({"dx": -10, "dy": 5}),
                vec!["windowmove", "--relative", ID2, "-10", "5"],
            ),
            (
                "resize",
                json!({"w": 800, "h": 600}),
                vec!["windowsize", ID2, "800", "600"],
            ),
        ];
        for (action, args, want) in cases {
            assert_eq!(
                dispatch_argv(action, ID2, &args).unwrap(),
                want.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "{action} {args}"
            );
        }
    }

    #[test]
    fn dispatch_never_emits_kwinscript() {
        // The arbitrary-JS primitive and every unlisted verb are
        // unreachable through the closed action set.
        for action in [
            "kwinscript",
            "set_desktop",
            "windowstate",
            "exec",
            "explode",
        ] {
            assert!(
                dispatch_argv(action, ID2, &json!({"x": 1, "y": 1, "w": 2, "h": 2})).is_err(),
                "{action} must be unreachable"
            );
        }
    }

    #[test]
    fn dispatch_requires_geometry() {
        assert!(dispatch_argv("move", ID2, &json!({})).is_err());
        assert!(dispatch_argv("move", ID2, &json!({"x": 1})).is_err());
        assert!(dispatch_argv("resize", ID2, &json!({"w": 0, "h": 0})).is_err());
        assert!(dispatch_argv("resize", ID2, &json!({})).is_err());
        // No relative-resize form exists in kdotool - honest error.
        assert!(dispatch_argv("resize", ID2, &json!({"dw": 5, "dh": 5})).is_err());
    }

    // ---- construction probes ----------------------------------------------

    #[test]
    fn with_pins_requires_kdotool() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(KdotoolWindow::with_pins(&pins).is_none());

        fake_kde(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = KdotoolWindow::with_pins(&pins).expect("kdotool pin resolves");
        assert!(w.kdotool.is_absolute());
    }

    #[test]
    fn new_is_none_outside_kde_session() {
        // SAFETY: test-only env mutation, restored before returning -
        // the same pattern the sibling gate tests in x11_window.rs /
        // clipboard.rs use.
        let saved_v = std::env::var_os("KDE_SESSION_VERSION");
        let saved_d = std::env::var_os("XDG_CURRENT_DESKTOP");
        unsafe {
            std::env::remove_var("KDE_SESSION_VERSION");
            std::env::remove_var("XDG_CURRENT_DESKTOP");
        }
        assert!(KdotoolWindow::new().is_none());
        if let Some(v) = saved_v {
            unsafe { std::env::set_var("KDE_SESSION_VERSION", v) };
        }
        if let Some(v) = saved_d {
            unsafe { std::env::set_var("XDG_CURRENT_DESKTOP", v) };
        }
    }

    #[test]
    fn kde_session_gate_forms() {
        // The gate itself: version marker, or a kde/plasma desktop name.
        // (Read directly so no env mutation is needed - `kde_session`
        // reads process env, so only the absent-env case is asserted;
        // the marker-present paths are covered implicitly by detection.)
        let saved_v = std::env::var_os("KDE_SESSION_VERSION");
        let saved_d = std::env::var_os("XDG_CURRENT_DESKTOP");
        unsafe {
            std::env::remove_var("KDE_SESSION_VERSION");
            std::env::set_var("XDG_CURRENT_DESKTOP", "KDE:wayland");
        }
        assert!(kde_session().is_some());
        unsafe { std::env::set_var("XDG_CURRENT_DESKTOP", "sway") };
        assert!(kde_session().is_none());
        unsafe { std::env::set_var("KDE_SESSION_VERSION", "6") };
        assert!(kde_session().is_some());
        if let Some(v) = saved_v {
            unsafe { std::env::set_var("KDE_SESSION_VERSION", v) };
        } else {
            unsafe { std::env::remove_var("KDE_SESSION_VERSION") };
        }
        if let Some(v) = saved_d {
            unsafe { std::env::set_var("XDG_CURRENT_DESKTOP", v) };
        } else {
            unsafe { std::env::remove_var("XDG_CURRENT_DESKTOP") };
        }
    }

    // ---- hermetic spawn paths (fake kdotool via resolve_in) ---------------

    #[tokio::test]
    async fn list_windows_parses_and_enriches() {
        let dir = tempfile::tempdir().unwrap();
        fake_kde(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = KdotoolWindow::with_pins(&pins).unwrap();

        let windows = w.list_windows().await.unwrap();
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].id, ID1);
        assert_eq!(windows[0].title, "notes: onboarding");
        assert_eq!(windows[0].class, "kitty");
        assert_eq!(windows[0].workspace, 1);
        assert_eq!(
            windows[0].rect,
            Rect {
                x: 10,
                y: 45,
                w: 625,
                h: 745
            }
        );
        assert_eq!(windows[0].pid, Some(37381));
        // The negative-position record parses through.
        assert_eq!(windows[1].rect.x, -5);
        assert!(windows[1].focused);
        assert!(!windows[0].focused);
        // Panel: onAllDesktops -> -1 (sticky convention), unreported pid.
        assert_eq!(windows[2].workspace, -1);
        assert_eq!(windows[2].pid, None);
        // No kdotool readout exists for these.
        assert!(
            windows
                .iter()
                .all(|x| x.floating.is_none() && x.fullscreen.is_none() && x.monitor.is_none())
        );
    }

    #[tokio::test]
    async fn active_window_describes_focused_id() {
        let dir = tempfile::tempdir().unwrap();
        fake_kde(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = KdotoolWindow::with_pins(&pins).unwrap();

        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, ID2);
        assert_eq!(active.title, "notes: planning");
        assert!(active.focused);
        assert_eq!(active.pid, Some(37382));
        assert_eq!(active.workspace, 2);

        // A vanished active window (empty describe) still yields a
        // minimal record rather than being dropped.
        for getter in [
            "getwindowname",
            "getwindowclassname",
            "getwindowgeometry",
            "getwindowpid",
            "get_desktop_for_window",
        ] {
            std::fs::remove_file(dir.path().join(format!("{getter}-{ID2}"))).ok();
        }
        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, ID2);
        assert_eq!(active.title, "");
        assert_eq!(active.workspace, -1);
        assert!(active.focused);
    }

    #[tokio::test]
    async fn active_window_none_when_helper_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(
            dir.path(),
            "kdotool",
            "#!/bin/sh\ncase \"$1\" in getactivewindow) exit 1;; esac\nexit 0\n",
        );
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = KdotoolWindow::with_pins(&pins).unwrap();
        assert!(w.active_window().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dispatch_routes_to_kdotool() {
        let dir = tempfile::tempdir().unwrap();
        fake_kde(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = KdotoolWindow::with_pins(&pins).unwrap();

        w.dispatch("focus", ID2, &json!({})).await.unwrap();
        w.dispatch("close", ID2, &json!({})).await.unwrap();
        w.dispatch("minimize", ID2, &json!({})).await.unwrap();
        w.dispatch("move", ID2, &json!({"x": 1, "y": 2}))
            .await
            .unwrap();
        w.dispatch("resize", ID2, &json!({"w": 3, "h": 4}))
            .await
            .unwrap();

        let log = kdotool_log(dir.path());
        assert_eq!(
            log,
            vec![
                format!("windowactivate {ID2}"),
                format!("windowclose {ID2}"),
                format!("windowminimize {ID2}"),
                format!("windowmove {ID2} 1 2"),
                format!("windowsize {ID2} 3 4"),
            ]
        );

        // A malformed id fails before any spawn.
        let n = log.len();
        assert!(w.dispatch("focus", "%1", &json!({})).await.is_err());
        assert!(w.dispatch("focus", "bogus id", &json!({})).await.is_err());
        assert_eq!(kdotool_log(dir.path()).len(), n);
    }
}
