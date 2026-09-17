//! river `WindowProvider` - `riverctl` subprocess for geometry, plus
//! `wlr-foreign-toplevel` delegation for everything river cannot do.
//!
//! river exposes **no window-list IPC**: `riverctl` manages the *focused*
//! view and the layout engine, full stop. But river is wlroots-based and
//! advertises `zwlr_foreign_toplevel_manager_v1`, so enumeration and
//! per-window activate/close/min/max/fullscreen route through
//! [`crate::providers::wlr_toplevel`] when the protocol is present
//! (probed once at construction):
//!
//! - `list_windows` / `active_window` delegate to foreign-toplevel;
//!   without it they return `Err` explaining the gap.
//! - `dispatch` geometry (`move`/`resize`, relative deltas) stays on
//!   `riverctl` against the focused view - foreign-toplevel has no
//!   geometry verbs.
//! - `dispatch` for `focus`/`close`/`minimize`/`maximize`/`fullscreen`
//!   (and the un- variants) goes to foreign-toplevel, which can address
//!   `wlr-toplevel-N` ids, not just the focused view. `close` on
//!   `"focused"`/empty stays on `riverctl close` - the proven path.
//!
//! Dispatch mapping (closed set - `run`, `spawn`, `map`, `send-to-output`,
//! `focus-output`, `focus-view`, `zoom`, `toggle-float`, `set-cursor-warp`
//! and every other `riverctl` verb are unreachable through
//! [`WindowProvider::dispatch`]):
//!
//! - `close` -> `riverctl close` (the focused view).
//! - `move` -> `riverctl move <left|right|up|down> <delta>` - relative
//!   only (`dx,dy`, dominant axis wins), deltas clamped to ±8192.
//!   riverctl moves are floating-view ops; on a tiled focus the
//!   compositor simply no-ops them. Absolute `x,y` has no riverctl
//!   form -> honest error.
//! - `resize` -> `riverctl resize <horizontal|vertical> <delta>` - one
//!   spawn per nonzero axis (`dw`/`dh`), deltas clamped to ±8192. No
//!   absolute `w,h` form exists -> honest error.
//! - `focus` -> error: riverctl's `focus-view` only cycles the stack,
//!   it cannot focus a specific window - and every dispatch call here
//!   already targets the focused view, making it a no-op at best.
//! - `minimize` -> error: river has no minimized state.
//!
//! Every spawn is the canonicalized absolute path pinned by
//! [`crate::security::whitelist`] at construction, under the scrubbed
//! environment + per-spawn timeout of [`crate::security::spawn`]. No
//! shell is involved - the closed match builds only the verbs above.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::security::{spawn, whitelist};
use crate::traits::{WindowInfo, WindowProvider};

/// river window management: `riverctl` for focused-view geometry,
/// `wlr-foreign-toplevel` for enumeration and per-window ops.
pub struct RiverWindow {
    /// Pinned `riverctl` - every geometry dispatch spawns it.
    riverctl: PathBuf,
    /// Whether `zwlr_foreign_toplevel_manager_v1` probed at construction.
    /// Stored (not re-probed per call) so hermetic tests never touch a
    /// real Wayland socket.
    toplevel: bool,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RiverWindow>();
};

/// Session gate: a live river session marker - `XDG_CURRENT_DESKTOP`
/// containing `river`, matching `SessionKind::River` detection. The
/// window ladder only reaches this provider on river sessions; the
/// check is the last-resort guard for direct [`RiverWindow::new`]
/// callers.
fn river_session() -> Option<()> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .ok()?
        .to_ascii_lowercase();
    desktop.contains("river").then_some(())
}

/// Pinned `<bin> <args>` -> stdout bytes; non-zero exit is an error.
/// (Sibling copies live in `kdotool_window.rs` / `x11_window.rs` /
/// `clipboard.rs`.)
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

impl RiverWindow {
    /// Available iff a river session marker is present and `riverctl`
    /// was pinned on `PATH` at construction.
    pub fn new() -> Option<Self> {
        river_session()?;
        Self::with_toplevel(&whitelist::resolve_binaries(), toplevel_available())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the river
    /// session gate - the testable seam: hermetic tests resolve a fresh
    /// `PinnedBins` over a tempdir `PATH` and exercise the real spawn
    /// paths without mutating process env. `toplevel` stays off here;
    /// [`Self::with_toplevel`] flips it for routing tests.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Self::with_toplevel(pins, false)
    }

    /// [`Self::with_pins`] with an explicit foreign-toplevel flag - the
    /// routing unit tests' seam (never constructs a real connection).
    pub fn with_toplevel(pins: &whitelist::PinnedBins, toplevel: bool) -> Option<Self> {
        Some(Self {
            riverctl: pins.get("riverctl")?.to_path_buf(),
            toplevel,
        })
    }
}

/// Where a `dispatch` call routes.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// `riverctl` subprocess on the focused view (geometry).
    Riverctl,
    /// `wlr-foreign-toplevel` on a tracked handle (enumeration-backed ops).
    Toplevel,
}

/// Does the compositor advertise `zwlr_foreign_toplevel_manager_v1`?
/// Off under no-wayland builds so `RiverWindow::new` still works.
fn toplevel_available() -> bool {
    #[cfg(feature = "wayland")]
    return crate::providers::wlr_toplevel::probe().is_ok();
    #[cfg(not(feature = "wayland"))]
    return false;
}

/// Routing table: geometry is `riverctl`-only (foreign-toplevel has no
/// geometry verbs); everything else is foreign-toplevel when available -
/// it can address `wlr-toplevel-N` ids, where riverctl is focused-view
/// only. `close` on the focused view keeps the proven `riverctl` path.
/// Non-indexed ids must name the focused view - a bogus id never
/// silently retargets it.
fn route(action: &str, window_id: &str, toplevel: bool) -> Result<Route> {
    let indexed = window_id.starts_with("wlr-toplevel-");
    if !indexed && !window_id.is_empty() && window_id != "focused" {
        bail!(
            "river: window id '{window_id}' is not addressable - \"focused\" or a wlr-toplevel-N id"
        );
    }
    match action {
        // Geometry: riverctl, focused-view only - an indexed id can never
        // be the target (river cannot move unfocused views).
        "move" | "resize" => {
            if indexed {
                bail!("river: move/resize act on the focused view only - pass \"focused\"");
            }
            Ok(Route::Riverctl)
        }
        // riverctl `close` is the proven path for the focused view.
        "close" if !indexed => Ok(Route::Riverctl),
        _ if toplevel => Ok(Route::Toplevel),
        _ if indexed => {
            bail!(
                "river: `{window_id}` needs wlr-foreign-toplevel, which this compositor did not advertise"
            )
        }
        _ => {
            bail!("river: `{action}` has no riverctl form and wlr-foreign-toplevel is unavailable")
        }
    }
}

#[async_trait]
impl WindowProvider for RiverWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        if self.toplevel {
            #[cfg(feature = "wayland")]
            return tokio::task::spawn_blocking(crate::providers::wlr_toplevel::enumerate).await?;
        }
        bail!(
            "river: no window-list IPC - riverctl manages the focused view and layout only; there is no way to enumerate windows"
        )
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        if self.toplevel {
            #[cfg(feature = "wayland")]
            return Ok(
                tokio::task::spawn_blocking(crate::providers::wlr_toplevel::enumerate)
                    .await??
                    .into_iter()
                    .find(|w| w.focused),
            );
        }
        bail!(
            "river: cannot report the focused window - riverctl exposes no way to read the focused view's title/app-id"
        )
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        match route(action, window_id, self.toplevel)? {
            Route::Riverctl => {
                for argv in dispatch_plan(action, args)? {
                    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
                    run(&self.riverctl, &argv).await?;
                }
                Ok(())
            }
            #[cfg(feature = "wayland")]
            Route::Toplevel => {
                let action = action.to_string();
                let id = if window_id.is_empty() {
                    crate::providers::wlr_toplevel::FOCUSED_SELECTOR.to_string()
                } else {
                    window_id.to_string()
                };
                let args = args.clone();
                tokio::task::spawn_blocking(move || {
                    crate::providers::wlr_toplevel::dispatch_op(&action, &id, &args)
                })
                .await?
            }
            #[cfg(not(feature = "wayland"))]
            Route::Toplevel => unreachable!("toplevel routing requires the wayland feature"),
        }
    }

    fn focused_view_selector(&self) -> Option<&'static str> {
        Some("focused")
    }
}

/// Bound on a single move/resize delta - river deltas are pixel counts;
/// ±8192 covers any real monitor several times over while keeping a
/// typo'd argument from producing an absurd compositor request.
const MAX_DELTA: i64 = 8192;

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// Build the `riverctl` argv list for a `dispatch` action (one argv
/// per spawn). Fixed mapping only - see the module docs for what is
/// deliberately unreachable.
fn dispatch_plan(action: &str, args: &Value) -> Result<Vec<Vec<String>>> {
    let plan: Vec<Vec<String>> = match action {
        "close" => vec![vec!["close".into()]],
        "move" => {
            let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) else {
                if arg_i64(args, "x").is_some() || arg_i64(args, "y").is_some() {
                    bail!("river: absolute move has no riverctl form - pass dx,dy")
                }
                bail!("river: move requires dx,dy")
            };
            if dx == 0 && dy == 0 {
                bail!("river: move requires a nonzero dx or dy")
            }
            // riverctl moves along one axis per invocation - the
            // dominant axis carries the request, and the direction
            // word encodes the sign so the delta is a magnitude.
            let (dir, delta) = if dx.abs() >= dy.abs() {
                (if dx > 0 { "right" } else { "left" }, dx)
            } else {
                (if dy > 0 { "down" } else { "up" }, dy)
            };
            vec![vec![
                "move".into(),
                dir.into(),
                delta.abs().clamp(0, MAX_DELTA).to_string(),
            ]]
        }
        "resize" => {
            if arg_i64(args, "w").is_some() || arg_i64(args, "h").is_some() {
                bail!("river: absolute resize has no riverctl form - pass dw,dh")
            }
            let mut cmds = Vec::new();
            for (key, axis) in [("dw", "horizontal"), ("dh", "vertical")] {
                if let Some(d) = arg_i64(args, key)
                    && d != 0
                {
                    cmds.push(vec![
                        "resize".into(),
                        axis.into(),
                        d.clamp(-MAX_DELTA, MAX_DELTA).to_string(),
                    ]);
                }
            }
            if cmds.is_empty() {
                bail!("river: resize requires a nonzero dw or dh")
            }
            cmds
        }
        // riverctl can only cycle focus (`focus-view next`) - a
        // specific-window focus does not exist. Reachable only when
        // foreign-toplevel is absent (otherwise `route` sent `focus` to
        // the toplevel path).
        "focus" => bail!("river: cannot focus a specific window - the focused view is implicit"),
        // river has no minimized/iconic window state (foreign-toplevel
        // `set_minimized` handles it when advertised).
        "minimize" => {
            bail!("river: no minimize state - 'toggle-float'/'send-to-output' are not minimize")
        }
        other => bail!("river: unsupported dispatch action '{other}'"),
    };
    Ok(plan)
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

    /// Fake `riverctl`: logs every invocation's argv to
    /// `<dir>/riverctl.log` and exits with the status in
    /// `<dir>/exit.code` (default 0).
    fn riverctl_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             echo \"$@\" >> \"$d/riverctl.log\"\n\
             code=$(cat \"$d/exit.code\" 2>/dev/null || echo 0)\n\
             exit \"$code\"\n",
            d = dir.display()
        )
    }

    fn riverctl_log(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("riverctl.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn fake_river(dir: &Path) {
        write_exe(dir, "riverctl", &riverctl_script(dir));
    }

    fn river(dir: &Path) -> RiverWindow {
        let pins = whitelist::PinnedBins::resolve_in(&[dir.to_path_buf()]);
        RiverWindow::with_pins(&pins).expect("riverctl pin resolves")
    }

    // ---- pure mapping -------------------------------------------------

    #[test]
    fn route_rejects_foreign_ids() {
        for bad in ["0", "12", "0x3", "focus", "focused;rm", "all"] {
            for toplevel in [false, true] {
                assert!(
                    route("close", bad, toplevel).is_err(),
                    "id {bad:?} must be rejected (toplevel={toplevel})"
                );
                assert!(
                    route("focus", bad, toplevel).is_err(),
                    "id {bad:?} must be rejected (toplevel={toplevel})"
                );
            }
        }
    }

    #[test]
    fn route_table() {
        // Geometry always routes to riverctl on the focused view.
        for toplevel in [false, true] {
            assert_eq!(route("move", "focused", toplevel).unwrap(), Route::Riverctl);
            assert_eq!(route("resize", "", toplevel).unwrap(), Route::Riverctl);
            assert!(route("move", "wlr-toplevel-0", toplevel).is_err());
        }
        // close on the focused view keeps the proven riverctl path.
        for toplevel in [false, true] {
            assert_eq!(
                route("close", "focused", toplevel).unwrap(),
                Route::Riverctl
            );
            assert_eq!(route("close", "", toplevel).unwrap(), Route::Riverctl);
        }
        // Without toplevel: non-geometry non-close ops are honest errors.
        for action in ["focus", "minimize", "maximize", "fullscreen"] {
            assert!(route(action, "focused", false).is_err(), "{action}");
        }
        assert!(route("close", "wlr-toplevel-0", false).is_err());
        // With toplevel: those same ops route to foreign-toplevel, on
        // focused and indexed selectors alike.
        for action in ["focus", "minimize", "maximize", "fullscreen", "close"] {
            assert_eq!(
                route(action, "wlr-toplevel-2", true).unwrap(),
                Route::Toplevel,
                "{action}"
            );
        }
        for action in ["focus", "minimize"] {
            assert_eq!(
                route(action, "focused", true).unwrap(),
                Route::Toplevel,
                "{action}"
            );
        }
    }

    #[test]
    fn dispatch_plan_maps_supported_actions() {
        assert_eq!(
            dispatch_plan("close", &json!({})).unwrap(),
            vec![vec!["close"]]
        );
        // Dominant axis wins for move.
        assert_eq!(
            dispatch_plan("move", &json!({"dx": 50, "dy": -10})).unwrap(),
            vec![vec!["move", "right", "50"]]
        );
        assert_eq!(
            dispatch_plan("move", &json!({"dx": -5, "dy": -40})).unwrap(),
            vec![vec!["move", "up", "40"]]
        );
        // One spawn per nonzero resize axis.
        assert_eq!(
            dispatch_plan("resize", &json!({"dw": 20})).unwrap(),
            vec![vec!["resize", "horizontal", "20"]]
        );
        assert_eq!(
            dispatch_plan("resize", &json!({"dw": 20, "dh": -40})).unwrap(),
            vec![
                vec!["resize", "horizontal", "20"],
                vec!["resize", "vertical", "-40"]
            ]
        );
    }

    #[test]
    fn dispatch_plan_clamps_deltas() {
        assert_eq!(
            dispatch_plan("move", &json!({"dx": 0, "dy": 99999})).unwrap(),
            vec![vec!["move", "down", "8192"]]
        );
        assert_eq!(
            dispatch_plan("resize", &json!({"dw": -99999})).unwrap(),
            vec![vec!["resize", "horizontal", "-8192"]]
        );
    }

    #[test]
    fn dispatch_plan_rejects_unmappable_forms() {
        // focus/minimize are honest gaps; absolute geometry has no
        // riverctl form; unknown actions never reach a spawn.
        for (action, args) in [
            ("focus", json!({})),
            ("minimize", json!({})),
            ("move", json!({"x": 1, "y": 2})),
            ("move", json!({"dx": 0, "dy": 0})),
            ("move", json!({})),
            ("resize", json!({"w": 100, "h": 100})),
            ("resize", json!({"dw": 0, "dh": 0})),
            ("resize", json!({})),
            ("run", json!({"cmd": "sh"})),
            ("focus-view", json!({})),
        ] {
            assert!(
                dispatch_plan(action, &args).is_err(),
                "{action} {args} must be rejected"
            );
        }
    }

    // ---- construction probes -------------------------------------------

    #[test]
    fn with_pins_requires_riverctl() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(RiverWindow::with_pins(&pins).is_none());

        fake_river(dir.path());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let w = RiverWindow::with_pins(&pins).expect("riverctl pin resolves");
        assert!(w.riverctl.is_absolute());
    }

    #[test]
    fn new_is_none_outside_river_session() {
        // SAFETY: test-only env mutation, restored before returning -
        // the same pattern the sibling gate tests use.
        let saved = std::env::var_os("XDG_CURRENT_DESKTOP");
        unsafe { std::env::remove_var("XDG_CURRENT_DESKTOP") };
        assert!(RiverWindow::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("XDG_CURRENT_DESKTOP", v) };
        }
    }

    // ---- hermetic spawn paths -------------------------------------------

    #[tokio::test]
    async fn list_and_active_are_honest_errors() {
        let dir = tempfile::tempdir().unwrap();
        fake_river(dir.path());
        let w = river(dir.path());

        let err = w.list_windows().await.unwrap_err();
        assert!(format!("{err}").contains("no window-list IPC"), "{err}");
        let err = w.active_window().await.unwrap_err();
        assert!(format!("{err}").contains("focused"), "{err}");
        // Nothing was spawned - the capability does not exist, so there
        // is no graceful riverctl fallback to attempt.
        assert!(riverctl_log(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn dispatch_routes_to_riverctl() {
        let dir = tempfile::tempdir().unwrap();
        fake_river(dir.path());
        let w = river(dir.path());

        w.dispatch("close", "focused", &json!({})).await.unwrap();
        // Empty id is the same focused-view selector.
        w.dispatch("move", "", &json!({"dx": -10, "dy": 5}))
            .await
            .unwrap();
        w.dispatch("resize", "focused", &json!({"dw": 20, "dh": -30}))
            .await
            .unwrap();

        assert_eq!(
            riverctl_log(dir.path()),
            vec![
                "close",
                "move left 10",
                "resize horizontal 20",
                "resize vertical -30",
            ]
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_foreign_ids_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        fake_river(dir.path());
        let w = river(dir.path());

        for bad in ["0", "12", "0x3", "all", "focused;rm"] {
            assert!(
                w.dispatch("close", bad, &json!({})).await.is_err(),
                "id {bad:?} must be rejected"
            );
        }
        // And the honest gaps never spawn either.
        assert!(w.dispatch("focus", "focused", &json!({})).await.is_err());
        assert!(w.dispatch("minimize", "focused", &json!({})).await.is_err());
        assert!(riverctl_log(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn dispatch_surfaces_nonzero_exit() {
        let dir = tempfile::tempdir().unwrap();
        fake_river(dir.path());
        std::fs::write(dir.path().join("exit.code"), "1").unwrap();
        let w = river(dir.path());
        let err = w
            .dispatch("close", "focused", &json!({}))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("exited"), "{err}");
    }
}
