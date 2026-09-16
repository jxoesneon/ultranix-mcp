//! GNOME Shell `WindowProvider` - the "Window Calls" extension over the
//! session D-Bus.
//!
//! Mutter exposes no public compositor window-management IPC (the
//! documented GNOME gap), and `org.gnome.Shell`'s `Eval` method is an
//! arbitrary-JavaScript primitive that is both commonly disabled and a
//! security hazard - it is deliberately **not**used here. The de-facto
//! standard bridge is the community "Window Calls" Shell extension
//! (<https://github.com/ickyicky/window-calls>, EGO extension 4724,
//! <https://extensions.gnome.org/extension/4724/window-calls/>), which
//! exports an object on the shell's own bus connection:
//!
//! * bus name: `org.gnome.Shell`
//! * object path: `/org/gnome/Shell/Extensions/Windows`
//! * interface: `org.gnome.Shell.Extensions.Windows`
//!
//! Install: `gnome-extensions install <window-calls zip>` (or via
//! Extension Manager / the EGO page above), then log out/in on Wayland.
//! When the extension is absent the constructor probe declines and the
//! ladder falls through to the next rung (or `ProviderUnavailable`).
//!
//! `List()` returns a JSON array - per the extension source the fields
//! are `id` (u32), `title`, `wm_class`, `wm_class_instance`, `pid`,
//! `frame_type`, `window_type`, `x`, `y`, `width`, `height`, `focus`
//! (bool), `in_current_workspace` (bool) and `workspace` (i32 index,
//! `-1` for sticky/all-workspace windows); `monitor` appears on some
//! versions. All fields are parsed defensively - extras are ignored,
//! missing ones default.
//!
//! Dispatch mapping (all verified against the extension's
//! `extension.js` D-Bus XML):
//!
//! | action                | method               | args            |
//! |-----------------------|----------------------|-----------------|
//! | `focus`               | `Activate`           | `(u)`           |
//! | `close`               | `Close`              | `(u)`           |
//! | `minimize`            | `Minimize`           | `(u)`           |
//! | `unminimize`          | `Unminimize`         | `(u)`           |
//! | `maximize`            | `Maximize`           | `(u)`           |
//! | `unmaximize`          | `Unmaximize`         | `(u)`           |
//! | `fullscreen`          | `MakeFullscreen`     | `(u)`           |
//! | `above`               | `MakeAbove`          | `(u)`           |
//! | `unabove`             | `UnmakeAbove`        | `(u)`           |
//! | `move` (`x`,`y`)      | `Move`               | `(u,i,i)`       |
//! | `move` (`dx`,`dy`)    | `Move`               | `(u,i,i)`       |
//! | `resize` (`w`,`h`)    | `Resize`             | `(u,u,u)`       |
//! | `resize` (`dw`,`dh`)  | `Resize`             | `(u,u,u)`       |
//! | `resize` (x,y,w,h)    | `MoveResize`         | `(u,i,i,u,u)`   |
//! | `move_to_workspace`   | `MoveToWorkspace`    | `(u,u)`         |
//!
//! Semantics notes (honest mappings):
//!
//! * `WindowInfo.id` is the decimal meta-window id (`u32`) - the same
//!   id every method takes as `winid`.
//! * `Activate` raises the window on its workspace and switches to that
//!   workspace (extension calls `workspace.activate_with_focus`).
//! * `Move`/`Resize`/`MoveResize` silently unmaximize first (extension
//!   behavior); GNOME has no floating/tiled distinction - `floating`
//!   reports `None`. `fullscreen` also reports `None`: `List()` does
//!   not carry it (`Details(winid)` does, but per-window calls would
//!   make `list_windows` O(N) round-trips - not worth it).
//! * Relative ops (`dx,dy`/`dw,dh`) anchor on the live `List()`
//!   geometry, mirroring `sway_window`.
//! * Everything else - `Details`, `GetTitle`, `GetFrameRect`,
//!   `GetFrameBounds` - is reachable on the bus but unused; the trait
//!   surface needs none of them.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use atspi::zbus::{self, zvariant};
use serde_json::Value;

use crate::traits::{Rect, WindowInfo, WindowProvider};

/// The shell owns the well-known name; the extension only exports the
/// object on the shell's connection.
const SHELL_BUS_NAME: &str = "org.gnome.Shell";
const WINDOWS_PATH: &str = "/org/gnome/Shell/Extensions/Windows";
const WINDOWS_IFACE: &str = "org.gnome.Shell.Extensions.Windows";
const INTROSPECT_IFACE: &str = "org.freedesktop.DBus.Introspectable";

/// Per-call D-Bus budget - a wedged shell must not hang a tool call.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on the `List()` JSON reply - a few hundred windows serialize
/// to tens of KiB; the cap mirrors wayfire's 1 MiB reply bound so a
/// hostile/buggy extension can't hand back an unbounded string.
const MAX_LIST_BYTES: usize = 1024 * 1024;

/// Probe budget: a session bus that cannot answer `Introspect` within
/// this window is treated as extension-less rather than stalling
/// startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// GNOME Shell window provider driven by the Window Calls D-Bus object.
///
/// Like [`crate::providers::atspi::AtspiUi`], the `zbus::Connection`
/// binds to the ambient tokio runtime - `new()` only *probes* (on a
/// private thread), and the real connection is established lazily on
/// first use.
pub struct GnomeShellWindow {
    conn: tokio::sync::OnceCell<zbus::Connection>,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GnomeShellWindow>();
};

impl GnomeShellWindow {
    /// Probe only: `Some` when the session bus is up and the Window
    /// Calls object introspects to `org.gnome.Shell.Extensions.Windows`
    /// (i.e. the extension is installed *and* enabled - a disabled
    /// extension unexports its object). No extension method is invoked.
    pub fn new() -> Option<Self> {
        if !windows_iface_present() {
            tracing::debug!("gnome-shell: {WINDOWS_IFACE} not introspectable");
            return None;
        }
        Some(Self {
            conn: tokio::sync::OnceCell::new(),
        })
    }

    /// Construct on a pre-built connection - the test seam for faking
    /// the bus and a hook for embedders that already hold one. Skips
    /// the probe; calls surface whatever the connection yields.
    pub fn with_connection(conn: zbus::Connection) -> Self {
        Self {
            conn: tokio::sync::OnceCell::new_with(Some(conn)),
        }
    }

    async fn conn(&self) -> Result<&zbus::Connection> {
        self.conn
            .get_or_try_init(|| async {
                wc_call(zbus::Connection::session())
                    .await
                    .context("session bus connect failed")
            })
            .await
    }

    /// One method call on the extension object; error replies surface
    /// as `Err` (unknown `winid` included - the extension throws).
    async fn call<B>(&self, method: &'static str, body: &B) -> Result<()>
    where
        B: serde::ser::Serialize + zvariant::DynamicType + Sync,
    {
        let conn = self.conn().await?;
        wc_call(conn.call_method(
            Some(SHELL_BUS_NAME),
            WINDOWS_PATH,
            Some(WINDOWS_IFACE),
            method,
            body,
        ))
        .await
        .with_context(|| format!("gnome-shell: {method} call failed"))?;
        Ok(())
    }

    /// `List()` -> raw JSON string.
    async fn list_json(&self) -> Result<String> {
        let conn = self.conn().await?;
        let reply = wc_call(conn.call_method(
            Some(SHELL_BUS_NAME),
            WINDOWS_PATH,
            Some(WINDOWS_IFACE),
            "List",
            &(),
        ))
        .await
        .context("gnome-shell: List call failed")?;
        let body = reply
            .body()
            .deserialize::<String>()
            .context("gnome-shell: List reply is not a string")?;
        if body.len() > MAX_LIST_BYTES {
            bail!(
                "gnome-shell: List reply too large ({} bytes > {MAX_LIST_BYTES})",
                body.len()
            );
        }
        Ok(body)
    }

    /// Live rect of `winid` - the anchor for relative `dx,dy`/`dw,dh`
    /// ops. `Err` when the id left the window list.
    async fn rect_of(&self, winid: u32) -> Result<Rect> {
        let json = self.list_json().await?;
        parse_window_list(&json)?
            .into_iter()
            .find(|w| w.id == winid.to_string())
            .map(|w| w.rect)
            .ok_or_else(|| anyhow!("gnome-shell: window id {winid} not found"))
    }

    async fn execute(&self, plan: Call) -> Result<()> {
        match plan {
            Call::Unary(method, winid) => self.call(method, &winid).await,
            Call::Move(winid, x, y) => self.call("Move", &(winid, x, y)).await,
            Call::Resize(winid, w, h) => self.call("Resize", &(winid, w, h)).await,
            Call::MoveResize(winid, x, y, w, h) => {
                self.call("MoveResize", &(winid, x, y, w, h)).await
            }
            Call::ToWorkspace(winid, ws) => self.call("MoveToWorkspace", &(winid, ws)).await,
        }
    }
}

#[async_trait]
impl WindowProvider for GnomeShellWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        parse_window_list(&self.list_json().await?)
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        Ok(self.list_windows().await?.into_iter().find(|w| w.focused))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        let winid = parse_winid(window_id)?;
        // Relative ops anchor on live geometry - fetched lazily so the
        // common paths stay single-call.
        let rect = if needs_rect(action, args) {
            Some(self.rect_of(winid).await?)
        } else {
            None
        };
        self.execute(action_plan(action, winid, args, rect)?).await
    }
}

// ---------- bus plumbing ----------

/// Run a D-Bus future under [`CALL_TIMEOUT`]; elapsed surfaces as an
/// error, keeping every shell interaction bounded.
async fn wc_call<F, T, E>(fut: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout(CALL_TIMEOUT, fut).await {
        Err(_) => Err(anyhow!(
            "gnome-shell D-Bus call timed out after {CALL_TIMEOUT:?}"
        )),
        Ok(Err(e)) => Err(anyhow::Error::new(e)),
        Ok(Ok(v)) => Ok(v),
    }
}

/// `true` when the extension object exists and advertises
/// [`WINDOWS_IFACE`]. Runs on a private thread + throwaway runtime -
/// like `portal_name_owned`, a `zbus::Connection` made here would bind
/// to a dead runtime and could not be reused anyway. One `Introspect`
/// call covers every absence shape: no session bus, `org.gnome.Shell`
/// unowned (non-GNOME session), or object not exported (extension not
/// installed/enabled) - all surface as call errors or missing-XML.
fn windows_iface_present() -> bool {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(async {
            tokio::time::timeout(PROBE_TIMEOUT, async {
                let bus = zbus::Connection::session().await.ok()?;
                let reply = bus
                    .call_method(
                        Some(SHELL_BUS_NAME),
                        WINDOWS_PATH,
                        Some(INTROSPECT_IFACE),
                        "Introspect",
                        &(),
                    )
                    .await
                    .ok()?;
                let xml: String = reply.body().deserialize().ok()?;
                Some(xml.contains(WINDOWS_IFACE))
            })
            .await
            .ok()
            .flatten()
        })
    })
    .join()
    .ok()
    .flatten()
    .unwrap_or(false)
}

// ---------- List() parsing ----------

/// Parse a `List()` JSON payload into window records. Non-array input
/// is an error (a violated contract, not an empty session); array
/// entries missing `id` are skipped - every D-Bus op keys on it, so an
/// id-less record is dead weight. Everything else defaults.
fn parse_window_list(json: &str) -> Result<Vec<WindowInfo>> {
    let v: Value = serde_json::from_str(json).context("gnome-shell: bad List JSON")?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("gnome-shell: List reply is not an array"))?;
    Ok(arr.iter().filter_map(entry_to_info).collect())
}

/// One `List()` entry -> [`WindowInfo`]. `id` is required; `class` is
/// `wm_class` with the `wm_class_instance` fallback.
fn entry_to_info(w: &Value) -> Option<WindowInfo> {
    let id = w.get("id").and_then(Value::as_u64)?;
    let i64_at = |key: &str| w.get(key).and_then(Value::as_i64).unwrap_or(0) as i32;
    Some(WindowInfo {
        id: id.to_string(),
        title: w
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        class: w
            .get("wm_class")
            .and_then(Value::as_str)
            .or_else(|| w.get("wm_class_instance").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string(),
        // `-1` marks sticky (all-workspaces) windows - the extension
        // reports the same sentinel when `get_workspace()` yields null.
        workspace: w.get("workspace").and_then(Value::as_i64).unwrap_or(-1) as i32,
        rect: Rect {
            x: i64_at("x"),
            y: i64_at("y"),
            w: i64_at("width"),
            h: i64_at("height"),
        },
        focused: w.get("focus").and_then(Value::as_bool).unwrap_or(false),
        // Neither is in the List() payload - see module docs.
        floating: None,
        fullscreen: None,
        pid: w.get("pid").and_then(Value::as_i64),
        monitor: w.get("monitor").and_then(Value::as_i64),
    })
}

// ---------- dispatch mapping ----------

/// A fully-planned extension call - the unit-testable output of
/// [`action_plan`]. Tuple bodies serialize as a top-level D-Bus
/// structure (`(u,i,i)`), which GIO receivers treat identically to
/// bare multi-arg bodies - the same convention `portal_input` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// `(u)` methods: `Activate`, `Close`, `Minimize`, `Unminimize`,
    /// `Maximize`, `Unmaximize`, `MakeFullscreen`, `MakeAbove`,
    /// `UnmakeAbove`.
    Unary(&'static str, u32),
    /// `Move(u, i, i)` - absolute position.
    Move(u32, i32, i32),
    /// `Resize(u, u, u)` - width, height.
    Resize(u32, u32, u32),
    /// `MoveResize(u, i, i, u, u)` - absolute position + size.
    MoveResize(u32, i32, i32, u32, u32),
    /// `MoveToWorkspace(u, u)` - workspace index.
    ToWorkspace(u32, u32),
}

/// Window ids are decimal u32 (`MetaWindow::get_id`); restricting to
/// ASCII digits keeps the id a single typed arg - there is no string
/// interpolation anywhere in this backend.
fn parse_winid(id: &str) -> Result<u32> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        bail!("gnome-shell: invalid window id '{id}' - window ids are decimal")
    }
    id.parse()
        .map_err(|_| anyhow!("gnome-shell: window id '{id}' out of range (u32)"))
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// `true` when the action plan needs the window's live rect - relative
/// `move`/`resize` forms only.
fn needs_rect(action: &str, args: &Value) -> bool {
    match action {
        "move" => args.get("dx").is_some() && !(args.get("x").is_some() && args.get("y").is_some()),
        "resize" => {
            (args.get("dw").is_some() || args.get("dh").is_some())
                && !(args.get("w").is_some() && args.get("h").is_some())
        }
        _ => false,
    }
}

/// Map a dispatch action onto the planned extension call. Closed set -
/// every other action bails.
fn action_plan(action: &str, winid: u32, args: &Value, rect: Option<Rect>) -> Result<Call> {
    let plan = match action {
        "focus" => Call::Unary("Activate", winid),
        "close" => Call::Unary("Close", winid),
        "minimize" => Call::Unary("Minimize", winid),
        "unminimize" => Call::Unary("Unminimize", winid),
        "maximize" => Call::Unary("Maximize", winid),
        "unmaximize" => Call::Unary("Unmaximize", winid),
        "fullscreen" => Call::Unary("MakeFullscreen", winid),
        "above" => Call::Unary("MakeAbove", winid),
        "unabove" => Call::Unary("UnmakeAbove", winid),
        "move" => {
            let to_i32 = |v: i64| -> Result<i32> {
                i32::try_from(v).map_err(|_| anyhow!("gnome-shell: move coord {v} out of range"))
            };
            if let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) {
                Call::Move(winid, to_i32(x)?, to_i32(y)?)
            } else if let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) {
                let r =
                    rect.ok_or_else(|| anyhow!("gnome-shell: move dx,dy needs live geometry"))?;
                Call::Move(
                    winid,
                    to_i32(i64::from(r.x) + dx)?,
                    to_i32(i64::from(r.y) + dy)?,
                )
            } else {
                bail!("gnome-shell: move requires x,y (or dx,dy)")
            }
        }
        "resize" => {
            let to_u32 = |v: i64, key: &str| -> Result<u32> {
                u32::try_from(v)
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or_else(|| anyhow!("gnome-shell: resize {key} must be >= 1"))
            };
            if let (Some(x), Some(y), Some(w), Some(h)) = (
                arg_i64(args, "x"),
                arg_i64(args, "y"),
                arg_i64(args, "w"),
                arg_i64(args, "h"),
            ) {
                Call::MoveResize(
                    winid,
                    i32::try_from(x).context("gnome-shell: resize x out of range")?,
                    i32::try_from(y).context("gnome-shell: resize y out of range")?,
                    to_u32(w, "w")?,
                    to_u32(h, "h")?,
                )
            } else if let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) {
                Call::Resize(winid, to_u32(w, "w")?, to_u32(h, "h")?)
            } else {
                // Relative resize - the extension takes absolute sizes
                // only, so anchor on live geometry like sway_window.
                let dw = arg_i64(args, "dw").unwrap_or(0);
                let dh = arg_i64(args, "dh").unwrap_or(0);
                if dw == 0 && dh == 0 {
                    bail!("gnome-shell: resize requires w,h (or dw,dh)")
                }
                let r =
                    rect.ok_or_else(|| anyhow!("gnome-shell: resize dw,dh needs live geometry"))?;
                Call::Resize(
                    winid,
                    to_u32(i64::from(r.w) + dw, "w")?,
                    to_u32(i64::from(r.h) + dh, "h")?,
                )
            }
        }
        "move_to_workspace" => {
            let ws = arg_i64(args, "workspace")
                .ok_or_else(|| anyhow!("gnome-shell: move_to_workspace requires workspace"))?;
            let ws =
                u32::try_from(ws).map_err(|_| anyhow!("gnome-shell: workspace must be >= 0"))?;
            Call::ToWorkspace(winid, ws)
        }
        other => bail!("gnome-shell: unsupported dispatch action '{other}'"),
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

    /// Shape mirrors a live `List()` reply: the extension's full field
    /// set plus an extra unknown field to prove it is ignored.
    const LIST: &str = r#"[
        {
            "wm_class": "Firefox",
            "wm_class_instance": "firefox",
            "pid": 4201,
            "id": 1610090767,
            "frame_type": 0,
            "window_type": 0,
            "title": "ultranix - GitHub",
            "x": 10,
            "y": 50,
            "width": 1910,
            "height": 1030,
            "focus": true,
            "in_current_workspace": true,
            "workspace": 0,
            "monitor": 0,
            "future_field": {"nested": true}
        },
        {
            "wm_class": "org.gnome.Terminal",
            "pid": 811,
            "id": 2205525109,
            "title": "eduardo@builder",
            "x": -8,
            "y": 1080,
            "width": 960,
            "height": 540,
            "focus": false,
            "in_current_workspace": false,
            "workspace": -1
        }
    ]"#;

    #[test]
    fn parse_list_full_shape() {
        let wins = parse_window_list(LIST).unwrap();
        assert_eq!(wins.len(), 2);
        let w = &wins[0];
        assert_eq!(w.id, "1610090767");
        assert_eq!(w.title, "ultranix - GitHub");
        assert_eq!(w.class, "Firefox");
        assert_eq!(w.workspace, 0);
        assert_eq!(
            w.rect,
            Rect {
                x: 10,
                y: 50,
                w: 1910,
                h: 1030
            }
        );
        assert!(w.focused);
        assert_eq!(w.floating, None);
        assert_eq!(w.fullscreen, None);
        assert_eq!(w.pid, Some(4201));
        assert_eq!(w.monitor, Some(0));
        // Sticky window: workspace -1, no monitor field.
        assert_eq!(wins[1].workspace, -1);
        assert_eq!(wins[1].monitor, None);
        assert_eq!(wins[1].rect.x, -8);
    }

    #[test]
    fn parse_list_tolerates_missing_fields() {
        let wins = parse_window_list(r#"[{"id": 7}]"#).unwrap();
        assert_eq!(wins.len(), 1);
        let w = &wins[0];
        assert_eq!(w.id, "7");
        assert_eq!(w.title, "");
        assert_eq!(w.class, "");
        assert_eq!(w.workspace, -1);
        assert_eq!(w.rect.w, 0);
        assert!(!w.focused);
        assert_eq!(w.pid, None);
    }

    #[test]
    fn parse_list_skips_idless_entries() {
        let wins = parse_window_list(r#"[{"title": "ghost"}, {"id": 3}]"#).unwrap();
        assert_eq!(wins.len(), 1);
        assert_eq!(wins[0].id, "3");
    }

    #[test]
    fn parse_list_rejects_non_arrays() {
        assert!(parse_window_list("{}").is_err());
        assert!(parse_window_list("not json").is_err());
        assert!(parse_window_list("null").is_err());
        assert_eq!(parse_window_list("[]").unwrap().len(), 0);
    }

    #[test]
    fn wm_class_instance_fallback() {
        let wins = parse_window_list(r#"[{"id": 1, "wm_class_instance": "inst"}]"#).unwrap();
        assert_eq!(wins[0].class, "inst");
    }

    #[test]
    fn winid_validation() {
        assert_eq!(parse_winid("1610090767").unwrap(), 1610090767);
        assert_eq!(parse_winid("0").unwrap(), 0);
        assert_eq!(parse_winid("4294967295").unwrap(), u32::MAX);
        for bad in [
            "",
            "abc",
            "-1",
            "+1",
            "1.5",
            "4294967296",
            "0x10",
            " 7",
            "7 ",
        ] {
            assert!(parse_winid(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn plan_unary_actions() {
        let args = json!({});
        let cases = [
            ("focus", "Activate"),
            ("close", "Close"),
            ("minimize", "Minimize"),
            ("unminimize", "Unminimize"),
            ("maximize", "Maximize"),
            ("unmaximize", "Unmaximize"),
            ("fullscreen", "MakeFullscreen"),
            ("above", "MakeAbove"),
            ("unabove", "UnmakeAbove"),
        ];
        for (action, method) in cases {
            assert_eq!(
                action_plan(action, 42, &args, None).unwrap(),
                Call::Unary(method, 42),
                "{action} should map to {method}"
            );
        }
    }

    #[test]
    fn plan_move_absolute_and_relative() {
        assert_eq!(
            action_plan("move", 9, &json!({"x": 100, "y": -20}), None).unwrap(),
            Call::Move(9, 100, -20)
        );
        // Relative needs the live rect anchor.
        let r = Rect {
            x: 10,
            y: 20,
            w: 100,
            h: 100,
        };
        assert_eq!(
            action_plan("move", 9, &json!({"dx": -5, "dy": 30}), Some(r)).unwrap(),
            Call::Move(9, 5, 50)
        );
        assert!(action_plan("move", 9, &json!({"dx": -5, "dy": 30}), None).is_err());
        assert!(action_plan("move", 9, &json!({"x": 1}), None).is_err());
        assert!(action_plan("move", 9, &json!({}), None).is_err());
        // Overflowing coordinates bail rather than wrapping.
        assert!(action_plan("move", 9, &json!({"x": 1, "y": i64::MAX}), None).is_err());
    }

    #[test]
    fn plan_resize_variants() {
        assert_eq!(
            action_plan("resize", 9, &json!({"w": 800, "h": 600}), None).unwrap(),
            Call::Resize(9, 800, 600)
        );
        assert_eq!(
            action_plan(
                "resize",
                9,
                &json!({"x": 0, "y": 0, "w": 800, "h": 600}),
                None
            )
            .unwrap(),
            Call::MoveResize(9, 0, 0, 800, 600)
        );
        let r = Rect {
            x: 0,
            y: 0,
            w: 500,
            h: 400,
        };
        assert_eq!(
            action_plan("resize", 9, &json!({"dw": -50, "dh": 100}), Some(r)).unwrap(),
            Call::Resize(9, 450, 500)
        );
        assert!(action_plan("resize", 9, &json!({"w": 0, "h": 5}), None).is_err());
        assert!(action_plan("resize", 9, &json!({"w": -5, "h": 5}), None).is_err());
        assert!(action_plan("resize", 9, &json!({}), None).is_err());
    }

    #[test]
    fn plan_workspace_and_unknown() {
        assert_eq!(
            action_plan("move_to_workspace", 9, &json!({"workspace": 3}), None).unwrap(),
            Call::ToWorkspace(9, 3)
        );
        assert!(action_plan("move_to_workspace", 9, &json!({}), None).is_err());
        assert!(action_plan("move_to_workspace", 9, &json!({"workspace": -1}), None).is_err());
        assert!(action_plan("exec", 9, &json!({}), None).is_err());
        assert!(action_plan("kill", 9, &json!({}), None).is_err());
    }

    #[test]
    fn needs_rect_only_for_relative_ops() {
        assert!(needs_rect("move", &json!({"dx": 1, "dy": 1})));
        assert!(!needs_rect("move", &json!({"x": 1, "y": 1})));
        assert!(needs_rect("resize", &json!({"dh": 1})));
        assert!(!needs_rect("resize", &json!({"w": 1, "h": 1})));
        assert!(!needs_rect("focus", &json!({"dx": 1})));
    }

    /// The tuple bodies the extension expects serialize to top-level
    /// D-Bus structure signatures - verified here so a zbus behavior
    /// change can't silently break the wire format.
    #[test]
    fn call_wire_signatures() {
        use zvariant::DynamicType;
        let sig = |plan: Call| -> String {
            match plan {
                Call::Unary(_, id) => id.signature(),
                Call::Move(id, x, y) => (id, x, y).signature(),
                Call::Resize(id, w, h) => (id, w, h).signature(),
                Call::MoveResize(id, x, y, w, h) => (id, x, y, w, h).signature(),
                Call::ToWorkspace(id, ws) => (id, ws).signature(),
            }
            .to_string()
        };
        assert_eq!(sig(Call::Unary("Activate", 1)), "u");
        assert_eq!(sig(Call::Move(1, 2, 3)), "(uii)");
        assert_eq!(sig(Call::Resize(1, 2, 3)), "(uuu)");
        assert_eq!(sig(Call::MoveResize(1, 2, 3, 4, 5)), "(uiiuu)");
        assert_eq!(sig(Call::ToWorkspace(1, 2)), "(uu)");
    }
}
