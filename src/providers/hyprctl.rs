//! Hyprland `WindowProvider` — compositor IPC equivalent to `hyprctl`.
//!
//! Two transports, probed once at construction ([`HyprctlWindow::new`]):
//!
//! * **Socket (preferred)** — `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock`
//!   (falling back to `/tmp/hypr/<HIS>/.socket.sock` when `XDG_RUNTIME_DIR` is
//!   unset). Wire format per the Hyprland IPC docs: write
//!   `[flags]/command args` (`j/clients`, `j/activewindow`, `dispatch …`),
//!   half-close, read the reply until EOF. Every request is a fresh
//!   connection — the compositor answers each connection synchronously, so a
//!   lingering socket would stall it.
//! * **`hyprctl` binary (fallback)** — the canonicalized absolute path of
//!   the `hyprctl` pinned from `PATH` at construction time (the same
//!   [`crate::security::whitelist`] resolver `SecurityContext` uses), so
//!   a later `PATH` hijack cannot substitute a trojan. Invoked as
//!   `hyprctl -j <sub>` / `hyprctl dispatch …` under a scrubbed
//!   environment ([`crate::security::spawn`]). Used only when the socket
//!   cannot be probed (e.g. an older compositor without the runtime dir).
//!
//! `dispatch` only ever emits the fixed dispatcher set
//! `focuswindow|movewindowpixel|resizewindowpixel|movetoworkspacesilent|closewindow`
//! — `exec` / `exec-once` are never reachable through this provider.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::traits::{Rect, WindowInfo, WindowProvider};

/// Bound on a single IPC round-trip; the compositor serves requests
/// synchronously, so a healthy reply is effectively instant.
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Hyprland window-management provider driven by compositor IPC.
pub struct HyprctlWindow {
    transport: Transport,
}

enum Transport {
    /// `<runtime>/hypr/<HIS>/.socket.sock`.
    Socket(PathBuf),
    /// `hyprctl` binary resolved on `PATH` at construction.
    Hyprctl(PathBuf),
}

impl HyprctlWindow {
    /// Construct only inside a live Hyprland session: requires
    /// `HYPRLAND_INSTANCE_SIGNATURE`, then cheap-probes the IPC socket
    /// (a connect-and-drop; Hyprland idles waiting for the request body)
    /// and finally the presence of `hyprctl` on `PATH`.
    pub fn new() -> Option<Self> {
        Self::with_pins(&crate::security::whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set — the testable
    /// seam: hermetic tests resolve a fresh `PinnedBins` over a tempdir
    /// `PATH` instead of the process-wide snapshot.
    pub fn with_pins(pins: &crate::security::whitelist::PinnedBins) -> Option<Self> {
        let his = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
        // The signature is joined into a socket path below — an absolute
        // or `..`-bearing value would escape the `…/hypr/` dir, so only
        // the real signature shape is accepted.
        if !valid_instance_signature(&his) {
            return None;
        }
        for path in socket_candidates(&his) {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Some(Self {
                    transport: Transport::Socket(path),
                });
            }
        }
        // Pin the whitelisted `hyprctl` once — the canonicalized path is
        // immune to a later `PATH` change (S-1).
        let bin = pins.get("hyprctl").map(Path::to_path_buf)?;
        Some(Self {
            transport: Transport::Hyprctl(bin),
        })
    }

    /// `hyprctl -j <sub>` (or `j/<sub>` on the socket) → parsed JSON.
    async fn query(&self, sub: &str) -> Result<Value> {
        let body = match &self.transport {
            Transport::Socket(path) => socket_request(path, &format!("j/{sub}")).await?,
            Transport::Hyprctl(bin) => hyprctl_run(bin, &["-j", sub]).await?,
        };
        let body = body.trim();
        if body.is_empty() {
            bail!("hyprland: empty reply for '{sub}'");
        }
        serde_json::from_str(body).with_context(|| format!("hyprland: bad JSON for '{sub}'"))
    }

    /// Send a `dispatch …` request; the socket replies `ok` on success.
    async fn send_dispatch(&self, request: &str) -> Result<()> {
        debug_assert!(request.starts_with("dispatch "));
        match &self.transport {
            Transport::Socket(path) => {
                let reply = socket_request(path, request).await?;
                if reply.trim() == "ok" {
                    Ok(())
                } else {
                    bail!("hyprland dispatch failed: {}", reply.trim())
                }
            }
            // Every token is provider-constructed and validated (fixed
            // dispatcher names, i64 geometry, alphanumeric window ids), so
            // a whitespace split into argv is injection-safe.
            Transport::Hyprctl(bin) => {
                let argv: Vec<&str> = request.split(' ').collect();
                let out = hyprctl_output(bin, &argv).await?;
                if out.status.success() {
                    Ok(())
                } else {
                    bail!(
                        "hyprctl dispatch failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                }
            }
        }
    }

    /// Address of the focused window, or `None` when unfocused/unreachable.
    async fn focused_address(&self) -> Option<String> {
        let v = self.query("activewindow").await.ok()?;
        let addr = v.get("address")?.as_str()?;
        if addr.is_empty() || addr == "0x0" {
            None
        } else {
            Some(addr.to_string())
        }
    }
}

#[async_trait]
impl WindowProvider for HyprctlWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        let clients = self.query("clients").await?;
        // A second round-trip marks `focused` by address; on failure fall
        // back to `focusHistoryID == 0` (most recently focused client).
        let focused = self.focused_address().await;
        parse_clients(&clients, focused.as_deref())
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        let v = self.query("activewindow").await?;
        parse_active(&v)
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        let request = dispatch_request(action, window_id, args)?;
        self.send_dispatch(&request).await
    }
}

// ---------- transports ----------

/// Real instance signatures are `[A-Za-z0-9_]+`; anything else (a path,
/// a `..` segment, whitespace) must never reach the socket-path join.
fn valid_instance_signature(his: &std::ffi::OsStr) -> bool {
    his.to_str()
        .is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Candidate socket paths: `$XDG_RUNTIME_DIR/hypr/<HIS>/` first, then the
/// `/tmp/hypr/<HIS>/` fallback Hyprland uses when the runtime dir is unset.
fn socket_candidates(his: &std::ffi::OsStr) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(2);
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
        && !rt.is_empty()
    {
        dirs.push(PathBuf::from(rt).join("hypr"));
    }
    dirs.push(PathBuf::from("/tmp/hypr"));
    dirs.into_iter()
        .map(|d| d.join(his).join(".socket.sock"))
        .filter(|p| p.exists())
        .collect()
}

/// One socket round-trip: connect, write the request verbatim, half-close,
/// read the reply to EOF. A fresh short-lived connection per request is
/// mandatory — an unclosed connection blocks the compositor's synchronous
/// IPC loop.
async fn socket_request(path: &Path, request: &str) -> Result<String> {
    let fut = async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        stream.write_all(request.as_bytes()).await?;
        stream.shutdown().await?;
        // Bound the reply size: an unresponsive/misbehaving compositor
        // must not grow an unbounded buffer.
        const MAX_REPLY: u64 = 64 * 1024 * 1024;
        let mut reply = String::new();
        stream.take(MAX_REPLY).read_to_string(&mut reply).await?;
        Ok::<String, anyhow::Error>(reply)
    };
    tokio::time::timeout(IPC_TIMEOUT, fut)
        .await
        .context("hyprland socket request timed out")?
}

/// Run the pinned `hyprctl <argv>` under the scrubbed spawn environment
/// and return the captured output, bounded by [`IPC_TIMEOUT`].
async fn hyprctl_output(bin: &Path, argv: &[&str]) -> Result<std::process::Output> {
    let mut cmd = crate::security::spawn::command(bin, argv);
    // `spawn::output_within` drains incrementally with a 4 MiB cap per
    // stream, replacing the old unbounded `cmd.output()`.
    tokio::time::timeout(
        IPC_TIMEOUT,
        crate::security::spawn::output_within(&mut cmd, IPC_TIMEOUT),
    )
    .await
    .context("hyprctl timed out")?
}

/// `hyprctl <argv>` → stdout, failing on non-zero exit.
async fn hyprctl_run(bin: &Path, argv: &[&str]) -> Result<String> {
    let out = hyprctl_output(bin, argv).await?;
    if out.status.success() {
        String::from_utf8(out.stdout).context("hyprctl: non-UTF-8 stdout")
    } else {
        bail!(
            "hyprctl {:?} failed: {}",
            argv,
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

// ---------- JSON mapping ----------

/// Map one `clients`/`activewindow` object onto [`WindowInfo`].
/// `focused_addr` is the `activewindow` address; when unknown, a client
/// with `focusHistoryID == 0` counts as focused.
fn client_to_info(v: &Value, focused_addr: Option<&str>) -> Option<WindowInfo> {
    let address = v.get("address")?.as_str()?;
    if address.is_empty() {
        return None;
    }
    let at = v.get("at")?.as_array()?;
    let size = v.get("size")?.as_array()?;
    let focused = match focused_addr {
        Some(addr) => addr == address,
        None => v.get("focusHistoryID").and_then(Value::as_i64) == Some(0),
    };
    Some(WindowInfo {
        id: address.to_string(),
        title: v
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        class: v
            .get("class")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // Negative ids are real workspaces (e.g. `special` is -98/-99).
        workspace: v
            .get("workspace")
            .and_then(|w| w.get("id"))
            .and_then(Value::as_i64)
            .unwrap_or(0) as i32,
        rect: Rect {
            x: at.first().and_then(Value::as_i64).unwrap_or(0) as i32,
            y: at.get(1).and_then(Value::as_i64).unwrap_or(0) as i32,
            w: size.first().and_then(Value::as_i64).unwrap_or(0) as i32,
            h: size.get(1).and_then(Value::as_i64).unwrap_or(0) as i32,
        },
        focused,
        floating: v.get("floating").and_then(Value::as_bool),
        // `fullscreen` is an int enum (0 none / 1 real / 2 maximized) —
        // expose it as "is fullscreen".
        fullscreen: v.get("fullscreen").and_then(Value::as_i64).map(|f| f != 0),
        pid: v.get("pid").and_then(Value::as_i64),
        monitor: v.get("monitor").and_then(Value::as_i64),
    })
}

/// `clients` reply → window list. Non-array replies are an error.
fn parse_clients(v: &Value, focused_addr: Option<&str>) -> Result<Vec<WindowInfo>> {
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("hyprland: 'clients' reply is not an array"))?;
    Ok(arr
        .iter()
        .filter_map(|c| client_to_info(c, focused_addr))
        .collect())
}

/// `activewindow` reply → `Some` window, or `None` when the compositor
/// reports nothing focused (`{}`, `null`, or a record without an address).
fn parse_active(v: &Value) -> Result<Option<WindowInfo>> {
    if v.is_null() || v.get("address").is_none() {
        return Ok(None);
    }
    Ok(client_to_info(v, None).map(|w| WindowInfo { focused: true, ..w }))
}

// ---------- dispatch mapping ----------

/// Window ids are compositor addresses (`0x…`); restricting to ASCII
/// alphanumerics keeps socket requests single-line and argv splits clean.
fn valid_window_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric())
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// Build the `dispatch <dispatcher> <args>` request string for an action.
/// Fixed mapping only — `exec`/`exec-once` can never be produced here.
fn dispatch_request(action: &str, window_id: &str, args: &Value) -> Result<String> {
    if !valid_window_id(window_id) {
        bail!("hyprland: invalid window id '{window_id}'");
    }
    let inner = match action {
        "focus" => format!("focuswindow address:{window_id}"),
        "move" => {
            if let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) {
                format!("movewindowpixel exact {x} {y},address:{window_id}")
            } else if let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) {
                format!("movewindowpixel {dx} {dy},address:{window_id}")
            } else {
                bail!("hyprland: move requires x,y (or dx,dy)")
            }
        }
        "resize" => {
            if let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) {
                if w < 1 || h < 1 {
                    bail!("hyprland: resize requires w,h >= 1")
                }
                format!("resizewindowpixel exact {w} {h},address:{window_id}")
            } else if let (Some(dw), Some(dh)) = (arg_i64(args, "dw"), arg_i64(args, "dh")) {
                format!("resizewindowpixel {dw} {dh},address:{window_id}")
            } else {
                bail!("hyprland: resize requires w,h (or dw,dh)")
            }
        }
        // `special:` (empty name) is the default special workspace —
        // Hyprland's off-screen "minimized" stash.
        "minimize" => format!("movetoworkspacesilent special:,address:{window_id}"),
        "close" => format!("closewindow address:{window_id}"),
        other => bail!("hyprland: unsupported dispatch action '{other}'"),
    };
    Ok(format!("dispatch {inner}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shape mirrors a live `hyprctl -j clients` capture; extra fields the
    /// compositor emits are included to prove they are ignored.
    const CLIENTS: &str = r#"[
        {
            "address": "0x55817dbad0a0",
            "mapped": true,
            "hidden": false,
            "at": [10, 45],
            "size": [625, 745],
            "workspace": {"id": 2, "name": "2"},
            "floating": false,
            "monitor": 0,
            "class": "kitty",
            "title": "devin: onboarding",
            "pid": 37381,
            "xwayland": false,
            "fullscreen": 0,
            "grouped": [],
            "focusHistoryID": 1
        },
        {
            "address": "0x55817de410c0",
            "mapped": true,
            "at": [645, 45],
            "size": [625, 745],
            "workspace": {"id": 2, "name": "2"},
            "floating": true,
            "class": "kitty",
            "title": "devin: planning",
            "focusHistoryID": 0
        },
        {
            "address": "0xdeadbeef",
            "at": [0, 0],
            "size": [100, 100],
            "workspace": {"id": -99, "name": "special"},
            "class": "scratch",
            "title": "",
            "focusHistoryID": 7
        }
    ]"#;

    const ACTIVE: &str = r#"{
        "address": "0x55817de410c0",
        "at": [645, 45],
        "size": [625, 745],
        "workspace": {"id": 2, "name": "2"},
        "class": "kitty",
        "title": "devin: planning",
        "focusHistoryID": 0
    }"#;

    fn clients_json() -> Value {
        serde_json::from_str(CLIENTS).unwrap()
    }

    #[test]
    fn parses_clients_into_window_info() {
        let windows = parse_clients(&clients_json(), Some("0x55817de410c0")).unwrap();
        assert_eq!(windows.len(), 3);
        let w = &windows[0];
        assert_eq!(w.id, "0x55817dbad0a0");
        assert_eq!(w.title, "devin: onboarding");
        assert_eq!(w.class, "kitty");
        assert_eq!(w.workspace, 2);
        assert_eq!(
            w.rect,
            Rect {
                x: 10,
                y: 45,
                w: 625,
                h: 745
            }
        );
        assert!(!w.focused);
        assert!(windows[1].focused);
        assert!(!windows[2].focused);
    }

    #[test]
    fn special_workspace_has_negative_id() {
        let windows = parse_clients(&clients_json(), None).unwrap();
        assert_eq!(windows[2].workspace, -99);
    }

    #[test]
    fn focused_falls_back_to_focus_history_id() {
        // No activewindow address available → focusHistoryID == 0 wins.
        let windows = parse_clients(&clients_json(), None).unwrap();
        assert!(windows[1].focused);
        assert!(!windows[0].focused);
    }

    #[test]
    fn parse_active_window() {
        let v: Value = serde_json::from_str(ACTIVE).unwrap();
        let w = parse_active(&v).unwrap().unwrap();
        assert_eq!(w.id, "0x55817de410c0");
        assert_eq!(w.class, "kitty");
        assert!(w.focused);
        assert_eq!(w.rect.w, 625);
    }

    #[test]
    fn parse_active_empty_is_none() {
        for payload in ["{}", "null"] {
            let v: Value = serde_json::from_str(payload).unwrap();
            assert!(parse_active(&v).unwrap().is_none(), "{payload}");
        }
    }

    #[test]
    fn parse_clients_rejects_non_array() {
        assert!(parse_clients(&json!({"oops": true}), None).is_err());
    }

    #[test]
    fn client_without_address_is_skipped() {
        let v = json!([{"title": "ghost", "at": [0, 0], "size": [1, 1],
                        "workspace": {"id": 1}}]);
        assert!(parse_clients(&v, None).unwrap().is_empty());
    }

    #[test]
    fn dispatch_maps_all_actions() {
        let id = "0x55817de410c0";
        assert_eq!(
            dispatch_request("focus", id, &json!({})).unwrap(),
            "dispatch focuswindow address:0x55817de410c0"
        );
        assert_eq!(
            dispatch_request("move", id, &json!({"x": 100, "y": 200})).unwrap(),
            "dispatch movewindowpixel exact 100 200,address:0x55817de410c0"
        );
        assert_eq!(
            dispatch_request("move", id, &json!({"dx": -10, "dy": 5})).unwrap(),
            "dispatch movewindowpixel -10 5,address:0x55817de410c0"
        );
        assert_eq!(
            dispatch_request("resize", id, &json!({"w": 800, "h": 600})).unwrap(),
            "dispatch resizewindowpixel exact 800 600,address:0x55817de410c0"
        );
        assert_eq!(
            dispatch_request("minimize", id, &json!({})).unwrap(),
            "dispatch movetoworkspacesilent special:,address:0x55817de410c0"
        );
        assert_eq!(
            dispatch_request("close", id, &json!({})).unwrap(),
            "dispatch closewindow address:0x55817de410c0"
        );
    }

    #[test]
    fn dispatch_never_emits_exec() {
        let id = "0x55817de410c0";
        for action in ["focus", "move", "resize", "minimize", "close"] {
            let args = json!({"x": 1, "y": 1, "w": 2, "h": 2, "dx": 1, "dy": 1});
            if let Ok(req) = dispatch_request(action, id, &args) {
                assert!(!req.contains("exec"), "{req}");
            }
        }
        assert!(dispatch_request("exec", id, &json!({})).is_err());
        assert!(dispatch_request("exec-once", id, &json!({})).is_err());
    }

    #[test]
    fn dispatch_rejects_unsafe_window_ids() {
        for id in ["", "0x1; exec foot", "0x1\nexec foot", "addr,other"] {
            assert!(
                dispatch_request("focus", id, &json!({})).is_err(),
                "id {id:?} must be rejected"
            );
        }
    }

    #[test]
    fn dispatch_requires_geometry() {
        let id = "0x55817de410c0";
        assert!(dispatch_request("move", id, &json!({})).is_err());
        assert!(dispatch_request("move", id, &json!({"x": 1})).is_err());
        assert!(dispatch_request("resize", id, &json!({"w": 0, "h": 0})).is_err());
        assert!(dispatch_request("resize", id, &json!({})).is_err());
    }

    #[test]
    fn dispatch_rejects_unknown_action() {
        assert!(dispatch_request("explode", "0x55817de410c0", &json!({})).is_err());
    }

    // ---------- HYPRLAND_INSTANCE_SIGNATURE gate ----------

    #[test]
    fn instance_signature_accepts_only_real_shapes() {
        use std::ffi::OsStr;
        for good in ["abcdef_1234567890", "v1_2", "_", "0"] {
            assert!(
                valid_instance_signature(OsStr::new(good)),
                "{good:?} must be accepted"
            );
        }
        // Anything that escapes or alters the `…/hypr/<HIS>/` join —
        // absolute paths, `..`, separators, whitespace, dots, dashes.
        for bad in [
            "",
            "..",
            "../evil",
            "/abs/path",
            "a/b",
            "sig name",
            "sig.sock",
            "sig-name",
        ] {
            assert!(
                !valid_instance_signature(OsStr::new(bad)),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn with_pins_rejects_hostile_signature() {
        use std::os::unix::fs::PermissionsExt;
        // A pinned `hyprctl` is present — the signature gate must still
        // reject before the socket join or the binary fallback matter.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("hyprctl");
        std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).unwrap();
        let pins = crate::security::whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(pins.get("hyprctl").is_some());

        let saved = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE");
        unsafe { std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "../../etc") };
        assert!(HyprctlWindow::with_pins(&pins).is_none());
        match saved {
            Some(v) => unsafe { std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", v) },
            None => unsafe { std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE") },
        }
    }

    /// Live smoke test — needs a running Hyprland session; read-only
    /// (`clients` + `activewindow`, never `dispatch`).
    /// Run with `cargo test --lib hyprctl -- --ignored`.
    #[tokio::test]
    #[ignore = "requires a live Hyprland session"]
    async fn live_list_and_active_window() {
        use crate::traits::WindowProvider;
        let Some(w) = HyprctlWindow::new() else {
            eprintln!("no Hyprland session; skipping");
            return;
        };
        let windows = WindowProvider::list_windows(&w).await.unwrap();
        assert!(!windows.is_empty());
        // At most one window may carry the focused flag.
        assert!(windows.iter().filter(|wi| wi.focused).count() <= 1);
        let _active = WindowProvider::active_window(&w).await.unwrap();
    }
}
