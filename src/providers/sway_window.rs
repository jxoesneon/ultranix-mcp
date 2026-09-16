//! Sway `WindowProvider` - direct sway IPC socket transport (`$SWAYSOCK`).
//!
//! Sway speaks the i3 IPC protocol: a 14-byte header `"i3-ipc"` +
//! `u32` payload length + `u32` message type (both little-endian),
//! followed by the payload. This provider uses two message types:
//!
//! * `GET_TREE` (4) - the full container tree; walked once per query and
//!   mapped onto [`WindowInfo`] (list + active window, geometry for
//!   relative moves).
//! * `RUN_COMMAND` (0) - `swaymsg` command strings scoped to a container
//!   via `[con_id=N]` criteria. Only a fixed command set is reachable
//!   through [`WindowProvider::dispatch`]: `focus`, `kill`, `move
//!   scratchpad`, `move absolute position`, `resize set`,
//!   `resize grow|shrink`. `exec`/`exec_always` and every other sway
//!   command are unreachable - commands are built by
//!   [`command_plan`] from a closed match, and con ids are restricted to
//!   decimal digits so no criteria string can be smuggled in.
//!
//! Semantics notes (honest mappings):
//!
//! * **minimize**-> `move scratchpad`. Sway has no iconic/minimized
//!   window state; the scratchpad is the compositor's stash for hidden
//!   windows, and `scratchpad show` is the un-minimize. That is sway's
//!   minimize, so the mapping is documented rather than emulated.
//! * **move/resize**are floating-window ops in sway (tiled windows are
//!   layout-managed); the compositor simply no-ops them on tiled nodes.
//! * `WindowInfo.id` is the decimal container id - the same id the
//!   `[con_id=N]` criterion takes. `monitor` is the index of the
//!   containing output in `GET_TREE` order (the pseudo-output `__i3`
//!   that backs the scratchpad counts). `workspace` is the workspace
//!   `num` (`-1` for the `__i3_scratch` stash and unnumbered
//!   workspaces). `floating`/`fullscreen`/`pid` come straight from the
//!   node record.
//! * `focused`: sway marks `focused: true` on every node along the
//!   single root->focused-leaf path, so exactly one *window* node carries
//!   it - that is the active window. An empty focused workspace yields
//!   `active_window() == None`.
//!
//! Transport mirrors `hyprctl.rs`: a fresh short-lived connection per
//! request (the compositor answers each connection synchronously), a
//! 2-second round-trip bound, and a capped reply read so a hostile or
//! wedged peer cannot stall a tool call or grow memory unboundedly.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::traits::{Rect, WindowInfo, WindowProvider};

/// i3/sway IPC magic - the first six bytes of every message.
const IPC_MAGIC: &[u8; 6] = b"i3-ipc";
/// IPC message type: execute a `swaymsg` command string.
const IPC_RUN_COMMAND: u32 = 0;
/// IPC message type: fetch the full container tree.
const IPC_GET_TREE: u32 = 4;

/// Bound on a single IPC round-trip; the compositor serves requests
/// synchronously, so a healthy reply is effectively instant.
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Cap on a reply payload - GET_TREE is a few hundred KB on busy
/// sessions; 64 MiB bounds a hostile/buggy reply without false
/// positives.
const MAX_REPLY_LEN: u32 = 64 * 1024 * 1024;

/// Sway window-management provider driven by the compositor IPC socket.
pub struct SwayWindow {
    socket: PathBuf,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SwayWindow>();
};

impl SwayWindow {
    /// Construct only inside a live sway session: requires `SWAYSOCK`
    /// (the IPC socket path sway exports to its session), then
    /// cheap-probes it with a connect-and-drop - sway idles waiting for
    /// the request header, so the probe is harmless.
    pub fn new() -> Option<Self> {
        let sock = std::env::var_os("SWAYSOCK")?;
        if sock.is_empty() {
            return None;
        }
        Self::probe(valid_swaysock(Path::new(&sock))?)
    }

    /// Construct against an explicit socket path - the hermetic-test
    /// seam (a fake i3-ipc responder) and a hook for embedders that pin
    /// a known socket.
    pub fn with_socket_path(path: PathBuf) -> Option<Self> {
        Self::probe(path)
    }

    /// `Some` when `path` accepts a connection.
    fn probe(path: PathBuf) -> Option<Self> {
        std::os::unix::net::UnixStream::connect(&path).ok()?;
        Some(Self { socket: path })
    }

    /// `GET_TREE` -> parsed root node.
    async fn tree(&self) -> Result<Value> {
        let body = ipc_request(&self.socket, IPC_GET_TREE, "").await?;
        serde_json::from_slice(&body).context("sway: bad GET_TREE JSON")
    }

    /// `RUN_COMMAND <payload>` - sway replies `[{"success":bool,...}]`,
    /// one entry per command in the payload; every entry must succeed.
    async fn run_command(&self, command: &str) -> Result<()> {
        let body = ipc_request(&self.socket, IPC_RUN_COMMAND, command).await?;
        let v: Value = serde_json::from_slice(&body).context("sway: bad RUN_COMMAND reply JSON")?;
        let results = v
            .as_array()
            .ok_or_else(|| anyhow!("sway: RUN_COMMAND reply is not an array"))?;
        for r in results {
            if r.get("success").and_then(Value::as_bool) != Some(true) {
                let detail = r
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                bail!("sway command {command:?} failed: {detail}");
            }
        }
        Ok(())
    }

    /// Current rect of container `con_id` - the anchor for relative
    /// `dx,dy` moves. `Err` when the id left the tree.
    async fn rect_of(&self, con_id: u64) -> Result<Rect> {
        let tree = self.tree().await?;
        find_node(&tree, con_id)
            .and_then(node_rect)
            .ok_or_else(|| anyhow!("sway: window id {con_id} not found in tree"))
    }
}

#[async_trait]
impl WindowProvider for SwayWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        Ok(collect_windows(&self.tree().await?))
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        Ok(collect_windows(&self.tree().await?)
            .into_iter()
            .find(|w| w.focused))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        let con_id = parse_con_id(window_id)?;
        // Relative moves anchor on the live rect - fetched lazily so the
        // common paths stay single-request.
        let rect = if action == "move" && args.get("dx").is_some() {
            Some(self.rect_of(con_id).await?)
        } else {
            None
        };
        for command in command_plan(action, con_id, args, rect)? {
            self.run_command(&command).await?;
        }
        Ok(())
    }
}

/// `SWAYSOCK` is process environment - a hostile value must not steer
/// the provider onto an arbitrary filesystem entry. Accept only an
/// existing unix socket, and - when `XDG_RUNTIME_DIR` is set (sway
/// always places the socket beneath it) - only one that canonically
/// lives under that dir. Anything else declines the provider rather
/// than connecting. (`with_socket_path` skips this: it is the explicit
/// pin/test seam.)
fn valid_swaysock(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let canonical = path.canonicalize().ok()?;
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
        && !rt.is_empty()
    {
        let rt = PathBuf::from(rt).canonicalize().ok()?;
        if !canonical.starts_with(rt) {
            return None;
        }
    }
    std::fs::metadata(&canonical)
        .ok()?
        .file_type()
        .is_socket()
        .then_some(canonical)
}

// ---------- IPC transport ----------

/// One IPC round-trip: connect, send the 14-byte header + payload,
/// half-close, read the reply header + bounded payload. A fresh
/// short-lived connection per request is mandatory - an unclosed
/// connection blocks the compositor's synchronous IPC loop.
async fn ipc_request(path: &Path, msg_type: u32, payload: &str) -> Result<Vec<u8>> {
    let fut = async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let body = payload.as_bytes();
        let mut hdr = [0u8; 14];
        hdr[..6].copy_from_slice(IPC_MAGIC);
        hdr[6..10].copy_from_slice(&(body.len() as u32).to_le_bytes());
        hdr[10..14].copy_from_slice(&msg_type.to_le_bytes());
        stream.write_all(&hdr).await?;
        stream.write_all(body).await?;
        stream.shutdown().await?;

        let mut rhdr = [0u8; 14];
        stream.read_exact(&mut rhdr).await?;
        if rhdr[..6] != IPC_MAGIC[..] {
            bail!("sway: reply with bad magic");
        }
        let len = u32::from_le_bytes(rhdr[6..10].try_into().unwrap());
        let rtype = u32::from_le_bytes(rhdr[10..14].try_into().unwrap());
        if rtype != msg_type {
            bail!("sway: reply type {rtype} does not match request {msg_type}");
        }
        if len > MAX_REPLY_LEN {
            bail!("sway: reply payload {len} exceeds {MAX_REPLY_LEN} cap");
        }
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };
    tokio::time::timeout(IPC_TIMEOUT, fut)
        .await
        .context("sway ipc request timed out")?
}

// ---------- GET_TREE mapping ----------

/// A node is a window when it is a `con`/`floating_con` carrying view
/// identity: `app_id` (Wayland), `window_properties`/`window` (X11), or
/// - the fallback for clients that set neither - a leaf with a `pid`.
fn is_window(node: &Value) -> bool {
    if node.get("app_id").is_some_and(Value::is_string)
        || node.get("window_properties").is_some_and(Value::is_object)
        || node.get("window").and_then(Value::as_i64).is_some()
    {
        return true;
    }
    node.get("pid").and_then(Value::as_i64).is_some()
        && node
            .get("nodes")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        && node
            .get("floating_nodes")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
}

/// `rect` field -> [`Rect`]. This is the container's absolute layout
/// position - `window_rect` is *relative to the container* (decoration
/// offset), so it is never the right screen-space geometry here.
fn node_rect(node: &Value) -> Option<Rect> {
    let r = node.get("rect")?;
    Some(Rect {
        x: r.get("x").and_then(Value::as_i64)? as i32,
        y: r.get("y").and_then(Value::as_i64)? as i32,
        w: r.get("width").and_then(Value::as_i64)? as i32,
        h: r.get("height").and_then(Value::as_i64)? as i32,
    })
}

/// Depth-first lookup of a node by container `id`.
fn find_node(node: &Value, con_id: u64) -> Option<&Value> {
    if node.get("id").and_then(Value::as_i64) == Some(con_id as i64) {
        return Some(node);
    }
    for key in ["nodes", "floating_nodes"] {
        if let Some(children) = node.get(key).and_then(Value::as_array) {
            for child in children {
                if let Some(hit) = find_node(child, con_id) {
                    return Some(hit);
                }
            }
        }
    }
    None
}

/// One node record -> [`WindowInfo`]. `workspace` is the enclosing
/// workspace's `num` (`-1` for `__i3_scratch` and unnumbered
/// workspaces); `monitor` is the enclosing output's index in
/// `GET_TREE` order.
fn node_to_info(node: &Value, workspace: i32, monitor: i64) -> WindowInfo {
    let id = node.get("id").and_then(Value::as_i64).unwrap_or(0);
    WindowInfo {
        id: id.to_string(),
        title: node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // Wayland app_id first, then the X11 WM_CLASS fallback.
        class: node
            .get("app_id")
            .and_then(Value::as_str)
            .or_else(|| {
                node.get("window_properties")
                    .and_then(|w| w.get("class"))
                    .and_then(Value::as_str)
            })
            .unwrap_or_default()
            .to_string(),
        workspace,
        rect: node_rect(node).unwrap_or(Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }),
        focused: node
            .get("focused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        floating: Some(node.get("type").and_then(Value::as_str) == Some("floating_con")),
        // `fullscreen_mode`: 0 none / 1 real / 2 global - expose "is".
        fullscreen: node
            .get("fullscreen_mode")
            .and_then(Value::as_i64)
            .map(|m| m != 0),
        pid: node.get("pid").and_then(Value::as_i64),
        monitor: Some(monitor),
    }
}

/// Workspace `num`, falling back to a numeric `name` (numbered
/// workspaces always carry `num`; named ones may not). `-1` when
/// neither parses - e.g. the `__i3_scratch` stash.
fn workspace_num(node: &Value) -> i32 {
    node.get("num")
        .and_then(Value::as_i64)
        .or_else(|| {
            node.get("name")
                .and_then(Value::as_str)
                .and_then(|n| n.parse::<i64>().ok())
        })
        .unwrap_or(-1) as i32
}

/// Recursive tree walk collecting window nodes under `node`.
/// `workspace`/`monitor` are the enclosing workspace num and output
/// index passed down from the root loop.
fn walk(node: &Value, workspace: i32, monitor: i64, out: &mut Vec<WindowInfo>) {
    let ntype = node.get("type").and_then(Value::as_str).unwrap_or("");
    let workspace = if ntype == "workspace" {
        workspace_num(node)
    } else {
        workspace
    };
    if matches!(ntype, "con" | "floating_con") && is_window(node) {
        out.push(node_to_info(node, workspace, monitor));
    }
    for key in ["nodes", "floating_nodes"] {
        if let Some(children) = node.get(key).and_then(Value::as_array) {
            for child in children {
                walk(child, workspace, monitor, out);
            }
        }
    }
}

/// `GET_TREE` root -> window list, in tree order (tiled `nodes` before
/// `floating_nodes` per container). Non-tree-shaped replies yield an
/// empty list rather than an error - sway's reply is authoritative.
fn collect_windows(root: &Value) -> Vec<WindowInfo> {
    let mut out = Vec::new();
    if let Some(nodes) = root.get("nodes").and_then(Value::as_array) {
        let mut monitor = 0i64;
        for node in nodes {
            if node.get("type").and_then(Value::as_str) == Some("output") {
                walk(node, -1, monitor, &mut out);
                monitor += 1;
            } else {
                // Dock/panel surfaces live directly under root on some
                // sway versions - walked without an output index.
                walk(node, -1, -1, &mut out);
            }
        }
    }
    out
}

// ---------- dispatch mapping ----------

/// Window ids are decimal container ids (`con_id`); restricting to
/// ASCII digits keeps criteria strings single-token and injection-safe.
fn parse_con_id(id: &str) -> Result<u64> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        bail!("sway: invalid window id '{id}' - con ids are decimal")
    }
    id.parse()
        .map_err(|_| anyhow!("sway: window id '{id}' out of range"))
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

/// Build the ordered `RUN_COMMAND` payloads for an action. Fixed mapping
/// only - `exec`/`exec_always`/`nop` and every other sway command can
/// never be produced here.
fn command_plan(
    action: &str,
    con_id: u64,
    args: &Value,
    rect: Option<Rect>,
) -> Result<Vec<String>> {
    let commands = match action {
        "focus" => vec![format!("[con_id={con_id}] focus")],
        "move" => {
            if let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) {
                vec![format!(
                    "[con_id={con_id}] move absolute position {x} px {y} px"
                )]
            } else if let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) {
                let r = rect.ok_or_else(|| anyhow!("sway: move dx,dy needs live geometry"))?;
                vec![format!(
                    "[con_id={con_id}] move absolute position {} px {} px",
                    i64::from(r.x) + dx,
                    i64::from(r.y) + dy
                )]
            } else {
                bail!("sway: move requires x,y (or dx,dy)")
            }
        }
        "resize" => {
            if let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) {
                if w < 1 || h < 1 {
                    bail!("sway: resize requires w,h >= 1")
                }
                vec![format!("[con_id={con_id}] resize set {w} px {h} px")]
            } else {
                // Relative resize maps to per-axis grow/shrink - sway
                // takes one dimension per command.
                let mut cmds = Vec::new();
                for (key, dim) in [("dw", "width"), ("dh", "height")] {
                    if let Some(d) = arg_i64(args, key)
                        && d != 0
                    {
                        let dir = if d > 0 { "grow" } else { "shrink" };
                        cmds.push(format!(
                            "[con_id={con_id}] resize {dir} {dim} {} px",
                            d.abs()
                        ));
                    }
                }
                if cmds.is_empty() {
                    bail!("sway: resize requires w,h (or dw,dh)")
                }
                cmds
            }
        }
        // sway has no minimized state - the scratchpad *is* the
        // minimized stash (see module docs).
        "minimize" => vec![format!("[con_id={con_id}] move scratchpad")],
        "close" => vec![format!("[con_id={con_id}] kill")],
        other => bail!("sway: unsupported dispatch action '{other}'"),
    };
    Ok(commands)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// Shape mirrors a live `swaymsg -t get_tree` capture: one real
    /// output with a numbered workspace (two tiled views + one X11
    /// floating view) plus the `__i3` scratch pseudo-output. Extra
    /// fields the compositor emits are included to prove they are
    /// ignored.
    const TREE: &str = r#"{
        "id": 1,
        "type": "root",
        "name": "root",
        "orientation": "horizontal",
        "rect": {"x": 0, "y": 0, "width": 1920, "height": 1080},
        "focused": false,
        "nodes": [
            {
                "id": 3,
                "type": "output",
                "name": "HDMI-A-1",
                "make": "Dell Inc.",
                "model": "U2720Q",
                "rect": {"x": 0, "y": 0, "width": 1920, "height": 1080},
                "focused": false,
                "nodes": [
                    {
                        "id": 5,
                        "type": "workspace",
                        "name": "1",
                        "num": 1,
                        "rect": {"x": 0, "y": 0, "width": 1920, "height": 1080},
                        "focused": true,
                        "focus": [11, 10],
                        "nodes": [
                            {
                                "id": 10,
                                "type": "con",
                                "name": "notes: onboarding",
                                "app_id": "kitty",
                                "pid": 37381,
                                "rect": {"x": 10, "y": 45, "width": 940, "height": 990},
                                "window_rect": {"x": 0, "y": 0, "width": 940, "height": 990},
                                "focused": false,
                                "fullscreen_mode": 0,
                                "marks": [],
                                "nodes": [],
                                "floating_nodes": []
                            },
                            {
                                "id": 11,
                                "type": "con",
                                "name": "notes: planning",
                                "app_id": "kitty",
                                "pid": 37382,
                                "rect": {"x": 960, "y": 45, "width": 940, "height": 990},
                                "window_rect": {"x": 0, "y": 0, "width": 940, "height": 990},
                                "focused": true,
                                "fullscreen_mode": 1,
                                "nodes": [],
                                "floating_nodes": []
                            }
                        ],
                        "floating_nodes": [
                            {
                                "id": 12,
                                "type": "floating_con",
                                "name": "Save As",
                                "app_id": null,
                                "window_properties": {
                                    "class": "Xdialog",
                                    "instance": "xdialog",
                                    "title": "Save As"
                                },
                                "pid": 40100,
                                "rect": {"x": 500, "y": 300, "width": 400, "height": 200},
                                "focused": false,
                                "fullscreen_mode": 0,
                                "nodes": [],
                                "floating_nodes": []
                            }
                        ]
                    }
                ],
                "floating_nodes": []
            },
            {
                "id": 4,
                "type": "output",
                "name": "__i3",
                "rect": {"x": 0, "y": 0, "width": 1920, "height": 1080},
                "focused": false,
                "nodes": [
                    {
                        "id": 6,
                        "type": "workspace",
                        "name": "__i3_scratch",
                        "num": -1,
                        "focused": false,
                        "nodes": [],
                        "floating_nodes": [
                            {
                                "id": 20,
                                "type": "floating_con",
                                "name": "scratch term",
                                "app_id": "kitty",
                                "pid": 41000,
                                "rect": {"x": 400, "y": 200, "width": 800, "height": 500},
                                "focused": false,
                                "fullscreen_mode": 0,
                                "nodes": [],
                                "floating_nodes": []
                            }
                        ]
                    }
                ]
            }
        ],
        "floating_nodes": []
    }"#;

    fn tree_json() -> Value {
        serde_json::from_str(TREE).unwrap()
    }

    // ---------- hermetic IPC server ----------

    /// A fake i3-ipc responder: serves `tree` for GET_TREE, records
    /// every RUN_COMMAND payload into `commands`, and replies with
    /// `cmd_reply`. Returns the bound socket path and the command log.
    fn fake_sway_server(
        dir: &Path,
        tree: &'static str,
        cmd_reply: &'static str,
    ) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
        let listener = std::os::unix::net::UnixListener::bind(dir.join("sway-ipc.sock"))
            .expect("bind fake sway socket");
        let path = dir.join("sway-ipc.sock");
        let commands: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cmds = commands.clone();
        // std listener + a tokio task per accepted connection keeps the
        // responder alive for the whole test without a runtime handle at
        // bind time.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let cmds = cmds.clone();
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut hdr = [0u8; 14];
                    if s.read_exact(&mut hdr).is_err() || hdr[..6] != IPC_MAGIC[..] {
                        return;
                    }
                    let len = u32::from_le_bytes(hdr[6..10].try_into().unwrap()) as usize;
                    let mtype = u32::from_le_bytes(hdr[10..14].try_into().unwrap());
                    let mut body = vec![0u8; len.min(1 << 20)];
                    if s.read_exact(&mut body).is_err() {
                        return;
                    }
                    let reply = match mtype {
                        IPC_GET_TREE => tree.to_string(),
                        IPC_RUN_COMMAND => {
                            cmds.lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&body).into_owned());
                            cmd_reply.to_string()
                        }
                        _ => "[]".to_string(),
                    };
                    let rb = reply.as_bytes();
                    let mut rh = [0u8; 14];
                    rh[..6].copy_from_slice(IPC_MAGIC);
                    rh[6..10].copy_from_slice(&(rb.len() as u32).to_le_bytes());
                    rh[10..14].copy_from_slice(&mtype.to_le_bytes());
                    let _ = s.write_all(&rh);
                    let _ = s.write_all(rb);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        (path, commands)
    }

    // ---------- pure mapping ----------

    #[test]
    fn parses_get_tree_fixture_into_window_info() {
        let windows = collect_windows(&tree_json());
        assert_eq!(windows.len(), 4);

        let w = &windows[0];
        assert_eq!(w.id, "10");
        assert_eq!(w.title, "notes: onboarding");
        assert_eq!(w.class, "kitty");
        assert_eq!(w.workspace, 1);
        assert_eq!(
            w.rect,
            Rect {
                x: 10,
                y: 45,
                w: 940,
                h: 990
            }
        );
        assert!(!w.focused);
        assert_eq!(w.floating, Some(false));
        assert_eq!(w.fullscreen, Some(false));
        assert_eq!(w.pid, Some(37381));
        assert_eq!(w.monitor, Some(0));
    }

    #[test]
    fn focused_leaf_is_the_active_window() {
        let windows = collect_windows(&tree_json());
        let focused: Vec<_> = windows.iter().filter(|w| w.focused).collect();
        assert_eq!(focused.len(), 1);
        assert_eq!(focused[0].id, "11");
        assert_eq!(focused[0].fullscreen, Some(true));
    }

    #[test]
    fn x11_view_uses_window_properties_class() {
        let windows = collect_windows(&tree_json());
        let x11 = windows.iter().find(|w| w.id == "12").unwrap();
        assert_eq!(x11.class, "Xdialog");
        assert_eq!(x11.floating, Some(true));
        assert_eq!(x11.workspace, 1);
        assert_eq!(x11.monitor, Some(0));
    }

    #[test]
    fn scratchpad_windows_report_workspace_minus_one() {
        let windows = collect_windows(&tree_json());
        let scratch = windows.iter().find(|w| w.id == "20").unwrap();
        assert_eq!(scratch.workspace, -1);
        // __i3 is the second output in tree order.
        assert_eq!(scratch.monitor, Some(1));
        assert!(!scratch.focused);
    }

    #[test]
    fn find_node_locates_deep_containers() {
        let tree = tree_json();
        assert_eq!(
            find_node(&tree, 12)
                .and_then(|n| n.get("name"))
                .and_then(Value::as_str),
            Some("Save As")
        );
        assert!(find_node(&tree, 9999).is_none());
    }

    // ---------- dispatch mapping ----------

    #[test]
    fn command_plan_maps_all_actions() {
        let none = json!({});
        assert_eq!(
            command_plan("focus", 11, &none, None).unwrap(),
            vec!["[con_id=11] focus"]
        );
        assert_eq!(
            command_plan("move", 11, &json!({"x": 100, "y": 200}), None).unwrap(),
            vec!["[con_id=11] move absolute position 100 px 200 px"]
        );
        assert_eq!(
            command_plan("resize", 11, &json!({"w": 800, "h": 600}), None).unwrap(),
            vec!["[con_id=11] resize set 800 px 600 px"]
        );
        assert_eq!(
            command_plan("minimize", 11, &none, None).unwrap(),
            vec!["[con_id=11] move scratchpad"]
        );
        assert_eq!(
            command_plan("close", 11, &none, None).unwrap(),
            vec!["[con_id=11] kill"]
        );
    }

    #[test]
    fn command_plan_relative_ops() {
        let rect = Rect {
            x: 10,
            y: 45,
            w: 940,
            h: 990,
        };
        assert_eq!(
            command_plan("move", 11, &json!({"dx": -10, "dy": 5}), Some(rect)).unwrap(),
            vec!["[con_id=11] move absolute position 0 px 50 px"]
        );
        assert_eq!(
            command_plan("resize", 11, &json!({"dw": 20, "dh": -30}), None).unwrap(),
            vec![
                "[con_id=11] resize grow width 20 px",
                "[con_id=11] resize shrink height 30 px"
            ]
        );
        // dx,dy without live geometry is an error, not a guess.
        assert!(command_plan("move", 11, &json!({"dx": 1, "dy": 1}), None).is_err());
    }

    #[test]
    fn command_plan_never_emits_exec() {
        let args = json!({"x": 1, "y": 1, "w": 2, "h": 2, "dx": 1, "dy": 1});
        for action in ["focus", "move", "resize", "minimize", "close"] {
            if let Ok(cmds) = command_plan(action, 11, &args, None) {
                for c in cmds {
                    assert!(!c.contains("exec"), "{c}");
                }
            }
        }
        assert!(command_plan("exec", 11, &json!({}), None).is_err());
        assert!(command_plan("nop", 11, &json!({}), None).is_err());
    }

    #[test]
    fn command_plan_requires_geometry() {
        assert!(command_plan("move", 11, &json!({}), None).is_err());
        assert!(command_plan("move", 11, &json!({"x": 1}), None).is_err());
        assert!(command_plan("resize", 11, &json!({"w": 0, "h": 0}), None).is_err());
        assert!(command_plan("resize", 11, &json!({}), None).is_err());
        assert!(command_plan("resize", 11, &json!({"dw": 0, "dh": 0}), None).is_err());
    }

    #[test]
    fn parse_con_id_accepts_only_decimal() {
        assert_eq!(parse_con_id("11").unwrap(), 11);
        for id in [
            "",
            "0x1",
            "1;exec foot",
            "1\nfocus",
            "-1",
            "1,foo",
            "99999999999999999999999999", // overflows u64
        ] {
            assert!(parse_con_id(id).is_err(), "id {id:?} must be rejected");
        }
    }

    #[test]
    fn constructor_declines_missing_socket() {
        assert!(SwayWindow::with_socket_path(PathBuf::from("/nonexistent.sock")).is_none());
    }

    // ---------- SWAYSOCK validation ----------

    /// Serializes the env-mutating `new()` tests - they all touch the
    /// same two vars and run on parallel test threads. Same convention
    /// as `security::history`'s `ENV_LOCK` (poison-tolerant).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Save/set/restore for the env-mutating `new()` tests - the same
    /// convention the sibling gate tests use.
    struct SavedEnv {
        swaysock: Option<std::ffi::OsString>,
        runtime_dir: Option<std::ffi::OsString>,
    }

    impl SavedEnv {
        fn capture() -> Self {
            Self {
                swaysock: std::env::var_os("SWAYSOCK"),
                runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            }
        }
    }

    impl Drop for SavedEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.swaysock {
                    Some(v) => std::env::set_var("SWAYSOCK", v),
                    None => std::env::remove_var("SWAYSOCK"),
                }
                match &self.runtime_dir {
                    Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
    }

    #[test]
    fn new_accepts_socket_under_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let rt = tempfile::tempdir().unwrap();
        // Bound but never accepted - the connect-probe succeeds on the
        // listener backlog alone.
        let _listener =
            std::os::unix::net::UnixListener::bind(rt.path().join("sway.sock")).unwrap();
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", rt.path());
            std::env::set_var("SWAYSOCK", rt.path().join("sway.sock"));
        }
        assert!(SwayWindow::new().is_some());
    }

    #[test]
    fn new_rejects_socket_outside_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let rt = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(elsewhere.path().join("sway.sock")).unwrap();
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", rt.path());
            std::env::set_var("SWAYSOCK", elsewhere.path().join("sway.sock"));
        }
        assert!(SwayWindow::new().is_none());
    }

    #[test]
    fn new_rejects_non_socket_paths() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let rt = tempfile::tempdir().unwrap();
        let regular = rt.path().join("regular.sock");
        std::fs::write(&regular, b"not a socket").unwrap();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", rt.path()) };
        for bad in [
            regular,
            rt.path().join("missing.sock"),
            rt.path().to_path_buf(),
        ] {
            unsafe { std::env::set_var("SWAYSOCK", &bad) };
            assert!(
                SwayWindow::new().is_none(),
                "{} must be rejected",
                bad.display()
            );
        }
    }

    // ---------- live stub round-trips ----------

    #[tokio::test]
    async fn list_and_active_window_over_socket() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _cmds) = fake_sway_server(dir.path(), TREE, r#"[{"success":true}]"#);
        let w = SwayWindow::with_socket_path(path).unwrap();

        let windows = w.list_windows().await.unwrap();
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[1].id, "11");

        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, "11");
        assert_eq!(active.class, "kitty");
    }

    #[tokio::test]
    async fn dispatch_sends_scoped_commands() {
        let dir = tempfile::tempdir().unwrap();
        let (path, cmds) = fake_sway_server(dir.path(), TREE, r#"[{"success":true}]"#);
        let w = SwayWindow::with_socket_path(path).unwrap();

        w.dispatch("focus", "11", &json!({})).await.unwrap();
        w.dispatch("move", "11", &json!({"x": 5, "y": 6}))
            .await
            .unwrap();
        w.dispatch("resize", "12", &json!({"dw": 10, "dh": -5}))
            .await
            .unwrap();
        w.dispatch("minimize", "12", &json!({})).await.unwrap();
        w.dispatch("close", "10", &json!({})).await.unwrap();

        let sent = cmds.lock().unwrap().clone();
        assert_eq!(
            sent,
            vec![
                "[con_id=11] focus",
                "[con_id=11] move absolute position 5 px 6 px",
                "[con_id=12] resize grow width 10 px",
                "[con_id=12] resize shrink height 5 px",
                "[con_id=12] move scratchpad",
                "[con_id=10] kill",
            ]
        );
    }

    #[tokio::test]
    async fn dispatch_relative_move_fetches_rect_first() {
        let dir = tempfile::tempdir().unwrap();
        let (path, cmds) = fake_sway_server(dir.path(), TREE, r#"[{"success":true}]"#);
        let w = SwayWindow::with_socket_path(path).unwrap();

        w.dispatch("move", "10", &json!({"dx": 100, "dy": 100}))
            .await
            .unwrap();
        let sent = cmds.lock().unwrap().clone();
        // rect(10,45) + (100,100) -> absolute 110,145.
        assert_eq!(
            sent,
            vec!["[con_id=10] move absolute position 110 px 145 px"]
        );
    }

    #[tokio::test]
    async fn dispatch_surfaces_command_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _cmds) = fake_sway_server(
            dir.path(),
            TREE,
            r#"[{"success":false,"error":"No such container"}]"#,
        );
        let w = SwayWindow::with_socket_path(path).unwrap();
        let err = w.dispatch("focus", "11", &json!({})).await.unwrap_err();
        assert!(format!("{err}").contains("No such container"), "{err}");
    }

    #[tokio::test]
    async fn dispatch_rejects_bad_id_before_connect() {
        // No server at all - validation must fail before any I/O.
        let w = SwayWindow {
            socket: PathBuf::from("/nonexistent.sock"),
        };
        assert!(w.dispatch("focus", "1;exec sh", &json!({})).await.is_err());
    }
}
