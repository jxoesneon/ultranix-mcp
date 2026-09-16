//! Wayfire `WindowProvider` — direct `ipc`/`ipc-rules` socket transport
//! (`$WAYFIRE_SOCKET`).
//!
//! Wayfire's `ipc` plugin speaks a length-prefixed JSON protocol: every
//! message is a 4-byte little-endian payload length followed by a UTF-8
//! JSON object. Requests are `{"method": "<name>", "data": {…}}`; the
//! reply is the method's result JSON (`{"result":"ok",…}` from
//! `wf::ipc::json_ok()`) or an error object (`{"error":"…"}` —
//! `{"error":"No such method found!"}` when the plugin registering the
//! method is not loaded). Asynchronous event pushes carry an `"event"`
//! key and are skipped while awaiting a reply.
//!
//! Methods used here (verified against wayfire's `ipc-rules.cpp` /
//! `wm-actions.cpp`; every one lives behind a plugin that must be
//! enabled in `core/plugins`, so an absent plugin surfaces as an
//! `error` reply, not a wrong result):
//!
//! * `window-rules/list-views` — bare array of `view_to_json` records:
//!   `id`, `pid`, `title`, `app-id`, `geometry` `{x,y,width,height}`,
//!   `output-id`, `role`, `layer`, `type`, `mapped`, `tiled-edges`,
//!   `fullscreen`, `minimized`, `activated`, `sticky`, `wset-index`.
//!   Field names are probed defensively (`app_id`, `state.focused`
//!   nesting) so older/foreign record shapes degrade to defaults
//!   instead of failing.
//! * `window-rules/get-focused-view` → `{"info": <view|null>}` — the
//!   active window (`list-views` carries no focus field of its own;
//!   `activated` is the per-view focus flag).
//! * `window-rules/view-info` `{id}` → `{"info": <view>}` — the
//!   geometry anchor for `configure-view`, which always takes a full
//!   rect.
//! * `window-rules/focus-view` / `window-rules/close-view` `{id}`.
//! * `window-rules/configure-view` `{id, geometry:{x,y,width,height}}`
//!   — applied as one pending-state transaction server-side.
//! * `wm-actions/set-minimized` `{view_id, state}` — registered by the
//!   `wm-actions` plugin, separate from `ipc-rules`; on builds without
//!   it `minimize` returns the compositor's `error` reply honestly.
//!
//! Semantics notes (honest mappings):
//!
//! * `WindowInfo.workspace` ← `wset-index`, the index of the view's
//!   workspace set — views carry no workspace coordinate (the 2D grid
//!   position is a property of the workspace set and is reported on
//!   outputs/wsets, not on views). `-1` when unassigned. When a record
//!   instead carries `workspace: {x,y,grid_width,…}` (other shapes),
//!   the flat `y*grid_width+x` index is used.
//! * `focused` ← `activated`, probed before `focused` and the nested
//!   `state.*` spellings other builds emit.
//! * `monitor` ← `output-id` (`-1`/absent → `None`); `pid` ← `pid`
//!   (wayfire reports `-1` for views with no client pid → `None`);
//!   `fullscreen` ← `fullscreen`.
//! * `floating` is always `None`: wayfire has no floating-vs-tiled
//!   window class — `tiled-edges` is a snap bitmask, not a layout
//!   class.
//! * Only `toplevel` views are listed: panels, desktop widgets and
//!   unmanaged surfaces cannot be addressed by `window-rules` methods
//!   anyway (`focus-view` rejects non-toplevel views server-side).
//!   When neither `role` nor `type` is present the view is kept —
//!   listing an unparseable view beats silently dropping it.
//!
//! Transport mirrors `sway_window.rs`: a fresh short-lived connection
//! per request (no subscription is ever opened), a 2-second round-trip
//! bound, and a capped reply read so a hostile or wedged peer cannot
//! stall a tool call or grow memory unboundedly.
//!
//! Socket discovery: `WAYFIRE_SOCKET` (wayfire exports it to its
//! session when `ipc` loads) is authoritative — a stale value declines
//! rather than guessing another session's socket, and the path must
//! live under the same root discovery would scan (`valid_socket`
//! canonicalizes and confines it). When unset, discovery probes
//! `$XDG_RUNTIME_DIR/wayfire-<display>…​.socket`, falling back to
//! `/tmp/…` only when `XDG_RUNTIME_DIR` is absent — the root wayfire
//! itself falls back to.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::traits::{Rect, WindowInfo, WindowProvider};

/// Bound on a single IPC round-trip; the compositor serves requests
/// synchronously, so a healthy reply is effectively instant.
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Cap on a reply payload — a view record is well under a kilobyte, so
/// 1 MiB covers ~1000-window sessions while bounding a hostile/buggy
/// reply.
const MAX_REPLY_LEN: u32 = 1024 * 1024;

/// Event pushes share the socket with replies when a subscription is
/// open (this provider never opens one); a wedged peer could still
/// stream them, so the reply scan is bounded.
const MAX_EVENT_SKIPS: usize = 16;

/// Wayfire window-management provider driven by the compositor IPC
/// socket.
pub struct WayfireWindow {
    socket: PathBuf,
}

/// Compile-time contract: `WindowProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WayfireWindow>();
};

impl WayfireWindow {
    /// Construct only inside a live wayfire session: `WAYFIRE_SOCKET`
    /// (the path the `ipc` plugin exports) is authoritative; when it is
    /// absent the known on-disk socket names are probed in order.
    /// Either way the path must be a socket that accepts a connection —
    /// a connect-and-drop probe, harmless since wayfire idles waiting
    /// for the length prefix.
    pub fn new() -> Option<Self> {
        if let Some(sock) = std::env::var_os("WAYFIRE_SOCKET") {
            if sock.is_empty() {
                return None;
            }
            return Self::probe(valid_socket(Path::new(&sock))?);
        }
        for candidate in guess_sockets() {
            if let Some(w) = Self::probe(candidate) {
                return Some(w);
            }
        }
        None
    }

    /// Construct against an explicit socket path — the hermetic-test
    /// seam (a fake length-prefixed-JSON responder) and a hook for
    /// embedders that pin a known socket.
    pub fn with_socket_path(path: PathBuf) -> Option<Self> {
        Self::probe(path)
    }

    /// `Some` when `path` accepts a connection.
    fn probe(path: PathBuf) -> Option<Self> {
        std::os::unix::net::UnixStream::connect(&path).ok()?;
        Some(Self { socket: path })
    }

    /// One method call → its reply JSON. An `{"error":…}` reply is a
    /// compositor-side failure and surfaces as `Err`.
    async fn call(&self, method: &str, data: Value) -> Result<Value> {
        let body = ipc_request(&self.socket, &json!({"method": method, "data": data})).await?;
        let reply: Value = serde_json::from_slice(&body).context("wayfire: bad reply JSON")?;
        if let Some(err) = reply.get("error").and_then(Value::as_str) {
            bail!("wayfire: {method} failed: {err}");
        }
        Ok(reply)
    }

    /// `window-rules/list-views` → the view records.
    async fn list_views(&self) -> Result<Vec<Value>> {
        let reply = self.call("window-rules/list-views", json!({})).await?;
        reply
            .as_array()
            .cloned()
            .ok_or_else(|| anyhow!("wayfire: list-views reply is not an array"))
    }

    /// Current geometry of view `view_id` — `configure-view` always
    /// takes a full rect, so relative *and* absolute move/resize anchor
    /// on the live record.
    async fn view_geometry(&self, view_id: u64) -> Result<Rect> {
        let reply = self
            .call("window-rules/view-info", json!({"id": view_id}))
            .await?;
        reply
            .get("info")
            .and_then(view_rect)
            .ok_or_else(|| anyhow!("wayfire: no geometry for view id {view_id}"))
    }
}

#[async_trait]
impl WindowProvider for WayfireWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        Ok(collect_windows(&self.list_views().await?))
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        let reply = self
            .call("window-rules/get-focused-view", json!({}))
            .await?;
        // `info` is null when nothing is focused.
        Ok(reply
            .get("info")
            .filter(|v| v.is_object())
            .map(|v| view_to_info(v, true)))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        let view_id = parse_view_id(window_id)?;
        // configure-view always wants the full rect — the anchor is
        // fetched lazily so non-geometry actions stay single-request.
        let rect = if matches!(action, "move" | "resize") {
            Some(self.view_geometry(view_id).await?)
        } else {
            None
        };
        for (method, data) in request_plan(action, view_id, args, rect)? {
            self.call(method, data).await?;
        }
        Ok(())
    }
}

/// `WAYFIRE_SOCKET` is process environment — a hostile value must not
/// steer the provider onto an arbitrary filesystem entry. Accept only
/// an existing unix socket canonically under wayfire's own socket
/// root: `XDG_RUNTIME_DIR` when set, `/tmp` otherwise (wayfire's ipc
/// plugin picks exactly those dirs — see `guess_sockets`). Anything
/// else declines the provider rather than connecting.
/// (`with_socket_path` skips this: it is the explicit pin/test seam.)
fn valid_socket(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let canonical = path.canonicalize().ok()?;
    let root = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let root = root.canonicalize().ok()?;
    if !canonical.starts_with(root) {
        return None;
    }
    std::fs::metadata(&canonical)
        .ok()?
        .file_type()
        .is_socket()
        .then_some(canonical)
}

/// Candidate socket paths when `WAYFIRE_SOCKET` is unset — the names
/// wayfire's `ipc` plugin picks itself: `wayfire-<display>-…​.socket`
/// under `XDG_RUNTIME_DIR`, or under `/tmp` when the runtime dir is
/// absent (matching `valid_socket`'s root). `<display>`
/// is `WAYLAND_DISPLAY` (basename — an absolute-path display name must
/// not escape the scan dir); without it the `wayfire-` prefix alone
/// matches. Socket files only, sorted for determinism.
fn guess_sockets() -> Vec<PathBuf> {
    let display = std::env::var_os("WAYLAND_DISPLAY")
        .filter(|v| !v.is_empty())
        .and_then(|v| Path::new(&v).file_name().map(|f| f.to_os_string()));
    let prefix = match display {
        Some(d) => format!("wayfire-{}", d.to_string_lossy()),
        None => "wayfire-".to_string(),
    };
    // Scan exactly the root `valid_socket` would accept: the runtime
    // dir when set, `/tmp` only when it is not — a same-UID drop in
    // `/tmp` must not shadow a real runtime-dir socket.
    let dirs: Vec<PathBuf> = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => vec![PathBuf::from(rt)],
        _ => vec![PathBuf::from("/tmp")],
    };

    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<PathBuf> = entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".socket"))
            })
            .collect();
        names.sort();
        out.extend(names);
    }
    out
}

// ---------- IPC transport ----------

/// One IPC round-trip: connect, send the 4-byte length prefix + JSON
/// request, half-close, read the first non-event reply. A fresh
/// short-lived connection per request keeps the compositor's
/// synchronous IPC loop unblocked and never accumulates subscription
/// state.
async fn ipc_request(path: &Path, request: &Value) -> Result<Vec<u8>> {
    let fut = async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let body = serde_json::to_vec(request)?;
        stream.write_all(&(body.len() as u32).to_le_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;

        let mut skipped = 0usize;
        loop {
            let mut lenbuf = [0u8; 4];
            stream.read_exact(&mut lenbuf).await?;
            let len = u32::from_le_bytes(lenbuf);
            if len > MAX_REPLY_LEN {
                bail!("wayfire: reply payload {len} exceeds {MAX_REPLY_LEN} cap");
            }
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await?;
            // Subscription pushes (`{"event":…}`) are not replies —
            // skip them, bounded, while awaiting the real answer.
            if skipped < MAX_EVENT_SKIPS
                && serde_json::from_slice::<Value>(&buf)
                    .ok()
                    .is_some_and(|v| v.get("event").is_some())
            {
                skipped += 1;
                continue;
            }
            return Ok::<Vec<u8>, anyhow::Error>(buf);
        }
    };
    tokio::time::timeout(IPC_TIMEOUT, fut)
        .await
        .context("wayfire ipc request timed out")?
}

// ---------- view record mapping ----------

/// A record is a managed window when it is a toplevel. Other roles
/// (`desktop-environment` panels, `unmanaged` override-redirects) are
/// never addressable through `window-rules` — excluded. When neither
/// `role` nor `type` exists the record is kept (unknown shape — the
/// fields below simply degrade).
fn is_window(view: &Value) -> bool {
    match (
        view.get("role").and_then(Value::as_str),
        view.get("type").and_then(Value::as_str),
    ) {
        (None, None) => true,
        (role, vtype) => role == Some("toplevel") || vtype == Some("toplevel"),
    }
}

/// `geometry`-shaped field → [`Rect`]. Values arrive as JSON numbers
/// (doubles on the compositor side) so `as_f64` covers both spellings.
fn field_rect(view: &Value, key: &str) -> Option<Rect> {
    let g = view.get(key)?;
    Some(Rect {
        x: g.get("x").and_then(Value::as_f64)? as i32,
        y: g.get("y").and_then(Value::as_f64)? as i32,
        w: g.get("width").and_then(Value::as_f64)? as i32,
        h: g.get("height").and_then(Value::as_f64)? as i32,
    })
}

/// The view's pending `geometry` first, then the bounding-box
/// fallbacks other shapes carry.
fn view_rect(view: &Value) -> Option<Rect> {
    field_rect(view, "geometry")
        .or_else(|| field_rect(view, "base-geometry"))
        .or_else(|| field_rect(view, "bbox"))
}

/// First present bool among flat and `state.*`-nested spellings of the
/// view flags.
fn flag(view: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|k| view.get(k).and_then(Value::as_bool))
        .or_else(|| {
            keys.iter().find_map(|k| {
                view.get("state")
                    .and_then(|s| s.get(k))
                    .and_then(Value::as_bool)
            })
        })
}

/// `wset-index` first (the scalar views actually carry), then the flat
/// `y*grid_width+x` index of a `workspace{x,y,grid_width,…}` object
/// other shapes may report. `-1` when neither is usable.
fn workspace_index(view: &Value) -> i32 {
    if let Some(i) = view.get("wset-index").and_then(Value::as_i64) {
        return i as i32;
    }
    let ws = view.get("workspace");
    let i = |k: &str| ws.and_then(|w| w.get(k)).and_then(Value::as_i64);
    match (i("x"), i("y"), i("grid_width")) {
        (Some(x), Some(y), Some(w)) if w > 0 => (y * w + x) as i32,
        _ => -1,
    }
}

/// One view record → [`WindowInfo`]. `focused` is supplied by the
/// caller (`activated` in list views; always true from
/// `get-focused-view`); unreported fields keep honest defaults.
fn view_to_info(view: &Value, focused: bool) -> WindowInfo {
    let id = view
        .get("id")
        .and_then(Value::as_u64)
        .or_else(|| view.get("id").and_then(Value::as_i64).map(|i| i as u64))
        .unwrap_or(0);
    WindowInfo {
        id: id.to_string(),
        title: view
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        class: view
            .get("app-id")
            .and_then(Value::as_str)
            .or_else(|| view.get("app_id").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string(),
        workspace: workspace_index(view),
        rect: view_rect(view).unwrap_or(Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }),
        focused,
        floating: None,
        fullscreen: flag(view, &["fullscreen"]),
        // wayfire reports pid -1 for views with no client pid.
        pid: view.get("pid").and_then(Value::as_i64).filter(|&p| p > 0),
        monitor: view
            .get("output-id")
            .and_then(Value::as_i64)
            .or_else(|| view.get("output_id").and_then(Value::as_i64))
            .filter(|&o| o >= 0),
    }
}

/// `list-views` array → window list, toplevels only, in compositor
/// order.
fn collect_windows(views: &[Value]) -> Vec<WindowInfo> {
    views
        .iter()
        .filter(|v| v.is_object() && is_window(v))
        .map(|v| {
            let focused = flag(v, &["activated", "focused"]).unwrap_or(false);
            view_to_info(v, focused)
        })
        .collect()
}

// ---------- dispatch mapping ----------

/// Window ids are decimal view ids; restricting to ASCII digits keeps
/// the `{"id":N}` payload injection-safe and matches the u64 the
/// compositor's `json_get_view_id` expects.
fn parse_view_id(id: &str) -> Result<u64> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        bail!("wayfire: invalid window id '{id}' — view ids are decimal")
    }
    id.parse()
        .map_err(|_| anyhow!("wayfire: window id '{id}' out of range"))
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key)?.as_i64()
}

fn configure(id: u64, r: Rect) -> (&'static str, Value) {
    (
        "window-rules/configure-view",
        json!({
            "id": id,
            "geometry": {"x": r.x, "y": r.y, "width": r.w, "height": r.h},
        }),
    )
}

/// Build the ordered `(method, data)` requests for an action. Fixed
/// mapping only — the `command/register-binding` exec primitives and
/// every other registered method are unreachable through
/// [`WindowProvider::dispatch`].
fn request_plan(
    action: &str,
    view_id: u64,
    args: &Value,
    rect: Option<Rect>,
) -> Result<Vec<(&'static str, Value)>> {
    let requests = match action {
        "focus" => vec![("window-rules/focus-view", json!({"id": view_id}))],
        "close" => vec![("window-rules/close-view", json!({"id": view_id}))],
        // `wm-actions/set-minimized` (wm-actions plugin) — wayfire's
        // real minimized state, not a scratchpad approximation.
        "minimize" => vec![(
            "wm-actions/set-minimized",
            json!({"view_id": view_id, "state": true}),
        )],
        "move" => {
            let r = rect.ok_or_else(|| anyhow!("wayfire: move needs live geometry"))?;
            let (x, y) = if let (Some(x), Some(y)) = (arg_i64(args, "x"), arg_i64(args, "y")) {
                (x as i32, y as i32)
            } else if let (Some(dx), Some(dy)) = (arg_i64(args, "dx"), arg_i64(args, "dy")) {
                (r.x + dx as i32, r.y + dy as i32)
            } else {
                bail!("wayfire: move requires x,y (or dx,dy)")
            };
            vec![configure(
                view_id,
                Rect {
                    x,
                    y,
                    w: r.w,
                    h: r.h,
                },
            )]
        }
        "resize" => {
            let r = rect.ok_or_else(|| anyhow!("wayfire: resize needs live geometry"))?;
            let (w, h) = if let (Some(w), Some(h)) = (arg_i64(args, "w"), arg_i64(args, "h")) {
                (w as i32, h as i32)
            } else if let (Some(dw), Some(dh)) = (arg_i64(args, "dw"), arg_i64(args, "dh")) {
                (r.w + dw as i32, r.h + dh as i32)
            } else {
                bail!("wayfire: resize requires w,h (or dw,dh)")
            };
            if w < 1 || h < 1 {
                bail!("wayfire: resize requires w,h >= 1")
            }
            vec![configure(
                view_id,
                Rect {
                    x: r.x,
                    y: r.y,
                    w,
                    h,
                },
            )]
        }
        other => bail!("wayfire: unsupported dispatch action '{other}'"),
    };
    Ok(requests)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// Shape mirrors a live `window-rules/list-views` capture (wayfire
    /// `view_to_json`): two toplevels plus a `desktop-environment`
    /// panel that must be filtered out. Extra fields are included to
    /// prove they are ignored.
    const VIEWS: &str = r#"[
        {
            "id": 4,
            "pid": 37381,
            "title": "devin: onboarding",
            "app-id": "kitty",
            "base-geometry": {"x": 10, "y": 45, "width": 940, "height": 990},
            "parent": -1,
            "geometry": {"x": 10, "y": 45, "width": 940, "height": 990},
            "bbox": {"x": 10, "y": 45, "width": 940, "height": 990},
            "output-id": 1,
            "output-name": "HDMI-A-1",
            "last-focus-timestamp": 123,
            "role": "toplevel",
            "mapped": true,
            "layer": "workspace",
            "tiled-edges": 0,
            "fullscreen": false,
            "minimized": false,
            "activated": false,
            "sticky": false,
            "wset-index": 0,
            "focusable": true,
            "type": "toplevel",
            "always-on-top": false,
            "always-on-bottom": false
        },
        {
            "id": 5,
            "pid": 37382,
            "title": "devin: planning",
            "app-id": "kitty",
            "geometry": {"x": 960, "y": 45, "width": 940, "height": 990},
            "output-id": 1,
            "output-name": "HDMI-A-1",
            "role": "toplevel",
            "mapped": true,
            "layer": "workspace",
            "tiled-edges": 0,
            "fullscreen": true,
            "minimized": false,
            "activated": true,
            "sticky": false,
            "wset-index": 0,
            "focusable": true,
            "type": "toplevel"
        },
        {
            "id": 6,
            "pid": -1,
            "title": "",
            "app-id": "waybar",
            "geometry": {"x": 0, "y": 0, "width": 1920, "height": 24},
            "output-id": 1,
            "role": "desktop-environment",
            "mapped": true,
            "layer": "top",
            "type": "panel"
        }
    ]"#;

    /// Older/foreign record shape: `app_id`, nested `state.*`, no
    /// `wset-index` but a `workspace` object.
    const VIEWS_LEGACY: &str = r#"[
        {
            "id": 9,
            "pid": 12,
            "title": "legacy",
            "app_id": "foot",
            "geometry": {"x": 1, "y": 2, "width": 3, "height": 4},
            "output_id": 2,
            "state": {"focused": true, "fullscreen": false, "minimized": true},
            "workspace": {"x": 1, "y": 2, "grid_width": 3, "grid_height": 3}
        }
    ]"#;

    fn views_json() -> Value {
        serde_json::from_str(VIEWS).unwrap()
    }

    // ---------- hermetic IPC server ----------

    /// A fake wayfire ipc responder: reads the length-prefixed JSON
    /// request, pushes its raw text onto `requests`, and replies with
    /// `handler(request)` framed the same way. Returns the bound
    /// socket path and the request log.
    fn fake_wayfire_server(
        dir: &Path,
        handler: impl Fn(&Value) -> String + Send + Sync + 'static,
    ) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
        let listener = std::os::unix::net::UnixListener::bind(dir.join("wayfire.sock"))
            .expect("bind fake wayfire socket");
        let path = dir.join("wayfire.sock");
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let reqs = requests.clone();
        let handler = Arc::new(handler);
        // std listener + a thread per connection keeps the responder
        // alive for the whole test without a runtime handle at bind
        // time — same convention as sway_window's fake server.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let reqs = reqs.clone();
                let handler = handler.clone();
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut lenbuf = [0u8; 4];
                    if s.read_exact(&mut lenbuf).is_err() {
                        return;
                    }
                    let len = u32::from_le_bytes(lenbuf) as usize;
                    let mut body = vec![0u8; len.min(1 << 20)];
                    if s.read_exact(&mut body).is_err() {
                        return;
                    }
                    let text = String::from_utf8_lossy(&body).into_owned();
                    reqs.lock().unwrap().push(text.clone());
                    let req: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let reply = handler(&req);
                    let rb = reply.as_bytes();
                    let _ = s.write_all(&(rb.len() as u32).to_le_bytes());
                    let _ = s.write_all(rb);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        (path, requests)
    }

    /// Standard handler: answers list-views / get-focused-view /
    /// view-info from the VIEWS fixture, every other method `ok`.
    fn standard_handler(req: &Value) -> String {
        match req.get("method").and_then(Value::as_str) {
            Some("window-rules/list-views") => VIEWS.to_string(),
            Some("window-rules/get-focused-view") => {
                let views: Vec<Value> = serde_json::from_str(VIEWS).unwrap();
                let focused = views
                    .into_iter()
                    .find(|v| v.get("activated").and_then(Value::as_bool) == Some(true));
                json!({"result": "ok", "info": focused}).to_string()
            }
            Some("window-rules/view-info") => {
                let id = req["data"]["id"].as_u64().unwrap_or(0);
                let views: Vec<Value> = serde_json::from_str(VIEWS).unwrap();
                let view = views
                    .into_iter()
                    .find(|v| v["id"].as_u64() == Some(id))
                    .unwrap_or(Value::Null);
                json!({"result": "ok", "info": view}).to_string()
            }
            _ => r#"{"result":"ok"}"#.to_string(),
        }
    }

    // ---------- pure mapping ----------

    #[test]
    fn parses_list_views_into_window_info() {
        let views = views_json();
        let windows = collect_windows(views.as_array().unwrap());
        // The desktop-environment panel is filtered out.
        assert_eq!(windows.len(), 2);

        let w = &windows[0];
        assert_eq!(w.id, "4");
        assert_eq!(w.title, "devin: onboarding");
        assert_eq!(w.class, "kitty");
        assert_eq!(w.workspace, 0);
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
        assert_eq!(w.floating, None);
        assert_eq!(w.fullscreen, Some(false));
        assert_eq!(w.pid, Some(37381));
        assert_eq!(w.monitor, Some(1));
    }

    #[test]
    fn activated_view_is_the_focused_window() {
        let views = views_json();
        let windows = collect_windows(views.as_array().unwrap());
        let focused: Vec<_> = windows.iter().filter(|w| w.focused).collect();
        assert_eq!(focused.len(), 1);
        assert_eq!(focused[0].id, "5");
        assert_eq!(focused[0].fullscreen, Some(true));
    }

    #[test]
    fn legacy_record_shape_degrades_gracefully() {
        let views: Value = serde_json::from_str(VIEWS_LEGACY).unwrap();
        let windows = collect_windows(views.as_array().unwrap());
        assert_eq!(windows.len(), 1);
        let w = &windows[0];
        assert_eq!(w.id, "9");
        assert_eq!(w.class, "foot");
        // workspace {x:1,y:2,grid_width:3} → flat 2*3+1.
        assert_eq!(w.workspace, 7);
        assert_eq!(
            w.rect,
            Rect {
                x: 1,
                y: 2,
                w: 3,
                h: 4
            }
        );
        assert!(w.focused);
        assert_eq!(w.fullscreen, Some(false));
        assert_eq!(w.pid, Some(12));
        assert_eq!(w.monitor, Some(2));
    }

    // ---------- dispatch mapping ----------

    #[test]
    fn request_plan_maps_all_actions() {
        let none = json!({});
        let rect = Rect {
            x: 10,
            y: 45,
            w: 940,
            h: 990,
        };
        assert_eq!(
            request_plan("focus", 5, &none, None).unwrap(),
            vec![("window-rules/focus-view", json!({"id": 5}))]
        );
        assert_eq!(
            request_plan("close", 5, &none, None).unwrap(),
            vec![("window-rules/close-view", json!({"id": 5}))]
        );
        assert_eq!(
            request_plan("minimize", 5, &none, None).unwrap(),
            vec![(
                "wm-actions/set-minimized",
                json!({"view_id": 5, "state": true})
            )]
        );
        assert_eq!(
            request_plan("move", 5, &json!({"x": 1, "y": 2}), Some(rect)).unwrap(),
            vec![(
                "window-rules/configure-view",
                json!({"id": 5, "geometry": {"x": 1, "y": 2, "width": 940, "height": 990}})
            )]
        );
        assert_eq!(
            request_plan("resize", 5, &json!({"w": 800, "h": 600}), Some(rect)).unwrap(),
            vec![(
                "window-rules/configure-view",
                json!({"id": 5, "geometry": {"x": 10, "y": 45, "width": 800, "height": 600}})
            )]
        );
    }

    #[test]
    fn request_plan_relative_ops() {
        let rect = Rect {
            x: 10,
            y: 45,
            w: 940,
            h: 990,
        };
        assert_eq!(
            request_plan("move", 5, &json!({"dx": -10, "dy": 5}), Some(rect)).unwrap(),
            vec![(
                "window-rules/configure-view",
                json!({"id": 5, "geometry": {"x": 0, "y": 50, "width": 940, "height": 990}})
            )]
        );
        assert_eq!(
            request_plan("resize", 5, &json!({"dw": 20, "dh": -30}), Some(rect)).unwrap(),
            vec![(
                "window-rules/configure-view",
                json!({"id": 5, "geometry": {"x": 10, "y": 45, "width": 960, "height": 960}})
            )]
        );
        // Missing live geometry is an error, not a guess.
        assert!(request_plan("move", 5, &json!({"dx": 1, "dy": 1}), None).is_err());
        assert!(request_plan("resize", 5, &json!({"dw": 1, "dh": 1}), None).is_err());
    }

    #[test]
    fn request_plan_never_reaches_exec_primitives() {
        // `command/register-binding` and every unlisted method are
        // unreachable through the closed action set.
        for action in ["command/register-binding", "exec", "nop", "watch"] {
            assert!(
                request_plan(action, 5, &json!({"x": 1, "y": 1}), None).is_err(),
                "{action} must be unreachable"
            );
        }
    }

    #[test]
    fn request_plan_requires_geometry() {
        let rect = Rect {
            x: 10,
            y: 45,
            w: 940,
            h: 990,
        };
        assert!(request_plan("move", 5, &json!({}), Some(rect)).is_err());
        assert!(request_plan("move", 5, &json!({"x": 1}), Some(rect)).is_err());
        assert!(request_plan("resize", 5, &json!({"w": 0, "h": 0}), Some(rect)).is_err());
        assert!(request_plan("resize", 5, &json!({}), Some(rect)).is_err());
        // Shrinking past zero still fails the >= 1 check.
        assert!(request_plan("resize", 5, &json!({"dw": -2000, "dh": 0}), Some(rect)).is_err());
    }

    #[test]
    fn parse_view_id_accepts_only_decimal() {
        assert_eq!(parse_view_id("11").unwrap(), 11);
        for id in [
            "",
            "0x1",
            "1,focus",
            "1\nclose",
            "-1",
            "1.5",
            "99999999999999999999999999", // overflows u64
        ] {
            assert!(parse_view_id(id).is_err(), "id {id:?} must be rejected");
        }
    }

    #[test]
    fn constructor_declines_missing_socket() {
        assert!(WayfireWindow::with_socket_path(PathBuf::from("/nonexistent.sock")).is_none());
    }

    // ---------- WAYFIRE_SOCKET / discovery ----------

    /// Serializes the env-mutating `new()` tests — same convention as
    /// sway_window's `ENV_LOCK` (poison-tolerant).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Save/set/restore for the env-mutating `new()` tests.
    struct SavedEnv {
        wayfire_socket: Option<std::ffi::OsString>,
        wayland_display: Option<std::ffi::OsString>,
        runtime_dir: Option<std::ffi::OsString>,
    }

    impl SavedEnv {
        fn capture() -> Self {
            Self {
                wayfire_socket: std::env::var_os("WAYFIRE_SOCKET"),
                wayland_display: std::env::var_os("WAYLAND_DISPLAY"),
                runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            }
        }
    }

    impl Drop for SavedEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.wayfire_socket {
                    Some(v) => std::env::set_var("WAYFIRE_SOCKET", v),
                    None => std::env::remove_var("WAYFIRE_SOCKET"),
                }
                match &self.wayland_display {
                    Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
                    None => std::env::remove_var("WAYLAND_DISPLAY"),
                }
                match &self.runtime_dir {
                    Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
    }

    #[test]
    fn new_accepts_env_socket() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        // Bound but never accepted — the connect-probe succeeds on the
        // listener backlog alone.
        let _listener = std::os::unix::net::UnixListener::bind(dir.path().join("wf.sock")).unwrap();
        unsafe {
            std::env::set_var("WAYFIRE_SOCKET", dir.path().join("wf.sock"));
            // Confinement: the env socket must canonically live under
            // wayfire's socket root (XDG_RUNTIME_DIR here, else /tmp).
            std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        }
        assert!(WayfireWindow::new().is_some());
    }

    #[test]
    fn new_rejects_env_socket_outside_socket_root() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(other.path().join("wf.sock")).unwrap();
        unsafe {
            std::env::set_var("WAYFIRE_SOCKET", other.path().join("wf.sock"));
            // XDG_RUNTIME_DIR set → sockets outside it are not
            // wayfire's; `new` declines rather than connecting.
            std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        }
        assert!(WayfireWindow::new().is_none());
    }

    #[test]
    fn new_rejects_non_socket_env_path() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular.sock");
        std::fs::write(&regular, b"not a socket").unwrap();
        unsafe {
            std::env::set_var("WAYFIRE_SOCKET", &regular);
            // The env var is authoritative: a bad value declines rather
            // than falling through to the directory scan.
            std::env::set_var("XDG_RUNTIME_DIR", dir.path());
            std::env::set_var("WAYLAND_DISPLAY", "wayfire-guessed-9");
        }
        let _listener = std::os::unix::net::UnixListener::bind(
            dir.path().join("wayfire-wayfire-guessed-9-.socket"),
        )
        .unwrap();
        assert!(WayfireWindow::new().is_none());
    }

    #[test]
    fn new_guesses_socket_under_runtime_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = SavedEnv::capture();
        let rt = tempfile::tempdir().unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(rt.path().join("wayfire-wl9-42.socket"))
                .unwrap();
        unsafe {
            std::env::remove_var("WAYFIRE_SOCKET");
            std::env::set_var("XDG_RUNTIME_DIR", rt.path());
            std::env::set_var("WAYLAND_DISPLAY", "wl9");
        }
        assert!(WayfireWindow::new().is_some());
    }

    // ---------- live stub round-trips ----------

    #[tokio::test]
    async fn list_and_active_window_over_socket() {
        let dir = tempfile::tempdir().unwrap();
        let (path, reqs) = fake_wayfire_server(dir.path(), standard_handler);
        let w = WayfireWindow::with_socket_path(path).unwrap();

        let windows = w.list_windows().await.unwrap();
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[1].id, "5");
        assert!(windows[1].focused);

        let active = w.active_window().await.unwrap().unwrap();
        assert_eq!(active.id, "5");
        assert_eq!(active.class, "kitty");

        let sent: Vec<Value> = reqs
            .lock()
            .unwrap()
            .iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(
            sent,
            vec![
                json!({"method": "window-rules/list-views", "data": {}}),
                json!({"method": "window-rules/get-focused-view", "data": {}}),
            ]
        );
    }

    #[tokio::test]
    async fn active_window_none_when_nothing_focused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _reqs) = fake_wayfire_server(dir.path(), |_req| {
            r#"{"result":"ok","info":null}"#.to_string()
        });
        let w = WayfireWindow::with_socket_path(path).unwrap();
        assert!(w.active_window().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dispatch_sends_exact_method_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let (path, reqs) = fake_wayfire_server(dir.path(), standard_handler);
        let w = WayfireWindow::with_socket_path(path).unwrap();

        w.dispatch("focus", "5", &json!({})).await.unwrap();
        w.dispatch("close", "4", &json!({})).await.unwrap();
        w.dispatch("minimize", "5", &json!({})).await.unwrap();
        w.dispatch("move", "4", &json!({"dx": 100, "dy": 100}))
            .await
            .unwrap();
        w.dispatch("resize", "4", &json!({"w": 800, "h": 600}))
            .await
            .unwrap();

        let sent: Vec<Value> = reqs
            .lock()
            .unwrap()
            .iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(
            sent,
            vec![
                json!({"method": "window-rules/focus-view", "data": {"id": 5}}),
                json!({"method": "window-rules/close-view", "data": {"id": 4}}),
                json!({"method": "wm-actions/set-minimized", "data": {"view_id": 5, "state": true}}),
                // move/resize fetch the live geometry anchor first…
                json!({"method": "window-rules/view-info", "data": {"id": 4}}),
                // …then send the full rect: (10,45)+(100,100), size kept.
                json!({"method": "window-rules/configure-view", "data": {"id": 4, "geometry": {"x": 110, "y": 145, "width": 940, "height": 990}}}),
                json!({"method": "window-rules/view-info", "data": {"id": 4}}),
                json!({"method": "window-rules/configure-view", "data": {"id": 4, "geometry": {"x": 10, "y": 45, "width": 800, "height": 600}}}),
            ]
        );
    }

    #[tokio::test]
    async fn dispatch_surfaces_compositor_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _reqs) = fake_wayfire_server(dir.path(), |_req| {
            r#"{"error":"No such method found!","method":"window-rules/focus-view"}"#.to_string()
        });
        let w = WayfireWindow::with_socket_path(path).unwrap();
        let err = w.dispatch("focus", "5", &json!({})).await.unwrap_err();
        assert!(format!("{err}").contains("No such method found"), "{err}");
    }

    #[tokio::test]
    async fn malformed_reply_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _reqs) = fake_wayfire_server(dir.path(), |_req| "not json".to_string());
        let w = WayfireWindow::with_socket_path(path).unwrap();
        assert!(w.list_windows().await.is_err());
    }

    #[tokio::test]
    async fn oversized_reply_is_an_error() {
        // Announces a payload beyond the cap, then closes — the cap
        // check must reject before the read.
        let dir = tempfile::tempdir().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(dir.path().join("big.sock")).unwrap();
        let path = dir.path().join("big.sock");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut lenbuf = [0u8; 4];
                    if s.read_exact(&mut lenbuf).is_err() {
                        return;
                    }
                    let len = u32::from_le_bytes(lenbuf) as usize;
                    let mut body = vec![0u8; len.min(1 << 20)];
                    if s.read_exact(&mut body).is_err() {
                        return;
                    }
                    let huge = (MAX_REPLY_LEN + 1).to_le_bytes();
                    let _ = s.write_all(&huge);
                    let _ = s.write_all(b"x");
                    let _ = s.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        let w = WayfireWindow::with_socket_path(path).unwrap();
        let err = w.list_windows().await.unwrap_err();
        assert!(format!("{err:?}").contains("cap"), "{err:?}");
    }

    #[tokio::test]
    async fn event_pushes_are_skipped_for_the_reply() {
        let dir = tempfile::tempdir().unwrap();
        // Two event pushes on the wire ahead of the real reply — the
        // reply scan must skip frames carrying an "event" key.
        let (path, _reqs) = fake_wayfire_multi(
            dir.path(),
            vec![
                r#"{"event":"view-mapped","data":{}}"#,
                r#"{"event":"view-focused","data":{}}"#,
                VIEWS,
            ],
        );
        let w = WayfireWindow::with_socket_path(path).unwrap();
        let windows = w.list_windows().await.unwrap();
        assert_eq!(windows.len(), 2);
    }

    /// Fake server writing each `replies` entry as its own frame —
    /// exercises the event-skip loop over real message boundaries.
    fn fake_wayfire_multi(
        dir: &Path,
        replies: Vec<&'static str>,
    ) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
        let listener = std::os::unix::net::UnixListener::bind(dir.join("wayfire-multi.sock"))
            .expect("bind fake wayfire socket");
        let path = dir.join("wayfire-multi.sock");
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let reqs = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let reqs = reqs.clone();
                let replies = replies.clone();
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut lenbuf = [0u8; 4];
                    if s.read_exact(&mut lenbuf).is_err() {
                        return;
                    }
                    let len = u32::from_le_bytes(lenbuf) as usize;
                    let mut body = vec![0u8; len.min(1 << 20)];
                    if s.read_exact(&mut body).is_err() {
                        return;
                    }
                    reqs.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&body).into_owned());
                    for reply in replies {
                        let rb = reply.as_bytes();
                        if s.write_all(&(rb.len() as u32).to_le_bytes()).is_err()
                            || s.write_all(rb).is_err()
                        {
                            return;
                        }
                    }
                    let _ = s.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        (path, requests)
    }

    #[tokio::test]
    async fn dispatch_rejects_bad_id_before_connect() {
        // No server at all — validation must fail before any I/O.
        let w = WayfireWindow {
            socket: PathBuf::from("/nonexistent.sock"),
        };
        assert!(w.dispatch("focus", "5;rm -rf /", &json!({})).await.is_err());
        assert!(w.dispatch("close", "abc", &json!({})).await.is_err());
        assert!(w.dispatch("focus", "", &json!({})).await.is_err());
    }
}
