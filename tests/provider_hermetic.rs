//! Hermetic provider tests — fake `grim`/`slurp`/`hyprctl` executables on a
//! tempdir `PATH` plus a fake Hyprland IPC socket bound under a tempdir
//! `XDG_RUNTIME_DIR`, so neither the real compositor nor the real binaries
//! are required.
//!
//! ## Env/PATH locking
//!
//! Every test here mutates process-global state (`PATH`,
//! `HYPRLAND_INSTANCE_SIGNATURE`, `XDG_RUNTIME_DIR`). Cargo runs all tests
//! of one integration binary on threads inside a single process, so a test
//! rewriting `PATH` would race a sibling's `which()`/`find_on_path` probe.
//! All of them therefore serialize on [`ENV_LOCK`] — the same env_guard
//! precedent used by the in-process lib tests in `src/security/history.rs`
//! and `src/state.rs`. `EnvGuard` snapshots each var it touches and restores
//! it on drop (panic included), and is always declared *after* the lock
//! guard so the restore still happens under the lock (drops run in reverse
//! declaration order).

// The env mutex must be held for the *entire* test — including .await
// points — because PATH/env are process-global and a restore must not
// interleave with a sibling's mutation. There is exactly one lock and no
// awaited code path re-acquires it, so holding a std MutexGuard across
// awaits cannot deadlock here.
#![allow(clippy::await_holding_lock)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde_json::json;
use ultranix_mcp::providers::grim_capture::GrimCapture;
use ultranix_mcp::providers::hyprctl::HyprctlWindow;
use ultranix_mcp::security::whitelist::PinnedBins;
use ultranix_mcp::traits::{CaptureProvider, Rect, WindowProvider};

/// Serializes every env/PATH-mutating test in this binary. Non-mutating
/// tests could skip it, but keeping the rule uniform avoids a future test
/// silently racing.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    // Poison-tolerant: a panicked test must not strand the rest of the suite.
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Snapshots and restores every env var it touches. Hold `ENV_LOCK` for the
/// guard's whole lifetime so a sibling test can't interleave set/restore.
struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn set(&mut self, key: &'static str, value: impl AsRef<OsStr>) {
        self.remember(key);
        // SAFETY: serialized by ENV_LOCK — no other thread in this test
        // binary touches the environment while the guard is held.
        unsafe { std::env::set_var(key, value) };
    }

    fn remove(&mut self, key: &'static str) {
        self.remember(key);
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(key) };
    }

    fn remember(&mut self, key: &'static str) {
        if !self.saved.iter().any(|(k, _)| *k == key) {
            self.saved.push((key, std::env::var_os(key)));
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            // SAFETY: still under ENV_LOCK (tests bind `env_guard()` first,
            // and it drops after this guard).
            match value {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Canonical 1×1 RGBA PNG, base64-embedded so the test file stays
/// self-contained (70 bytes decoded).
const PNG_1X1_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/// Minimal base64 decoder (no dev-dep just for one fixture).
fn b64decode(s: &str) -> Vec<u8> {
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            other => panic!("bad base64 byte {other:#x}"),
        };
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    out
}

fn png_1x1() -> Vec<u8> {
    let png = b64decode(PNG_1X1_B64);
    assert_eq!(&png[..4], b"\x89PNG");
    png
}

/// Write `body` as an executable file named `name` inside `dir`.
fn write_exe(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// `dir` prepended to the inherited `PATH` — fake binaries win the `which`
/// probe, while script externals (`cat`) still resolve.
fn path_with(dir: &Path) -> OsString {
    let mut p = OsString::from(dir.as_os_str());
    if let Some(rest) = std::env::var_os("PATH") {
        p.push(":");
        p.push(rest);
    }
    p
}

/// A `grim [-g geom] <out.png>` lookalike: writes the PNG fixture to its
/// last argv. Builtins only (`while`/`shift`/`printf`), so it works even
/// with a stripped-down `PATH`.
fn grim_script() -> String {
    // PNG bytes as a `printf` format string: printable bytes verbatim,
    // the rest as fixed-width octal escapes (always 3 digits so a trailing
    // literal digit can't merge into an escape).
    let mut fmt = String::new();
    for b in png_1x1() {
        match b {
            b'%' => fmt.push_str("%%"),
            b'\\' => fmt.push_str("\\\\"),
            b'\'' => fmt.push_str("'\\''"),
            0x20..=0x7e => fmt.push(b as char),
            _ => write!(fmt, "\\{b:03o}").unwrap(),
        }
    }
    format!(
        "#!/bin/sh\n\
         while [ $# -gt 1 ]; do shift; done\n\
         printf '{fmt}' > \"$1\"\n"
    )
}

/// Fake `hyprctl`: `hyprctl -j <sub>` prints `<dir>/reply-<sub>`; any other
/// argv (`dispatch …`) prints `<dir>/dispatch` and exits 0. A `<dir>/fail`
/// sentinel forces exit 1 for any call; a missing reply file makes `cat`
/// exit non-zero, covering the non-zero-exit path too.
fn hyprctl_script(dir: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         d='{d}'\n\
         if [ -f \"$d/fail\" ]; then echo 'simulated hyprctl failure' >&2; exit 1; fi\n\
         if [ \"$1\" = \"-j\" ]; then exec cat \"$d/reply-$2\"; fi\n\
         exec cat \"$d/dispatch\"\n",
        d = dir.display()
    )
}

fn write_reply(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(format!("reply-{name}")), body).unwrap();
}

/// `hyprctl -j clients` fixture — same shape as the live capture in
/// `src/providers/hyprctl.rs`'s unit tests.
const CLIENTS: &str = r#"[
    {
        "address": "0x55817dbad0a0",
        "at": [10, 45],
        "size": [625, 745],
        "workspace": {"id": 2, "name": "2"},
        "class": "kitty",
        "title": "devin: onboarding",
        "focusHistoryID": 1
    },
    {
        "address": "0x55817de410c0",
        "at": [645, 45],
        "size": [625, 745],
        "workspace": {"id": 2, "name": "2"},
        "class": "kitty",
        "title": "devin: planning",
        "focusHistoryID": 0
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

/// A unique `HYPRLAND_INSTANCE_SIGNATURE` so socket probing can never
/// collide with a real Hyprland session under `/tmp/hypr/`.
fn unique_his() -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    format!(
        "ultranix-hermetic-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Fake Hyprland IPC endpoint: for each accepted connection, read the
/// request to EOF (the provider half-closes), reply with the longest-
/// matching prefix in `replies`, and close. A `bye` request stops the loop
/// so tests can `join` the thread instead of leaking a blocked `accept`.
fn fake_hyprland(listener: UnixListener, replies: HashMap<String, String>) {
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        let mut req = String::new();
        if s.read_to_string(&mut req).is_err() {
            continue;
        }
        if req == "bye" {
            return;
        }
        // `HyprctlWindow::new()` probes with a connect-and-drop — an empty
        // request. Answer it by closing, and never let a write to an
        // already-dead peer kill the responder loop.
        if req.is_empty() {
            continue;
        }
        let reply = replies
            .iter()
            .filter(|(k, _)| req.starts_with(k.as_str()))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "unknown-command".to_string());
        let _ = s.write_all(reply.as_bytes());
    }
}

/// Stop a `fake_hyprland` responder and join its thread.
fn stop_hyprland(sock: &Path, server: std::thread::JoinHandle<()>) {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(b"bye").unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    server.join().unwrap();
}

// ---------------------------------------------------------------------------
// grim
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grim_full_capture_returns_real_png() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    write_exe(dir.path(), "grim", &grim_script());
    env.set("PATH", path_with(dir.path()));

    let cap =
        GrimCapture::with_pins(&PinnedBins::resolve()).expect("fake grim must resolve on PATH");
    let frame = cap.capture_frame(None).await.unwrap();
    assert_eq!(&frame.png[..4], b"\x89PNG");
    assert_eq!((frame.width, frame.height), (1, 1));
    // The bytes are the fixture verbatim — a real decode happened.
    assert_eq!(frame.png, png_1x1());
}

#[tokio::test]
async fn grim_region_capture_pipes_slurp_geometry_into_grim() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    // slurp supplies the `-g` geometry; grim still writes the fixture to
    // its last argv, so an end-to-end success proves both spawns ran.
    write_exe(dir.path(), "grim", &grim_script());
    write_exe(dir.path(), "slurp", "#!/bin/sh\necho '0,0 2x2'\n");
    env.set("PATH", path_with(dir.path()));

    let cap = GrimCapture::with_pins(&PinnedBins::resolve()).unwrap();
    let frame = cap
        .capture_frame(Some(Rect {
            x: 5,
            y: 6,
            w: 7,
            h: 8,
        }))
        .await
        .unwrap();
    assert_eq!((frame.width, frame.height), (1, 1));
}

#[tokio::test]
async fn grim_region_capture_fails_with_slurp() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    write_exe(dir.path(), "grim", &grim_script());
    write_exe(dir.path(), "slurp", "#!/bin/sh\nexit 1\n");
    env.set("PATH", path_with(dir.path()));

    let cap = GrimCapture::with_pins(&PinnedBins::resolve()).unwrap();
    let rect = Rect {
        x: 0,
        y: 0,
        w: 10,
        h: 10,
    };
    let err = cap.capture_frame(Some(rect)).await.unwrap_err();
    assert!(
        err.to_string().contains("slurp cancelled or failed"),
        "{err}"
    );

    // Empty stdout from a "successful" slurp is also an error.
    write_exe(dir.path(), "slurp", "#!/bin/sh\nprintf '\\n'\n");
    let err = cap.capture_frame(Some(rect)).await.unwrap_err();
    assert!(err.to_string().contains("empty geometry"), "{err}");
}

#[tokio::test]
async fn grim_failure_and_garbage_output_are_errors() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    env.set("PATH", path_with(dir.path()));

    write_exe(dir.path(), "grim", "#!/bin/sh\nexit 1\n");
    let cap = GrimCapture::with_pins(&PinnedBins::resolve()).unwrap();
    let err = cap.capture_frame(None).await.unwrap_err();
    assert!(err.to_string().contains("grim exited"), "{err}");

    // Exit 0 but not a PNG — the decode guard must reject it.
    write_exe(
        dir.path(),
        "grim",
        "#!/bin/sh\nwhile [ $# -gt 1 ]; do shift; done\necho nope > \"$1\"\n",
    );
    let err = cap.capture_frame(None).await.unwrap_err();
    assert!(err.to_string().contains("not a PNG"), "{err}");
}

#[tokio::test]
async fn grim_without_extras_uses_rect_geometry_and_reports_no_cursor() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    write_exe(dir.path(), "grim", &grim_script());
    // PATH is only the tempdir: grim resolves, slurp/hyprctl can't — and
    // the builtin-only grim script still runs.
    env.set("PATH", dir.path());

    let cap = GrimCapture::with_pins(&PinnedBins::resolve()).unwrap();
    // No slurp → the requested rect goes verbatim to `grim -g`.
    let frame = cap
        .capture_frame(Some(Rect {
            x: 1,
            y: 2,
            w: 3,
            h: 4,
        }))
        .await
        .unwrap();
    assert_eq!((frame.width, frame.height), (1, 1));

    let err = cap.cursor_position().await.unwrap_err();
    assert!(err.to_string().contains("hyprctl not on PATH"), "{err}");
    let err = cap.screen_info().await.unwrap_err();
    assert!(err.to_string().contains("hyprctl not on PATH"), "{err}");
}

#[tokio::test]
async fn grim_cursor_and_screen_info_via_fake_hyprctl() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    write_exe(dir.path(), "grim", &grim_script());
    write_exe(dir.path(), "hyprctl", &hyprctl_script(dir.path()));
    write_reply(dir.path(), "cursorpos", "{\"x\":11,\"y\":22}");
    write_reply(
        dir.path(),
        "monitors",
        r#"[{"name":"eDP-1","width":1920,"height":1080}]"#,
    );
    env.set("PATH", path_with(dir.path()));

    let cap = GrimCapture::with_pins(&PinnedBins::resolve()).unwrap();
    assert_eq!(cap.cursor_position().await.unwrap(), (11, 22));
    let info = cap.screen_info().await.unwrap();
    assert_eq!(info[0]["name"], json!("eDP-1"));

    // Non-zero exit / unparseable replies surface as errors.
    write_reply(dir.path(), "cursorpos", "garbage");
    assert!(cap.cursor_position().await.is_err());
    std::fs::write(dir.path().join("fail"), "").unwrap();
    assert!(cap.screen_info().await.is_err());
}

#[test]
fn grim_new_returns_none_when_absent_from_path() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap(); // empty — no grim anywhere
    env.set("PATH", dir.path());
    assert!(GrimCapture::with_pins(&PinnedBins::resolve()).is_none());
}

// ---------------------------------------------------------------------------
// hyprctl — env probe
// ---------------------------------------------------------------------------

#[test]
fn hyprctl_new_requires_instance_signature() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    env.remove("HYPRLAND_INSTANCE_SIGNATURE");
    assert!(HyprctlWindow::new().is_none());
    env.set("HYPRLAND_INSTANCE_SIGNATURE", "");
    assert!(HyprctlWindow::new().is_none());
}

#[test]
fn hyprctl_new_returns_none_without_socket_or_binary() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let bin = tempfile::tempdir().unwrap(); // empty PATH — no hyprctl
    let rt = tempfile::tempdir().unwrap(); // empty runtime dir — no socket
    env.set("HYPRLAND_INSTANCE_SIGNATURE", unique_his());
    env.set("XDG_RUNTIME_DIR", rt.path());
    env.set("PATH", bin.path());
    // Unique HIS ⇒ /tmp/hypr/<his>/.socket.sock can't exist either —
    // and the fresh pin set over the empty PATH carries no hyprctl.
    assert!(HyprctlWindow::with_pins(&PinnedBins::resolve()).is_none());
}

// ---------------------------------------------------------------------------
// hyprctl — binary transport
// ---------------------------------------------------------------------------

/// Set up the `Hyprctl` (binary) transport: a fake `hyprctl` on PATH, a
/// unique HIS, and an `XDG_RUNTIME_DIR` without a socket so the probe
/// falls through to the binary. Returns the live provider.
fn binary_transport(dir: &Path, rt: &Path, env: &mut EnvGuard) -> HyprctlWindow {
    write_exe(dir, "hyprctl", &hyprctl_script(dir));
    env.set("HYPRLAND_INSTANCE_SIGNATURE", unique_his());
    env.set("XDG_RUNTIME_DIR", rt);
    env.set("PATH", path_with(dir));
    HyprctlWindow::with_pins(&PinnedBins::resolve()).expect("fake hyprctl must resolve on PATH")
}

#[tokio::test]
async fn hyprctl_binary_transport_parses_clients_active_and_dispatch() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let rt = tempfile::tempdir().unwrap();
    write_reply(dir.path(), "clients", CLIENTS);
    write_reply(dir.path(), "activewindow", ACTIVE);
    std::fs::write(dir.path().join("dispatch"), "ok").unwrap();
    let w = binary_transport(dir.path(), rt.path(), &mut env);

    let windows = w.list_windows().await.unwrap();
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].id, "0x55817dbad0a0");
    assert_eq!(
        windows[0].rect,
        Rect {
            x: 10,
            y: 45,
            w: 625,
            h: 745
        }
    );
    assert!(!windows[0].focused);
    // Second round-trip to `activewindow` marks focus by address.
    assert!(windows[1].focused);

    let active = w.active_window().await.unwrap().unwrap();
    assert_eq!(active.id, "0x55817de410c0");
    assert!(active.focused);

    w.dispatch("focus", "0x55817de410c0", &json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn hyprctl_binary_transport_error_paths() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let rt = tempfile::tempdir().unwrap();
    let w = binary_transport(dir.path(), rt.path(), &mut env);

    // Malformed JSON → parse error.
    write_reply(dir.path(), "clients", "not json");
    let err = w.list_windows().await.unwrap_err();
    assert!(err.to_string().contains("bad JSON"), "{err}");

    // Empty reply → explicit bail.
    write_reply(dir.path(), "clients", "   ");
    let err = w.list_windows().await.unwrap_err();
    assert!(err.to_string().contains("empty reply"), "{err}");

    // Empty array → Ok(empty).
    write_reply(dir.path(), "clients", "[]");
    assert!(w.list_windows().await.unwrap().is_empty());

    // Records missing `address`/`at`/`size` are skipped, not fatal.
    write_reply(
        dir.path(),
        "clients",
        r#"[{"title":"ghost"},{"address":"0x1","at":[0,0],"size":[1,1],"workspace":{"id":1}}]"#,
    );
    // Second call inside list_windows queries activewindow — give it a
    // "nothing focused" payload.
    write_reply(dir.path(), "activewindow", "{}");
    let windows = w.list_windows().await.unwrap();
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].id, "0x1");
    assert!(!windows[0].focused); // focusHistoryID absent → not focused

    // `activewindow` "{}" / "null" → Ok(None).
    assert!(w.active_window().await.unwrap().is_none());
    write_reply(dir.path(), "activewindow", "null");
    assert!(w.active_window().await.unwrap().is_none());

    // Missing reply file → `cat` exits 1 → transport-level error.
    std::fs::remove_file(dir.path().join("reply-activewindow")).unwrap();
    let err = w.active_window().await.unwrap_err();
    assert!(err.to_string().contains("failed"), "{err}");

    // Dispatch: non-zero exit carries stderr into the error.
    std::fs::write(dir.path().join("dispatch"), "ok").unwrap();
    std::fs::write(dir.path().join("fail"), "").unwrap();
    let err = w
        .dispatch("close", "0x55817de410c0", &json!({}))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("simulated hyprctl failure"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// hyprctl — socket transport
// ---------------------------------------------------------------------------

/// Bind a fake Hyprland IPC socket under `rt`/hypr/<his>/ and point the env
/// at it, so `HyprctlWindow::new()` picks the `Socket` transport.
fn socket_transport(
    rt: &Path,
    env: &mut EnvGuard,
    replies: HashMap<String, String>,
) -> (HyprctlWindow, PathBuf, std::thread::JoinHandle<()>) {
    let his = unique_his();
    let sock_dir = rt.join("hypr").join(&his);
    std::fs::create_dir_all(&sock_dir).unwrap();
    let sock = sock_dir.join(".socket.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || fake_hyprland(listener, replies));
    env.set("HYPRLAND_INSTANCE_SIGNATURE", &his);
    env.set("XDG_RUNTIME_DIR", rt);
    (
        HyprctlWindow::new().expect("bound socket must probe as a session"),
        sock,
        server,
    )
}

#[tokio::test]
async fn hyprctl_socket_transport_roundtrips() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let rt = tempfile::tempdir().unwrap();
    let replies = HashMap::from([
        ("j/clients".to_string(), CLIENTS.to_string()),
        ("j/activewindow".to_string(), ACTIVE.to_string()),
        ("dispatch".to_string(), "ok".to_string()),
    ]);
    let (w, sock, server) = socket_transport(rt.path(), &mut env, replies);

    // list_windows = two connections (clients, then activewindow).
    let windows = w.list_windows().await.unwrap();
    assert_eq!(windows.len(), 2);
    assert!(windows[1].focused);
    assert!(!windows[0].focused);

    let active = w.active_window().await.unwrap().unwrap();
    assert_eq!(active.id, "0x55817de410c0");

    w.dispatch("close", "0x55817de410c0", &json!({}))
        .await
        .unwrap();

    stop_hyprland(&sock, server);
}

#[tokio::test]
async fn hyprctl_socket_transport_error_paths() {
    let _env = env_guard();
    let mut env = EnvGuard::new();
    let rt = tempfile::tempdir().unwrap();
    let replies = HashMap::from([
        ("j/clients".to_string(), "garbage".to_string()),
        ("j/activewindow".to_string(), String::new()),
        ("dispatch".to_string(), "err: invalid window".to_string()),
    ]);
    let (w, sock, server) = socket_transport(rt.path(), &mut env, replies);

    // Garbage JSON on the socket → parse error.
    let err = w.list_windows().await.unwrap_err();
    assert!(err.to_string().contains("bad JSON"), "{err}");

    // Empty reply → explicit bail.
    let err = w.active_window().await.unwrap_err();
    assert!(err.to_string().contains("empty reply"), "{err}");

    // Dispatch reply other than "ok" → compositor error surfaces.
    let err = w
        .dispatch("focus", "0x55817de410c0", &json!({}))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("hyprland dispatch failed: err: invalid window"),
        "{err}"
    );

    stop_hyprland(&sock, server);
}
