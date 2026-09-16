//! Tier-2 nested-compositor integration rig (docs/TESTING_STRATEGY.md
//! §2.2, ROADMAP Phase 5 "Nested-Hyprland integration test rig").
//!
//! The compositor lifecycle — spawn, `HYPRLAND_INSTANCE_SIGNATURE`/
//! `wayland-*` socket discovery, teardown — is inherently shell-shaped,
//! so it lives in `scripts/nested-test.sh` together with the JSON-RPC
//! stdio driver (initialize → `tools/list` == 39 → `get_windows` →
//! `screen_info` → `screenshot` PNG-magic → `get_ui_tree` → EOF
//! shutdown). This file is the cargo-facing entry point.
//!
//! Two tests:
//!
//! * [`stdio_mock_transport_smoke`] — hermetic, runs in default `cargo
//!   test`. Drives the same wire protocol over a spawned
//!   `ultranix-mcp --mock --transport stdio`, so the JSON-RPC contract the
//!   live rig asserts is exercised on every CI run (Tier-1 §1.2 "stdio
//!   transport" row).
//! * [`nested_compositor_live`] — `#[ignore]`d and inert unless
//!   `ULTRANIX_MCP_LIVE_TESTS=1`: shells `scripts/nested-test.sh`, which
//!   spawns a nested Hyprland (or headless sway/weston fallback) under a
//!   private `XDG_RUNTIME_DIR` — the real session's sockets are
//!   unreachable by construction, and only read-only tools are called.
//!
//! Run live: `ULTRANIX_MCP_LIVE_TESTS=1 cargo test --test nested -- --ignored`

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

/// The built server binary: `CARGO_BIN_EXE_*` when run under cargo, else
/// the debug target path.
fn server_bin() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_ultranix-mcp") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/ultranix-mcp")
}

/// Newline-delimited JSON-RPC stdio client over a spawned server.
/// Responses arrive on an mpsc channel fed by a reader thread so waits
/// can carry timeouts.
struct StdioClient {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Value>,
}

impl StdioClient {
    fn spawn(cmd: &mut Command) -> std::io::Result<Self> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        if let Ok(v) = serde_json::from_str::<Value>(&l)
                            && tx.send(v).is_err()
                        {
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });
        Ok(Self { child, stdin, rx })
    }

    fn send(&mut self, msg: Value) {
        let mut line = serde_json::to_string(&msg).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("write request to server stdin");
        self.stdin.flush().expect("flush request");
    }

    /// Read messages until the response carrying `id` arrives (server
    /// notifications are skipped).
    fn reply(&self, id: i64, timeout: Duration) -> Value {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .unwrap_or(Duration::ZERO);
            let msg = self
                .rx
                .recv_timeout(left.max(Duration::from_millis(50)))
                .unwrap_or_else(|_| panic!("timeout waiting for reply id={id}"));
            if msg.get("id").and_then(Value::as_i64) == Some(id) {
                return msg;
            }
        }
    }

    fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        self.reply(id, Duration::from_secs(30))
    }

    fn notify(&mut self, method: &str) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": {}}));
    }

    /// stdio MCP has no `shutdown` method: EOF on stdin is the teardown;
    /// rmcp exits 0 on it.
    fn shutdown(mut self) {
        drop(self.stdin);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait().expect("poll server exit") {
                Some(status) => {
                    assert!(status.success(), "server exited with {status}");
                    return;
                }
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                None => {
                    let _ = self.child.kill();
                    panic!("server did not exit on stdin EOF within 10s");
                }
            }
        }
    }
}

/// The read-only portion of the rig flow, run against whatever session
/// the spawned server resolved. Shared by the hermetic smoke test.
fn drive_readonly_flow(client: &mut StdioClient, expect_providers: bool) {
    let r = client.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ultranix-nested-test", "version": "0"},
        }),
    );
    let server = r.pointer("/result/serverInfo/name").and_then(Value::as_str);
    assert_eq!(server, Some("ultranix-mcp"), "initialize reply: {r}");

    client.notify("notifications/initialized");

    let r = client.request(2, "tools/list", json!({}));
    let tools = r
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list reply: {r}"));
    assert_eq!(
        tools.len(),
        39,
        "tools/list must advertise exactly 39 tools"
    );

    for (id, name) in [(3, "get_windows"), (4, "screen_info"), (5, "screenshot")] {
        let r = client.request(id, "tools/call", json!({"name": name, "arguments": {}}));
        if expect_providers {
            // Live nested compositor: providers resolve; a successful
            // CallToolResult carries at least one content item.
            let result = r.get("result").unwrap_or_else(|| panic!("{name}: {r}"));
            assert_ne!(
                result.get("isError"),
                Some(&Value::Bool(true)),
                "{name}: isError result: {r}"
            );
            let content = result.get("content").and_then(Value::as_array);
            assert!(
                content.is_some_and(|c| !c.is_empty()),
                "{name}: empty content"
            );
            if name == "screenshot" {
                let img = content
                    .expect("content asserted")
                    .iter()
                    .find(|c| c.get("type").and_then(Value::as_str) == Some("image"));
                let data = img
                    .and_then(|c| c.get("data"))
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("screenshot: no image content: {r}"));
                // PNG magic `\x89PNG\r\n\x1a\n` base64-encoded.
                assert!(
                    data.starts_with("iVBORw0KGgo"),
                    "screenshot: image content is not a PNG"
                );
            }
        } else {
            // Mock providers still answer every call; assert only the
            // envelope (a structured result or error — never silence).
            assert!(
                r.get("result").is_some() || r.get("error").is_some(),
                "{name}: malformed reply {r}"
            );
        }
    }
}

/// Hermetic Tier-1 stdio smoke: spawn `ultranix-mcp --mock`, drive the
/// JSON-RPC handshake + read-only calls, assert 39 tools and a PNG.
/// Needs no display — runs on every `cargo test`.
#[test]
fn stdio_mock_transport_smoke() {
    let bin = server_bin();
    assert!(
        bin.is_file(),
        "server binary not found at {} (run under `cargo test`)",
        bin.display()
    );
    let mut client = StdioClient::spawn(
        Command::new(&bin)
            .args(["--transport", "stdio", "--mock"])
            .env("ULTRANIX_MCP_LOG_LEVEL", "warn"),
    )
    .expect("spawn ultranix-mcp --mock");

    // Mock providers resolve every slot — same assertions as the live
    // rig, including the PNG magic prefix.
    drive_readonly_flow(&mut client, true);
    client.shutdown();
}

/// Tier-2 live rig: shell `scripts/nested-test.sh`, which owns the
/// compositor lifecycle + assertions. Inert unless explicitly opted in —
/// `cargo test` never runs ignored tests, and `-- --ignored` runs skip
/// cleanly without `ULTRANIX_MCP_LIVE_TESTS=1`.
#[test]
#[ignore = "live nested-compositor test: requires ULTRANIX_MCP_LIVE_TESTS=1"]
fn nested_compositor_live() {
    if std::env::var("ULTRANIX_MCP_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("nested_compositor_live: skipped (set ULTRANIX_MCP_LIVE_TESTS=1)");
        return;
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/nested-test.sh");
    assert!(script.is_file(), "missing {}", script.display());

    let mut cmd = Command::new("bash");
    cmd.arg(&script);
    // Point the rig at the binary cargo just built unless the caller
    // already chose one.
    if std::env::var_os("ULTRANIX_MCP_BIN").is_none()
        && let Some(p) = option_env!("CARGO_BIN_EXE_ultranix-mcp")
    {
        cmd.env("ULTRANIX_MCP_BIN", p);
    }
    let status = cmd.status().expect("spawn scripts/nested-test.sh");
    assert!(status.success(), "nested-test.sh failed: {status}");
}
