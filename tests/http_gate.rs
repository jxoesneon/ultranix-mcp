//! Integration tests for `UltraNixServer::serve_http` (src/server.rs):
//! the `/mcp` auth + rate-limit gate (`HttpGate`/`ApiKeyStore`/
//! `RateLimiter`) and the open `/health`, `/readyz`, `/metrics`
//! surfaces, plus an end-to-end `tools/call` over the streamable-HTTP
//! transport.
//!
//! `serve_http` snapshots its `ApiKeyStore`/`RateLimiter` from the
//! *process* environment at startup, so every test configures
//! `ULTRANIX_MCP_*` vars through [`EnvGuard`]: it serializes on
//! [`ENV_LOCK`] (env is process-global — tests run on threads in this
//! binary), clears every gate-relevant var, applies the per-test
//! overrides, and restores the ambient values on drop. The guard is held
//! for the whole test so no parallel test can observe a half-configured
//! environment.
//!
//! `serve_stdio` is intentionally *not* re-covered here:
//! `tests/nested.rs::stdio_mock_transport_smoke` already spawns
//! `ultranix-mcp --transport stdio --mock`, drives the
//! initialize → initialized → `tools/list` handshake, and asserts the
//! 40-tool catalog plus a `tools/call` round-trip.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use ultranix_mcp::providers::Providers;
use ultranix_mcp::security::SecurityContext;
use ultranix_mcp::security::policy::{Policy, Role};
use ultranix_mcp::server::UltraNixServer;

/// Env mutation is process-global: every test in this file serializes
/// through this lock for its full duration.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Every `ULTRANIX_MCP_*` var `serve_http` consults — directly or via
/// `SecurityContext`/`ApiKeyStore`/`RateLimiter`/audit/history. Cleared
/// before each test so ambient developer/CI env can never leak in.
const ENV_VARS: &[&str] = &[
    "ULTRANIX_MCP_API_KEY",
    "ULTRANIX_MCP_API_KEY_EXPIRES",
    "ULTRANIX_MCP_API_KEY_FILE",
    "ULTRANIX_MCP_DISABLE_AUTH",
    "ULTRANIX_MCP_RATE_LIMIT",
    "ULTRANIX_MCP_STATE_DIR",
    "ULTRANIX_MCP_HISTORY_SECRET",
    "ULTRANIX_MCP_AUDIT_RETENTION_DAYS",
    "ULTRANIX_MCP_AUDIT_SECRET",
];

/// `uxcp_<64 lowercase hex>` — configured as the server's key in most
/// tests. Format-valid per `auth::is_valid_key`.
const TEST_KEY: &str = "uxcp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Valid format but never configured — drives the `unknown` 401 path.
const UNKNOWN_KEY: &str = "uxcp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Holds `ENV_LOCK` for the test's duration; restores every saved var on
/// drop (before the lock is released).
struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    /// Clear all [`ENV_VARS`], then apply `overrides`. `overrides` keys
    /// must be members of [`ENV_VARS`] so drop-restore is total.
    fn apply(overrides: &[(&'static str, Option<&str>)]) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut saved = Vec::with_capacity(ENV_VARS.len());
        for &var in ENV_VARS {
            saved.push((var, std::env::var_os(var)));
            // SAFETY: serialized by ENV_LOCK; originals restored in Drop.
            unsafe { std::env::remove_var(var) };
        }
        for &(var, val) in overrides {
            debug_assert!(ENV_VARS.contains(&var), "override {var} not in ENV_VARS");
            // SAFETY: serialized by ENV_LOCK.
            unsafe {
                match val {
                    Some(v) => std::env::set_var(var, v),
                    None => std::env::remove_var(var),
                }
            }
        }
        Self { _lock: lock, saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for &(var, ref val) in &self.saved {
            // SAFETY: `Drop::drop` runs before any field is dropped, so
            // the ENV_LOCK guard in `_lock` is still held here.
            unsafe {
                match val {
                    Some(v) => std::env::set_var(var, v),
                    None => std::env::remove_var(var),
                }
            }
        }
    }
}

/// A running `serve_http` instance on a private port; the server task is
/// aborted on drop.
struct TestServer {
    port: u16,
    join: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(join) = &self.join {
            join.abort();
        }
    }
}

/// `UltraNixServer` + security pipeline over `state_dir` (a per-test
/// tempdir), bound to a free loopback port, polled until `/health`
/// answers 200 (≤5 s) — which also proves the env snapshot
/// (`ApiKeyStore::from_env`, `RateLimiter::from_env`) already ran, since
/// both precede the bind in `serve_http`.
fn spawn_server(rt: &tokio::runtime::Runtime, state_dir: &Path) -> TestServer {
    spawn_server_with_policy(
        rt,
        state_dir,
        ultranix_mcp::security::policy::Policy::default(),
    )
}

fn spawn_server_with_policy(
    rt: &tokio::runtime::Runtime,
    state_dir: &Path,
    policy: ultranix_mcp::security::policy::Policy,
) -> TestServer {
    // Reserve a free port, release it, then let the server bind it — the
    // race window is tiny and loopback-only.
    let port = TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port();

    let mut security = SecurityContext::new(state_dir, false, false).expect("security context");
    security.set_policy(policy);
    let server = UltraNixServer::new(Providers::all_mocks(), vec![])
        .with_security(security, "test-session".into());
    let bind = format!("127.0.0.1:{port}");
    let join = rt.spawn(async move { server.serve_http(&bind).await });
    let mut srv = TestServer {
        port,
        join: Some(join),
    };

    let client = http_client();
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(join) = &srv.join
            && join.is_finished()
        {
            // Surface the startup error instead of a bare timeout.
            let join = srv.join.take().expect("join handle present");
            let outcome = rt.block_on(join);
            panic!("serve_http exited before /health answered: {outcome:?}");
        }
        match client.get(&url).send() {
            Ok(r) if r.status().as_u16() == 200 => return srv,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => panic!("serve_http on :{port} did not answer /health within 5s"),
        }
    }
}

fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest blocking client")
}

fn mcp_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

/// A `POST /mcp` request builder pre-set with the headers the
/// streamable-HTTP transport requires (`Accept` must name *both*
/// `application/json` and `text/event-stream`; `Content-Type` must be
/// JSON).
fn mcp_post(
    client: &reqwest::blocking::Client,
    port: u16,
    body: &Value,
) -> reqwest::blocking::RequestBuilder {
    client
        .post(mcp_url(port))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .body(body.to_string())
}

fn initialize_body(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "http-gate-test", "version": "0.0.0"},
        }
    })
}

/// Run the MCP initialize handshake against `/mcp`. Returns
/// `(mcp-session-id, raw SSE body)`. Asserts 200 + event-stream.
fn mcp_initialize(
    client: &reqwest::blocking::Client,
    port: u16,
    credential: Option<(&'static str, String)>,
) -> (String, String) {
    let mut req = mcp_post(client, port, &initialize_body(1));
    if let Some((name, value)) = credential {
        req = req.header(name, value);
    }
    let resp = req.send().expect("initialize POST");
    let status = resp.status().as_u16();
    let session = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().expect("initialize body");
    assert_eq!(status, 200, "initialize status; body={body}");
    assert!(
        ctype.contains("text/event-stream"),
        "initialize content-type {ctype:?} is not SSE"
    );
    let session = session.expect("initialize response must carry mcp-session-id");
    (session, body)
}

/// `notifications/initialized` on an established session — transport
/// answers 202 Accepted.
fn mcp_notify_initialized(client: &reqwest::blocking::Client, port: u16, session: &str) {
    let resp = mcp_post(
        client,
        port,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
    )
    .header("mcp-session-id", session)
    .header("x-api-key", TEST_KEY)
    .send()
    .expect("initialized notification");
    assert_eq!(
        resp.status().as_u16(),
        202,
        "initialized: {:?}",
        resp.status()
    );
}

/// `tools/call` on an established session; returns the JSON-RPC response
/// object extracted from the SSE `data:` frame.
fn mcp_call_tool(
    client: &reqwest::blocking::Client,
    port: u16,
    session: &str,
    id: i64,
    name: &str,
) -> Value {
    let resp = mcp_post(
        client,
        port,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        }),
    )
    .header("mcp-session-id", session)
    .header("x-api-key", TEST_KEY)
    .send()
    .expect("tools/call POST");
    assert_eq!(resp.status().as_u16(), 200, "tools/call status");
    let body = resp.text().expect("tools/call body");
    sse_json(&body, id)
}

/// Extract the JSON-RPC message for request `id` from an SSE body —
/// scans `data:` frames (the stream may also carry a priming event with
/// empty data and `retry:`).
fn sse_json(body: &str, id: i64) -> Value {
    for line in body.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(data)
                && v.get("id").and_then(Value::as_i64) == Some(id)
            {
                return v;
            }
        }
    }
    panic!("no SSE data frame for id {id} in body: {body}");
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("tokio runtime")
}

// ---------------------------------------------------------------------------
// Auth gate
// ---------------------------------------------------------------------------

#[test]
fn mcp_post_without_credential_is_401_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let resp = mcp_post(&client, srv.port, &initialize_body(1))
        .send()
        .expect("POST /mcp");
    assert_eq!(resp.status().as_u16(), 401);
    let body: Value = serde_json::from_str(&resp.text().unwrap()).expect("401 JSON body");
    assert_eq!(body["error"], "missing");
}

#[test]
fn mcp_post_with_malformed_key_is_401() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let resp = mcp_post(&client, srv.port, &initialize_body(1))
        .header("x-api-key", "not-a-uxcp-key")
        .send()
        .expect("POST /mcp");
    assert_eq!(resp.status().as_u16(), 401);
    let body: Value = serde_json::from_str(&resp.text().unwrap()).expect("401 JSON body");
    assert_eq!(body["error"], "malformed");
}

#[test]
fn mcp_post_with_unknown_key_is_401() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    // Format-valid (`uxcp_<64 hex>`) but not the configured key.
    let resp = mcp_post(&client, srv.port, &initialize_body(1))
        .header("x-api-key", UNKNOWN_KEY)
        .send()
        .expect("POST /mcp");
    assert_eq!(resp.status().as_u16(), 401);
    let body: Value = serde_json::from_str(&resp.text().unwrap()).expect("401 JSON body");
    assert_eq!(body["error"], "unknown");
}

#[test]
fn valid_x_api_key_initializes_over_sse() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let (_session, body) =
        mcp_initialize(&client, srv.port, Some(("x-api-key", TEST_KEY.to_string())));
    let reply = sse_json(&body, 1);
    let name = reply
        .pointer("/result/serverInfo/name")
        .and_then(Value::as_str);
    assert_eq!(name, Some("ultranix-mcp"), "initialize reply: {reply}");
}

#[test]
fn authorization_bearer_variant_initializes() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let (_session, body) = mcp_initialize(
        &client,
        srv.port,
        Some(("authorization", format!("Bearer {TEST_KEY}"))),
    );
    let reply = sse_json(&body, 1);
    assert_eq!(
        reply
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("ultranix-mcp"),
        "bearer initialize reply: {reply}"
    );
}

#[test]
fn empty_keyring_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    // No API key configured anywhere: every request must be rejected.
    let _env = EnvGuard::apply(&[("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str())]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let resp = mcp_post(&client, srv.port, &initialize_body(1))
        .header("x-api-key", TEST_KEY)
        .send()
        .expect("POST /mcp");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "fail-closed: no configured keys must still reject"
    );
}

// ---------------------------------------------------------------------------
// Open loopback endpoints
// ---------------------------------------------------------------------------

#[test]
fn health_returns_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let resp = client
        .get(format!("http://127.0.0.1:{}/health", srv.port))
        .send()
        .expect("GET /health");
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = serde_json::from_str(&resp.text().unwrap()).expect("health JSON");
    assert_eq!(body["status"], "ok");
}

#[test]
fn readyz_reports_mock_provider_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    // No credential — /readyz is deliberately outside the gate.
    let resp = client
        .get(format!("http://127.0.0.1:{}/readyz", srv.port))
        .send()
        .expect("GET /readyz");
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = serde_json::from_str(&resp.text().unwrap()).expect("readyz JSON");
    assert_eq!(body["ready"], true);
    for slot in [
        "capture",
        "input",
        "window",
        "ui_automation",
        "vision",
        "browser",
        "overlay",
    ] {
        assert_eq!(
            body["providers"][slot], true,
            "readyz providers.{slot} should be true under all_mocks: {body}"
        );
    }
}

#[test]
fn metrics_exposes_tool_call_counters() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    // Drive one real call so a `tool="screen_info"` sample exists in the
    // process-global registry.
    let (session, _init) =
        mcp_initialize(&client, srv.port, Some(("x-api-key", TEST_KEY.to_string())));
    mcp_notify_initialized(&client, srv.port, &session);
    let _ = mcp_call_tool(&client, srv.port, &session, 2, "screen_info");

    let resp = client
        .get(format!("http://127.0.0.1:{}/metrics", srv.port))
        .send()
        .expect("GET /metrics");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().unwrap();
    assert!(
        body.contains("# TYPE ultranix_mcp_tool_calls_total counter"),
        "metrics exposition missing tool_calls_total: {body}"
    );
    assert!(
        body.contains("ultranix_mcp_tool_calls_total{tool=\"screen_info\",outcome=\"ok\"}"),
        "metrics exposition missing screen_info sample: {body}"
    );
}

// ---------------------------------------------------------------------------
// Rate limit + dev escape hatch
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_burst_returns_429() {
    let tmp = tempfile::tempdir().unwrap();
    // 1 req/s refill with the 20-token burst floor: a 30-request burst
    // must overflow the bucket deterministically.
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_RATE_LIMIT", Some("1")),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let mut allowed = 0u32;
    let mut rejected = 0u32;
    for i in 0..30 {
        // `ping` never creates a session (422 past the gate — session
        // routing wants `initialize` first); what matters is that the
        // token bucket adjudicates each request before the MCP layer.
        let resp = mcp_post(
            &client,
            srv.port,
            &json!({"jsonrpc": "2.0", "id": i, "method": "ping"}),
        )
        .header("x-api-key", TEST_KEY)
        .send()
        .expect("burst POST");
        match resp.status().as_u16() {
            429 => {
                assert!(
                    resp.headers().get("retry-after").is_some(),
                    "429 must carry a Retry-After header"
                );
                rejected += 1;
            }
            _ => allowed += 1,
        }
    }
    assert!(
        rejected >= 1,
        "30-request burst at 1 rps/burst-20 must yield 429s (allowed={allowed})"
    );
    assert!(
        allowed >= 15,
        "burst capacity should admit ~20 before limiting (allowed={allowed})"
    );
}

#[test]
fn disable_auth_dev_hatch_reaches_mcp_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_DISABLE_AUTH", Some("true")),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    // No credential at all — auth is off, so the request must reach the
    // MCP transport (200 SSE), not the 401 gate.
    let (_session, body) = mcp_initialize(&client, srv.port, None);
    let reply = sse_json(&body, 1);
    assert_eq!(
        reply
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("ultranix-mcp"),
        "disable-auth initialize reply: {reply}"
    );
}

// ---------------------------------------------------------------------------
// End-to-end tools/call through the secured pipeline
// ---------------------------------------------------------------------------

#[test]
fn tools_call_over_http_returns_mock_json() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    let rt = runtime();
    let srv = spawn_server(&rt, tmp.path());
    let client = http_client();

    let (session, _init) =
        mcp_initialize(&client, srv.port, Some(("x-api-key", TEST_KEY.to_string())));
    mcp_notify_initialized(&client, srv.port, &session);

    // screen_info → MockCapture's deterministic monitor JSON, routed via
    // call_tool_secured (security is Some) → audit + metrics recorded.
    let reply = mcp_call_tool(&client, srv.port, &session, 2, "screen_info");
    let text = reply
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("screen_info reply: {reply}"));
    let doc: Value = serde_json::from_str(text).expect("screen_info JSON payload");
    assert_eq!(doc["monitors"][0]["name"], "mock");
    assert_eq!(doc["monitors"][0]["width"], 1920);

    // get_windows → MockWindow's single "mock-window" entry.
    let reply = mcp_call_tool(&client, srv.port, &session, 3, "get_windows");
    let text = reply
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("get_windows reply: {reply}"));
    let doc: Value = serde_json::from_str(text).expect("get_windows JSON payload");
    assert_eq!(doc[0]["title"], "mock-window");

    // key_id propagation: the authenticated key's id (first 8 hex of
    // SHA-256(key)) must land on the tool call's audit record, not null.
    let expected = {
        use sha2::{Digest, Sha256};
        Sha256::digest(TEST_KEY.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()[..8]
            .to_string()
    };
    let log = tmp.path().join("logs").join("audit.jsonl");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut found = false;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(&log) {
            found = contents.lines().any(|l| {
                serde_json::from_str::<Value>(l)
                    .map(|v| v["tool"] == "screen_info" && v["key_id"] == expected)
                    .unwrap_or(false)
            });
            if found {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(found, "no audit record carried key_id={expected}");
}

// ---------------------------------------------------------------------------
// Per-key runtime policy scoping (v1.3.0)
// ---------------------------------------------------------------------------

/// `tools/list` on an established session; returns the advertised tool
/// names extracted from the SSE `data:` frame.
fn mcp_list_tool_names(
    client: &reqwest::blocking::Client,
    port: u16,
    session: &str,
) -> Vec<String> {
    let resp = mcp_post(
        client,
        port,
        &json!({"jsonrpc": "2.0", "id": 90, "method": "tools/list", "params": {}}),
    )
    .header("mcp-session-id", session)
    .header("x-api-key", TEST_KEY)
    .send()
    .expect("tools/list POST");
    assert_eq!(resp.status().as_u16(), 200, "tools/list status");
    let body = resp.text().expect("tools/list body");
    let reply = sse_json(&body, 90);
    reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list reply: {reply}"))
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

/// First 8 hex chars of SHA-256(key) — the `key_id` `http_gate` derives
/// from the authenticated credential and `policy.keys` maps to a role.
fn test_key_id() -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(TEST_KEY.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..8]
        .to_string()
}

#[test]
fn per_key_role_scopes_list_and_call() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = EnvGuard::apply(&[
        ("ULTRANIX_MCP_API_KEY", Some(TEST_KEY)),
        ("ULTRANIX_MCP_STATE_DIR", tmp.path().to_str()),
    ]);
    // TEST_KEY's fingerprint → a role allowing only `screen_info`; every
    // other tool is hidden from tools/list and denied on tools/call.
    let policy = Policy {
        roles: HashMap::from([(
            "observer".to_string(),
            Role {
                allow_tools: Some(HashSet::from(["screen_info".to_string()])),
                ..Role::default()
            },
        )]),
        keys: HashMap::from([(test_key_id(), "observer".to_string())]),
        ..Policy::default()
    };
    let rt = runtime();
    let srv = spawn_server_with_policy(&rt, tmp.path(), policy);
    let client = http_client();

    let (session, _init) =
        mcp_initialize(&client, srv.port, Some(("x-api-key", TEST_KEY.to_string())));
    mcp_notify_initialized(&client, srv.port, &session);

    let names = mcp_list_tool_names(&client, srv.port, &session);
    assert_eq!(names, vec!["screen_info".to_string()]);

    // The hidden tool cannot be invoked by guessing its name.
    let reply = mcp_call_tool(&client, srv.port, &session, 3, "get_windows");
    assert_eq!(
        reply.pointer("/error/code").and_then(Value::as_i64),
        Some(-32019),
        "denied call reply: {reply}"
    );
    assert_eq!(
        reply
            .pointer("/error/data/denial_reason")
            .and_then(Value::as_str),
        Some("not_in_tool_list")
    );

    // The allowed tool still executes.
    let reply = mcp_call_tool(&client, srv.port, &session, 4, "screen_info");
    assert!(reply.pointer("/result/content/0/text").is_some(), "{reply}");
}
