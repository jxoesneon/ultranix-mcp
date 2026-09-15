//! CDP `BrowserProvider` — Chrome DevTools Protocol over loopback.
//!
//! Drives a Chromium-family browser started with
//! `--remote-debugging-port=9222` (or already exposing a CDP listener on
//! `127.0.0.1:9222`). The bridge is deliberately narrow: discover a page
//! target over the `/json/*` HTTP surface, upgrade to its
//! `webSocketDebuggerUrl`, enable the `Runtime` domain, and answer
//! [`BrowserProvider::query_selector`] with one `Runtime.evaluate` call.
//!
//! ## Wire flow
//!
//! 1. `ensure_ready` → `GET http://<endpoint>/json/list`, pick the first
//!    `"type": "page"` target (fall back to `/json/version` when no list
//!    entry qualifies), open the returned `ws://` URL, send
//!    `Runtime.enable`.
//! 2. `query_selector` → `Runtime.evaluate` of a fixed expression whose
//!    only variable part is the selector embedded as a **JSON string
//!    literal** (`serde_json::to_string`), so quotes/newlines in the
//!    selector can never break out of the generated JavaScript.
//! 3. The reply's `result.result.value` is itself a JSON document
//!    (`JSON.stringify` on the page side); it is parsed and returned as
//!    `{"matches": [...]}` — the raw Phase-0 shape `web_query` normalises.
//!
//! ## Safety
//!
//! * **Loopback only.** The endpoint host is validated as `127.0.0.0/8`,
//!   `::1`, or `localhost` (normalised to `127.0.0.1`); the
//!   `webSocketDebuggerUrl` returned by the endpoint is validated the
//!   same way, so a hostile local process cannot redirect the bridge to
//!   a remote WebSocket.
//! * **No selector splicing.** The selector is embedded via JSON encoding
//!   and additionally validated (1..=1024 chars, no control bytes, no
//!   `javascript:`) before any network traffic.
//! * **Bounded.** Every stage (TCP probe, HTTP fetch, WS handshake, RPC
//!   reply) runs under a timeout; the HTTP body is capped at 1 MiB and
//!   matches at [`MAX_MATCHES`].
//! * **Self-healing.** Any transport/RPC failure drops the cached
//!   connection; the next call re-discovers and reconnects.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::traits::BrowserProvider;

/// Default CDP port (`--remote-debugging-port=9222`), loopback only.
const DEFAULT_PORT: u16 = 9222;
/// TCP-connect budget for the `new()` availability probe — a refused
/// loopback connection returns instantly; this only bounds filtered ports.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
/// `/json/*` HTTP fetch budget.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
/// WebSocket handshake budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// One JSON-RPC round-trip budget (Runtime.enable / Runtime.evaluate).
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on a `/json/*` response body (target lists stay in the low KiB).
const MAX_HTTP_BODY: u64 = 1 << 20;
/// Selector length cap — mirrors the `web_query` tool contract.
const MAX_SELECTOR_CHARS: usize = 1024;
/// Hard cap on matched elements serialized into one reply.
const MAX_MATCHES: usize = 256;

/// CDP-backed [`BrowserProvider`].
///
/// [`CdpBrowser::new`] is a bare TCP probe — the HTTP discovery and
/// WebSocket handshake are lazy (`ensure_ready`), so construction never
/// needs a tokio runtime and never talks to the browser.
pub struct CdpBrowser {
    endpoint: Endpoint,
    conn: Mutex<Option<CdpConn>>,
}

#[derive(Debug)]
struct Endpoint {
    /// Loopback host — IP literal, or `"localhost"` normalised to
    /// `127.0.0.1` at construction.
    host: String,
    port: u16,
}

/// A live WebSocket session plus the JSON-RPC id counter.
struct CdpConn {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl CdpBrowser {
    /// `Some` only when a listener accepts TCP on `127.0.0.1:9222`.
    /// A connect-and-drop probe: CDP endpoints tolerate it (the HTTP
    /// request is never sent, so nothing is logged browser-side).
    pub fn new() -> Option<Self> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_PORT));
        probe_addr(addr).then(|| Self::endpoint("127.0.0.1".to_string(), DEFAULT_PORT))
    }

    /// Explicit-endpoint constructor (tests, non-default ports). Rejects
    /// any host that is not loopback — the bridge must never leave the
    /// local machine.
    pub fn with_endpoint(host: &str, port: u16) -> Result<Self> {
        ensure!(
            is_loopback_host(host),
            "cdp: refusing non-loopback endpoint host '{host}'"
        );
        ensure!(port != 0, "cdp: port 0 is not a usable endpoint");
        Ok(Self::endpoint(normalize_host(host), port))
    }

    fn endpoint(host: String, port: u16) -> Self {
        Self {
            endpoint: Endpoint { host, port },
            conn: Mutex::new(None),
        }
    }

    /// Target `webSocketDebuggerUrl`: `/json/list` first (page target —
    /// the Runtime domain only exists on page/worker targets), then
    /// `/json/version` as a fallback for endpoints that expose only the
    /// browser-level socket.
    async fn discover_ws_url(&self) -> Result<String> {
        match self.http_get("/json/list").await {
            Ok(list) => {
                if let Some(url) = pick_page_target(&list) {
                    return normalize_ws_url(&url);
                }
                tracing::debug!("cdp: /json/list has no page target; trying /json/version");
            }
            Err(e) => {
                tracing::debug!(error = %e, "cdp: /json/list failed; trying /json/version");
            }
        }
        let version = self.http_get("/json/version").await?;
        let url = version
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("cdp: /json/version lacks webSocketDebuggerUrl"))?;
        normalize_ws_url(url)
    }

    /// Minimal `GET <path>` on the CDP HTTP surface. Chrome answers with
    /// `Content-Length` + connection close; chunked transfer is decoded
    /// as a fallback for other CDP front-ends.
    async fn http_get(&self, path: &str) -> Result<Value> {
        debug_assert!(path.starts_with("/json"));
        let fut = async {
            let mut stream =
                TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port)).await?;
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                self.host_header()
            );
            stream.write_all(request.as_bytes()).await?;
            let mut buf = Vec::with_capacity(4096);
            stream.take(MAX_HTTP_BODY).read_to_end(&mut buf).await?;
            parse_http_response(&buf)
        };
        tokio::time::timeout(HTTP_TIMEOUT, fut)
            .await
            .context("cdp: HTTP probe timed out")?
    }

    /// `Host:` header value — IPv6 literals need brackets.
    fn host_header(&self) -> String {
        if self.endpoint.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.endpoint.host, self.endpoint.port)
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        }
    }
}

impl CdpConn {
    /// One JSON-RPC round-trip: send `{id, method, params}`, then skip
    /// events and foreign-id replies until our `id` answers. Failures
    /// here are transport-level — callers drop the connection.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"id": id, "method": method, "params": params});
        self.ws
            .send(Message::text(request.to_string()))
            .await
            .context("cdp: websocket send failed")?;
        let reply = tokio::time::timeout(RPC_TIMEOUT, self.wait_reply(id))
            .await
            .context("cdp: rpc reply timed out")??;
        if let Some(err) = reply.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            bail!("cdp {method} failed: {msg}");
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Read frames until the reply for `id` arrives. CDP pushes events
    /// (`{"method": ...}` with no `id`) and, once `Runtime.enable` has
    /// run, `Runtime.executionContextCreated` floods are normal — all
    /// non-matching messages are skipped.
    async fn wait_reply(&mut self, id: u64) -> Result<Value> {
        while let Some(msg) = self.ws.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let v: Value = serde_json::from_str(text.as_str())
                        .context("cdp: reply frame is not JSON")?;
                    if v.get("id").and_then(Value::as_u64) == Some(id) {
                        return Ok(v);
                    }
                }
                // Ping/Pong/Binary carry no JSON-RPC payload; Pong replies
                // to Ping are produced by tungstenite internally.
                Ok(
                    Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_),
                ) => {}
                Ok(Message::Close(_)) => bail!("cdp: websocket closed while awaiting reply"),
                Err(e) => return Err(e).context("cdp: websocket read failed"),
            }
        }
        bail!("cdp: websocket closed while awaiting reply")
    }
}

#[async_trait]
impl BrowserProvider for CdpBrowser {
    /// Lazy connect: no-op while a session is cached, otherwise run
    /// discovery → WS handshake → `Runtime.enable`.
    async fn ensure_ready(&self) -> Result<()> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let ws_url = self.discover_ws_url().await?;
        let (ws, _resp) = tokio::time::timeout(CONNECT_TIMEOUT, connect_async(ws_url.as_str()))
            .await
            .context("cdp: websocket connect timed out")?
            .context("cdp: websocket handshake failed")?;
        let mut conn = CdpConn { ws, next_id: 1 };
        conn.call("Runtime.enable", json!({})).await?;
        *guard = Some(conn);
        tracing::info!(
            host = self.endpoint.host.as_str(),
            port = self.endpoint.port,
            "cdp browser attached"
        );
        Ok(())
    }

    async fn query_selector(&self, selector: &str) -> Result<Value> {
        validate_selector(selector)?;
        self.ensure_ready().await?;
        let params = json!({
            "expression": query_expression(selector)?,
            "returnByValue": true,
        });
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().context("cdp: connection unavailable")?;
        match conn.call("Runtime.evaluate", params).await {
            Ok(result) => parse_evaluate_result(&result),
            Err(e) => {
                // Drop the session so the next call reconnects cleanly.
                *guard = None;
                Err(e)
            }
        }
    }
}

// ---------- selector / expression handling ----------

/// Provider-side selector gate — defence in depth under the tool layer.
/// The selector is also JSON-encoded into the expression, so even a
/// passing string cannot break out of the generated JavaScript.
fn validate_selector(selector: &str) -> Result<()> {
    ensure!(!selector.is_empty(), "cdp: selector must not be empty");
    ensure!(
        selector.chars().count() <= MAX_SELECTOR_CHARS,
        "cdp: selector exceeds {MAX_SELECTOR_CHARS} chars"
    );
    ensure!(
        !selector.chars().any(char::is_control),
        "cdp: selector contains control characters"
    );
    ensure!(
        !selector.to_ascii_lowercase().contains("javascript:"),
        "cdp: selector contains a javascript: pseudo-url"
    );
    Ok(())
}

/// Build the `Runtime.evaluate` expression. The selector is embedded as a
/// JSON string literal — never spliced — so `"` / `\` / quotes cannot
/// corrupt the generated code. The page-side `JSON.stringify` yields a
/// JSON array we parse back into `{"matches": [...]}`.
fn query_expression(selector: &str) -> Result<String> {
    let sel = serde_json::to_string(selector).context("cdp: selector is not encodable")?;
    Ok(format!(
        "JSON.stringify([...document.querySelectorAll({sel})]\
         .slice(0,{MAX_MATCHES})\
         .map(e=>{{const r=e.getBoundingClientRect();\
         return {{tag:e.tagName.toLowerCase(),id:e.id||null,\
         text:(e.textContent||\"\").replace(/\\s+/g,\" \").trim().slice(0,200),\
         rect:{{x:r.x,y:r.y,w:r.width,h:r.height}}}}}}))"
    ))
}

/// `Runtime.evaluate` result → `{"matches": [...]}`.
/// `exceptionDetails` (e.g. an invalid selector throwing inside
/// `querySelectorAll`) maps onto an error rather than an empty match.
fn parse_evaluate_result(result: &Value) -> Result<Value> {
    if let Some(exc) = result.get("exceptionDetails") {
        let detail = exc
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(Value::as_str)
            .or_else(|| exc.get("text").and_then(Value::as_str))
            .unwrap_or("js exception");
        bail!("cdp evaluate: {}", truncate(detail, 200));
    }
    let raw = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(Value::as_str)
        .context("cdp: Runtime.evaluate returned no string value")?;
    let matches: Value = serde_json::from_str(raw).context("cdp: evaluate payload is not JSON")?;
    ensure!(
        matches.is_array(),
        "cdp: evaluate payload is not a match array"
    );
    Ok(json!({"matches": matches}))
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

// ---------- endpoint / URL validation ----------

/// Loopback check: `127.0.0.0/8` and `::1` IP literals, plus `localhost`
/// (normalised to `127.0.0.1` before any DNS-dependent use).
fn is_loopback_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

/// `"localhost"` → `"127.0.0.1"` so connects never depend on resolver
/// behaviour; IP literals pass through unchanged.
fn normalize_host(host: &str) -> String {
    if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_string()
    } else {
        host.to_string()
    }
}

/// Validate and normalise a `webSocketDebuggerUrl`: `ws://` scheme,
/// loopback authority, `localhost` rewritten to `127.0.0.1`. Rebuilt from
/// parts so a URL with an embedded userinfo or unexpected shape can't
/// smuggle a non-loopback dial target past the check.
fn normalize_ws_url(raw: &str) -> Result<String> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("cdp: malformed webSocketDebuggerUrl '{raw}'"))?;
    ensure!(
        uri.scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("ws")),
        "cdp: webSocketDebuggerUrl must use the ws:// scheme"
    );
    let authority = uri.authority().context("cdp: ws url has no authority")?;
    ensure!(
        !authority.as_str().contains('@'),
        "cdp: ws url must not carry userinfo"
    );
    // `Uri::host` may keep the IPv6 brackets ("[::1]") — strip them so the
    // loopback check sees a bare literal.
    let host = uri
        .host()
        .context("cdp: ws url has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    ensure!(
        is_loopback_host(host),
        "cdp: refusing non-loopback ws host '{host}'"
    );
    let host_part = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        normalize_host(host)
    };
    let port = uri.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Ok(format!("ws://{host_part}:{port}{path}"))
}

/// First `"type": "page"` target's debugger URL; falls back to any entry
/// carrying one (e.g. a `newtab`-less endpoint listing only a worker).
fn pick_page_target(list: &Value) -> Option<String> {
    let arr = list.as_array()?;
    let ws_url = |t: &Value| {
        t.get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .filter(|u| u.starts_with("ws://"))
            .map(str::to_string)
    };
    arr.iter()
        .find(|t| t.get("type").and_then(Value::as_str) == Some("page"))
        .and_then(&ws_url)
        .or_else(|| arr.iter().find_map(ws_url))
}

/// Cheap synchronous TCP-connect probe used by [`CdpBrowser::new`].
fn probe_addr(addr: SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

// ---------- minimal HTTP/1.1 response parsing ----------

/// `HTTP/1.1 <status>` + headers + body → parsed JSON body. Handles both
/// `Content-Length` (Chrome's shape) and `Transfer-Encoding: chunked`.
fn parse_http_response(raw: &[u8]) -> Result<Value> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("cdp: malformed http response (no header terminator)")?;
    let head = std::str::from_utf8(&raw[..split]).context("cdp: non-UTF-8 http headers")?;
    let status = head.lines().next().unwrap_or_default();
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .with_context(|| format!("cdp: bad http status line '{status}'"))?;
    ensure!((200..300).contains(&code), "cdp: http status {code}");
    let chunked = head.lines().skip(1).any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let body = &raw[split + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    serde_json::from_slice(&body).context("cdp: http body is not JSON")
}

/// RFC 9112 chunked transfer decoding (extensions ignored; trailers end
/// at the zero-size chunk).
fn decode_chunked(mut buf: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = buf
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("cdp: bad chunk header")?;
        let size_field =
            std::str::from_utf8(&buf[..line_end]).context("cdp: non-UTF-8 chunk header")?;
        let size =
            usize::from_str_radix(size_field.split(';').next().unwrap_or_default().trim(), 16)
                .context("cdp: bad chunk size")?;
        buf = &buf[line_end + 2..];
        if size == 0 {
            break;
        }
        ensure!(buf.len() >= size + 2, "cdp: truncated chunk");
        out.extend_from_slice(&buf[..size]);
        buf = &buf[size + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_tungstenite::accept_async;

    // ---------- hermetic CDP stub ----------
    //
    // One TCP listener answers both surfaces: a peek at the request line
    // routes `/json*` to a plain-HTTP responder and everything else to a
    // real tokio-tungstenite server handshake + JSON-RPC loop.

    #[derive(Debug, Clone, Copy)]
    enum StubMode {
        /// Protocol-correct replies; `Runtime.evaluate` decodes the
        /// selector literal out of the expression and echoes it inside
        /// the canned match — proving JSON-encoded (not spliced) embeds.
        Happy,
        /// `Runtime.evaluate` is answered with a foreign id, then the
        /// socket is closed: the client must fail instead of hanging.
        IdMismatch,
        /// `Runtime.evaluate` replies with `exceptionDetails`.
        JsException,
    }

    async fn spawn_stub(mode: StubMode) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle_stub_conn(stream, port, mode));
            }
        });
        (port, task)
    }

    async fn handle_stub_conn(mut stream: TcpStream, port: u16, mode: StubMode) {
        match peek_request_path(&mut stream).await {
            Some(path) if path.starts_with("/json") => stub_http(stream, port, &path).await,
            Some(_) => stub_ws(stream, mode).await,
            None => {}
        }
    }

    /// Peek (never consume) until the request line is complete.
    async fn peek_request_path(stream: &mut TcpStream) -> Option<String> {
        let mut buf = vec![0u8; 1024];
        let mut n = 0;
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_secs(2), stream.peek(&mut buf)).await {
                Ok(Ok(0)) => return None,
                Ok(Ok(m)) => {
                    n = m;
                    if buf[..n].contains(&b'\n') {
                        break;
                    }
                }
                _ => return None,
            }
        }
        let head = String::from_utf8_lossy(&buf[..n]);
        let path = head.lines().next()?.split_whitespace().nth(1)?;
        Some(path.to_string())
    }

    /// Consume the request head (avoids a reset-on-close racing the reply).
    async fn read_http_head(stream: &mut TcpStream) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(m) => {
                    buf.extend_from_slice(&chunk[..m]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                        break;
                    }
                }
            }
        }
    }

    async fn stub_http(mut stream: TcpStream, port: u16, path: &str) {
        read_http_head(&mut stream).await;
        let body = if path.starts_with("/json/list") || path == "/json" {
            json!([{
                "type": "page",
                "id": "stub-page-1",
                "title": "CDP stub",
                "url": "about:blank",
                "webSocketDebuggerUrl":
                    format!("ws://127.0.0.1:{port}/devtools/page/stub-page-1"),
            }])
        } else {
            json!({
                "Browser": "stub/0.0",
                "webSocketDebuggerUrl":
                    format!("ws://127.0.0.1:{port}/devtools/browser/stub-1"),
            })
        }
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    async fn stub_ws(stream: TcpStream, mode: StubMode) {
        let Ok(mut ws) = accept_async(stream).await else {
            return;
        };
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(text) = msg else {
                continue;
            };
            let Ok(req) = serde_json::from_str::<Value>(text.as_str()) else {
                continue;
            };
            let Some(id) = req.get("id").and_then(Value::as_u64) else {
                continue;
            };
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let reply = match method {
                "Runtime.enable" => json!({"id": id, "result": {}}),
                "Runtime.evaluate" => match mode {
                    StubMode::IdMismatch => {
                        let foreign = json!({"id": id + 9_999, "result": {}});
                        let _ = ws.send(Message::text(foreign.to_string())).await;
                        let _ = ws.send(Message::Close(None)).await;
                        return;
                    }
                    StubMode::JsException => json!({
                        "id": id,
                        "result": {"exceptionDetails": {
                            "text": "SyntaxError",
                            "exception": {"description":
                                "SyntaxError: Failed to execute 'querySelectorAll'"},
                        }},
                    }),
                    StubMode::Happy => {
                        let expr = req
                            .pointer("/params/expression")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        // An event frame and a foreign-id reply precede the
                        // real answer — the client must skip both.
                        let event = json!({"method": "Runtime.consoleAPICalled", "params": {}});
                        let _ = ws.send(Message::text(event.to_string())).await;
                        let foreign = json!({"id": id + 5_000, "result": {}});
                        let _ = ws.send(Message::text(foreign.to_string())).await;
                        match extract_selector_arg(expr) {
                            Ok(sel) => {
                                let matches = json!([{
                                    "tag": "button",
                                    "id": "go",
                                    "text": "Go",
                                    "rect": {"x": 1, "y": 2, "w": 30, "h": 12},
                                    "selector": sel,
                                }]);
                                json!({
                                    "id": id,
                                    "result": {"result": {
                                        "type": "string",
                                        "value": matches.to_string(),
                                    }},
                                })
                            }
                            Err(e) => json!({
                                "id": id,
                                "result": {"exceptionDetails": {"text": e}},
                            }),
                        }
                    }
                },
                other => json!({
                    "id": id,
                    "error": {"code": -32601, "message": format!("stub: unsupported {other}")},
                }),
            };
            if ws.send(Message::text(reply.to_string())).await.is_err() {
                return;
            }
        }
    }

    /// Pull the `document.querySelectorAll(<literal>)` argument out of the
    /// generated expression and decode it as a JSON string. Fails when
    /// the selector was spliced raw — that is precisely what the happy
    /// path tests prove cannot happen.
    fn extract_selector_arg(expr: &str) -> Result<String, String> {
        let pos = expr
            .find("querySelectorAll(")
            .ok_or("expression has no querySelectorAll call")?;
        let rest = expr[pos + "querySelectorAll(".len()..].trim_start();
        if !rest.starts_with('"') {
            return Err("selector argument is not a JSON string literal".into());
        }
        let bytes = rest.as_bytes();
        let mut end = 1;
        while end < bytes.len() {
            match bytes[end] {
                b'\\' => end += 2,
                b'"' => break,
                _ => end += 1,
            }
        }
        if end >= bytes.len() {
            return Err("unterminated selector literal".into());
        }
        serde_json::from_str::<String>(&rest[..=end])
            .map_err(|e| format!("selector literal is not valid JSON: {e}"))
    }

    // ---------- endpoint / probe ----------

    #[test]
    fn non_loopback_endpoints_rejected() {
        for host in [
            "8.8.8.8",
            "192.168.0.1",
            "10.0.0.1",
            "203.0.113.7",
            "172.16.0.5",
            "0.0.0.0",
            "::",
            "example.com",
            "",
        ] {
            assert!(
                CdpBrowser::with_endpoint(host, 9222).is_err(),
                "{host:?} must be rejected"
            );
        }
        assert!(CdpBrowser::with_endpoint("127.0.0.1", 0).is_err());
    }

    #[test]
    fn loopback_endpoints_accepted() {
        for host in ["127.0.0.1", "127.0.0.53", "::1", "localhost", "LOCALHOST"] {
            assert!(
                CdpBrowser::with_endpoint(host, 9222).is_ok(),
                "{host:?} must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn tcp_probe_detects_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(probe_addr(addr));
        let port = addr.port();
        drop(listener);
        assert!(!probe_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port))));
    }

    #[test]
    fn new_is_a_bare_probe() {
        // Environment-dependent (a dev box may run a real CDP browser):
        // assert only that the probe returns without hanging or panicking.
        let _ = CdpBrowser::new();
    }

    #[test]
    fn ws_url_validation() {
        assert_eq!(
            normalize_ws_url("ws://127.0.0.1:9222/devtools/page/x").unwrap(),
            "ws://127.0.0.1:9222/devtools/page/x"
        );
        // localhost is normalised to the loopback literal.
        assert_eq!(
            normalize_ws_url("ws://localhost:9222/devtools/page/x").unwrap(),
            "ws://127.0.0.1:9222/devtools/page/x"
        );
        assert!(normalize_ws_url("ws://[::1]:9222/devtools/page/x").is_ok());
        for bad in [
            "http://127.0.0.1:9222/x",    // wrong scheme
            "ws://evil.example.com/x",    // remote host
            "ws://8.8.8.8:1/x",           // remote ip
            "ws://user@127.0.0.1:9222/x", // userinfo
            "ws://127.0.0.1.evil.com/x",  // lookalike hostname
            "not-a-url",
        ] {
            assert!(normalize_ws_url(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn page_target_selection() {
        let list = json!([
            {"type": "service_worker", "webSocketDebuggerUrl": "ws://127.0.0.1:9/sw"},
            {"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:9/p"},
        ]);
        assert_eq!(
            pick_page_target(&list).as_deref(),
            Some("ws://127.0.0.1:9/p")
        );
        // No page: any target with a debugger URL is the fallback.
        let no_page = json!([{"type": "worker", "webSocketDebuggerUrl": "ws://127.0.0.1:9/w"}]);
        assert_eq!(
            pick_page_target(&no_page).as_deref(),
            Some("ws://127.0.0.1:9/w")
        );
        assert!(pick_page_target(&json!([])).is_none());
        assert!(pick_page_target(&json!({"not": "a list"})).is_none());
    }

    // ---------- selector / expression ----------

    #[test]
    fn selector_validation() {
        for sel in ["div", "#id > .cls", "a[href*='x?y=1&z=\"2\"]"] {
            assert!(validate_selector(sel).is_ok(), "{sel:?}");
        }
        for sel in [
            "",
            "div\n.foo",
            "a\0b",
            "javascript:alert(1)",
            "JAVASCRIPT:x",
        ] {
            assert!(validate_selector(sel).is_err(), "{sel:?}");
        }
        let long = "a".repeat(MAX_SELECTOR_CHARS + 1);
        assert!(validate_selector(&long).is_err());
    }

    #[test]
    fn expression_embeds_selector_as_json_literal() {
        let expr = query_expression("div.card").unwrap();
        assert!(expr.contains("querySelectorAll(\"div.card\")"), "{expr}");
        assert!(!expr.contains("returnByValue")); // that's a param, not the expression
        let quoted = query_expression("a[b=\"c\\d\"]").unwrap();
        assert_eq!(extract_selector_arg(&quoted).unwrap(), "a[b=\"c\\d\"]");
    }

    #[test]
    fn evaluate_result_parsing() {
        let ok = json!({"result": {"type": "string", "value": "[{\"tag\":\"a\"}]"}});
        assert_eq!(
            parse_evaluate_result(&ok).unwrap(),
            json!({"matches": [{"tag": "a"}]})
        );
        let exc = json!({"exceptionDetails": {"text": "SyntaxError"}});
        assert!(parse_evaluate_result(&exc).is_err());
        let no_value = json!({"result": {"type": "undefined"}});
        assert!(parse_evaluate_result(&no_value).is_err());
        let not_array = json!({"result": {"type": "string", "value": "{\"x\":1}"}});
        assert!(parse_evaluate_result(&not_array).is_err());
    }

    // ---------- HTTP parsing ----------

    #[test]
    fn http_response_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        assert_eq!(parse_http_response(raw).unwrap(), json!({"a": 1}));
    }

    #[test]
    fn http_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), json!({"a": 1}));
    }

    #[test]
    fn http_response_rejects_bad_status_and_shape() {
        assert!(parse_http_response(b"HTTP/1.1 404 Not Found\r\n\r\n{}").is_err());
        assert!(parse_http_response(b"garbage-without-terminator").is_err());
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\n\r\nnot json").is_err());
    }

    // ---------- live stub tests ----------

    #[tokio::test]
    async fn query_selector_happy_path() {
        let (port, _stub) = spawn_stub(StubMode::Happy).await;
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        browser.ensure_ready().await.unwrap();
        let v = browser.query_selector("div.card").await.unwrap();
        let matches = v["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["tag"], "button");
        assert_eq!(matches[0]["id"], "go");
        assert_eq!(
            matches[0]["rect"],
            json!({"x": 1, "y": 2, "w": 30, "h": 12})
        );
        // The stub echoes the selector it decoded from the expression.
        assert_eq!(matches[0]["selector"], "div.card");
    }

    #[tokio::test]
    async fn query_selector_lazy_connects() {
        // No explicit ensure_ready: the first query connects by itself.
        let (port, _stub) = spawn_stub(StubMode::Happy).await;
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        let v = browser.query_selector("main h1").await.unwrap();
        assert_eq!(v["matches"][0]["selector"], "main h1");
    }

    #[tokio::test]
    async fn quoted_selector_roundtrips_via_json_encoding() {
        let (port, _stub) = spawn_stub(StubMode::Happy).await;
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        // Quotes + backslash: spliced embedding would break the JS; the
        // stub only answers when the literal decodes back to the input.
        let sel = r#"div[data-x="it's \"quoted\" \ end"]"#;
        let v = browser.query_selector(sel).await.unwrap();
        assert_eq!(v["matches"][0]["selector"], sel);
    }

    #[tokio::test]
    async fn rpc_id_mismatch_errors_and_recovers() {
        let (port, _stub) = spawn_stub(StubMode::IdMismatch).await;
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        browser.ensure_ready().await.unwrap();
        assert!(browser.query_selector("div").await.is_err());
        // The failed call dropped the session; a fresh attach succeeds.
        browser.ensure_ready().await.unwrap();
    }

    #[tokio::test]
    async fn js_exception_details_surface_as_error() {
        let (port, _stub) = spawn_stub(StubMode::JsException).await;
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        let err = browser.query_selector(">>>").await.unwrap_err();
        assert!(format!("{err}").contains("SyntaxError"), "{err}");
    }

    #[tokio::test]
    async fn connection_refused_is_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let browser = CdpBrowser::with_endpoint("127.0.0.1", port).unwrap();
        assert!(browser.ensure_ready().await.is_err());
        assert!(browser.query_selector("div").await.is_err());
    }

    #[tokio::test]
    async fn invalid_selector_fails_before_network() {
        // Endpoint is unreachable — validation must reject first.
        let browser = CdpBrowser::with_endpoint("127.0.0.1", 1).unwrap();
        for sel in ["", "div\n.foo", "javascript:alert(1)"] {
            assert!(browser.query_selector(sel).await.is_err(), "{sel:?}");
        }
    }
}
