//! rmcp server wiring: `tools/list` + `tools/call`, category filtering,
//! stdio and streamable-HTTP transports.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, serve_server};

use crate::providers::Providers;
use crate::tools;

/// Shared server state: provider registry + enabled tool categories.
#[derive(Clone)]
pub struct UltraNixServer {
    providers: Arc<Providers>,
    /// Enabled categories (`None` = all).
    categories: Option<Arc<Vec<String>>>,
    /// Security pipeline (consent gate, audit, pinned binaries).
    /// `None` = Phase-0 unsecured mode (tests).
    security: Option<Arc<crate::security::SecurityContext>>,
    /// CSPRNG session id binding consent tokens on stdio.
    session_id: Arc<str>,
}

impl UltraNixServer {
    pub fn new(providers: Providers, categories: Vec<String>) -> Self {
        Self {
            providers: Arc::new(providers),
            categories: if categories.is_empty() {
                None
            } else {
                Some(Arc::new(categories))
            },
            security: None,
            session_id: Arc::from("stdio-unbound"),
        }
    }

    /// Attach the security context and caller-identity session id.
    /// The configured category set is mirrored onto the context so the
    /// secured dispatch path — including `replay_action` re-entry —
    /// enforces the same filter `tools/list` advertises.
    pub fn with_security(
        mut self,
        mut security: crate::security::SecurityContext,
        session_id: String,
    ) -> Self {
        security.categories = self.categories.as_deref().map(|v| v.to_vec());
        self.security = Some(Arc::new(security));
        self.session_id = Arc::from(session_id.as_str());
        self
    }

    /// Serve MCP over stdio (JSON-RPC on stdout, logs on stderr).
    pub async fn serve_stdio(self) -> anyhow::Result<()> {
        crate::metrics::set_sessions("stdio", 1);
        let service = serve_server(self, rmcp::transport::stdio()).await?;
        service.waiting().await?;
        crate::metrics::set_sessions("stdio", 0);
        Ok(())
    }

    /// Serve MCP over streamable HTTP on `bind` (canonical: 127.0.0.1:3010,
    /// endpoint path `/mcp`).
    ///
    /// `/mcp` is gated by `ApiKeyStore` auth (fail-closed unless
    /// `ULTRANIX_MCP_DISABLE_AUTH=true`) plus the per-identity token
    /// bucket. `/health`, `/readyz`, `/metrics` stay open on loopback —
    /// they carry no secrets.
    pub async fn serve_http(self, bind: &str) -> anyhow::Result<()> {
        use rmcp::transport::streamable_http_server::{
            StreamableHttpServerConfig, session::local::LocalSessionManager,
            tower::StreamableHttpService,
        };

        let this = self.clone();
        let service = StreamableHttpService::new(
            move || Ok(this.clone()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        );

        let keys = crate::security::auth::ApiKeyStore::from_env()
            .map_err(|e| anyhow::anyhow!("API key store: {e:#}"))?;
        if keys.is_disabled() {
            tracing::warn!("ULTRANIX_MCP_DISABLE_AUTH=true: HTTP auth disabled — dev only");
        }
        let gate = HttpGate {
            keys: Arc::new(keys),
            limiter: Arc::new(crate::security::ratelimit::RateLimiter::from_env()),
            security: self.security.clone(),
        };

        let providers = self.providers.clone();
        let mcp = axum::Router::new()
            .nest_service("/mcp", service)
            .route_layer(axum::middleware::from_fn_with_state(gate, http_gate));
        let app = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
            )
            .route(
                "/readyz",
                axum::routing::get(move || {
                    let providers = providers.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "ready": true,
                            "providers": {
                                "capture": providers.capture.is_some(),
                                "input": providers.input.is_some(),
                                "window": providers.window.is_some(),
                                "ui_automation": providers.ui_automation.is_some(),
                                "vision": providers.vision.is_some(),
                                "browser": providers.browser.is_some(),
                            }
                        }))
                    }
                }),
            )
            .route(
                "/metrics",
                axum::routing::get(|| async { crate::metrics::exposition() }),
            )
            .merge(mcp);

        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(%bind, "streamable-HTTP transport listening");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

/// Shared state for the `/mcp` gate: key store + token bucket + the
/// security context for auditing rejections.
#[derive(Clone)]
struct HttpGate {
    keys: Arc<crate::security::auth::ApiKeyStore>,
    limiter: Arc<crate::security::ratelimit::RateLimiter>,
    /// `Some` in production (audit rejections); `None` in Phase-0
    /// unsecured mode.
    security: Option<Arc<crate::security::SecurityContext>>,
}

/// `/mcp` middleware: authenticate (fail-closed unless the dev escape
/// hatch is set) → rate-limit by caller identity (`key_id` when
/// authenticated, remote address otherwise) → pass through.
/// Failures are 401/429 with no stack detail (SECURITY.md error
/// hygiene); every rejection is audited (when a security context is
/// attached) and bumps `ultranix_mcp_rate_limit_rejections_total`.
async fn http_gate(
    axum::extract::State(gate): axum::extract::State<HttpGate>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let headers = req.headers();
    let header_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());
    let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
    let remote_id = remote.ip().to_string();
    // Canonical hash of the request line for the audit record — raw
    // request data (headers, bodies) never reaches the log.
    let request_hash = crate::security::consent::args_hash(&serde_json::json!({
        "method": req.method().as_str(),
        "path": req.uri().path(),
    }));
    let audit_rejection = |outcome: &str, identity: &str| {
        if let Some(sec) = &gate.security {
            let _ = sec.audit.record(
                "http_gate",
                &request_hash,
                outcome,
                0,
                crate::security::audit::CallContext {
                    key_id: None,
                    caller: Some(identity),
                    consent: None,
                },
            );
        }
    };

    let identity = if gate.keys.is_disabled() {
        remote_id
    } else {
        match gate.keys.authenticate_verbose(header_key, bearer) {
            Ok(id) => id.key_id.unwrap_or(remote_id),
            Err(f) => {
                crate::metrics::record_rate_rejection("auth");
                audit_rejection("auth_rejected", &remote_id);
                tracing::warn!(reason = f.reason(), %remote, "HTTP auth rejected");
                return (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({"error": f.reason()})),
                )
                    .into_response();
            }
        }
    };

    if !gate.limiter.check(&identity) {
        crate::metrics::record_rate_rejection("rate_limit");
        audit_rejection("rate_limited", &identity);
        // The bucket refills at `rps` tokens/second — one refill period
        // is the earliest a retry can succeed.
        let retry_after = (1.0 / gate.limiter.rps()).ceil().max(1.0) as u64;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
            axum::Json(serde_json::json!({"error": "rate limit exceeded"})),
        )
            .into_response();
    }
    next.run(req).await
}

impl ServerHandler for UltraNixServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info({
            let mut info = Implementation::from_build_env();
            info.name = "ultranix-mcp".into();
            info.version = env!("CARGO_PKG_VERSION").into();
            info
        })
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: tools::list_tools(self.categories.as_deref().map(|v| v.as_slice())),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = params.arguments.unwrap_or_default();
        let result = match &self.security {
            Some(sec) => {
                tools::call_tool_secured(
                    &params.name,
                    args,
                    &self.providers,
                    sec,
                    &self.session_id,
                    None, // HTTP key_id arrives with Phase-4 auth
                )
                .await
            }
            // Unsecured path still honours the category filter — a
            // filtered tool is MethodNotFound, not merely unlisted.
            None => match tools::category_gate(
                &params.name,
                self.categories.as_deref().map(|v| v.as_slice()),
            ) {
                Some(err) => Err(err),
                None => tools::call_tool(&params.name, args, &self.providers).await,
            },
        };
        result.map(CallToolResponse::Complete)
    }
}
