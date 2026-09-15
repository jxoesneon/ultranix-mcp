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
    pub fn with_security(
        mut self,
        security: crate::security::SecurityContext,
        session_id: String,
    ) -> Self {
        self.security = Some(Arc::new(security));
        self.session_id = Arc::from(session_id.as_str());
        self
    }

    /// Serve MCP over stdio (JSON-RPC on stdout, logs on stderr).
    pub async fn serve_stdio(self) -> anyhow::Result<()> {
        let service = serve_server(self, rmcp::transport::stdio()).await?;
        service.waiting().await?;
        Ok(())
    }

    /// Serve MCP over streamable HTTP on `bind` (canonical: 127.0.0.1:3010,
    /// endpoint path `/mcp`).
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
        let app = axum::Router::new().nest_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(%bind, "streamable-HTTP transport listening");
        axum::serve(listener, app).await?;
        Ok(())
    }
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
            None => tools::call_tool(&params.name, args, &self.providers).await,
        };
        result.map(CallToolResponse::Complete)
    }
}
