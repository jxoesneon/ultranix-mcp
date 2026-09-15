//! ultranix-mcp entrypoint — transport selection, provider bootstrap,
//! stderr tracing (stdout is reserved for MCP JSON-RPC).

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use ultranix_mcp::backend::detect::{SessionInfo, detect_providers};
use ultranix_mcp::providers::Providers;
use ultranix_mcp::security::SecurityContext;
use ultranix_mcp::server::UltraNixServer;
use ultranix_mcp::state::StateDir;

#[derive(Debug, Clone, ValueEnum)]
enum Transport {
    Stdio,
    Http,
}

#[derive(Debug, Parser)]
#[command(
    name = "ultranix-mcp",
    version,
    about = "Linux desktop automation MCP server"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// Transport to serve.
    #[arg(long, value_enum, default_value_t = Transport::Stdio)]
    transport: Transport,

    /// Alias for `--transport stdio`.
    #[arg(long, conflicts_with = "transport")]
    stdio: bool,

    /// Restrict the advertised tool surface to these categories
    /// (comma-separated: mouse,keyboard,vision,automation,admin).
    #[arg(long, value_delimiter = ',')]
    category: Vec<String>,

    /// HTTP bind address (only with --transport http).
    #[arg(long, default_value = "127.0.0.1:3010")]
    bind: String,

    /// Bypass the destructive-tool consent gate (operator opt-out;
    /// every gated call is still audited, stamped "consent: bypassed").
    #[arg(long)]
    allow_destructive: bool,

    /// Force mock providers regardless of detected backends (testing).
    #[arg(long)]
    mock: bool,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Print a fresh `uxcp_*` API key (store it via
    /// ULTRANIX_MCP_API_KEY or a file under ~/.ultranix-mcp/api-keys/).
    Keygen,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Cmd::Keygen) = cli.command {
        println!("{}", ultranix_mcp::security::auth::keygen());
        return Ok(());
    }

    // stdout is the JSON-RPC channel on stdio — diagnostics go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("ULTRANIX_MCP_LOG_LEVEL")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = StateDir::bootstrap()?;
    tracing::info!(data_dir = %state.root().display(), "ultranix-mcp starting");

    if cli.allow_destructive {
        tracing::warn!("--allow-destructive: consent gate bypassed (audited)");
    }

    let session = SessionInfo::detect();
    let providers = if cli.mock {
        Providers::all_mocks()
    } else {
        detect_providers(&session)
    };

    let security = SecurityContext::new(
        state.root(),
        cli.allow_destructive,
        matches!(
            session.session_type,
            ultranix_mcp::backend::detect::SessionType::X11
        ),
    )?;
    let session_id = ultranix_mcp::security::consent::new_session_id();

    let server = UltraNixServer::new(providers, cli.category).with_security(security, session_id);

    let use_stdio = cli.stdio || matches!(cli.transport, Transport::Stdio);
    if use_stdio {
        server.serve_stdio().await
    } else {
        server.serve_http(&cli.bind).await
    }
}
