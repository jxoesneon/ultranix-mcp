//! ultranix-mcp entrypoint — transport selection, provider bootstrap,
//! stderr tracing (stdout is reserved for MCP JSON-RPC).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

use ultranix_mcp::providers::Providers;
use ultranix_mcp::server::UltraNixServer;

#[derive(Debug, Clone, ValueEnum)]
enum Transport {
    Stdio,
    Http,
}

#[derive(Debug, Parser)]
#[command(name = "ultranix-mcp", version, about = "Linux desktop automation MCP server")]
struct Cli {
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
}

fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ultranix-mcp")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // stdout is the JSON-RPC channel on stdio — diagnostics go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("ULTRANIX_MCP_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let dir = data_dir();
    std::fs::create_dir_all(dir.join("logs"))?;
    tracing::info!(data_dir = %dir.display(), "ultranix-mcp starting");

    // Phase 0: mock providers only. Real backends register in detect.rs
    // from Phase 1 onward.
    let providers = Providers::all_mocks();
    let server = UltraNixServer::new(providers, cli.category);

    let use_stdio = cli.stdio || matches!(cli.transport, Transport::Stdio);
    if use_stdio {
        server.serve_stdio().await
    } else {
        server.serve_http(&cli.bind).await
    }
}
