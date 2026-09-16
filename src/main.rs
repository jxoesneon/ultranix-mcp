//! ultranix-mcp entrypoint - transport selection, provider bootstrap,
//! stderr tracing (stdout is reserved for MCP JSON-RPC).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use ultranix_mcp::backend::detect::{SessionInfo, detect_providers};
use ultranix_mcp::providers::Providers;
use ultranix_mcp::security::SecurityContext;
use ultranix_mcp::security::audit::HMAC_SECRET_ENV;
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
    /// (comma-separated: mouse,keyboard,vision,automation,admin,clipboard).
    #[arg(long, value_delimiter = ',')]
    category: Vec<String>,

    /// HTTP bind address (only with --transport http).
    #[arg(long, env = "ULTRANIX_MCP_BIND", default_value = "127.0.0.1:3010")]
    bind: String,

    /// Bypass the destructive-tool consent gate (operator opt-out;
    /// every gated call is still audited, stamped "consent: bypassed").
    #[arg(long)]
    allow_destructive: bool,

    /// Read-only mode: advertise and allow only the non-mutating
    /// observation catalog (applies to the default role). Input,
    /// window-control, system command, clipboard writes, and plugin_run
    /// are denied with `denial_reason=readonly_mode`.
    #[arg(long)]
    readonly: bool,

    /// Comma-separated list of tools the default role is explicitly
    /// allowed to call. Replaces the policy file's default-role
    /// allowlist (under `--readonly` it merges into the union of the
    /// readonly preset and the file allowlist); every unlisted tool is
    /// denied. Scopes to the default role only - named roles in a
    /// policy file are unaffected.
    #[arg(long, value_delimiter = ',')]
    allow_tools: Vec<String>,

    /// Comma-separated list of tools explicitly denied to the default
    /// role even if a category or allowlist would otherwise permit them.
    /// Scopes to the default role only.
    #[arg(long, value_delimiter = ',')]
    deny_tools: Vec<String>,

    /// Path to a TOML policy file defining named roles and per-key
    /// mappings (`~/.config/ultranix-mcp/policy.toml` is the default
    /// when this flag is omitted and the file exists). An explicitly
    /// named file that is missing or malformed aborts startup -
    /// fail-closed.
    #[arg(long)]
    policy: Option<PathBuf>,

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

    // Optional Sentry error reporting: initialised only when
    // ULTRANIX_MCP_SENTRY_DSN is set *and* parses - unset, empty, or
    // malformed means no client is ever built (zero cost, no transport
    // threads). The DSN is resolved before subscriber init so the
    // sentry-tracing layer can be attached in the same registry; the raw
    // value is kept so a malformed one can be warned about once the
    // subscriber is live (a warning emitted earlier would be dropped).
    #[cfg(feature = "sentry")]
    let sentry_dsn_raw = std::env::var("ULTRANIX_MCP_SENTRY_DSN").ok();
    #[cfg(feature = "sentry")]
    let sentry_dsn = sentry_dsn_raw.as_deref().and_then(parse_sentry_dsn);

    // stdout is the JSON-RPC channel on stdio - diagnostics go to stderr.
    let base = tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_env("ULTRANIX_MCP_LOG_LEVEL")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr));

    // `Option<layer>` is itself a `Layer`: the sentry-tracing layer
    // forwards `tracing::error!` events to Sentry only when a DSN is
    // configured; `None` adds nothing. `sentry` feature off -> no layer.
    #[cfg(feature = "sentry")]
    let base = base.with(
        sentry_dsn
            .is_some()
            .then(sentry::integrations::tracing::layer),
    );

    base.init();
    ultranix_mcp::metrics::set_build_info();

    #[cfg(feature = "sentry")]
    {
        if let (Some(raw), None) = (&sentry_dsn_raw, &sentry_dsn)
            && !raw.trim().is_empty()
        {
            tracing::warn!("ULTRANIX_MCP_SENTRY_DSN is set but unparsable; Sentry disabled");
        }

        // Panic + error reporting goes live here and stays live until the
        // guard drops at end of `main` (which also flushes pending events).
        let _sentry_guard = sentry_dsn.map(|dsn| {
            tracing::info!("Sentry error reporting enabled via ULTRANIX_MCP_SENTRY_DSN");
            let mut opts = sentry::ClientOptions::new();
            opts.dsn = Some(dsn);
            opts.release = Some(env!("CARGO_PKG_VERSION").into());
            // Pre-send redaction per PRIVACY.md: `uxcp_*` key material is
            // scrubbed, absolute paths are reduced to basename + parent-dir
            // hash, and the `device` context (hostname) is dropped.
            opts.before_send = Some(std::sync::Arc::new(sentry_redact));
            sentry::init(opts)
        });
    }

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

    let audit_secret = std::env::var(HMAC_SECRET_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut security = SecurityContext::new(
        state.root(),
        cli.allow_destructive,
        matches!(
            session.session_type,
            ultranix_mcp::backend::detect::SessionType::X11
        ),
    )?
    .with_audit_secret(audit_secret);
    let default_policy_path = dirs::config_dir()
        .map(|p| p.join("ultranix-mcp").join("policy.toml"))
        .filter(|p| p.is_file());
    let policy = ultranix_mcp::security::policy::Policy::from_file_and_cli(
        cli.policy.as_deref().or(default_policy_path.as_deref()),
        cli.readonly,
        &cli.allow_tools,
        &cli.deny_tools,
    )?;
    // Surface the silent-degradation cases the operator cannot otherwise see.
    let cli_flags_scoped =
        cli.readonly || !cli.allow_tools.is_empty() || !cli.deny_tools.is_empty();
    if cli_flags_scoped && !policy.roles.is_empty() {
        tracing::warn!(
            "CLI policy flags scope to default_role only; named roles in the policy file are unaffected"
        );
    }
    let keys_configured = !policy.keys.is_empty();
    if keys_configured {
        let default = &policy.default_role;
        if !default.readonly && default.allow_tools.is_none() && default.deny_tools.is_empty() {
            tracing::warn!(
                "policy keys map is configured but default_role is unrestricted - unmapped keys get the full tool surface"
            );
        }
    }
    security.set_policy(policy);
    let session_id = ultranix_mcp::security::consent::new_session_id();

    let server = UltraNixServer::new(providers, cli.category).with_security(security, session_id);

    let use_stdio = cli.stdio || matches!(cli.transport, Transport::Stdio);
    let auth_disabled = std::env::var_os(ultranix_mcp::security::auth::ENV_DISABLE_AUTH)
        .map(|v| ultranix_mcp::security::auth::is_truthy(&v))
        .unwrap_or(false);
    if keys_configured && (use_stdio || auth_disabled) {
        tracing::warn!(
            "policy keys map is configured but per-key scoping will never resolve - caller identity is absent on stdio and when auth is disabled"
        );
    }
    if use_stdio {
        server.serve_stdio().await
    } else {
        server.serve_http(&cli.bind).await
    }
}

/// Parse a configured DSN; `None` for empty or unparsable values (the
/// server then runs exactly as if the variable were absent). Pure - the
/// caller reports the malformed case once tracing is live.
#[cfg(feature = "sentry")]
fn parse_sentry_dsn(raw: &str) -> Option<sentry::types::Dsn> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    raw.parse().ok()
}

/// `uxcp_<64 hex>` API-key material must never reach Sentry. Scan for
/// the `uxcp_` prefix and blank the run when it is 64 hex chars.
#[cfg(feature = "sentry")]
fn scrub_keys(s: &str) -> String {
    const PREFIX: &str = "uxcp_";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(PREFIX) {
        out.push_str(&rest[..i]);
        let tail = &rest[i + PREFIX.len()..];
        let key_len = tail.chars().take_while(|c| c.is_ascii_hexdigit()).count();
        if key_len == 64 {
            out.push_str("[REDACTED]");
            rest = &tail[64..];
        } else {
            out.push_str(PREFIX);
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// Absolute path -> `<basename>#<8-hex hash of parent>` (PRIVACY.md).
#[cfg(feature = "sentry")]
fn hash_path(p: &str) -> String {
    let path = std::path::Path::new(p);
    let base = path
        .file_name()
        .map(|b| b.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string());
    let parent = path
        .parent()
        .map(|p| p.to_string_lossy())
        .unwrap_or_default();
    let digest = blake3::hash(parent.as_bytes()).to_hex();
    format!("{base}#{}", &digest[..8])
}

/// Pre-send scrub for Sentry events (PRIVACY.md "Redaction rules
/// applied before send"): `uxcp_*` keys redacted, stack-frame
/// filenames hashed, `device` context (hostname) dropped.
#[cfg(feature = "sentry")]
fn sentry_redact(
    mut event: sentry::protocol::Event<'static>,
) -> Option<sentry::protocol::Event<'static>> {
    if let Some(m) = &mut event.message {
        *m = scrub_keys(m);
    }
    for exc in event.exception.values.iter_mut() {
        if let Some(v) = &mut exc.value {
            *v = scrub_keys(v);
        }
        if let Some(st) = &mut exc.stacktrace {
            for f in st.frames.iter_mut() {
                if let Some(fi) = f.filename.as_mut()
                    && fi.starts_with('/')
                {
                    *fi = hash_path(fi);
                }
            }
        }
    }
    for bc in event.breadcrumbs.values.iter_mut() {
        if let Some(m) = &mut bc.message {
            *m = scrub_keys(m);
        }
    }
    event.contexts.remove("device");
    // `sentry-contexts` fills server_name with the machine hostname -
    // drop it too (PRIVACY.md redaction contract).
    event.server_name = None;
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "sentry")]
    fn sentry_disabled_when_dsn_unset_or_empty() {
        // The common case: no env var -> no DSN -> `sentry::init` never
        // runs. (Skipped if the ambient environment happens to set one.)
        if std::env::var_os("ULTRANIX_MCP_SENTRY_DSN").is_none() {
            assert!(
                std::env::var("ULTRANIX_MCP_SENTRY_DSN")
                    .ok()
                    .and_then(|raw| parse_sentry_dsn(&raw))
                    .is_none()
            );
        }
        assert!(parse_sentry_dsn("").is_none());
        assert!(parse_sentry_dsn("   ").is_none());
    }

    #[test]
    #[cfg(feature = "sentry")]
    fn sentry_disabled_on_malformed_dsn() {
        // Set-but-broken must behave like unset - init is opt-in only
        // for values that actually parse.
        assert!(parse_sentry_dsn("not a dsn").is_none());
        assert!(parse_sentry_dsn("uxcp_deadbeef").is_none());
    }

    #[test]
    #[cfg(feature = "sentry")]
    fn scrub_keys_redacts_uxcp_material() {
        let key = format!("uxcp_{}", "a".repeat(64));
        assert_eq!(scrub_keys(&format!("k={key} tail")), "k=[REDACTED] tail");
        // Non-64-hex runs and short prefixes pass through.
        assert_eq!(scrub_keys("uxcp_deadbeef"), "uxcp_deadbeef");
        assert_eq!(scrub_keys("no keys here"), "no keys here");
    }

    #[test]
    #[cfg(feature = "sentry")]
    fn hash_path_keeps_basename_hashes_parent() {
        let h = hash_path("/home/u/.ultranix-mcp/history.json");
        assert!(h.starts_with("history.json#"));
        assert!(!h.contains("/home/u"));
        assert_eq!(
            hash_path("relative.rs"),
            "relative.rs#".to_string() + &blake3::hash(b"").to_hex()[..8]
        );
    }

    #[test]
    #[cfg(feature = "sentry")]
    fn sentry_redact_strips_key_device_and_paths() {
        use sentry::protocol::{Breadcrumb, Event, Exception, Frame, Stacktrace, Values};
        let key = format!("uxcp_{}", "b".repeat(64));
        let mut event = Event {
            message: Some(format!("failed with {key}")),
            breadcrumbs: Values::from(vec![Breadcrumb {
                message: Some(key.clone()),
                ..Default::default()
            }]),
            exception: Values::from(vec![Exception {
                value: Some(format!("boom {key}")),
                stacktrace: Some(Stacktrace {
                    frames: vec![Frame {
                        filename: Some("/home/u/src/x.rs".into()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        };
        event.contexts.insert(
            "device".into(),
            sentry::protocol::Context::Other(Default::default()),
        );
        let event = sentry_redact(event).unwrap();
        assert!(event.server_name.is_none());
        assert!(!event.message.unwrap().contains(&key));
        assert!(
            !event.exception.values[0]
                .value
                .as_deref()
                .unwrap()
                .contains(&key)
        );
        let f = &event.exception.values[0]
            .stacktrace
            .as_ref()
            .unwrap()
            .frames[0];
        assert!(f.filename.as_deref().unwrap().starts_with("x.rs#"));
        assert!(!event.contexts.contains_key("device"));
    }

    #[test]
    fn cli_defaults_to_stdio() {
        let cli = Cli::try_parse_from(["ultranix-mcp"]).unwrap();
        assert!(cli.command.is_none());
        assert!(matches!(cli.transport, Transport::Stdio));
        assert!(!cli.stdio);
        assert!(cli.category.is_empty());
        assert!(!cli.allow_destructive);
        assert!(!cli.mock);
        assert!(!cli.readonly);
        assert!(cli.allow_tools.is_empty());
        assert!(cli.deny_tools.is_empty());
        assert!(cli.policy.is_none());
    }

    #[test]
    fn cli_parses_policy_flags() {
        let cli = Cli::try_parse_from([
            "ultranix-mcp",
            "--readonly",
            "--allow-tools",
            "screenshot,get_windows",
            "--deny-tools",
            "plugin_run",
            "--policy",
            "/tmp/policy.toml",
        ])
        .unwrap();
        assert!(cli.readonly);
        assert_eq!(cli.allow_tools, vec!["screenshot", "get_windows"]);
        assert_eq!(cli.deny_tools, vec!["plugin_run"]);
        assert_eq!(
            cli.policy.as_deref(),
            Some(std::path::Path::new("/tmp/policy.toml"))
        );
    }

    #[test]
    fn cli_parses_transport_and_categories() {
        let cli = Cli::try_parse_from([
            "ultranix-mcp",
            "--transport",
            "http",
            "--bind",
            "0.0.0.0:9999",
            "--category",
            "mouse,keyboard",
            "--allow-destructive",
        ])
        .unwrap();
        assert!(matches!(cli.transport, Transport::Http));
        assert_eq!(cli.bind, "0.0.0.0:9999");
        assert_eq!(cli.category, vec!["mouse", "keyboard"]);
        assert!(cli.allow_destructive);
    }

    #[test]
    fn cli_stdio_flag_conflicts_with_transport() {
        // `--stdio --transport http` is contradictory -> clap error.
        assert!(Cli::try_parse_from(["ultranix-mcp", "--stdio", "--transport", "http"]).is_err());
        // `--stdio --transport stdio` is also a conflict (explicit
        // `--transport` collides with the alias flag regardless of value).
        assert!(Cli::try_parse_from(["ultranix-mcp", "--stdio", "--transport", "stdio"]).is_err());
        assert!(Cli::try_parse_from(["ultranix-mcp", "--stdio"]).is_ok());
    }

    #[test]
    fn cli_keygen_subcommand() {
        let cli = Cli::try_parse_from(["ultranix-mcp", "keygen"]).unwrap();
        assert!(matches!(cli.command, Some(Cmd::Keygen)));
        assert!(Cli::try_parse_from(["ultranix-mcp", "bogus"]).is_err());
    }

    #[test]
    #[cfg(feature = "sentry")]
    fn sentry_enabled_on_valid_dsn() {
        let dsn =
            parse_sentry_dsn("https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/1");
        assert!(dsn.is_some());
        // Surrounding whitespace is tolerated.
        assert!(
            parse_sentry_dsn("  https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/1  ")
                .is_some()
        );
    }
}
