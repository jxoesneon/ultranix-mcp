//! Security layer — the request-pipeline defenses from SECURITY.md:
//! input sanitization, path whitelist, arg-constrained command
//! whitelist, consent gate, hash-chained audit log, and capture-output
//! scratch dirs / no-follow opens.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::state::StateDir;

use audit::AuditLog;
use consent::ConsentGate;
use whitelist::PinnedBins;

pub mod audit;
pub mod auth;
pub mod captures;
pub mod consent;
pub mod history;
pub mod paths;
pub mod ratelimit;
pub mod sanitize;
pub mod spawn;
pub mod whitelist;

/// The security subsystem, built once at startup and shared by every tool
/// invocation.
///
/// Construction order matters: the audit log is opened first so that
/// everything after it — including the `--allow-destructive` bypass
/// notice — can be recorded; the command whitelist is then resolved along
/// `PATH` exactly once so a later `PATH` hijack cannot substitute a
/// trojan for a pinned binary.
pub struct SecurityContext {
    /// Consent gate for the destructive tool class (docs/TOOLS.md
    /// "Destructive-Action Consent"): single-use, 60 s TTL tokens bound
    /// to `{caller_id, tool, args_hash}`.
    pub consent: ConsentGate,
    /// Hash-chained JSONL audit sink — every tool call, accepted or
    /// rejected, appends exactly one record.
    pub audit: AuditLog,
    /// Whitelisted binaries resolved to absolute paths at startup.
    /// `None`-equivalent members (absent from `PATH` at pin time) are
    /// rejected as unavailable by [`PinnedBins::validate_command`].
    pub pins: PinnedBins,
    /// `true` under the X11/XWayland fallback session — gates `xdotool`
    /// and `wmctrl` in [`PinnedBins::validate_command`].
    pub x11_active: bool,
    /// `--allow-destructive` operator opt-out. Mirrors
    /// [`ConsentGate::allow_destructive`]; gated calls still write their
    /// audit record stamped `"consent": "bypassed"`.
    pub allow_destructive: bool,
    /// Launch-time `--category` filter mirrored onto the context so the
    /// secured dispatch path — including `replay_action`'s re-entry —
    /// enforces it without signature churn
    /// (docs/API_VERSIONING.md "Category Filters"; `None` = all
    /// categories enabled). [`UltraNixServer::with_security`] copies
    /// the server's configured set here.
    pub categories: Option<Vec<String>>,
    /// State root this context was built for — the lazy
    /// [`history::HistoryStore`] opens `<data_dir>/history.json` here.
    data_dir: PathBuf,
    /// Process-lazy encrypted action history. Root-scoped (unlike
    /// `HistoryStore::shared`, which resolves the ambient state dir), so
    /// tests and isolated contexts stay hermetic. `Arc`-held so secured
    /// dispatch can move the blocking record/write path onto
    /// `spawn_blocking` (EFF-1).
    history: std::sync::OnceLock<std::sync::Arc<history::HistoryStore>>,
}

impl SecurityContext {
    /// Build the context for one server process:
    ///
    /// - ensures the `data_dir` state layout exists at `0700`
    ///   ([`StateDir::ensure_layout`] — idempotent, so a caller that
    ///   already ran [`StateDir::bootstrap`] pays only the chmods),
    /// - opens (creating if needed) `<data_dir>/logs/audit.jsonl` —
    ///   file `0600`, hash chain resumed across restarts,
    /// - constructs the consent gate with the `allow_destructive`
    ///   bypass flag,
    /// - resolves and pins the command whitelist along `PATH` once.
    ///
    /// `x11_active` should come from session detection
    /// ([`crate::backend::detect`]) — it is `true` only when the
    /// X11/XWayland fallback backend is in play.
    pub fn new(
        data_dir: impl AsRef<Path>,
        allow_destructive: bool,
        x11_active: bool,
    ) -> anyhow::Result<Self> {
        let state = StateDir::at(data_dir.as_ref());
        state
            .ensure_layout()
            .context("bootstrap state dir layout")?;
        // SECURITY.md names the log `logs/audit.jsonl`.
        let audit =
            AuditLog::open(&state.logs_dir().join("audit.jsonl")).context("open audit log")?;
        if allow_destructive {
            tracing::warn!(
                "--allow-destructive set: consent gate bypassed — \
                 gated calls are stamped consent=bypassed in the audit log"
            );
        }
        Ok(Self {
            consent: ConsentGate::new(allow_destructive),
            audit,
            pins: whitelist::resolve_binaries(),
            x11_active,
            allow_destructive,
            categories: None,
            data_dir: data_dir.as_ref().to_path_buf(),
            history: std::sync::OnceLock::new(),
        })
    }

    /// Lazily-opened AES-256-GCM action history at
    /// `<data_dir>/history.json`, behind an `Arc` so blocking record
    /// calls can be handed to `tokio::task::spawn_blocking`.
    fn history_store(&self) -> anyhow::Result<&std::sync::Arc<history::HistoryStore>> {
        if let Some(store) = self.history.get() {
            return Ok(store);
        }
        let store = std::sync::Arc::new(history::HistoryStore::open(&self.data_dir)?);
        Ok(self.history.get_or_init(|| store))
    }

    /// Lazily-opened AES-256-GCM action history at
    /// `<data_dir>/history.json`. The store is opened on first use and
    /// cached for the context's lifetime; a transient race between two
    /// first callers resolves to a single store (`get_or_init`).
    pub fn history(&self) -> anyhow::Result<&history::HistoryStore> {
        self.history_store().map(std::sync::Arc::as_ref)
    }

    /// Owned handle to the same lazily-opened store as [`Self::history`]
    /// — for `spawn_blocking` call sites that must own what they send.
    pub fn history_arc(&self) -> anyhow::Result<std::sync::Arc<history::HistoryStore>> {
        self.history_store().map(std::sync::Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_constructs_against_fresh_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = SecurityContext::new(tmp.path(), false, false).unwrap();
        assert!(!ctx.allow_destructive);
        assert!(!ctx.x11_active);
        assert!(!ctx.consent.allow_destructive());
        assert!(
            ctx.audit
                .path()
                .ends_with(Path::new("logs").join("audit.jsonl"))
        );
        // Pins may legitimately be empty on a host without the binaries —
        // construction must not depend on them.
        let _ = &ctx.pins;
    }

    #[test]
    fn context_threads_flags_into_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = SecurityContext::new(tmp.path(), true, true).unwrap();
        assert!(ctx.allow_destructive);
        assert!(ctx.x11_active);
        assert!(ctx.consent.allow_destructive());
    }
}
