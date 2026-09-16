//! Runtime state directory - `~/.ultranix-mcp/` with XDG-aware overrides.
//!
//! Layout:
//! ```text
//! <root>/logs/         audit + diagnostic logs
//! <root>/models/       ONNX vision models (Phase 3)
//! <root>/captures/     saved frames from the capture tools
//! <root>/history.json  encrypted action history (Phase 4)
//! ```
//!
//! Root resolution precedence (spec-canonical - docs pin `~/.ultranix-mcp/`):
//! 1. `ULTRANIX_MCP_STATE_DIR` - explicit override (tests, packaging)
//! 2. `HOME` -> `$HOME/.ultranix-mcp` - the established default, matching
//!    `main.rs`'s `data_dir()`
//! 3. `./.ultranix-mcp` - last-resort relative fallback (no HOME, e.g. a
//!    bare container)
//!
//! `XDG_STATE_HOME` is deliberately *not* consulted: the spec fixes the
//! state root at `~/.ultranix-mcp/` so docs, audit paths, and key files
//! cannot drift between two candidate locations.
//!
//! Every directory in the layout is created - or tightened, if it already
//! exists - to mode `0700`: history and audit logs are sensitive and must
//! never be group/other-readable.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Subdirectories [`StateDir::bootstrap`] guarantees, all mode `0700`.
pub const SUBDIRS: [&str; 3] = ["logs", "models", "captures"];

/// A resolved, bootstrapped runtime state root.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Resolve the root from the process environment and create the full
    /// directory layout with `0700` permissions.
    pub fn bootstrap() -> Result<Self> {
        let dir = Self::at(Self::resolve_root(|key| std::env::var_os(key)));
        dir.ensure_layout()?;
        Ok(dir)
    }

    /// A `StateDir` rooted at an explicit path. Does no IO - call
    /// [`StateDir::ensure_layout`] to create the layout on disk.
    /// Used by tests and by callers that manage root resolution themselves.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Pure root resolution against an arbitrary env lookup - the
    /// unit-testable core. Empty-string values are treated as unset.
    pub fn resolve_root(get: impl Fn(&str) -> Option<OsString>) -> PathBuf {
        let non_empty = |key: &str| get(key).filter(|v| !v.is_empty());

        if let Some(dir) = non_empty("ULTRANIX_MCP_STATE_DIR") {
            return PathBuf::from(dir);
        }
        // XDG_STATE_HOME intentionally ignored - see module docs.
        non_empty("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ultranix-mcp")
    }

    /// Create `<root>` and every [`SUBDIRS`] entry, enforcing `0700` on
    /// each (including pre-existing directories with looser modes).
    /// Idempotent.
    pub fn ensure_layout(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        for sub in SUBDIRS {
            create_private_dir(&self.root.join(sub))?;
        }
        Ok(())
    }

    /// Ensure `path`'s parent directory exists and is `0700`. Used before
    /// writing state files so a file can never land in a loosely-permissioned
    /// parent (e.g. a future nested history path).
    pub fn ensure_parent(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        Ok(())
    }

    /// The resolved state root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<root>/logs` - audit + diagnostic logs.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `<root>/models` - ONNX vision models.
    pub fn models_dir(&self) -> PathBuf {
        self.root.join("models")
    }

    /// `<root>/captures` - saved capture frames.
    pub fn captures_dir(&self) -> PathBuf {
        self.root.join("captures")
    }

    /// `<root>/history.json` - the encrypted action history index
    /// (Phase 4). Its parent is the root, already `0700`.
    pub fn history_path(&self) -> PathBuf {
        self.root.join("history.json")
    }

    /// `<root>/logs/audit.jsonl` - the append-only audit log. Its parent is
    /// `logs/`, already `0700`.
    pub fn audit_path(&self) -> PathBuf {
        self.logs_dir().join("audit.jsonl")
    }
}

impl AsRef<Path> for StateDir {
    fn as_ref(&self) -> &Path {
        self.root()
    }
}

/// `create_dir_all` + tighten to `0700`. Chmod runs unconditionally so a
/// pre-existing directory with a looser mode is corrected.
fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating state dir {}", path.display()))?;
    set_private_permissions(path)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    // No portable mode bits - Linux-only crate, kept for check builds.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Env mutation is process-global: serialize every test that touches
    /// `std::env::set_var`/`remove_var` through this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Fake env lookup over a fixed key/value set (pure resolution tests).
    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(v)))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    /// A unique non-existent path under the system temp dir.
    fn temp_path(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "ultranix-mcp-state-test-{}-{n}-{tag}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // --- pure root resolution ---

    #[test]
    fn resolve_root_prefers_explicit_override() {
        let root = StateDir::resolve_root(fake_env(&[
            ("ULTRANIX_MCP_STATE_DIR", "/custom/state"),
            ("XDG_STATE_HOME", "/xdg/state"),
            ("HOME", "/home/u"),
        ]));
        assert_eq!(root, PathBuf::from("/custom/state"));
    }

    #[test]
    fn resolve_root_ignores_xdg_state_home() {
        // Spec pins the state root at ~/.ultranix-mcp - XDG_STATE_HOME is
        // deliberately not consulted.
        let root = StateDir::resolve_root(fake_env(&[
            ("XDG_STATE_HOME", "/xdg/state"),
            ("HOME", "/home/u"),
        ]));
        assert_eq!(root, PathBuf::from("/home/u/.ultranix-mcp"));
    }

    #[test]
    fn resolve_root_defaults_to_home_dot_ultranix_mcp() {
        let root = StateDir::resolve_root(fake_env(&[("HOME", "/home/u")]));
        assert_eq!(root, PathBuf::from("/home/u/.ultranix-mcp"));
    }

    #[test]
    fn resolve_root_falls_back_to_relative_dir_without_home() {
        let root = StateDir::resolve_root(fake_env(&[]));
        assert_eq!(root, PathBuf::from("./.ultranix-mcp"));
    }

    #[test]
    fn resolve_root_treats_empty_values_as_unset() {
        let root = StateDir::resolve_root(fake_env(&[
            ("ULTRANIX_MCP_STATE_DIR", ""),
            ("XDG_STATE_HOME", ""),
            ("HOME", "/home/u"),
        ]));
        assert_eq!(root, PathBuf::from("/home/u/.ultranix-mcp"));
    }

    // --- bootstrap layout ---

    #[test]
    fn bootstrap_creates_layout_with_0700() {
        let root = temp_path("layout");
        let dir = StateDir::at(&root);
        dir.ensure_layout().unwrap();

        for sub in SUBDIRS {
            let p = root.join(sub);
            assert!(p.is_dir(), "missing subdir {}", p.display());
        }
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&root), 0o700);
            for sub in SUBDIRS {
                assert_eq!(mode_of(&root.join(sub)), 0o700, "bad mode on {sub}");
            }
        }
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ensure_layout_is_idempotent() {
        let root = temp_path("idem");
        let dir = StateDir::at(&root);
        dir.ensure_layout().unwrap();
        dir.ensure_layout().unwrap();
        assert!(dir.logs_dir().is_dir());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    #[cfg(unix)]
    fn ensure_layout_tightens_loose_existing_dir() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_path("loose");
        fs::create_dir_all(root.join("logs")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        StateDir::at(&root).ensure_layout().unwrap();
        assert_eq!(mode_of(&root), 0o700);
        assert_eq!(mode_of(&root.join("logs")), 0o700);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn path_accessors() {
        let dir = StateDir::at("/tmp/whatever");
        assert_eq!(dir.root(), Path::new("/tmp/whatever"));
        assert_eq!(dir.logs_dir(), Path::new("/tmp/whatever/logs"));
        assert_eq!(dir.models_dir(), Path::new("/tmp/whatever/models"));
        assert_eq!(dir.captures_dir(), Path::new("/tmp/whatever/captures"));
        assert_eq!(dir.history_path(), Path::new("/tmp/whatever/history.json"));
        assert_eq!(
            dir.audit_path(),
            Path::new("/tmp/whatever/logs/audit.jsonl")
        );
    }

    #[test]
    fn ensure_parent_creates_missing_parent_with_0700() {
        let root = temp_path("parent");
        let dir = StateDir::at(&root);
        dir.ensure_layout().unwrap();

        let nested = root.join("logs").join("deep").join("audit.jsonl");
        dir.ensure_parent(&nested).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(nested.parent().unwrap()), 0o700);
        fs::remove_dir_all(&root).ok();
    }

    // --- env-mutating bootstrap tests (serialized via ENV_LOCK) ---

    #[test]
    fn bootstrap_honors_state_dir_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = temp_path("env-override");

        // SAFETY: serialized by ENV_LOCK; vars restored before unlock.
        unsafe {
            std::env::set_var("ULTRANIX_MCP_STATE_DIR", &root);
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("HOME");
        }
        let dir = StateDir::bootstrap().unwrap();
        unsafe {
            std::env::remove_var("ULTRANIX_MCP_STATE_DIR");
        }

        assert_eq!(dir.root(), root.as_path());
        assert!(dir.captures_dir().is_dir());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn bootstrap_falls_back_to_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let home = temp_path("env-home");
        fs::create_dir_all(&home).unwrap();

        let saved_home = std::env::var_os("HOME");
        // SAFETY: serialized by ENV_LOCK; HOME restored before unlock.
        unsafe {
            std::env::remove_var("ULTRANIX_MCP_STATE_DIR");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::set_var("HOME", &home);
        }
        let dir = StateDir::bootstrap().unwrap();
        unsafe {
            match saved_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        assert_eq!(dir.root(), home.join(".ultranix-mcp").as_path());
        assert!(dir.history_path().starts_with(home.join(".ultranix-mcp")));
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn bootstrap_ignores_xdg_state_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let xdg = temp_path("env-xdg");
        let home = temp_path("env-home-xdg");
        fs::create_dir_all(&xdg).unwrap();
        fs::create_dir_all(&home).unwrap();

        let saved_xdg = std::env::var_os("XDG_STATE_HOME");
        let saved_home = std::env::var_os("HOME");
        // SAFETY: serialized by ENV_LOCK; vars restored before unlock.
        unsafe {
            std::env::remove_var("ULTRANIX_MCP_STATE_DIR");
            std::env::set_var("XDG_STATE_HOME", &xdg);
            std::env::set_var("HOME", &home);
        }
        let dir = StateDir::bootstrap().unwrap();
        unsafe {
            match saved_xdg {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match saved_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        // XDG_STATE_HOME must not divert the canonical root.
        assert_eq!(dir.root(), home.join(".ultranix-mcp").as_path());
        fs::remove_dir_all(&xdg).ok();
        fs::remove_dir_all(&home).ok();
    }
}
