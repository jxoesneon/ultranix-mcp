//! AES-256-GCM-encrypted action history — `<state_root>/history.json`.
//!
//! Spec: SECURITY.md "Storage", docs/TOOLS.md (`get_action_history`,
//! `replay_action`, `clear_action_history`), ROADMAP Phase 4.
//!
//! Whole-file encryption: the plaintext is one JSON document
//! `{"version": 1, "records": [ActionRecord, …]}` serialized with
//! `serde_json`, sealed under a random 96-bit nonce; the on-disk byte layout
//! is `nonce || ciphertext || tag` (the tag is the trailing 16 bytes emitted
//! by `aes-gcm`). Any tamper — bit flip, truncation, substitution — fails
//! the GCM tag check and surfaces as a `HistoryError` at the tool layer.
//!
//! Key material, in precedence order:
//! 1. `ULTRANIX_MCP_HISTORY_SECRET` — operator-supplied secret; SHA-256 of
//!    its UTF-8 bytes is the key, so any string works. Rotation makes
//!    existing history unreadable (documented caveat — re-encrypt on
//!    rotation).
//! 2. `<state_root>/history.key` — a per-install 32-byte CSPRNG secret,
//!    generated on first use, file mode `0600`, containing dir `0700`.
//!
//! Opening the store is lazy: no directory, key, or history file is created
//! until the first [`HistoryStore::record`]. Read-only operations on a
//! system that has never recorded an action simply see an empty history.
//!
//! The store is append-only and whole-file rewritten on every record —
//! trivially affordable at the `MAX_RECORDS` cap. Records carry a monotonic
//! `index` so `replay_action{index}` selectors stay stable across FIFO
//! evictions and restarts.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::StateDir;

/// Hard cap on retained records — oldest are evicted FIFO on overflow.
pub const MAX_RECORDS: usize = 10_000;

/// Env var carrying the operator-supplied history secret (SECURITY.md).
pub const SECRET_ENV: &str = "ULTRANIX_MCP_HISTORY_SECRET";

/// Key file name inside the state root.
const KEY_FILE: &str = "history.key";

/// History file name inside the state root.
const HISTORY_FILE: &str = "history.json";

/// On-disk plaintext envelope version.
const FORMAT_VERSION: u32 = 1;

/// AES-GCM standard nonce size (96-bit).
const NONCE_LEN: usize = 12;

/// `result_summary` is truncated to this many chars (docs/TOOLS.md).
pub const RESULT_SUMMARY_MAX: usize = 200;

/// One recorded action — the unit stored in `history.json` and returned by
/// `get_action_history` / resolved by `replay_action`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    /// ULID, 26 chars, Crockford Base32 — lexically sortable by time.
    pub id: String,
    /// Monotonic history index (0-based, assigned at append). Stable
    /// across FIFO evictions — surviving records keep their index.
    pub index: u64,
    /// Tool name, e.g. `mouse_click`.
    pub tool: String,
    /// Raw recorded arguments (`type_text.text` is redacted to
    /// `"<redacted:N chars>"` before storage). Verbatim so history can be
    /// replayed.
    pub args_json: Value,
    /// ≤ [`RESULT_SUMMARY_MAX`]-char human-readable result summary.
    pub result_summary: String,
    /// Caller identity: HTTP `key_id` or the stdio session id.
    pub caller: String,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Wall time of the invocation.
    pub duration_ms: u64,
    /// Outcome class — `ok`, `tool_error`, `error`, `consent_required`, …
    /// (same vocabulary as the audit log).
    pub outcome: String,
}

/// What a caller supplies to [`HistoryStore::record`] — the store assigns
/// `id` (ULID), `index`, and `ts` itself so instrumentation cannot forge
/// ordering.
#[derive(Debug, Clone)]
pub struct NewActionRecord {
    /// Tool name.
    pub tool: String,
    /// Raw call arguments.
    pub args_json: Value,
    /// Result summary (truncated to [`RESULT_SUMMARY_MAX`] chars).
    pub result_summary: String,
    /// Caller identity (`key_id` or session id).
    pub caller: String,
    /// Wall time of the invocation.
    pub duration_ms: u64,
    /// Outcome class (audit vocabulary).
    pub outcome: String,
}

/// Plaintext envelope — what actually gets encrypted into `history.json`.
#[derive(Debug, Serialize, Deserialize)]
struct FilePayload {
    version: u32,
    records: Vec<ActionRecord>,
}

struct Inner {
    /// Chronological order, oldest first.
    records: Vec<ActionRecord>,
    /// Index the next appended record will receive.
    next_index: u64,
    /// Resolved key material — `None` until the first encrypt/decrypt.
    key: Option<[u8; 32]>,
}

/// Append-only, AES-256-GCM-encrypted action-history store. Thread-safe:
/// all mutable state sits behind a mutex; methods take `&self` (mirrors
/// [`crate::security::audit::AuditLog`]).
pub struct HistoryStore {
    /// Resolved state root (`~/.ultranix-mcp` or `ULTRANIX_MCP_STATE_DIR`).
    root: PathBuf,
    /// `<root>/history.json`.
    path: PathBuf,
    /// `<root>/history.key`.
    key_path: PathBuf,
    /// Retention cap (usually [`MAX_RECORDS`]; tunable for tests).
    max_records: usize,
    inner: Mutex<Inner>,
}

impl HistoryStore {
    /// Open the store under `state_root`, decrypting any existing
    /// `history.json`. Creates nothing on disk — the layout, key file, and
    /// history file all materialize on the first [`record`](Self::record)
    /// (or `record`-triggered key generation).
    ///
    /// Fails when `history.json` exists but cannot be decrypted: tampered
    /// file, wrong/rotated `ULTRANIX_MCP_HISTORY_SECRET`, or a missing/
    /// malformed `history.key`.
    pub fn open(state_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_cap(state_root, MAX_RECORDS)
    }

    /// [`open`](Self::open) with an explicit retention cap — for tests and
    /// diagnostics; production uses [`MAX_RECORDS`].
    pub fn open_with_cap(state_root: impl AsRef<Path>, max_records: usize) -> anyhow::Result<Self> {
        let root = state_root.as_ref().to_path_buf();
        let store = Self {
            path: root.join(HISTORY_FILE),
            key_path: root.join(KEY_FILE),
            root,
            max_records,
            inner: Mutex::new(Inner {
                records: Vec::new(),
                next_index: 0,
                key: None,
            }),
        };
        store.load()?;
        Ok(store)
    }

    /// Open the store at the resolved process state root
    /// (`ULTRANIX_MCP_STATE_DIR`, else `~/.ultranix-mcp`).
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(StateDir::resolve_root(|k| std::env::var_os(k)))
    }

    /// The process-wide store, lazily opened at the resolved state root.
    /// The tool layer uses this when no explicit store is threaded through
    /// dispatch; `call_tool_secured` instrumentation should use the same
    /// handle so reads observe its own writes.
    ///
    /// The first-open result is cached for the process — including failure.
    pub fn shared() -> anyhow::Result<&'static HistoryStore> {
        static SHARED: OnceLock<Result<HistoryStore, String>> = OnceLock::new();
        match SHARED.get_or_init(|| Self::open_default().map_err(|e| format!("{e:#}"))) {
            Ok(store) => Ok(store),
            Err(e) => Err(anyhow::anyhow!("history store init failed: {e}")),
        }
    }

    /// Path of the encrypted history file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path of the per-install key file.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Append `entry`; the store assigns `id`, `index`, `ts`, applies the
    /// `type_text.text` redaction and the [`RESULT_SUMMARY_MAX`] truncation,
    /// evicts FIFO over the cap, then rewrites the encrypted file. On a
    /// persist failure the in-memory state is left untouched.
    pub fn record(&self, entry: NewActionRecord) -> anyhow::Result<ActionRecord> {
        let mut inner = self.inner.lock().expect("history store poisoned");
        let key = self.resolve_key(&mut inner, true)?;

        let rec = ActionRecord {
            id: ulid::Ulid::new().to_string(),
            index: inner.next_index,
            tool: entry.tool.clone(),
            args_json: redact_args(&entry.tool, entry.args_json),
            result_summary: truncate_chars(&entry.result_summary, RESULT_SUMMARY_MAX),
            caller: entry.caller,
            ts: chrono::Utc::now().to_rfc3339(),
            duration_ms: entry.duration_ms,
            outcome: entry.outcome,
        };

        // Append in place, then persist the post-eviction tail as a
        // borrowed slice — the serializer walks the slice directly, so
        // neither `records` nor its clone is materialized (EFF-1). A
        // failed write pops the pushed record, leaving memory consistent
        // with the untouched file.
        inner.records.push(rec.clone());
        let keep_from = inner.records.len().saturating_sub(self.max_records);
        if let Err(e) = self.persist(&key, &inner.records[keep_from..]) {
            inner.records.pop();
            return Err(e);
        }
        if keep_from > 0 {
            inner.records.drain(..keep_from);
        }

        inner.next_index += 1;
        Ok(rec)
    }

    /// Newest-first records, at most `limit`.
    pub fn list(&self, limit: usize) -> Vec<ActionRecord> {
        let inner = self.inner.lock().expect("history store poisoned");
        inner.records.iter().rev().take(limit).cloned().collect()
    }

    /// Look up a record by its monotonic `index`.
    pub fn get_by_index(&self, index: u64) -> Option<ActionRecord> {
        let inner = self.inner.lock().expect("history store poisoned");
        inner.records.iter().find(|r| r.index == index).cloned()
    }

    /// Look up a record by its 26-char ULID.
    pub fn get_by_id(&self, id: &str) -> Option<ActionRecord> {
        let inner = self.inner.lock().expect("history store poisoned");
        inner.records.iter().find(|r| r.id == id).cloned()
    }

    /// Securely wipe `history.json` (overwrite with zeros, then delete) and
    /// reset the in-memory index. Returns the number of records removed.
    /// Idempotent: clearing an absent/empty store returns `0`.
    pub fn clear(&self) -> anyhow::Result<usize> {
        let mut inner = self.inner.lock().expect("history store poisoned");
        let removed = inner.records.len();
        if self.path.exists() {
            // Overwrite-then-delete so the ciphertext can't linger in slack.
            let len = fs::metadata(&self.path)
                .with_context(|| format!("stat {}", self.path.display()))?
                .len() as usize;
            fs::write(&self.path, vec![0u8; len])
                .with_context(|| format!("overwrite {}", self.path.display()))?;
            fs::remove_file(&self.path)
                .with_context(|| format!("remove {}", self.path.display()))?;
        }
        inner.records.clear();
        inner.next_index = 0;
        Ok(removed)
    }

    /// Number of retained records.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("history store poisoned")
            .records
            .len()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Load and decrypt `history.json` if it exists. A missing or empty
    /// file is a fresh store, not an error.
    fn load(&self) -> anyhow::Result<()> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| format!("read {}", self.path.display()));
            }
        };
        if bytes.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().expect("history store poisoned");
        // Existing history with no resolvable secret is a hard failure —
        // never generate a fresh key just to report "corrupt".
        let key = self.resolve_key(&mut inner, false)?;
        let payload = decrypt(&key, &bytes)?;
        if payload.version != FORMAT_VERSION {
            bail!(
                "unsupported {} version {}",
                self.path.display(),
                payload.version
            );
        }
        inner.next_index = payload
            .records
            .iter()
            .map(|r| r.index)
            .max()
            .map_or(0, |i| i + 1);
        let mut records = payload.records;
        if records.len() > self.max_records {
            let excess = records.len() - self.max_records;
            records.drain(..excess);
        }
        inner.records = records;
        Ok(())
    }

    /// Resolve the 32-byte key: env secret (SHA-256) → `history.key` →
    /// CSPRNG generation. `generate=false` refuses the last step so a
    /// `load` on existing history never mints a mismatched key.
    fn resolve_key(&self, inner: &mut Inner, generate: bool) -> anyhow::Result<[u8; 32]> {
        if let Some(key) = inner.key {
            return Ok(key);
        }
        let key: [u8; 32] = if let Some(secret) = std::env::var_os(SECRET_ENV)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string_lossy().into_owned())
        {
            Sha256::digest(secret.as_bytes()).into()
        } else if self.key_path.exists() {
            // Enforce the `0600` contract *before* reading (S-8): a
            // group/world-readable key file is a hard failure, same as
            // the API-key file rule in `security::auth`.
            crate::security::auth::enforce_private_file(&self.key_path)?;
            let raw = fs::read(&self.key_path)
                .with_context(|| format!("read {}", self.key_path.display()))?;
            raw.try_into().map_err(|_| {
                anyhow::anyhow!("{} must be exactly 32 bytes", self.key_path.display())
            })?
        } else {
            if !generate {
                bail!(
                    "history exists but no secret: set {SECRET_ENV} or restore {}",
                    self.key_path.display()
                );
            }
            let mut k = [0u8; 32];
            rand::fill(&mut k);
            StateDir::at(&self.root).ensure_parent(&self.key_path)?;
            write_private(&self.key_path, &k)?;
            k
        };
        inner.key = Some(key);
        Ok(key)
    }

    /// Serialize + encrypt + atomically replace `history.json`. The
    /// payload borrows `records` — serializing a `&[ActionRecord]`
    /// produces the same JSON array without cloning the vector.
    fn persist(&self, key: &[u8; 32], records: &[ActionRecord]) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct PayloadRef<'a> {
            version: u32,
            records: &'a [ActionRecord],
        }
        let plaintext = serde_json::to_vec(&PayloadRef {
            version: FORMAT_VERSION,
            records,
        })
        .context("serialize history payload")?;

        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| anyhow::anyhow!("history encryption failed"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        StateDir::at(&self.root).ensure_parent(&self.path)?;
        let tmp = self.path.with_file_name(format!(
            "{}.tmp",
            self.path.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_private(&tmp, &out)?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        set_mode(&self.path, 0o600)?;
        Ok(())
    }
}

/// `nonce || ciphertext || tag` → plaintext records payload.
fn decrypt(key: &[u8; 32], bytes: &[u8]) -> anyhow::Result<FilePayload> {
    if bytes.len() < NONCE_LEN + 16 {
        bail!("history.json too short for nonce + tag");
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            anyhow::anyhow!("history.json decrypt failed — tampered file or wrong secret")
        })?;
    serde_json::from_slice(&plaintext).context("history plaintext is not valid JSON")
}

/// Write `data` to `path` with mode `0600` (created or tightened).
fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("write {}", path.display()))?;
    f.flush().ok();
    drop(f);
    set_mode(path, 0o600) // enforce on pre-existing files too
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

/// `type_text.text` → `"<redacted:N chars>"`; everything else verbatim.
fn redact_args(tool: &str, mut args: Value) -> Value {
    if tool == "type_text"
        && let Some(obj) = args.as_object_mut()
        && let Some(text) = obj.get("text").and_then(Value::as_str)
    {
        let n = text.chars().count();
        obj.insert(
            "text".into(),
            Value::String(format!("<redacted:{n} chars>")),
        );
    }
    args
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// Env mutation is process-global, and `ULTRANIX_MCP_HISTORY_SECRET`
    /// changes which key a store resolves — a test that sets it must not
    /// race a sibling's `record`/`open`. Every store-touching test holds
    /// this guard for its duration.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap()
    }

    fn entry(tool: &str, args: Value) -> NewActionRecord {
        NewActionRecord {
            tool: tool.to_string(),
            args_json: args,
            result_summary: "did the thing".to_string(),
            caller: "test-session".to_string(),
            duration_ms: 7,
            outcome: "ok".to_string(),
        }
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn record_then_reopen_roundtrips() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let id;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            let rec = store
                .record(entry("mouse_click", json!({"x": 1, "y": 2})))
                .unwrap();
            id = rec.id.clone();
            assert_eq!(store.len(), 1);
        }
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert_eq!(store.len(), 1);
        let rec = store.get_by_id(&id).unwrap();
        assert_eq!(rec.tool, "mouse_click");
        assert_eq!(rec.args_json, json!({"x": 1, "y": 2}));
        assert_eq!(rec.index, 0);
        assert_eq!(rec.outcome, "ok");
        assert_eq!(rec.caller, "test-session");
        chrono::DateTime::parse_from_rfc3339(&rec.ts).unwrap();
    }

    #[test]
    fn at_rest_is_not_plaintext() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        store
            .record(entry("mouse_click", json!({"x": 640, "y": 420})))
            .unwrap();
        let bytes = fs::read(store.path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("mouse_click"));
        assert!(!text.contains("640"));
        // nonce + ciphertext + tag, larger than the plaintext is possible.
        assert!(bytes.len() > NONCE_LEN + 16);
    }

    /// Force the `history.key` file path (not the env secret) while
    /// `guard` runs; restores the prior env state on drop.
    fn without_env_secret() -> impl Drop {
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: serialized by ENV_LOCK; restores exactly what
                // the test found.
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var(SECRET_ENV, v),
                        None => std::env::remove_var(SECRET_ENV),
                    }
                }
            }
        }
        let saved = std::env::var_os(SECRET_ENV);
        // SAFETY: serialized by ENV_LOCK, restored by the guard.
        unsafe { std::env::remove_var(SECRET_ENV) };
        Restore(saved)
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_key_file_is_refused() {
        let _env = env_guard();
        let _secret = without_env_secret();
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // A pre-existing key file with loose mode must fail *before* its
        // bytes are trusted (S-8) — same rule as API-key files.
        let key = tmp.path().join(KEY_FILE);
        fs::write(&key, [7u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        let store = HistoryStore::open(tmp.path()).unwrap();
        let err = store.record(entry("sleep", json!({"ms": 1}))).unwrap_err();
        assert!(
            format!("{err:#}").contains("group/world-readable"),
            "unexpected error: {err:#}"
        );

        // Tightening the mode restores the store.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        store.record(entry("sleep", json!({"ms": 1}))).unwrap();
    }

    #[test]
    fn tampered_file_fails_decrypt() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
            path = store.path().to_path_buf();
        }
        let mut bytes = fs::read(&path).unwrap();
        // Flip a byte inside the ciphertext (past the 12-byte nonce).
        let pos = NONCE_LEN + 5;
        bytes[pos] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = HistoryStore::open(tmp.path())
            .err()
            .expect("tampered history must fail to open");
        assert!(
            format!("{err:#}").contains("decrypt failed")
                || format!("{err:#}").contains("tampered"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn truncated_file_fails_decrypt() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
            path = store.path().to_path_buf();
        }
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 8]).unwrap();
        assert!(HistoryStore::open(tmp.path()).is_err());
    }

    #[test]
    fn ids_are_26_char_ulids() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        let rec = store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        assert_eq!(rec.id.len(), 26);
        assert!(
            rec.id
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "not Crockford Base32: {}",
            rec.id
        );
        // Parses back as a ULID.
        rec.id.parse::<ulid::Ulid>().unwrap();
    }

    #[test]
    fn index_and_id_resolution() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        let a = store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        let b = store.record(entry("sleep", json!({"ms": 2}))).unwrap();
        assert_eq!(a.index, 0);
        assert_eq!(b.index, 1);
        assert_eq!(store.get_by_index(0).unwrap().id, a.id);
        assert_eq!(store.get_by_index(1).unwrap().id, b.id);
        assert!(store.get_by_index(2).is_none());
        assert_eq!(store.get_by_id(&b.id).unwrap().index, 1);
        assert!(store.get_by_id("01J9XKQV0R6T4H2Y8ZQ3N0AB12").is_none());
    }

    #[test]
    fn list_is_newest_first_and_limited() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        for i in 0..5 {
            store
                .record(NewActionRecord {
                    result_summary: format!("rec {i}"),
                    ..entry("sleep", json!({"ms": i}))
                })
                .unwrap();
        }
        let all = store.list(50);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].result_summary, "rec 4");
        assert_eq!(all[4].result_summary, "rec 0");
        let two = store.list(2);
        assert_eq!(two.len(), 2);
        assert_eq!(two[1].result_summary, "rec 3");
    }

    #[test]
    fn fifo_cap_evicts_oldest_and_index_stays_stable() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open_with_cap(tmp.path(), 3).unwrap();
        for i in 0..5 {
            store
                .record(NewActionRecord {
                    result_summary: format!("rec {i}"),
                    ..entry("sleep", json!({}))
                })
                .unwrap();
        }
        assert_eq!(store.len(), 3);
        // indices 0,1 evicted; 2,3,4 retained with original indices.
        assert!(store.get_by_index(0).is_none());
        assert!(store.get_by_index(1).is_none());
        assert_eq!(store.get_by_index(2).unwrap().result_summary, "rec 2");
        assert_eq!(store.get_by_index(4).unwrap().result_summary, "rec 4");
        // Reopen: next index continues from max+1, not from len.
        let store = HistoryStore::open_with_cap(tmp.path(), 3).unwrap();
        let rec = store.record(entry("sleep", json!({}))).unwrap();
        assert_eq!(rec.index, 5);
    }

    #[test]
    fn missing_key_is_generated_0600_dir_0700() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("state");
        let store = HistoryStore::open(&root).unwrap();
        // Opening is lazy — nothing on disk yet.
        assert!(!root.exists());
        store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        assert!(store.path().is_file());
        assert!(store.key_path().is_file());
        #[cfg(unix)]
        {
            assert_eq!(mode_of(store.key_path()), 0o600);
            assert_eq!(mode_of(store.path()), 0o600);
            assert_eq!(mode_of(&root), 0o700);
        }
        // Key file is 32 raw bytes.
        assert_eq!(fs::metadata(store.key_path()).unwrap().len(), 32);
    }

    #[test]
    fn open_without_history_creates_nothing() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert!(store.is_empty());
        assert!(!store.path().exists());
        assert!(!store.key_path().exists());
        assert!(store.list(10).is_empty());
    }

    #[test]
    fn env_secret_derives_key_and_isolation() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by ENV_LOCK; var removed before unlock.
        unsafe {
            std::env::set_var(SECRET_ENV, "correct horse battery staple");
        }
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
            // Env secret takes precedence — no key file is minted.
            assert!(!store.key_path().exists());
        }
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            assert_eq!(store.len(), 1);
        }
        unsafe {
            std::env::remove_var(SECRET_ENV);
        }
        // Without the env secret and no key file, existing history cannot
        // be opened.
        let err = HistoryStore::open(tmp.path())
            .err()
            .expect("history without secret must fail to open");
        assert!(
            format!("{err:#}").contains("no secret"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn wrong_env_secret_fails_decrypt() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by ENV_LOCK.
        unsafe {
            std::env::set_var(SECRET_ENV, "secret-one");
        }
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        }
        unsafe {
            std::env::set_var(SECRET_ENV, "secret-two");
        }
        assert!(HistoryStore::open(tmp.path()).is_err());
        unsafe {
            std::env::remove_var(SECRET_ENV);
        }
    }

    #[test]
    fn type_text_args_are_redacted() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        let rec = store
            .record(entry(
                "type_text",
                json!({"text": "hunter2", "delay_ms": 0}),
            ))
            .unwrap();
        assert_eq!(rec.args_json["text"], json!("<redacted:7 chars>"));
        assert_eq!(rec.args_json["delay_ms"], json!(0));
        // The plaintext secret never reaches disk.
        let bytes = fs::read(store.path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("hunter2"));
    }

    #[test]
    fn result_summary_truncated_to_200_chars() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        let rec = store
            .record(NewActionRecord {
                result_summary: "x".repeat(500),
                ..entry("sleep", json!({}))
            })
            .unwrap();
        assert_eq!(rec.result_summary.chars().count(), 200);
    }

    #[test]
    fn clear_wipes_file_and_resets_index() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
            store.record(entry("sleep", json!({"ms": 2}))).unwrap();
            path = store.path().to_path_buf();
            assert_eq!(store.clear().unwrap(), 2);
            assert!(store.is_empty());
            assert!(!path.exists());
            // Index reset: next record is index 0 again.
            let rec = store.record(entry("sleep", json!({"ms": 3}))).unwrap();
            assert_eq!(rec.index, 0);
        }
        // Reopen is fresh state too.
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_by_index(0).unwrap().args_json, json!({"ms": 3}));
    }

    #[test]
    fn clear_on_empty_store_is_zero() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert_eq!(store.clear().unwrap(), 0);
        assert!(!store.path().exists());
    }
}
