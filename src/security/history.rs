//! AES-256-GCM-encrypted action history - `<state_root>/history.json`.
//!
//! Spec: SECURITY.md "Storage", docs/TOOLS.md (`get_action_history`,
//! `replay_action`, `clear_action_history`), ROADMAP Phase 4.
//!
//! On-disk layout **v2**(current): an 8-byte magic header
//! ([`V2_MAGIC`]) followed by one sealed frame per record -
//! `u32le len || nonce[12] || ciphertext||tag` - where `len` counts the
//! `nonce || ciphertext||tag` bytes and each frame seals a single JSON
//! `ActionRecord` under its own random 96-bit nonce. `record()`
//! therefore appends one frame in O(1) instead of rewriting the file;
//! only FIFO-cap evictions (and the v1->v2 migration) rewrite it.
//!
//! Frames are **hash-chained through their GCM AAD**: a frame's AAD is
//! the SHA-256 of the previous frame's raw bytes (the first frame's is
//! SHA-256 of [`V2_MAGIC`]). Reordering, deleting, duplicating, or
//! splicing frames - including across files under the same key - breaks
//! the chain and fails a tag check on open; `index` is additionally
//! verified strictly increasing. Caveat, stated honestly: a truncated
//! *tail* still yields a valid shorter prefix - inherent to append-only
//! formats - but the gap between the file's last index and reality is
//! detectable by the caller, and any interior edit is not.
//!
//! On-disk layout **v1**(legacy, read-only): `nonce || ciphertext||tag`
//! sealing one JSON document `{"version": 1, "records": [...]}`. A v1
//! file is detected by the absence of [`V2_MAGIC`] (its leading bytes
//! are a CSPRNG nonce, so a magic collision is cryptographically
//! negligible), served normally, and rewritten as v2 on the next
//! `record()` - no explicit migration step.
//!
//! Any tamper - bit flip, truncation, substitution - fails a frame's
//! GCM tag check and surfaces as a `HistoryError` at the tool layer;
//! v2 load errors name the failing record index rather than silently
//! truncating the tail.
//!
//! Key material, in precedence order:
//! 1. `ULTRANIX_MCP_HISTORY_SECRET` - operator-supplied secret; SHA-256
//!    of its UTF-8 bytes is the key, so any string works. Rotation
//!    makes existing history unreadable (documented caveat -
//!    re-encrypt on rotation).
//! 2. `<state_root>/history.key` - a per-install 32-byte CSPRNG secret,
//!    generated on first use, file mode `0600`, containing dir `0700`.
//!
//! Opening the store is lazy: no directory, key, or history file is
//! created until the first [`HistoryStore::record`]. Read-only
//! operations on a system that has never recorded an action simply see
//! an empty history.
//!
//! Records carry a monotonic `index` so `replay_action{index}`
//! selectors stay stable across FIFO evictions and restarts.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::StateDir;

/// Hard cap on retained records - oldest are evicted FIFO on overflow.
pub const MAX_RECORDS: usize = 10_000;

/// Env var carrying the operator-supplied history secret (SECURITY.md).
pub const SECRET_ENV: &str = "ULTRANIX_MCP_HISTORY_SECRET";

/// Key file name inside the state root.
const KEY_FILE: &str = "history.key";

/// History file name inside the state root.
const HISTORY_FILE: &str = "history.json";

/// On-disk plaintext envelope version (v1 whole-blob files only).
const FORMAT_VERSION: u32 = 1;

/// v2 magic header - the first 8 bytes of a framed history file.
/// Distinguishes v2 from v1, whose leading bytes are a random nonce.
const V2_MAGIC: &[u8; 8] = b"UNXHIST2";

/// AES-GCM standard nonce size (96-bit).
const NONCE_LEN: usize = 12;

/// Byte width of a frame's little-endian length prefix. The length
/// counts the `nonce || ciphertext||tag` bytes that follow it.
const FRAME_LEN_SIZE: usize = 4;

/// `result_summary` is truncated to this many chars (docs/TOOLS.md).
pub const RESULT_SUMMARY_MAX: usize = 200;

/// One recorded action - the unit stored in `history.json` and returned by
/// `get_action_history` / resolved by `replay_action`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    /// ULID, 26 chars, Crockford Base32 - lexically sortable by time.
    pub id: String,
    /// Monotonic history index (0-based, assigned at append). Stable
    /// across FIFO evictions - surviving records keep their index.
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
    /// Outcome class - `ok`, `tool_error`, `error`, `consent_required`, ...
    /// (same vocabulary as the audit log).
    pub outcome: String,
}

/// What a caller supplies to [`HistoryStore::record`] - the store assigns
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

/// Plaintext envelope - what actually gets encrypted into `history.json`.
#[derive(Debug, Serialize, Deserialize)]
struct FilePayload {
    version: u32,
    records: Vec<ActionRecord>,
}

/// On-disk layout of `history.json` as last written (or read) by this
/// process - the store is the file's only writer, so tracking the
/// format in memory is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskFormat {
    /// No history file on disk (fresh store, or post-`clear`).
    Absent,
    /// Legacy whole-blob file: `nonce || ciphertext` of one JSON
    /// document. Served read-only; the next `record()` rewrites it as
    /// v2 (migration).
    V1,
    /// Framed file: [`V2_MAGIC`] + per-record sealed frames -
    /// `record()` appends in O(1).
    V2,
}

struct Inner {
    /// Chronological order, oldest first.
    records: Vec<ActionRecord>,
    /// Index the next appended record will receive.
    next_index: u64,
    /// Resolved key material - `None` until the first encrypt/decrypt.
    key: Option<[u8; 32]>,
    /// Layout currently on disk - decides append vs. rewrite in
    /// [`HistoryStore::record`].
    disk_format: DiskFormat,
    /// AAD the next appended frame must seal with - SHA-256 of the last
    /// frame currently on disk ([`magic_aad`] when the file is absent or
    /// freshly rewritten empty). The store is the file's only writer, so
    /// tracking the tail in memory is exact.
    tail_aad: [u8; 32],
}

/// Debug is implemented manually (never derived): the `Inner` state
/// holds raw AES key material that must never reach a log line.
impl std::fmt::Debug for HistoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryStore")
            .field("root", &self.root)
            .field("path", &self.path)
            .field("key_path", &self.key_path)
            .field("max_records", &self.max_records)
            .finish_non_exhaustive()
    }
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
    /// `history.json`. Creates nothing on disk - the layout, key file, and
    /// history file all materialize on the first [`record`](Self::record)
    /// (or `record`-triggered key generation).
    ///
    /// Fails when `history.json` exists but cannot be decrypted: tampered
    /// file, wrong/rotated `ULTRANIX_MCP_HISTORY_SECRET`, or a missing/
    /// malformed `history.key`.
    pub fn open(state_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_cap(state_root, MAX_RECORDS)
    }

    /// [`open`](Self::open) with an explicit retention cap - for tests and
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
                disk_format: DiskFormat::Absent,
                tail_aad: magic_aad(),
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
    /// The first-open result is cached for the process - including failure.
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
    /// evicts FIFO over the cap, then persists: one frame appended on the
    /// v2 layout, a full v2 rewrite on eviction or legacy-v1 migration.
    /// On a persist failure the in-memory state is left untouched.
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

        // Append in place, then persist. Three cases (EFF-1):
        //   * FIFO eviction (`keep_from > 0`) - rewrite the kept tail.
        //     Batched: over-cap drains down to `max - evict_batch`, so at
        //     saturation the O(n) rewrite amortizes over ~`evict_batch`
        //     appends instead of running on every single call.
        //   * Disk is already v2 - append the one new frame, O(1).
        //   * Absent or legacy v1 - rewrite everything as v2 (the
        //     migration path; also how the first-ever record lands).
        // A failed write pops the pushed record, leaving memory
        // consistent with the untouched file.
        inner.records.push(rec.clone());
        let keep_from = if inner.records.len() > self.max_records {
            inner.records.len().saturating_sub(
                self.max_records
                    .saturating_sub(evict_batch(self.max_records)),
            )
        } else {
            0
        };
        let persisted = if keep_from > 0 || inner.disk_format != DiskFormat::V2 {
            self.persist_v2(&key, &inner.records[keep_from..])
        } else {
            // Append is the O(1) hot path. If it fails because the file
            // was deleted out from under us (rare), fall back to a full
            // rewrite - this both recovers from the missing file and
            // preserves the store's monotonic indices.
            match self.append_frame(&key, &rec, &inner.tail_aad) {
                Ok(tail) => Ok(tail),
                Err(e) if e.to_string().contains("No such file") => {
                    self.persist_v2(&key, &inner.records[keep_from..])
                }
                Err(e) => Err(e),
            }
        };
        let tail_aad = match persisted {
            Ok(tail_aad) => tail_aad,
            Err(e) => {
                inner.records.pop();
                return Err(e);
            }
        };
        inner.disk_format = DiskFormat::V2;
        inner.tail_aad = tail_aad;
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

    /// Look up a record by its monotonic `index`. `records` is
    /// index-ordered (appends are monotonic; evictions drain from the
    /// head), so the lookup is a binary search, not a scan.
    pub fn get_by_index(&self, index: u64) -> Option<ActionRecord> {
        let inner = self.inner.lock().expect("history store poisoned");
        let i = inner.records.partition_point(|r| r.index < index);
        inner.records.get(i).filter(|r| r.index == index).cloned()
    }

    /// Newest-first records whose `tool` contains `needle`
    /// (case-insensitive substring - same match rule as
    /// `get_action_history`'s `action` filter), at most `limit`.
    /// Filters before cloning so a filtered query does not copy the
    /// whole store.
    pub fn list_filtered(&self, needle: &str, limit: usize) -> Vec<ActionRecord> {
        let inner = self.inner.lock().expect("history store poisoned");
        inner
            .records
            .iter()
            .rev()
            .filter(|r| r.tool.to_lowercase().contains(needle))
            .take(limit)
            .cloned()
            .collect()
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
        inner.disk_format = DiskFormat::Absent;
        inner.tail_aad = magic_aad();
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
        // Existing history with no resolvable secret is a hard failure -
        // never generate a fresh key just to report "corrupt".
        let key = self.resolve_key(&mut inner, false)?;
        // Layout detection: the v2 magic header, else the v1 whole-blob
        // envelope (whose leading bytes are a random nonce - a magic
        // collision is cryptographically negligible).
        let mut records = if bytes.starts_with(V2_MAGIC) {
            inner.disk_format = DiskFormat::V2;
            let (records, tail_aad) = parse_frames(&key, &bytes[V2_MAGIC.len()..])?;
            inner.tail_aad = tail_aad;
            records
        } else {
            inner.disk_format = DiskFormat::V1;
            let payload = decrypt(&key, &bytes)?;
            if payload.version != FORMAT_VERSION {
                bail!(
                    "unsupported {} version {}",
                    self.path.display(),
                    payload.version
                );
            }
            payload.records
        };
        inner.next_index = records.iter().map(|r| r.index).max().map_or(0, |i| i + 1);
        if records.len() > self.max_records {
            let excess = records.len() - self.max_records;
            records.drain(..excess);
        }
        inner.records = records;
        Ok(())
    }

    /// Resolve the 32-byte key: env secret (SHA-256) -> `history.key` ->
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

    /// Serialize + seal each record into the v2 framed layout and
    /// atomically replace `history.json` (tmp file + rename - a torn
    /// rewrite can never land). Used by eviction and the v1->v2
    /// migration; `record()`'s hot path appends instead. Returns the
    /// chain tail - the AAD the next appended frame must seal with.
    fn persist_v2(&self, key: &[u8; 32], records: &[ActionRecord]) -> anyhow::Result<[u8; 32]> {
        let mut out = Vec::with_capacity(V2_MAGIC.len() + records.len() * 64);
        out.extend_from_slice(V2_MAGIC);
        let mut aad = magic_aad();
        for rec in records {
            let frame = seal_frame(key, rec, &aad)?;
            aad = frame_aad(&frame);
            out.extend_from_slice(&frame);
        }

        StateDir::at(&self.root).ensure_parent(&self.path)?;
        let tmp = self.path.with_file_name(format!(
            "{}.tmp",
            self.path.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_private(&tmp, &out)?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        set_mode(&self.path, 0o600)?;
        Ok(aad)
    }

    /// Append one sealed frame to the existing v2 file - `record()`'s
    /// O(1) hot path. A failed or torn write is rolled back to the
    /// pre-append length best-effort so the tail can never poison the
    /// next load; the caller still sees the error and drops the record.
    /// Returns the new chain tail on success.
    fn append_frame(
        &self,
        key: &[u8; 32],
        rec: &ActionRecord,
        aad: &[u8; 32],
    ) -> anyhow::Result<[u8; 32]> {
        let frame = seal_frame(key, rec, aad)?;
        let base_len = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let mut opts = OpenOptions::new();
        opts.append(true);
        let mut f = opts
            .open(&self.path)
            .with_context(|| format!("open {} for append", self.path.display()))?;
        if let Err(e) = f.write_all(&frame).and_then(|()| f.flush()) {
            // Roll back a possibly-torn tail frame: a partial frame at
            // EOF would fail the next `load()` outright.
            let _ = f.set_len(base_len);
            return Err(e).with_context(|| format!("append {}", self.path.display()));
        }
        let _ = f.sync_data();
        drop(f);
        set_mode(&self.path, 0o600)?;
        Ok(frame_aad(&frame))
    }
}

/// AAD anchoring the frame chain: SHA-256 of [`V2_MAGIC`] - every chain
/// starts here, so frames can never validate out of file context.
fn magic_aad() -> [u8; 32] {
    Sha256::digest(V2_MAGIC).into()
}

/// AAD for the frame following `prev_frame`: SHA-256 of its raw bytes
/// (`len || nonce || ciphertext||tag`). Chaining the previous ciphertext
/// into the next frame's authentication binds order and position -
/// reordering, deleting, duplicating, or splicing frames breaks the
/// chain at the next tag check.
fn frame_aad(prev_frame: &[u8]) -> [u8; 32] {
    Sha256::digest(prev_frame).into()
}

/// Eviction batch size: when the record count exceeds the cap, drain to
/// `max - batch` rather than `max`. Without batching, a saturated store
/// would rewrite the entire file on *every* `record()` - O(MAX_RECORDS)
/// seals plus a multi-MB write per tool call. With batching, that cost
/// amortizes over ~`batch` appends (~1,000 calls at [`MAX_RECORDS`]).
fn evict_batch(max_records: usize) -> usize {
    (max_records / 10).max(1)
}

/// One record -> one sealed v2 frame:
/// `u32le len || nonce[12] || ciphertext||tag`, `len` counting the
/// `nonce || ciphertext||tag` bytes. `aad` chains this frame to the
/// previous one (see [`frame_aad`]).
fn seal_frame(key: &[u8; 32], rec: &ActionRecord, aad: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(rec).context("serialize history record")?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("history encryption failed"))?;

    let mut frame = Vec::with_capacity(FRAME_LEN_SIZE + NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&((NONCE_LEN + ciphertext.len()) as u32).to_le_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

/// V2 frame stream (everything after [`V2_MAGIC`]) -> records in file
/// order plus the chain tail (the AAD a subsequent append must use).
/// Frames are hash-chained through their GCM AAD - each frame
/// authenticates against the SHA-256 of the previous frame's raw bytes,
/// starting from the magic - so any malformed frame, interior edit,
/// reorder, deletion, or splice fails a tag check or the
/// strictly-increasing `index` check, naming the failing frame index;
/// never a silent truncation.
fn parse_frames(key: &[u8; 32], mut bytes: &[u8]) -> anyhow::Result<(Vec<ActionRecord>, [u8; 32])> {
    let mut records = Vec::new();
    let mut index = 0usize;
    let mut aad = magic_aad();
    let mut prev_index: Option<u64> = None;
    while !bytes.is_empty() {
        if bytes.len() < FRAME_LEN_SIZE {
            bail!(
                "history record {index}: truncated length prefix ({} byte(s) left)",
                bytes.len()
            );
        }
        let len = u32::from_le_bytes(bytes[..FRAME_LEN_SIZE].try_into().unwrap()) as usize;
        // Smallest legal frame: nonce + a 16-byte GCM tag over an
        // empty plaintext. Anything shorter is corrupt, not empty.
        if len < NONCE_LEN + 16 {
            bail!("history record {index}: invalid frame length {len}");
        }
        if bytes.len() < FRAME_LEN_SIZE + len {
            bail!(
                "history record {index}: truncated frame (want {len} bytes, have {})",
                bytes.len().saturating_sub(FRAME_LEN_SIZE)
            );
        }
        // The chain hash covers the full frame *including* the length
        // prefix - the same bytes `seal_frame`/`persist_v2` hashed.
        let frame = &bytes[..FRAME_LEN_SIZE + len];
        let (nonce, ciphertext) = frame[FRAME_LEN_SIZE..].split_at(NONCE_LEN);
        let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "history record {index} decrypt failed - tampered file or wrong secret"
                )
            })?;
        let rec: ActionRecord = serde_json::from_slice(&plaintext)
            .with_context(|| format!("history record {index} is not valid JSON"))?;
        // Semantic belt-and-braces over the AAD chain: record indexes
        // must be strictly increasing in file order - a reorder that
        // somehow survived the chain still fails here.
        if let Some(prev) = prev_index
            && rec.index <= prev
        {
            bail!(
                "history record {index}: non-increasing index {} after {prev}",
                rec.index
            );
        }
        prev_index = Some(rec.index);
        aad = frame_aad(frame);
        records.push(rec);
        bytes = &bytes[FRAME_LEN_SIZE + len..];
        index += 1;
    }
    Ok((records, aad))
}

/// `nonce || ciphertext || tag` -> plaintext records payload.
fn decrypt(key: &[u8; 32], bytes: &[u8]) -> anyhow::Result<FilePayload> {
    if bytes.len() < NONCE_LEN + 16 {
        bail!("history.json too short for nonce + tag");
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            anyhow::anyhow!("history.json decrypt failed - tampered file or wrong secret")
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

/// Secrets must not persist into a queryable, replayable store:
/// `type_text.text` and `clipboard_set.text` -> `"<redacted:N chars>"`
/// (typed text and clipboard payloads are exactly where password
/// managers and secrets pass through); `plugin_run.params` ->
/// `"<redacted:N params>"` - a plugin wrapping `type_text` or
/// `clipboard_set` would otherwise smuggle the same secret the
/// step-level redaction hides into the macro record, past the
/// `args_contain_redacted` replay guard. A tool name outside the
/// static catalog is a plugin-exposed tool: its args are arbitrary
/// caller params - the same channel `plugin_run.params` hides - so
/// the whole object collapses to `"<redacted:N params>"`. Everything
/// else verbatim.
fn redact_args(tool: &str, mut args: Value) -> Value {
    let Some(obj) = args.as_object_mut() else {
        return args;
    };
    match tool {
        "type_text" | "clipboard_set" => {
            if let Some(text) = obj.get("text").and_then(Value::as_str) {
                let n = text.chars().count();
                obj.insert(
                    "text".into(),
                    Value::String(format!("<redacted:{n} chars>")),
                );
            }
        }
        "plugin_run" => {
            if let Some(params) = obj.get("params").and_then(Value::as_object) {
                let n = params.len();
                obj.insert(
                    "params".into(),
                    Value::String(format!("<redacted:{n} params>")),
                );
            }
        }
        _ => {
            if crate::tools::category_of(tool).is_none() && !obj.is_empty() {
                let n = obj.len();
                return serde_json::json!({
                    "params": format!("<redacted:{n} params>")
                });
            }
        }
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
    /// changes which key a store resolves - a test that sets it must not
    /// race a sibling's `record`/`open`. Every store-touching test holds
    /// this guard for its duration.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        // Poison-tolerant: one panicking store test must not cascade
        // `PoisonError` into every sibling holding the lock.
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
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
        // bytes are trusted (S-8) - same rule as API-key files.
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
        // Flip a byte inside a sealed frame (the trailing GCM tag) -
        // layout-agnostic: any tamper must fail the tag check.
        let pos = bytes.len() - 1;
        bytes[pos] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = HistoryStore::open(tmp.path()).expect_err("tampered history must fail to open");
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
        // Opening is lazy - nothing on disk yet.
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
            // Env secret takes precedence - no key file is minted.
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
        let err =
            HistoryStore::open(tmp.path()).expect_err("history without secret must fail to open");
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

    // ---- v2 framed format ---------------------------------------------

    /// `(payload_start, payload_len)` of every frame in a v2 file -
    /// test-side parser for locating/corrupting individual frames.
    fn frame_offsets(bytes: &[u8]) -> Vec<(usize, usize)> {
        assert!(bytes.starts_with(V2_MAGIC), "test expects a v2 file");
        let mut out = Vec::new();
        let mut pos = V2_MAGIC.len();
        while pos + FRAME_LEN_SIZE <= bytes.len() {
            let len =
                u32::from_le_bytes(bytes[pos..pos + FRAME_LEN_SIZE].try_into().unwrap()) as usize;
            out.push((pos + FRAME_LEN_SIZE, len));
            pos += FRAME_LEN_SIZE + len;
        }
        assert_eq!(pos, bytes.len(), "test file must parse cleanly");
        out
    }

    #[test]
    fn record_writes_v2_frames_and_appends_without_rewrite() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        let after_one = fs::read(store.path()).unwrap();
        // v2 magic header + exactly one frame.
        assert!(after_one.starts_with(V2_MAGIC));
        assert_eq!(frame_offsets(&after_one).len(), 1);

        store.record(entry("sleep", json!({"ms": 2}))).unwrap();
        let after_two = fs::read(store.path()).unwrap();
        assert_eq!(frame_offsets(&after_two).len(), 2);
        // The append path must not rewrite: the entire previous file is
        // an untouched prefix of the new one (a rewrite would reseal
        // frame 0 under a fresh nonce and diverge within it).
        assert!(
            after_two.starts_with(&after_one),
            "record() rewrote the file instead of appending a frame"
        );
        // ...and reopening still serves both records in order.
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.get_by_index(0).unwrap().args_json, json!({"ms": 1}));
        assert_eq!(store.get_by_index(1).unwrap().args_json, json!({"ms": 2}));
    }

    #[test]
    fn seal_frame_parse_frames_roundtrip() {
        let key = [7u8; 32];
        let rec = ActionRecord {
            id: "01J9XKQV0R6T4H2Y8ZQ3N0AB12".into(),
            index: 41,
            tool: "mouse_click".into(),
            args_json: json!({"x": 1}),
            result_summary: "ok".into(),
            caller: "s".into(),
            ts: "2026-01-01T00:00:00Z".into(),
            duration_ms: 3,
            outcome: "ok".into(),
        };
        let frame = seal_frame(&key, &rec, &magic_aad()).unwrap();
        let (parsed, tail) = parse_frames(&key, &frame).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].index, 41);
        assert_eq!(parsed[0].tool, "mouse_click");
        assert_eq!(tail, frame_aad(&frame));
        // Wrong key fails the tag, naming record 0.
        let err = parse_frames(&[9u8; 32], &frame).unwrap_err();
        assert!(format!("{err:#}").contains("record 0"), "{err:#}");
        // A frame sealed mid-chain (wrong AAD) fails just as a wrong
        // key does - position is authenticated, not just content.
        let wrong_pos = seal_frame(&key, &rec, &[0u8; 32]).unwrap();
        assert!(parse_frames(&key, &wrong_pos).is_err());
    }

    /// Craft a legacy v1 file (whole-blob `nonce || ciphertext`) sealed
    /// under `key` - the layout v1.1.0 wrote.
    fn seal_v1_file(key: &[u8; 32], records: Vec<ActionRecord>) -> Vec<u8> {
        let payload = FilePayload {
            version: FORMAT_VERSION,
            records,
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .unwrap();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn v1_file_is_served_then_migrated_on_next_record() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        // Pin the key via the env secret so the hand-crafted file and
        // the store resolve identical key material.
        unsafe {
            std::env::set_var(SECRET_ENV, "migration-test-secret");
        }
        let key: [u8; 32] = Sha256::digest(b"migration-test-secret").into();
        let legacy = ActionRecord {
            id: "01J9XKQV0R6T4H2Y8ZQ3N0AB12".into(),
            index: 0,
            tool: "sleep".into(),
            args_json: json!({"ms": 1}),
            result_summary: "legacy".into(),
            caller: "old".into(),
            ts: "2026-01-01T00:00:00Z".into(),
            duration_ms: 1,
            outcome: "ok".into(),
        };
        fs::write(
            tmp.path().join(HISTORY_FILE),
            seal_v1_file(&key, vec![legacy]),
        )
        .unwrap();

        {
            // v1 is served transparently.
            let store = HistoryStore::open(tmp.path()).unwrap();
            assert_eq!(store.len(), 1);
            assert_eq!(store.get_by_index(0).unwrap().result_summary, "legacy");
            // The next record migrates the file to v2.
            store.record(entry("sleep", json!({"ms": 2}))).unwrap();
            let bytes = fs::read(store.path()).unwrap();
            assert!(bytes.starts_with(V2_MAGIC), "record() must migrate v1->v2");
            assert_eq!(frame_offsets(&bytes).len(), 2);
        }
        // Reopen: legacy + new records, indices stable.
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.get_by_index(0).unwrap().result_summary, "legacy");
        assert_eq!(
            store.get_by_index(1).unwrap().result_summary,
            "did the thing"
        );
        unsafe {
            std::env::remove_var(SECRET_ENV);
        }
    }

    #[test]
    fn corrupt_mid_file_frame_names_the_record_index() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            for i in 0..3 {
                store.record(entry("sleep", json!({"ms": i}))).unwrap();
            }
            path = store.path().to_path_buf();
        }
        let mut bytes = fs::read(&path).unwrap();
        let offsets = frame_offsets(&bytes);
        // Corrupt a ciphertext byte inside the *middle* frame (index 1).
        let mid = offsets[1].0 + NONCE_LEN + 2;
        bytes[mid] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = HistoryStore::open(tmp.path()).expect_err("corrupt frame must fail open");
        assert!(
            format!("{err:#}").contains("record 1"),
            "error must name the record index: {err:#}"
        );
    }

    #[test]
    fn truncated_frame_and_bad_length_name_the_index() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            store.record(entry("sleep", json!({"ms": 1}))).unwrap();
            store.record(entry("sleep", json!({"ms": 2}))).unwrap();
            path = store.path().to_path_buf();
        }
        // Torn tail: drop the last 5 bytes -> frame 1 is truncated.
        let clean = fs::read(&path).unwrap();
        fs::write(&path, &clean[..clean.len() - 5]).unwrap();
        let err = HistoryStore::open(tmp.path()).expect_err("torn tail frame must fail open");
        assert!(format!("{err:#}").contains("record 1"), "{err:#}");

        // Impossible length: zero out frame 1's length prefix on the
        // clean file.
        let mut bytes = clean.clone();
        let offsets = frame_offsets(&bytes);
        let len_at = offsets[1].0 - FRAME_LEN_SIZE;
        bytes[len_at..len_at + FRAME_LEN_SIZE].fill(0);
        fs::write(&path, &bytes).unwrap();
        let err = HistoryStore::open(tmp.path()).expect_err("invalid frame length must fail open");
        assert!(
            format!("{err:#}").contains("record 1")
                && format!("{err:#}").contains("invalid frame length"),
            "{err:#}"
        );
    }

    #[test]
    fn frame_chain_detects_reorder_delete_duplicate_and_splice() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let store = HistoryStore::open(tmp.path()).unwrap();
            for i in 0..3 {
                store.record(entry("sleep", json!({"ms": i}))).unwrap();
            }
            path = store.path().to_path_buf();
        }
        let clean = fs::read(&path).unwrap();
        let offsets = frame_offsets(&clean);
        // Frame span including the 4-byte length prefix.
        let span = |i: usize| (offsets[i].0 - FRAME_LEN_SIZE, offsets[i].0 + offsets[i].1);
        let (s0, e0) = span(0);
        let (s1, e1) = span(1);

        // Reorder: swap frames 0 and 1 - frame 1's AAD no longer
        // matches its position even though each tag is individually
        // well-formed.
        let mut reordered = clean.clone();
        reordered.splice(
            s0..e1,
            clean[s1..e1].iter().chain(clean[s0..e0].iter()).copied(),
        );
        fs::write(&path, &reordered).unwrap();
        assert!(
            HistoryStore::open(tmp.path()).is_err(),
            "reordered frames must fail the chain"
        );

        // Interior deletion: drop frame 1 - frame 2's AAD expects
        // frame 1's bytes, so the gap fails authentication.
        let mut deleted = clean.clone();
        deleted.splice(s1..e1, std::iter::empty());
        fs::write(&path, &deleted).unwrap();
        assert!(
            HistoryStore::open(tmp.path()).is_err(),
            "a deleted interior frame must fail the chain"
        );

        // Duplication: repeat frame 1 - the duplicate is sealed for
        // the wrong predecessor.
        let mut dup = clean.clone();
        dup.splice(e1..e1, clean[s1..e1].iter().copied());
        fs::write(&path, &dup).unwrap();
        assert!(
            HistoryStore::open(tmp.path()).is_err(),
            "a duplicated frame must fail the chain"
        );

        // Cross-file splice under the SAME key: both stores derive the
        // key from the env secret, so the foreign frame's ciphertext is
        // valid - only its chain position is wrong. Fresh dirs: `tmp`'s
        // file above was sealed under its own generated key.
        unsafe {
            std::env::set_var(SECRET_ENV, "shared-splice-secret");
        }
        let tmp2 = tempfile::tempdir().unwrap();
        let path2;
        {
            let store = HistoryStore::open(tmp2.path()).unwrap();
            for i in 0..3 {
                store.record(entry("sleep", json!({"ms": i}))).unwrap();
            }
            path2 = store.path().to_path_buf();
        }
        let other = tempfile::tempdir().unwrap();
        {
            let other_store = HistoryStore::open(other.path()).unwrap();
            other_store
                .record(entry("sleep", json!({"ms": 99})))
                .unwrap();
        }
        let clean2 = fs::read(&path2).unwrap();
        let offsets2 = frame_offsets(&clean2);
        let s1b = offsets2[1].0 - FRAME_LEN_SIZE;
        let foreign = fs::read(other.path().join(HISTORY_FILE)).unwrap();
        let f_offsets = frame_offsets(&foreign);
        let foreign_frame =
            &foreign[f_offsets[0].0 - FRAME_LEN_SIZE..f_offsets[0].0 + f_offsets[0].1];
        let mut spliced = clean2.clone();
        spliced.splice(s1b..s1b, foreign_frame.iter().copied());
        fs::write(&path2, &spliced).unwrap();
        assert!(
            HistoryStore::open(tmp2.path()).is_err(),
            "a spliced foreign frame must fail the chain even under the same key"
        );
        unsafe {
            std::env::remove_var(SECRET_ENV);
        }
    }

    #[test]
    fn clipboard_set_and_plugin_run_args_are_redacted() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        let rec = store
            .record(entry(
                "clipboard_set",
                json!({"text": "secret-paste", "mime": "text/plain"}),
            ))
            .unwrap();
        assert_eq!(rec.args_json["text"], json!("<redacted:12 chars>"));
        assert_eq!(rec.args_json["mime"], json!("text/plain"));
        // A plugin wrapping a secret-bearing tool can't smuggle the
        // value through the macro record either.
        let rec = store
            .record(entry(
                "plugin_run",
                json!({"name": "p", "params": {"text": "hunter2", "n": 1}}),
            ))
            .unwrap();
        assert_eq!(rec.args_json["params"], json!("<redacted:2 params>"));
        assert_eq!(rec.args_json["name"], json!("p"));
        // Neither secret reaches disk.
        let bytes = fs::read(store.path()).unwrap();
        let lossy = String::from_utf8_lossy(&bytes);
        assert!(!lossy.contains("secret-paste"));
        assert!(!lossy.contains("hunter2"));
    }

    #[test]
    fn plugin_exposed_tool_args_are_redacted() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let store = HistoryStore::open(tmp.path()).unwrap();
        // A tool name outside the static catalog is plugin-exposed: its
        // args are arbitrary caller params - the same secret channel
        // `plugin_run.params` hides - so the whole object collapses to
        // a redaction marker (which also trips the replay guard).
        let rec = store
            .record(entry(
                "deploy_notes",
                json!({"password": "hunter2", "region": "us-east-1"}),
            ))
            .unwrap();
        assert_eq!(rec.args_json, json!({"params": "<redacted:2 params>"}));
        // Catalog tools keep verbatim args; an empty plugin-tool call
        // has nothing to redact.
        let rec = store.record(entry("deploy_notes", json!({}))).unwrap();
        assert_eq!(rec.args_json, json!({}));
        let rec = store.record(entry("sleep", json!({"ms": 10}))).unwrap();
        assert_eq!(rec.args_json["ms"], json!(10));
        // The secret never reaches disk.
        let bytes = fs::read(store.path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("hunter2"));
    }

    #[test]
    fn v2_header_only_file_is_an_empty_store() {
        let _env = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        // A bare magic header is a valid v2 file with zero frames.
        fs::write(tmp.path().join(HISTORY_FILE), V2_MAGIC).unwrap();
        // Still needs a resolvable secret to open - the env one works.
        unsafe {
            std::env::set_var(SECRET_ENV, "header-only");
        }
        let store = HistoryStore::open(tmp.path()).unwrap();
        assert!(store.is_empty());
        // Appending to a header-only file keeps it valid v2.
        store.record(entry("sleep", json!({}))).unwrap();
        let bytes = fs::read(store.path()).unwrap();
        assert_eq!(frame_offsets(&bytes).len(), 1);
        unsafe {
            std::env::remove_var(SECRET_ENV);
        }
    }

    #[test]
    fn fifo_eviction_rewrites_but_stays_v2() {
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
        let bytes = fs::read(store.path()).unwrap();
        assert!(bytes.starts_with(V2_MAGIC));
        // Eviction rewrote the file: exactly the 3 surviving frames
        // (cap=3, batch=1 -> first over-cap drains two, landing on 3).
        assert_eq!(frame_offsets(&bytes).len(), 3);
        // Batched eviction: at saturation the store drains to
        // `cap - evict_batch` (= 2 here) rather than `cap`, so the next
        // ~batch appends go back to the O(1) frame-append path instead
        // of rewriting the file on every call.
        store.record(entry("sleep", json!({}))).unwrap();
        let bytes = fs::read(store.path()).unwrap();
        assert_eq!(frame_offsets(&bytes).len(), 2);
        let store = HistoryStore::open_with_cap(tmp.path(), 3).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.get_by_index(0).is_none());
        assert!(store.get_by_index(2).is_none());
        assert!(store.get_by_index(3).is_none());
        assert_eq!(
            store.get_by_index(5).unwrap().result_summary,
            "did the thing"
        );
        // Post-eviction appends are O(1) again - index 6 lands as a
        // single frame, no rewrite.
        store.record(entry("sleep", json!({}))).unwrap();
        let bytes = fs::read(store.path()).unwrap();
        assert_eq!(frame_offsets(&bytes).len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn failed_append_leaves_memory_and_file_consistent() {
        let _env = env_guard();
        let _secret = without_env_secret();
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("state");
        let store = HistoryStore::open(&root).unwrap();
        store.record(entry("sleep", json!({"ms": 1}))).unwrap();
        // Make the history file read-only: the frame append must fail,
        // the in-memory record must roll back, and the on-disk file
        // must stay loadable (no torn tail).
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o400)).unwrap();
        let err = store.record(entry("sleep", json!({"ms": 2}))).unwrap_err();
        assert!(
            format!("{err:#}").contains("append") || format!("{err:#}").contains("open"),
            "{err:#}"
        );
        assert_eq!(store.len(), 1);
        assert!(store.get_by_index(1).is_none());
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600)).unwrap();
        // The file still parses - and the store recovers once writable.
        let reopened = HistoryStore::open(&root).unwrap();
        assert_eq!(reopened.len(), 1);
        store.record(entry("sleep", json!({"ms": 2}))).unwrap();
        assert_eq!(store.len(), 2);
    }
}
