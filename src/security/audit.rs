//! Hash-chained JSONL audit log — SECURITY.md "Storage" and
//! docs/TOOLS.md "Destructive-Action Consent" / rate-limit audit notes.
//!
//! Every tool invocation — accepted or rejected — is appended to
//! `~/.ultranix-mcp/logs/audit.jsonl`. Each record carries
//! `{timestamp, tool, args_hash, outcome, duration_ms, key_id, caller,
//! consent?, denial_reason?, prev_hash, hmac?}` where `prev_hash` is the
//! SHA-256 of the *previous record's serialized bytes* (the JSON line,
//! newline excluded). The genesis record's `prev_hash` is `"0"*64`. Raw
//! arguments are **never** persisted — only the same canonical
//! `args_hash` the consent gate binds to. When
//! [`HMAC_SECRET_ENV`] is set, `hmac` carries an HMAC-SHA256 over the
//! canonical record *without* the `hmac` field, and `prev_hash` still
//! covers the final serialized line including it.
//!
//! **Rotation / retention.** `audit.jsonl` is always the live file. When
//! the UTC day rolls over — checked on every `record` and at `open` (via
//! the first record's timestamp) — the finished file is renamed to
//! `audit-YYYY-MM-DD.jsonl` under `logs/` and a fresh `audit.jsonl`
//! starts a new chain at `GENESIS`, so every file is self-verifying.
//! Archives older than `ULTRANIX_MCP_AUDIT_RETENTION_DAYS` (default
//! [`DEFAULT_RETENTION_DAYS`] = 30; `0` keeps archives forever) are
//! pruned at open and after each rotation.
//!
//! File mode `0600`, containing dir `0700`. The chain makes silent edits
//! detectable; per THREAT_MODEL.md R-6 there is no external anchor — a
//! same-UID attacker who rewrites the file can recompute the chain, so
//! shipping records onward (journald/SIEM) is the real tamper evidence.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;
use chrono::NaiveDate;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `prev_hash` of the first record in a fresh log.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Default archive retention in days, overridable via
/// [`RETENTION_ENV`]. Archives dated more than this many days before
/// today are deleted at open and after each day-rollover rotation.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

/// Env override for audit retention: a day count. `0` keeps archives
/// forever; an unparseable value falls back to [`DEFAULT_RETENTION_DAYS`].
pub const RETENTION_ENV: &str = "ULTRANIX_MCP_AUDIT_RETENTION_DAYS";

/// Env override for the audit-log HMAC secret. When set and non-empty,
/// every record is signed with HMAC-SHA256 over its canonical JSON.
pub const HMAC_SECRET_ENV: &str = "ULTRANIX_MCP_AUDIT_SECRET";

/// One audit record — the serialized line shape. Field order is fixed by
/// declaration order so the chain hashes a stable encoding.
#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    /// RFC 3339 UTC timestamp.
    timestamp: String,
    /// Tool name (e.g. `system_command`) or pipeline event id.
    tool: &'a str,
    /// SHA-256 of canonical args — raw args are never logged.
    args_hash: &'a str,
    /// `ok`, an error `data.kind`, `consent.required`, …
    outcome: &'a str,
    /// Wall time of the invocation.
    duration_ms: u64,
    /// API key id on HTTP; absent/stdio → `null`.
    key_id: Option<&'a str>,
    /// Caller identity the consent gate bound to: `key_id` on HTTP, the
    /// session id on stdio. `null` only when neither exists.
    caller: Option<&'a str>,
    /// Consent stamp for gated calls: `"bypassed"` under
    /// `--allow-destructive`, absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    consent: Option<&'a str>,
    /// Policy denial reason, e.g. `readonly_mode`, `not_in_tool_list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    denial_reason: Option<&'a str>,
    /// SHA-256 of the previous record's serialized bytes; `"0"*64` genesis.
    prev_hash: &'a str,
    /// HMAC-SHA256 over the canonical JSON of this record *without* this
    /// field. Present only when an HMAC secret was configured at open.
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac: Option<String>,
}

/// Owned mirror of [`AuditRecord`] used for chain/HMAC verification. Field
/// order must match [`AuditRecord`] exactly so re-serialization is byte
/// identical to the canonical pre-HMAC form. `deny_unknown_fields` makes
/// unknown JSON members a parse error — otherwise an attacker could pad
/// the *last* record with forged fields that re-serialization silently
/// drops while its HMAC still verifies. Consequence: adding a field to
/// `AuditRecord` requires a lockstep update here plus a verifier upgrade.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiableRecord {
    timestamp: String,
    tool: String,
    args_hash: String,
    outcome: String,
    duration_ms: u64,
    key_id: Option<String>,
    caller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    denial_reason: Option<String>,
    prev_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hmac: Option<String>,
}

/// Who made the call and how consent applied — the record fields that
/// describe the caller rather than the call. Bundled into one struct so
/// [`AuditLog::record`] stays under the argument-count lint.
#[derive(Debug, Clone, Copy, Default)]
pub struct CallContext<'a> {
    /// API key id on HTTP; `None` on stdio.
    pub key_id: Option<&'a str>,
    /// Identity the consent gate bound to: `key_id` on HTTP, the session
    /// id on stdio.
    pub caller: Option<&'a str>,
    /// Consent stamp for gated calls: `"bypassed"` under
    /// `--allow-destructive`, `"verified"` after a token check, `None`
    /// for ungated calls.
    pub consent: Option<&'a str>,
}

/// Append-only, hash-chained audit sink.
pub struct AuditLog {
    /// Live file — always `<logs>/audit.jsonl` in production.
    path: PathBuf,
    /// Archive retention in days; `None` keeps archives forever.
    retention: Option<u64>,
    /// Optional HMAC-SHA256 signing key, derived from the configured
    /// secret via SHA-256(secret).
    hmac_key: Option<Vec<u8>>,
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    /// SHA-256 hex of the last line written (or [`GENESIS`]).
    prev_hash: String,
    /// UTC date the live file covers — the trigger for day rotation.
    date: NaiveDate,
}

impl AuditLog {
    /// Open (creating if needed) the log at `path`. The containing
    /// directory is created `0700`; the file is forced to `0600`.
    ///
    /// If the file already has records, the chain is resumed: the last
    /// line's hash becomes `prev_hash`, so appends after restart remain
    /// verifiable end-to-end.
    ///
    /// A pre-existing live file whose first record predates today (UTC)
    /// is first rotated to `audit-YYYY-MM-DD.jsonl`, then archives older
    /// than the retention window ([`RETENTION_ENV`], default
    /// [`DEFAULT_RETENTION_DAYS`]) are pruned.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_with_retention(path, retention_from_env())
    }

    /// [`AuditLog::open`] with an explicit retention policy — the
    /// testable core (the public entry point derives it from
    /// [`RETENTION_ENV`]). `None` keeps archives forever.
    pub fn open_with_retention(path: &Path, retention: Option<u64>) -> anyhow::Result<Self> {
        let today = chrono::Utc::now().date_naive();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("create audit dir {}", dir.display()))?;
            set_mode(dir, 0o700)?;
            // A live file whose first record is from a previous day is a
            // stale log left by an earlier process — archive it before
            // appending so each file holds exactly one UTC day.
            if let Some(date) = first_record_date(path)?
                && date != today
            {
                rotate_file(path, date)?;
            }
            prune_archives(dir, today, retention, stem_of(path))?;
        }
        let mut file = open_append(path)?;
        set_mode(path, 0o600)?; // enforce on pre-existing files too

        let prev_hash = last_line_hash(&mut file)?.unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path: path.to_path_buf(),
            retention,
            hmac_key: None,
            inner: Mutex::new(Inner {
                file,
                prev_hash,
                date: today,
            }),
        })
    }

    /// Attach (or replace) the HMAC signing secret. Empty strings are
    /// treated as `None`.
    pub fn with_audit_secret(mut self, secret: Option<String>) -> Self {
        self.hmac_key = secret
            .filter(|s| !s.trim().is_empty())
            .map(|s| derive_hmac_key(&s));
        self
    }

    /// Where this log lives on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record. `args_hash` is the caller-computed canonical
    /// args hash ([`crate::security::consent::args_hash`]) — this API
    /// deliberately cannot receive raw arguments.
    pub fn record(
        &self,
        tool: &str,
        args_hash: &str,
        outcome: &str,
        duration_ms: u64,
        ctx: CallContext<'_>,
        denial_reason: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().expect("audit log poisoned");
        let now = chrono::Utc::now();
        let today = now.date_naive();
        if today != inner.date {
            // Day rolled over: archive the finished day under its date,
            // start a fresh chain at GENESIS, and apply retention.
            rotate_file(&self.path, inner.date)?;
            inner.file = open_append(&self.path)?;
            inner.prev_hash = GENESIS.to_string();
            inner.date = today;
            if let Some(dir) = self.path.parent() {
                prune_archives(dir, today, self.retention, stem_of(&self.path))?;
            }
        }
        // Client-supplied tool names are unbounded; cap them so a record
        // stays well under the ~1 KiB the chain-resume tail scan assumes.
        let tool = {
            const MAX_TOOL_LEN: usize = 128;
            if tool.len() <= MAX_TOOL_LEN {
                tool
            } else {
                let mut end = MAX_TOOL_LEN;
                while !tool.is_char_boundary(end) {
                    end -= 1;
                }
                &tool[..end]
            }
        };
        let mut rec = AuditRecord {
            timestamp: now.to_rfc3339(),
            tool,
            args_hash,
            outcome,
            duration_ms,
            key_id: ctx.key_id,
            caller: ctx.caller,
            consent: ctx.consent,
            denial_reason,
            prev_hash: &inner.prev_hash,
            hmac: None,
        };
        // The pre-HMAC canonical serialization only exists to be signed —
        // skip it when no secret is configured so the common path
        // serializes each record exactly once.
        if let Some(key) = &self.hmac_key {
            let canonical = serde_json::to_string(&rec).context("serialize audit record")?;
            rec.hmac = Some(hmac_sha256_hex(key, canonical.as_bytes()));
        }
        let line = serde_json::to_string(&rec).context("serialize audit record with hmac")?;
        writeln!(inner.file, "{line}").context("append audit record")?;
        inner.file.flush().context("flush audit record")?;
        inner.prev_hash = sha256_hex(line.as_bytes());
        Ok(())
    }

    /// Re-verify the whole chain on disk: every record's `prev_hash` must
    /// equal SHA-256 of the preceding line's raw bytes, starting from
    /// [`GENESIS`]. Returns `Ok(false)` on the first mismatch.
    pub fn verify_chain(&self) -> anyhow::Result<bool> {
        // Flush any in-flight write first.
        self.inner
            .lock()
            .expect("audit log poisoned")
            .file
            .flush()
            .context("flush before verify")?;
        verify_chain_at(&self.path)
    }

    /// Re-verify the chain and, if `secret` is supplied, every record's
    /// HMAC-SHA256 signature. See [`verify_hmac_at`].
    pub fn verify_hmac(&self, secret: Option<&str>) -> anyhow::Result<bool> {
        self.inner
            .lock()
            .expect("audit log poisoned")
            .file
            .flush()
            .context("flush before verify")?;
        verify_hmac_at(&self.path, secret)
    }
}

/// Standalone chain verification for a log file path — usable in tests and
/// integrity tooling without opening an [`AuditLog`].
pub fn verify_chain_at(path: &Path) -> anyhow::Result<bool> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut expected = GENESIS.to_string();
    for raw_line in bytes.split(|b| *b == b'\n') {
        if raw_line.is_empty() {
            continue; // tolerate a trailing newline
        }
        let rec: serde_json::Value =
            serde_json::from_slice(raw_line).context("audit line is not valid JSON")?;
        let claimed = rec
            .get("prev_hash")
            .and_then(serde_json::Value::as_str)
            .context("audit record missing prev_hash")?;
        if claimed != expected {
            return Ok(false);
        }
        expected = sha256_hex(raw_line);
    }
    Ok(true)
}

/// Re-verify both the hash chain and, if `secret` is supplied, every
/// record's `hmac` field. With a secret, any line missing an `hmac` or
/// whose HMAC does not match the canonical JSON (record without the `hmac`
/// field) returns `Ok(false)`. With `secret = None` this is equivalent to
/// [`verify_chain_at`].
pub fn verify_hmac_at(path: &Path, secret: Option<&str>) -> anyhow::Result<bool> {
    let key = secret.map(derive_hmac_key);
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut expected = GENESIS.to_string();
    for raw_line in bytes.split(|b| *b == b'\n') {
        if raw_line.is_empty() {
            continue; // tolerate a trailing newline
        }
        let mut rec: VerifiableRecord =
            serde_json::from_slice(raw_line).context("audit line is not valid JSON")?;
        if let Some(ref k) = key {
            let Some(claimed) = rec.hmac.take() else {
                return Ok(false);
            };
            let canonical = serde_json::to_string(&rec)
                .context("re-serialize audit record for hmac verification")?;
            // Constant-time MAC comparison on raw bytes — the hex strings
            // are only the serialized form.
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(k).expect("HMAC accepts any key length");
            mac.update(canonical.as_bytes());
            match hex_to_bytes(&claimed) {
                Some(bytes) if mac.verify_slice(&bytes).is_ok() => {}
                _ => return Ok(false),
            }
        }
        if rec.prev_hash != expected {
            return Ok(false);
        }
        expected = sha256_hex(raw_line);
    }
    Ok(true)
}

/// SHA-256 hex of the last non-empty line in `file` — used to resume the
/// chain on reopen. Reads only the tail (records are < 1 KiB each).
fn last_line_hash(file: &mut File) -> anyhow::Result<Option<String>> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let tail = len.min(64 * 1024);
    file.seek(SeekFrom::End(-(tail as i64)))?;
    let mut buf = vec![0u8; tail as usize];
    file.read_exact(&mut buf)?;
    // Drop a possibly-truncated leading partial line.
    let start = if tail < len {
        buf.iter()
            .position(|b| *b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(buf.len())
    } else {
        0
    };
    let last = buf[start..].split(|b| *b == b'\n').rfind(|l| !l.is_empty());
    file.seek(SeekFrom::End(0))?;
    Ok(last.map(sha256_hex))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.as_slice() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Derive a 32-byte HMAC key from a configured secret: SHA-256(secret).
fn derive_hmac_key(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).as_slice().to_vec()
}

/// Decode a lowercase hex string to bytes; `None` on odd length or
/// non-hex input. Verification-side helper for [`verify_hmac_at`].
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// HMAC-SHA256 over `data` using `key`, returned as a lowercase hex string.
fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut s = String::with_capacity(64);
    for b in bytes.as_slice() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Open `path` for append, creating it `0600` if missing — the shared
/// file-open behind [`AuditLog::open_with_retention`] and rotation.
fn open_append(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open audit log {}", path.display()))
}

/// The log's file stem (`audit` for `audit.jsonl`) — archive names and
/// pruning are both scoped to it.
fn stem_of(path: &Path) -> &str {
    path.file_stem().and_then(|s| s.to_str()).unwrap_or("audit")
}

/// Archive retention from [`RETENTION_ENV`]: unset or unparseable →
/// [`DEFAULT_RETENTION_DAYS`]; `0` → `None` (keep archives forever).
fn retention_from_env() -> Option<u64> {
    match std::env::var(RETENTION_ENV) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT_RETENTION_DAYS),
        },
        Err(_) => Some(DEFAULT_RETENTION_DAYS),
    }
}

/// UTC date of the first record in `path`, or `None` when the file is
/// absent, empty, or its first line has no parseable RFC 3339
/// `timestamp` (a corrupt head is left in place rather than archived
/// under a guessed date).
fn first_record_date(path: &Path) -> anyhow::Result<Option<NaiveDate>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    // Records are < 1 KiB; the first line always fits in 4 KiB.
    let mut buf = vec![0u8; 4096];
    let n = file
        .read(&mut buf)
        .with_context(|| format!("read {}", path.display()))?;
    let Some(line) = buf[..n].split(|b| *b == b'\n').find(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let Ok(rec) = serde_json::from_slice::<serde_json::Value>(line) else {
        return Ok(None);
    };
    Ok(rec
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.date_naive()))
}

/// Rename the finished live file `path` to `<stem>-YYYY-MM-DD.jsonl`
/// beside it. On collision (`-2`, `-3`, … suffixes) the archive is never
/// overwritten — a duplicated name means an operator restored files by
/// hand, and losing either copy is worse than an extra file.
fn rotate_file(path: &Path, date: NaiveDate) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("audit path has no UTF-8 stem")?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("jsonl");
    let date_s = date.format("%Y-%m-%d");
    let mut target = dir.join(format!("{stem}-{date_s}.{ext}"));
    let mut n = 2u32;
    while target.exists() {
        target = dir.join(format!("{stem}-{date_s}-{n}.{ext}"));
        n += 1;
    }
    fs::rename(path, &target).with_context(|| {
        format!(
            "rotate audit log {} -> {}",
            path.display(),
            target.display()
        )
    })?;
    set_mode(&target, 0o600)?; // already 0600; enforce on odd cases anyway
    Ok(())
}

/// `<stem>-YYYY-MM-DD[-N].jsonl` → its date, else `None`. The `[-N]`
/// suffix (rotation-collision escape hatch) is ignored for dating.
fn archive_date(name: &str, stem: &str) -> Option<NaiveDate> {
    let rest = name
        .strip_prefix(stem)?
        .strip_prefix('-')?
        .strip_suffix(".jsonl")?;
    NaiveDate::parse_from_str(rest.get(..10)?, "%Y-%m-%d").ok()
}

/// Delete date-named archive files under `dir` whose date is more than
/// `retention` days before `today`. `None` keeps everything. Unrelated
/// or unparseable filenames are never touched.
fn prune_archives(
    dir: &Path,
    today: NaiveDate,
    retention: Option<u64>,
    stem: &str,
) -> anyhow::Result<()> {
    let Some(days) = retention else { return Ok(()) };
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read dir {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(date) = archive_date(name, stem) else {
            continue;
        };
        if today.signed_duration_since(date).num_days() > days as i64 {
            fs::remove_file(entry.path())
                .with_context(|| format!("prune archive {}", entry.path().display()))?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn log_in(dir: &Path) -> AuditLog {
        AuditLog::open(&dir.join("logs").join("audit.jsonl")).expect("open audit log")
    }

    fn log_in_with_secret(dir: &Path, secret: &str) -> AuditLog {
        AuditLog::open(&dir.join("logs").join("audit.jsonl"))
            .expect("open audit log")
            .with_audit_secret(Some(secret.to_string()))
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_dir_0700_and_file_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in(tmp.path());
        assert_eq!(mode(log.path()), 0o600);
        assert_eq!(mode(log.path().parent().unwrap()), 0o700);
    }

    #[test]
    fn records_are_jsonl_with_required_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in(tmp.path());
        log.record(
            "system_command",
            "abc123",
            "ok",
            12,
            CallContext {
                key_id: Some("key1"),
                caller: Some("sess-1"),
                consent: None,
            },
            None,
        )
        .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(line["tool"], "system_command");
        assert_eq!(line["args_hash"], "abc123");
        assert_eq!(line["outcome"], "ok");
        assert_eq!(line["duration_ms"], 12);
        assert_eq!(line["key_id"], "key1");
        assert_eq!(line["caller"], "sess-1");
        assert_eq!(line["prev_hash"], GENESIS);
        // RFC3339 timestamp parses.
        chrono::DateTime::parse_from_rfc3339(line["timestamp"].as_str().unwrap()).unwrap();
    }

    #[test]
    fn raw_args_never_appear_in_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in(tmp.path());
        // The API takes only a hash — feed a hash of a secret-shaped arg and
        // confirm the raw secret isn't anywhere in the file. (Neutral tool
        // name: "system_command" itself contains the substring "command".)
        log.record("tool", "d34db33f", "ok", 1, CallContext::default(), None)
            .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        assert!(!content.contains("hunter2"));
        assert!(!content.contains("command"));
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        {
            let log = log_in(tmp.path());
            for i in 0..5 {
                log.record(
                    "tool",
                    &format!("h{i}"),
                    "ok",
                    i,
                    CallContext::default(),
                    None,
                )
                .unwrap();
            }
            assert!(log.verify_chain().unwrap());
        }
        // Tamper: flip a byte in the middle record.
        let mut content = fs::read_to_string(&path).unwrap();
        // Flip a byte inside the `"outcome"` value of the middle record —
        // +11 lands on the first char of `"ok"`, keeping the line valid
        // JSON while breaking the hash chain.
        let pos = content
            .lines()
            .nth(2)
            .map(|_| content.match_indices("\"outcome\"").nth(2).unwrap().0 + 11)
            .unwrap();
        let bytes = unsafe { content.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'x' { b'y' } else { b'x' };
        fs::write(&path, &content).unwrap();
        assert!(
            !verify_chain_at(&path).unwrap(),
            "tamper must break the chain"
        );
    }

    #[test]
    fn truncation_is_detectable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        {
            let log = log_in(tmp.path());
            for i in 0..3 {
                log.record(
                    "tool",
                    &format!("h{i}"),
                    "ok",
                    i,
                    CallContext::default(),
                    None,
                )
                .unwrap();
            }
        }
        // Drop the last line: chain still verifies for what remains, but a
        // verifier that knows the count catches it — and appending a forged
        // tail fails.
        let content = fs::read_to_string(&path).unwrap();
        let truncated: String = content.lines().take(2).map(|l| format!("{l}\n")).collect();
        fs::write(&path, &truncated).unwrap();
        assert!(verify_chain_at(&path).unwrap()); // prefix still self-consistent
        // Forge a replacement tail — prev_hash won't match.
        let bad_tail = format!(
            "{truncated}{{\"timestamp\":\"t\",\"tool\":\"x\",\"args_hash\":\"y\",\"outcome\":\"ok\",\"duration_ms\":0,\"key_id\":null,\"prev_hash\":\"{GENESIS}\"}}\n"
        );
        fs::write(&path, bad_tail).unwrap();
        assert!(!verify_chain_at(&path).unwrap());
    }

    #[test]
    fn reopen_resumes_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        {
            let log = log_in(tmp.path());
            log.record("a", "h1", "ok", 1, CallContext::default(), None)
                .unwrap();
        }
        {
            let log = log_in(tmp.path());
            log.record("b", "h2", "ok", 1, CallContext::default(), None)
                .unwrap();
            assert!(log.verify_chain().unwrap());
        }
        assert!(verify_chain_at(&path).unwrap());
        // Second record's prev_hash must be sha256 of the first line.
        let content = fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        let first = lines.next().unwrap();
        let second: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(second["prev_hash"], sha256_hex(first.as_bytes()));
    }

    #[test]
    fn consent_bypass_stamp_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in(tmp.path());
        log.record(
            "system_command",
            "h",
            "ok",
            1,
            CallContext {
                key_id: Some("k"),
                caller: Some("s"),
                consent: Some("bypassed"),
            },
            None,
        )
        .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["consent"], "bypassed");
        // Absent when not stamped.
        log.record("tool", "h", "ok", 1, CallContext::default(), None)
            .unwrap();
        let second: serde_json::Value = serde_json::from_str(
            fs::read_to_string(log.path())
                .unwrap()
                .lines()
                .nth(1)
                .unwrap(),
        )
        .unwrap();
        assert!(second.get("consent").is_none());
    }

    #[test]
    fn empty_log_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "").unwrap();
        assert!(verify_chain_at(&path).unwrap());
    }

    /// One hand-crafted JSONL record with a fixed RFC 3339 timestamp —
    /// used to seed "stale" live files without waiting a day.
    fn seeded_record(ts: &str, tool: &str) -> String {
        format!(
            "{{\"timestamp\":\"{ts}\",\"tool\":\"{tool}\",\"args_hash\":\"h\",\"outcome\":\"ok\",\"duration_ms\":1,\"key_id\":null,\"caller\":null,\"prev_hash\":\"{GENESIS}\"}}\n"
        )
    }

    #[test]
    fn stale_live_file_rotates_to_date_name_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        fs::write(
            &path,
            seeded_record("2020-03-04T10:00:00+00:00", "old_tool"),
        )
        .unwrap();

        // Retention `None`: a 2020 archive is far outside any day
        // window — it would be pruned the instant it is rotated.
        let log = AuditLog::open_with_retention(&path, None).unwrap();
        // The stale file was renamed under its record date; the live
        // path is a fresh file.
        assert!(dir.join("audit-2020-03-04.jsonl").is_file());
        assert_eq!(log.path(), path.as_path());
        log.record("new_tool", "h2", "ok", 1, CallContext::default(), None)
            .unwrap();

        // The archive keeps its original content and verifies
        // standalone; the new file chains from GENESIS.
        let archived = fs::read_to_string(dir.join("audit-2020-03-04.jsonl")).unwrap();
        assert!(archived.contains("old_tool"));
        assert!(verify_chain_at(&dir.join("audit-2020-03-04.jsonl")).unwrap());
        let live = fs::read_to_string(&path).unwrap();
        let rec: serde_json::Value = serde_json::from_str(live.trim()).unwrap();
        assert_eq!(rec["tool"], "new_tool");
        assert_eq!(rec["prev_hash"], GENESIS);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn rotation_name_collision_gets_numeric_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).unwrap();
        // A pre-existing archive for the same date forces the suffix.
        fs::write(dir.join("audit-2020-03-04.jsonl"), "prior archive\n").unwrap();
        let path = dir.join("audit.jsonl");
        fs::write(&path, seeded_record("2020-03-04T10:00:00+00:00", "old")).unwrap();

        // Retention None so the freshly-rotated archives aren't pruned.
        let _log = AuditLog::open_with_retention(&path, None).unwrap();
        assert!(dir.join("audit-2020-03-04.jsonl").is_file());
        assert!(dir.join("audit-2020-03-04-2.jsonl").is_file());
        assert_eq!(
            fs::read_to_string(dir.join("audit-2020-03-04.jsonl")).unwrap(),
            "prior archive\n"
        );
        assert!(
            fs::read_to_string(dir.join("audit-2020-03-04-2.jsonl"))
                .unwrap()
                .contains("old")
        );
    }

    #[test]
    fn archives_older_than_retention_are_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).unwrap();
        let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
        let recent = dir.join(format!("audit-{}.jsonl", yesterday.format("%Y-%m-%d")));
        fs::write(dir.join("audit-2000-01-01.jsonl"), "ancient\n").unwrap();
        fs::write(&recent, "recent\n").unwrap();
        // Unrelated files are never touched.
        fs::write(dir.join("other.log"), "keep me\n").unwrap();
        fs::write(dir.join("audit-notadate.jsonl"), "keep me\n").unwrap();

        let _log = AuditLog::open_with_retention(&dir.join("audit.jsonl"), Some(30)).unwrap();
        assert!(
            !dir.join("audit-2000-01-01.jsonl").exists(),
            "expired archive kept"
        );
        assert!(recent.is_file(), "in-window archive pruned");
        assert!(dir.join("other.log").is_file());
        assert!(dir.join("audit-notadate.jsonl").is_file());
    }

    #[test]
    fn retention_none_keeps_all_archives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audit-2000-01-01.jsonl"), "ancient\n").unwrap();
        let _log = AuditLog::open_with_retention(&dir.join("audit.jsonl"), None).unwrap();
        assert!(dir.join("audit-2000-01-01.jsonl").is_file());
    }

    #[test]
    fn same_day_reopen_does_not_rotate() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        let path = dir.join("audit.jsonl");
        {
            let log = AuditLog::open_with_retention(&path, Some(30)).unwrap();
            log.record("a", "h1", "ok", 1, CallContext::default(), None)
                .unwrap();
        }
        let log = AuditLog::open_with_retention(&path, Some(30)).unwrap();
        // No archive was created; the same-day file resumed its chain.
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .all(|e| e.unwrap().file_name().to_str().unwrap() == "audit.jsonl")
        );
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn hmac_absent_when_secret_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in(tmp.path());
        log.record("tool", "h1", "ok", 1, CallContext::default(), None)
            .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(line.get("hmac").is_none());
    }

    #[test]
    fn hmac_present_when_secret_set() {
        let tmp = tempfile::tempdir().unwrap();
        let log = log_in_with_secret(tmp.path(), "super-secret");
        log.record("tool", "h1", "ok", 1, CallContext::default(), None)
            .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        let hmac = line
            .get("hmac")
            .expect("hmac field must be present")
            .as_str()
            .unwrap();
        assert_eq!(hmac.len(), 64);
        assert!(hmac.chars().all(|c| c.is_ascii_hexdigit()));
        // The hmac must come after prev_hash in the serialized line.
        let prev_pos = content.find("prev_hash").unwrap();
        let hmac_pos = content.find("hmac").unwrap();
        assert!(hmac_pos > prev_pos);
    }

    #[test]
    fn verify_hmac_passes_with_correct_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        let log = AuditLog::open(&path)
            .unwrap()
            .with_audit_secret(Some("correct-secret".to_string()));
        for i in 0..3 {
            log.record(
                "tool",
                &format!("h{i}"),
                "ok",
                i,
                CallContext::default(),
                None,
            )
            .unwrap();
        }
        assert!(log.verify_chain().unwrap());
        assert!(verify_hmac_at(&path, Some("correct-secret")).unwrap());
        // Method form too.
        assert!(log.verify_hmac(Some("correct-secret")).unwrap());
    }

    #[test]
    fn verify_hmac_fails_with_wrong_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        let log = AuditLog::open(&path)
            .unwrap()
            .with_audit_secret(Some("correct-secret".to_string()));
        log.record("tool", "h1", "ok", 1, CallContext::default(), None)
            .unwrap();
        assert!(!verify_hmac_at(&path, Some("wrong-secret")).unwrap());
        assert!(!log.verify_hmac(Some("wrong-secret")).unwrap());
    }

    #[test]
    fn verify_hmac_fails_when_line_lacks_hmac() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap(); // no secret
        log.record("tool", "h1", "ok", 1, CallContext::default(), None)
            .unwrap();
        assert!(verify_hmac_at(&path, None).unwrap());
        // A verifier that supplies a secret sees a missing hmac as failure.
        assert!(!verify_hmac_at(&path, Some("any-secret")).unwrap());
    }

    #[test]
    fn chain_still_verifies_with_hmac_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        let log = AuditLog::open(&path)
            .unwrap()
            .with_audit_secret(Some("chain-secret".to_string()));
        for i in 0..4 {
            log.record(
                "tool",
                &format!("h{i}"),
                "ok",
                i,
                CallContext::default(),
                None,
            )
            .unwrap();
        }
        // Hash-chain verification ignores the hmac field entirely.
        assert!(log.verify_chain().unwrap());
        assert!(verify_chain_at(&path).unwrap());
        // prev_hash of record N must still be SHA-256 of the raw previous
        // line (which now includes the hmac).
        let content = fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        let first = lines.next().unwrap();
        let second: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(second["prev_hash"], sha256_hex(first.as_bytes()));
    }

    #[test]
    fn hmac_tampering_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("audit.jsonl");
        let log = AuditLog::open(&path)
            .unwrap()
            .with_audit_secret(Some("tamper-secret".to_string()));
        log.record("tool", "h1", "ok", 1, CallContext::default(), None)
            .unwrap();
        assert!(verify_hmac_at(&path, Some("tamper-secret")).unwrap());

        // Corrupt the hmac hex string in place.
        let mut content = fs::read_to_string(&path).unwrap();
        let hmac_start = content.find("\"hmac\":\"").unwrap() + 8;
        let bytes = unsafe { content.as_bytes_mut() };
        // Flip one hex digit in the hmac value.
        bytes[hmac_start] = if bytes[hmac_start] == b'0' {
            b'f'
        } else {
            b'0'
        };
        fs::write(&path, &content).unwrap();

        // Chain verification still passes because prev_hash hashes the
        // (now modified) raw line, but HMAC verification must fail.
        assert!(verify_chain_at(&path).unwrap());
        assert!(!verify_hmac_at(&path, Some("tamper-secret")).unwrap());
    }
}
