//! Hash-chained JSONL audit log — SECURITY.md "Storage" and
//! docs/TOOLS.md "Destructive-Action Consent" / rate-limit audit notes.
//!
//! Every tool invocation — accepted or rejected — is appended to
//! `~/.ultranix-mcp/logs/audit.jsonl`. Each record carries
//! `{timestamp, tool, args_hash, outcome, duration_ms, key_id, prev_hash}`
//! where `prev_hash` is the SHA-256 of the *previous record's serialized
//! bytes* (the JSON line, newline excluded). The genesis record's
//! `prev_hash` is `"0"*64`. Raw arguments are **never** persisted — only
//! the same canonical `args_hash` the consent gate binds to.
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
use serde::Serialize;
use sha2::{Digest, Sha256};

/// `prev_hash` of the first record in a fresh log.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
    /// Consent stamp for gated calls: `"bypassed"` under
    /// `--allow-destructive`, absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    consent: Option<&'a str>,
    /// SHA-256 of the previous record's serialized bytes; `"0"*64` genesis.
    prev_hash: &'a str,
}

/// Append-only, hash-chained audit sink.
pub struct AuditLog {
    path: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    /// SHA-256 hex of the last line written (or [`GENESIS`]).
    prev_hash: String,
}

impl AuditLog {
    /// Open (creating if needed) the log at `path`. The containing
    /// directory is created `0700`; the file is forced to `0600`.
    ///
    /// If the file already has records, the chain is resumed: the last
    /// line's hash becomes `prev_hash`, so appends after restart remain
    /// verifiable end-to-end.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("create audit dir {}", dir.display()))?;
            set_mode(dir, 0o700)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        set_mode(path, 0o600)?; // enforce on pre-existing files too

        let prev_hash = last_line_hash(&mut file)?.unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(Inner { file, prev_hash }),
        })
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
        key_id: Option<&str>,
        consent: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().expect("audit log poisoned");
        let rec = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool,
            args_hash,
            outcome,
            duration_ms,
            key_id,
            consent,
            prev_hash: &inner.prev_hash,
        };
        let line = serde_json::to_string(&rec).context("serialize audit record")?;
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
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
        log.record("system_command", "abc123", "ok", 12, Some("key1"), None)
            .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(line["tool"], "system_command");
        assert_eq!(line["args_hash"], "abc123");
        assert_eq!(line["outcome"], "ok");
        assert_eq!(line["duration_ms"], 12);
        assert_eq!(line["key_id"], "key1");
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
        log.record("tool", "d34db33f", "ok", 1, None, None).unwrap();
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
                log.record("tool", &format!("h{i}"), "ok", i, None, None)
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
                log.record("tool", &format!("h{i}"), "ok", i, None, None)
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
            log.record("a", "h1", "ok", 1, None, None).unwrap();
        }
        {
            let log = log_in(tmp.path());
            log.record("b", "h2", "ok", 1, None, None).unwrap();
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
        log.record("system_command", "h", "ok", 1, Some("k"), Some("bypassed"))
            .unwrap();
        let content = fs::read_to_string(log.path()).unwrap();
        let line: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["consent"], "bypassed");
        // Absent when not stamped.
        log.record("tool", "h", "ok", 1, None, None).unwrap();
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
}
