//! API-key authentication for the streamable-HTTP transport —
//! docs/API_KEY_MANAGEMENT.md and SECURITY.md "Request pipeline" layer 1.
//!
//! Keys are `uxcp_<64 lowercase hex>` — 32 CSPRNG bytes (256 bits of
//! entropy). Only SHA-256 digests are held in memory; presented
//! credentials are hashed and compared in constant time, and no
//! plaintext key is ever logged or persisted. The `key_id` — the first
//! 8 hex chars of the SHA-256 digest — is the only identifier that may
//! appear in logs and audit records.
//!
//! Sourcing precedence (first *configured* source wins; a shadowed
//! lower-precedence source is warned about):
//!
//! 1. `ULTRANIX_MCP_API_KEY` — single key or comma-separated list, with
//!    optional positionally-aligned `ULTRANIX_MCP_API_KEY_EXPIRES`
//!    (RFC 3339 timestamps, empty entries = no expiry).
//! 2. `ULTRANIX_MCP_API_KEY_FILE` — path to a key file; mode `0600`
//!    enforced — a group/world-readable file refuses to load.
//! 3. `<state_root>/api-keys/*.json` — convention fallback; same `0600`
//!    requirement per file.
//!
//! Key files accept either JSON — a single record object or an array of
//! `{"key": "uxcp_…", "key_id"?: "…", "expires_at"?: "<RFC 3339>",
//! "scopes"?: ["…"]}` — or a line format of
//! `key [expires=<RFC 3339>] [key_id=<id>] [scopes=a,b]` with `#`
//! comments and blank lines allowed.
//!
//! Failure posture is fail-closed: with [`AuthMode::Required`] and no
//! configured keys every request is rejected — there is no bootstrap or
//! dev key, ever. `ULTRANIX_MCP_DISABLE_AUTH=true` is the single escape
//! hatch ([`AuthMode::Disabled`]) and is for loopback development only;
//! enabling it prints a loud stderr warning on every boot.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::state::StateDir;

/// Fixed key prefix — "ultranix control plane" (API_KEY_MANAGEMENT.md §1).
pub const KEY_PREFIX: &str = "uxcp_";
/// Hex characters after the prefix: 32 CSPRNG bytes → 64 lowercase hex.
pub const KEY_HEX_LEN: usize = 64;

/// Single key or comma-separated list (rotation overlap), env source.
pub const ENV_API_KEY: &str = "ULTRANIX_MCP_API_KEY";
/// Positionally-aligned RFC 3339 expiry list for [`ENV_API_KEY`].
pub const ENV_API_KEY_EXPIRES: &str = "ULTRANIX_MCP_API_KEY_EXPIRES";
/// Path to a key file (mode `0600` enforced).
pub const ENV_API_KEY_FILE: &str = "ULTRANIX_MCP_API_KEY_FILE";
/// Dev escape hatch: `=true` disables HTTP auth entirely.
pub const ENV_DISABLE_AUTH: &str = "ULTRANIX_MCP_DISABLE_AUTH";
/// Convention key directory under the state root (API_KEY_MANAGEMENT.md §3).
pub const KEY_DIR_NAME: &str = "api-keys";

/// Whether HTTP requests must present a valid `uxcp_*` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// A valid key is required on every HTTP request.
    Required,
    /// `ULTRANIX_MCP_DISABLE_AUTH=true` — every request passes. Loopback
    /// development only: anyone who can reach `:3010` controls the
    /// session's mouse and keyboard.
    Disabled,
}

/// Identity of an authenticated caller. Contains no key material — only
/// the `key_id` (first 8 hex chars of SHA-256(key)) which is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    /// Rate-limit/audit identity of the presenting key. `None` only under
    /// [`AuthMode::Disabled`] — the middleware should then fall back to
    /// the remote socket address (API_KEY_MANAGEMENT.md §5).
    pub key_id: Option<String>,
    /// Scopes declared by the key record; empty means unrestricted.
    pub scopes: Vec<String>,
}

/// Why a request failed authentication — distinct enough for the
/// `auth.failure{reason}` / `auth.expired_key` audit split
/// (API_KEY_MANAGEMENT.md §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    /// Neither credential carried a usable token.
    Missing,
    /// A credential was present but not `uxcp_<64 lowercase hex>`.
    Malformed,
    /// Valid format, but the key is not configured.
    Unknown,
    /// Valid, configured key presented past its `expires_at`.
    Expired {
        /// The expired key's `key_id` — safe to log.
        key_id: String,
        /// The expiry that was exceeded.
        expires_at: DateTime<Utc>,
    },
}

impl AuthFailure {
    /// `reason` string for `auth.failure` audit records.
    /// [`AuthFailure::Expired`] maps to the distinct `auth.expired_key`
    /// event rather than a generic failure reason.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Unknown => "unknown",
            Self::Expired { .. } => "expired_key",
        }
    }
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "no API key presented"),
            Self::Malformed => write!(f, "presented credential is not a uxcp_ key"),
            Self::Unknown => write!(f, "presented key is not configured"),
            Self::Expired { key_id, expires_at } => {
                write!(f, "key {key_id} expired at {expires_at}")
            }
        }
    }
}

/// Result of [`ApiKeyStore::rotate`]: the new plaintext key plus the
/// overlap window stamped on the retired keys.
#[derive(Debug, Clone)]
pub struct RotationResult {
    /// The freshly generated plaintext key — the only place plaintext
    /// key material leaves the store. Show it once, then discard.
    pub new_key: String,
    /// `key_id` of the new key (safe to log).
    pub new_key_id: String,
    /// Expiry stamped on every previously-held key — the end of the
    /// zero-downtime overlap window.
    pub old_keys_expire_at: DateTime<Utc>,
}

/// A key record as loaded from configuration, before hashing.
struct RawRecord {
    key: String,
    /// `key_id` declared in the record; validated against the computed
    /// value and overridden on mismatch.
    declared_key_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
}

/// What the store actually keeps: the digest, never the plaintext.
#[derive(Debug)]
struct StoredKey {
    /// SHA-256 of the key string.
    hash: [u8; 32],
    /// First 8 hex chars of `hash`.
    key_id: String,
    expires_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
}

/// The on-disk JSON record shape — a single object or an array of these.
#[derive(Debug, Deserialize)]
struct JsonKeyRecord {
    key: String,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

/// Loaded API-key set for the HTTP transport. Build once at startup via
/// [`ApiKeyStore::from_env`] (or [`ApiKeyStore::load`] with an injected
/// env lookup for tests); share across the request path. `Send + Sync`.
#[derive(Debug)]
pub struct ApiKeyStore {
    mode: AuthMode,
    /// Includes expired-but-loaded records — they still produce the
    /// distinct `auth.expired_key` failure rather than `unknown`.
    keys: Vec<StoredKey>,
}

impl ApiKeyStore {
    /// Load from the real process environment, resolving the convention
    /// key dir under [`StateDir::resolve_root`].
    ///
    /// Errors are hard startup failures (unreadable key file, loose
    /// permissions, malformed JSON) — the caller should refuse to bind
    /// the HTTP listener. An empty-but-valid load is *not* an error:
    /// fail-closed rejection happens per-request in [`Self::authenticate`].
    pub fn from_env() -> anyhow::Result<Self> {
        let get = |k: &str| std::env::var_os(k);
        let root = StateDir::resolve_root(get);
        Self::load(get, &root)
    }

    /// The testable core: resolve sources through `get` and scan
    /// `<state_root>/api-keys/*.json`. See module docs for precedence.
    pub fn load(get: impl Fn(&str) -> Option<OsString>, state_root: &Path) -> anyhow::Result<Self> {
        let non_empty = |key: &str| get(key).filter(|v| !v.is_empty());

        let mode = match non_empty(ENV_DISABLE_AUTH) {
            Some(v) if is_truthy(&v) => AuthMode::Disabled,
            _ => AuthMode::Required,
        };
        if mode == AuthMode::Disabled {
            // Spec demands a loud stderr warning, not just tracing — the
            // harness may not have initialized a subscriber yet.
            eprintln!(
                "*** ultranix-mcp: {ENV_DISABLE_AUTH} is set — HTTP API-key auth is DISABLED. \
                 Anyone who can reach the HTTP listener can drive this desktop. \
                 Loopback development only. ***"
            );
            tracing::warn!("auth.disabled: {ENV_DISABLE_AUTH} set — HTTP auth off (dev hatch)");
        }

        let key_dir = state_root.join(KEY_DIR_NAME);
        let env_val = non_empty(ENV_API_KEY);
        let file_val = non_empty(ENV_API_KEY_FILE).map(PathBuf::from);
        let dir_present = dir_has_json(&key_dir);

        let raw: Vec<RawRecord> = if let Some(v) = env_val {
            if file_val.is_some() || dir_present {
                tracing::warn!(
                    "config.key.shadowed: {ENV_API_KEY} set — \
                     {ENV_API_KEY_FILE} and {} are ignored",
                    key_dir.display()
                );
            }
            let expires = non_empty(ENV_API_KEY_EXPIRES).map(|v| v.to_string_lossy().into_owned());
            parse_env_records(&v.to_string_lossy(), expires.as_deref())
        } else if let Some(path) = file_val {
            if dir_present {
                tracing::warn!(
                    "config.key.shadowed: {ENV_API_KEY_FILE} set — {} is ignored",
                    key_dir.display()
                );
            }
            load_key_file(&path)?
        } else if dir_present {
            load_key_dir(&key_dir)?
        } else {
            Vec::new()
        };

        let keys = records_to_keys(raw);
        let now = Utc::now();
        let (active, expired): (Vec<&StoredKey>, Vec<&StoredKey>) = keys
            .iter()
            .partition(|k| k.expires_at.is_none_or(|e| e > now));
        tracing::info!(
            active = active.len(),
            expired_loaded = expired.len(),
            key_ids = ?active.iter().map(|k| k.key_id.as_str()).collect::<Vec<_>>(),
            "auth.keys.loaded"
        );
        if mode == AuthMode::Required && active.is_empty() {
            tracing::warn!(
                "no active API keys configured — HTTP transport will reject \
                 every request (fail closed); set {ENV_API_KEY} or generate \
                 a key with `ultranix-mcp keygen`"
            );
        }
        Ok(Self { mode, keys })
    }

    /// The resolved auth posture for this process.
    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    /// `true` under [`AuthMode::Disabled`] — the dev escape hatch.
    pub fn is_disabled(&self) -> bool {
        self.mode == AuthMode::Disabled
    }

    /// Total key records held, including expired-but-loaded ones.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// No key records at all (active or expired).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `key_id`s of the currently valid keys — for the `auth.keys.loaded`
    /// audit event. Safe to log: these are hash prefixes, not key material.
    pub fn active_key_ids(&self) -> Vec<String> {
        let now = Utc::now();
        self.keys
            .iter()
            .filter(|k| k.expires_at.is_none_or(|e| e > now))
            .map(|k| k.key_id.clone())
            .collect()
    }

    /// `key_id`s of expired-but-loaded keys — reported separately by
    /// `auth.keys.loaded` (API_KEY_MANAGEMENT.md §6).
    pub fn expired_key_ids(&self) -> Vec<String> {
        let now = Utc::now();
        self.keys
            .iter()
            .filter(|k| k.expires_at.is_some_and(|e| e <= now))
            .map(|k| k.key_id.clone())
            .collect()
    }

    /// Authenticate one HTTP request. `header_key` is the `X-API-Key`
    /// header value (canonical); `bearer` is the `Authorization` header
    /// value — either the raw `Bearer <token>` form (case-insensitive
    /// scheme) or the bare token. A non-empty `header_key` wins when both
    /// are present. Returns `Some(identity)` on success, `None` on any
    /// failure — use [`Self::authenticate_verbose`] when the caller needs
    /// the failure reason for `auth.failure`/`auth.expired_key` audits.
    ///
    /// Under [`AuthMode::Disabled`] every request succeeds with
    /// `key_id: None`.
    pub fn authenticate(
        &self,
        header_key: Option<&str>,
        bearer: Option<&str>,
    ) -> Option<KeyIdentity> {
        self.authenticate_verbose(header_key, bearer).ok()
    }

    /// [`Self::authenticate`] with the failure reason preserved.
    pub fn authenticate_verbose(
        &self,
        header_key: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<KeyIdentity, AuthFailure> {
        if self.mode == AuthMode::Disabled {
            return Ok(KeyIdentity {
                key_id: None,
                scopes: Vec::new(),
            });
        }
        let presented = extract_credential(header_key, bearer).ok_or(AuthFailure::Missing)?;
        if !is_valid_key(presented) {
            return Err(AuthFailure::Malformed);
        }
        let hash = sha256_bytes(presented.as_bytes());
        // No early exit: the scan runs over the whole key set so match
        // position doesn't leak through timing.
        let mut found: Option<&StoredKey> = None;
        for k in &self.keys {
            if ct_eq(&hash, &k.hash) {
                found = Some(k);
            }
        }
        match found {
            Some(k) => {
                if let Some(expires_at) = k.expires_at
                    && expires_at <= Utc::now()
                {
                    return Err(AuthFailure::Expired {
                        key_id: k.key_id.clone(),
                        expires_at,
                    });
                }
                Ok(KeyIdentity {
                    key_id: Some(k.key_id.clone()),
                    scopes: k.scopes.clone(),
                })
            }
            None => Err(AuthFailure::Unknown),
        }
    }

    /// Rotate: generate a fresh key, append it (no expiry), and stamp
    /// `now + grace` as the expiry on every previously-held key so they
    /// self-revoke at the end of the overlap window. A key that already
    /// expires sooner keeps its earlier expiry.
    pub fn rotate(&mut self, grace: Duration) -> RotationResult {
        let delta = chrono::TimeDelta::from_std(grace).unwrap_or(chrono::TimeDelta::MAX);
        let retire_at = Utc::now()
            .checked_add_signed(delta)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        for k in &mut self.keys {
            k.expires_at = Some(k.expires_at.map_or(retire_at, |e| e.min(retire_at)));
        }
        let new_key = keygen();
        let new_key_id = key_id(&new_key);
        self.keys.push(StoredKey {
            hash: sha256_bytes(new_key.as_bytes()),
            key_id: new_key_id.clone(),
            expires_at: None,
            scopes: Vec::new(),
        });
        RotationResult {
            new_key,
            new_key_id,
            old_keys_expire_at: retire_at,
        }
    }
}

/// Generate a fresh `uxcp_<64 lowercase hex>` key — 32 bytes from the OS
/// CSPRNG (256 bits). For the `ultranix-mcp keygen` CLI subcommand; the
/// equivalent shell is `echo "uxcp_$(openssl rand -hex 32)"`
/// (API_KEY_MANAGEMENT.md §2).
pub fn keygen() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    format!("{KEY_PREFIX}{}", hex_lower(&bytes))
}

/// The public identity of a key: first 8 hex chars of `SHA-256(key)`
/// (API_KEY_MANAGEMENT.md §5). Safe to log and audit; the same value is
/// used as the rate-limit bucket identity.
pub fn key_id(key: &str) -> String {
    hex_lower(&sha256_bytes(key.as_bytes()))[..8].to_string()
}

/// Format check: `^uxcp_[0-9a-f]{64}$`. Format validity says nothing
/// about whether the key is configured — that is what
/// [`ApiKeyStore::authenticate`] is for.
pub fn is_valid_key(key: &str) -> bool {
    let Some(hex) = key.strip_prefix(KEY_PREFIX) else {
        return false;
    };
    hex.len() == KEY_HEX_LEN
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b <= b'f')
}

/// Pick the presented credential: `X-API-Key` wins iff non-empty;
/// otherwise the `Authorization` value with a case-insensitive
/// `Bearer ` scheme prefix stripped (a bare token is also accepted so
/// the middleware may pass either form).
fn extract_credential<'a>(header_key: Option<&'a str>, bearer: Option<&'a str>) -> Option<&'a str> {
    if let Some(k) = header_key.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(k);
    }
    let b = bearer?.trim();
    // Strip a `Bearer` scheme (case-insensitive) only when it stands
    // alone or is followed by whitespace — `bearerxyz` is a (malformed)
    // token, not a scheme. A scheme with no token after it is `Missing`.
    let token = match b.get(..6) {
        Some(scheme) if scheme.eq_ignore_ascii_case("bearer") => {
            let rest = b.get(6..).unwrap_or("");
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                rest.trim()
            } else {
                b
            }
        }
        _ => b,
    };
    if token.is_empty() { None } else { Some(token) }
}

/// `ULTRANIX_MCP_DISABLE_AUTH` truthiness: `true` (any case) or `1`.
fn is_truthy(v: &OsString) -> bool {
    let s = v.to_string_lossy();
    let s = s.trim();
    s.eq_ignore_ascii_case("true") || s == "1"
}

/// `key1,key2` env list + positionally-aligned `expires` list.
fn parse_env_records(list: &str, expires_list: Option<&str>) -> Vec<RawRecord> {
    let expires: Vec<Option<DateTime<Utc>>> = expires_list
        .map(|l| {
            l.split(',')
                .map(|e| {
                    let e = e.trim();
                    if e.is_empty() {
                        None
                    } else {
                        match parse_rfc3339(e) {
                            Some(t) => Some(t),
                            None => {
                                tracing::warn!(
                                    "{ENV_API_KEY_EXPIRES}: entry {e:?} is not RFC 3339 — \
                                     treated as no expiry"
                                );
                                None
                            }
                        }
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    list.split(',')
        .enumerate()
        .filter(|(_, k)| !k.trim().is_empty())
        .map(|(i, k)| RawRecord {
            key: k.trim().to_string(),
            declared_key_id: None,
            expires_at: expires.get(i).copied().flatten(),
            scopes: Vec::new(),
        })
        .collect()
}

/// Read and parse one key file. Mode `0600` (or stricter — anything
/// without group/other bits) is enforced before reading: a
/// group/world-readable key file is a hard startup failure per
/// API_KEY_MANAGEMENT.md §3.
fn load_key_file(path: &Path) -> anyhow::Result<Vec<RawRecord>> {
    enforce_private_file(path)?;
    let content =
        fs::read_to_string(path).with_context(|| format!("read key file {}", path.display()))?;
    parse_key_records(&content, path)
}

/// Scan `<dir>/*.json` (sorted for deterministic order), enforcing
/// `0600` on each file. Non-`.json` entries are ignored.
fn load_key_dir(dir: &Path) -> anyhow::Result<Vec<RawRecord>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read key dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for f in files {
        out.extend(load_key_file(&f)?);
    }
    Ok(out)
}

/// Does `<dir>` exist and contain at least one `*.json` entry? Used for
/// precedence and `config.key.shadowed` detection without parsing.
fn dir_has_json(dir: &Path) -> bool {
    fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok()).any(|e| {
                e.path().is_file() && e.path().extension().and_then(|x| x.to_str()) == Some("json")
            })
        })
        .unwrap_or(false)
}

/// Dispatch on content shape: `{`/`[` → JSON record(s); otherwise the
/// line format.
fn parse_key_records(content: &str, source: &Path) -> anyhow::Result<Vec<RawRecord>> {
    let t = content.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        parse_json_records(t, source)
    } else {
        Ok(parse_line_records(content, source))
    }
}

/// JSON key file: a single record object or an array of records.
fn parse_json_records(content: &str, source: &Path) -> anyhow::Result<Vec<RawRecord>> {
    let value: serde_json::Value = serde_json::from_str(content)
        .with_context(|| format!("parse key file {}", source.display()))?;
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => bail!(
            "{}: key file must be a JSON object or array of records",
            source.display()
        ),
    };
    items
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            let r: JsonKeyRecord = serde_json::from_value(v).with_context(|| {
                format!(
                    "{}: record #{i} is not a valid key record",
                    source.display()
                )
            })?;
            let expires_at = match &r.expires_at {
                Some(s) => Some(parse_rfc3339(s).with_context(|| {
                    format!(
                        "{}: record #{i} expires_at is not RFC 3339",
                        source.display()
                    )
                })?),
                None => None,
            };
            Ok(RawRecord {
                key: r.key,
                declared_key_id: r.key_id,
                expires_at,
                scopes: r.scopes.unwrap_or_default(),
            })
        })
        .collect()
}

/// Line key format: `key [expires=<RFC 3339>] [key_id=<id>]
/// [scopes=a,b]` per line; blank lines and `#` comments skipped.
fn parse_line_records(content: &str, source: &Path) -> Vec<RawRecord> {
    let mut out = Vec::new();
    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut rec = RawRecord {
            key: fields.next().unwrap_or_default().to_string(),
            declared_key_id: None,
            expires_at: None,
            scopes: Vec::new(),
        };
        for tok in fields {
            match tok.split_once('=') {
                Some(("expires", v)) => match parse_rfc3339(v) {
                    Some(t) => rec.expires_at = Some(t),
                    None => tracing::warn!(
                        "{}:{}: bad expires= timestamp {v:?} — treated as no expiry",
                        source.display(),
                        lineno + 1
                    ),
                },
                Some(("key_id", v)) => rec.declared_key_id = Some(v.to_string()),
                Some(("scopes", v)) => {
                    rec.scopes = v
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                _ => tracing::warn!(
                    "{}:{}: unrecognized key-record field {tok:?} ignored",
                    source.display(),
                    lineno + 1
                ),
            }
        }
        out.push(rec);
    }
    out
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|d| d.with_timezone(&Utc))
        .ok()
}

/// Validate format, dedup, hash, and fold declared metadata into the
/// in-memory key set. Malformed entries are skipped with a warning — a
/// bad line must not silently widen the accepted set, but one typo
/// should not discard the other keys either.
fn records_to_keys(records: Vec<RawRecord>) -> Vec<StoredKey> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut out = Vec::new();
    for r in records {
        let key = r.key.trim();
        if !is_valid_key(key) {
            tracing::warn!("auth.keys.load: skipping malformed key entry (bad format)");
            continue;
        }
        let hash = sha256_bytes(key.as_bytes());
        if !seen.insert(hash) {
            tracing::warn!(
                key_id = %key_id(key),
                "auth.keys.load: duplicate key ignored"
            );
            continue;
        }
        let computed = key_id(key);
        if let Some(declared) = &r.declared_key_id
            && declared != &computed
        {
            tracing::warn!(
                declared = %declared,
                computed = %computed,
                "auth.keys.load: record key_id mismatch — using computed id"
            );
        }
        out.push(StoredKey {
            hash,
            key_id: computed,
            expires_at: r.expires_at,
            scopes: r.scopes,
        });
    }
    out
}

/// SHA-256 of a presented/stored key — the only form held in memory.
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Constant-time equality over fixed-length digests: XOR-fold with no
/// early exit, so neither match position nor prefix length leaks through
/// timing. (No `subtle` dep — documented per the security design; the
/// inputs are always exactly 32-byte SHA-256 digests.)
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Refuse to read a credential file whose mode grants group/other any
/// bits — the shared `0600` rule reused by `history.key` (S-8).
#[cfg(unix)]
pub(crate) fn enforce_private_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .with_context(|| format!("stat key file {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "key file {} is group/world-readable (mode {mode:04o}) — \
             chmod 0600 required, refusing to load",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn enforce_private_file(_path: &Path) -> anyhow::Result<()> {
    // No portable mode bits — Linux-only crate, kept for check builds.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    /// Env mutation is process-global: serialize tests that touch
    /// `std::env` through this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(v)))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    /// A valid-format deterministic test key (`uxcp_` + 64 hex of `n`).
    fn test_key(n: u64) -> String {
        format!("uxcp_{n:064x}")
    }

    #[cfg(unix)]
    fn write_file(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn load_with(pairs: &[(&str, &str)], root: &Path) -> ApiKeyStore {
        ApiKeyStore::load(fake_env(pairs), root).expect("load")
    }

    // --- key shape ---

    #[test]
    fn keygen_produces_valid_unique_keys() {
        let a = keygen();
        let b = keygen();
        assert!(is_valid_key(&a));
        assert!(is_valid_key(&b));
        assert_ne!(a, b);
        assert_eq!(a.len(), 5 + 64);
    }

    #[test]
    fn format_validation_is_strict() {
        assert!(is_valid_key(&test_key(0xabc)));
        assert!(is_valid_key(&format!("uxcp_{}", "f".repeat(64))));
        for bad in [
            "",
            "uxcp_",
            "nope",
            &format!("uxcp_{}", "f".repeat(63)),  // short
            &format!("uxcp_{}", "f".repeat(65)),  // long
            &format!("uxcp_{}", "F".repeat(64)),  // uppercase hex
            &format!("UXCP_{}", "f".repeat(64)),  // uppercase prefix
            &format!("uxcp_{} ", "f".repeat(64)), // trailing space
            &format!("uxcp_{}g", "f".repeat(63)), // non-hex char
        ] {
            assert!(!is_valid_key(bad), "accepted bad key: {bad:?}");
        }
    }

    #[test]
    fn key_id_is_first_8_of_sha256_hex() {
        let key = test_key(1);
        let expected: String = hex_lower(&Sha256::digest(key.as_bytes()))[..8].to_string();
        assert_eq!(key_id(&key), expected);
        assert_eq!(key_id(&key).len(), 8);
        assert_ne!(key_id(&test_key(1)), key_id(&test_key(2)));
    }

    // --- sourcing & precedence ---

    #[test]
    fn env_source_authenticates_via_x_api_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(&[(ENV_API_KEY, &test_key(1))], tmp.path());
        assert_eq!(store.mode(), AuthMode::Required);
        let id = store
            .authenticate(Some(&test_key(1)), None)
            .expect("valid key authenticates");
        assert_eq!(id.key_id.as_deref(), Some(key_id(&test_key(1)).as_str()));
    }

    #[test]
    fn env_source_supports_comma_separated_overlap() {
        let tmp = tempfile::tempdir().unwrap();
        let list = format!(" {}, {} ", test_key(1), test_key(2));
        let store = load_with(&[(ENV_API_KEY, &list)], tmp.path());
        assert_eq!(store.len(), 2);
        assert!(store.authenticate(Some(&test_key(1)), None).is_some());
        assert!(store.authenticate(Some(&test_key(2)), None).is_some());
        assert!(store.authenticate(Some(&test_key(3)), None).is_none());
    }

    #[test]
    fn env_beats_file_and_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let keyfile = tmp.path().join("keys.txt");
        write_file(&keyfile, &format!("{}\n", test_key(2)), 0o600);
        let dir = tmp.path().join(KEY_DIR_NAME);
        fs::create_dir_all(&dir).unwrap();
        write_file(
            &dir.join("k.json"),
            &format!("{{\"key\":\"{}\"}}", test_key(3)),
            0o600,
        );
        let kf = keyfile.to_string_lossy().into_owned();
        let store = load_with(
            &[(ENV_API_KEY, &test_key(1)), (ENV_API_KEY_FILE, &kf)],
            tmp.path(),
        );
        // Only the env key works — lower-precedence sources are shadowed.
        assert!(store.authenticate(Some(&test_key(1)), None).is_some());
        assert!(store.authenticate(Some(&test_key(2)), None).is_none());
        assert!(store.authenticate(Some(&test_key(3)), None).is_none());
    }

    #[test]
    fn file_beats_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let keyfile = tmp.path().join("keys.txt");
        write_file(&keyfile, &format!("{}\n", test_key(2)), 0o600);
        let dir = tmp.path().join(KEY_DIR_NAME);
        fs::create_dir_all(&dir).unwrap();
        write_file(
            &dir.join("k.json"),
            &format!("{{\"key\":\"{}\"}}", test_key(3)),
            0o600,
        );
        let kf = keyfile.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &kf)], tmp.path());
        assert!(store.authenticate(Some(&test_key(2)), None).is_some());
        assert!(store.authenticate(Some(&test_key(3)), None).is_none());
    }

    #[test]
    fn dir_scan_is_the_convention_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(KEY_DIR_NAME);
        fs::create_dir_all(&dir).unwrap();
        write_file(
            &dir.join("a.json"),
            &format!("{{\"key\":\"{}\"}}", test_key(4)),
            0o600,
        );
        write_file(
            &dir.join("b.json"),
            &format!(
                "[{{\"key\":\"{}\"}},{{\"key\":\"{}\"}}]",
                test_key(5),
                test_key(6)
            ),
            0o600,
        );
        // Non-.json entries are ignored, not errors.
        write_file(&dir.join("notes.txt"), "uxcp_not_a_key", 0o644);
        let store = load_with(&[], tmp.path());
        for n in [4u64, 5, 6] {
            assert!(store.authenticate(Some(&test_key(n)), None).is_some());
        }
        assert!(store.authenticate(Some(&test_key(7)), None).is_none());
    }

    #[test]
    fn configured_but_garbage_env_still_wins_and_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let keyfile = tmp.path().join("keys.txt");
        write_file(&keyfile, &format!("{}\n", test_key(2)), 0o600);
        let kf = keyfile.to_string_lossy().into_owned();
        // Env set to garbage: it is the winning source, yields zero keys,
        // and must NOT silently fall through to the file key.
        let store = load_with(
            &[(ENV_API_KEY, "not-a-key"), (ENV_API_KEY_FILE, &kf)],
            tmp.path(),
        );
        assert!(store.is_empty());
        assert!(store.authenticate(Some(&test_key(2)), None).is_none());
    }

    // --- key file formats ---

    #[test]
    fn file_json_single_and_array_records() {
        let tmp = tempfile::tempdir().unwrap();
        let single = tmp.path().join("one.json");
        write_file(&single, &format!("{{\"key\":\"{}\"}}", test_key(10)), 0o600);
        let p = single.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        assert!(store.authenticate(Some(&test_key(10)), None).is_some());

        let arr = tmp.path().join("many.json");
        write_file(
            &arr,
            &format!(
                "[{{\"key\":\"{}\",\"scopes\":[\"read\"]}},{{\"key\":\"{}\"}}]",
                test_key(11),
                test_key(12)
            ),
            0o600,
        );
        let p = arr.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        let id = store.authenticate(Some(&test_key(11)), None).unwrap();
        assert_eq!(id.scopes, vec!["read".to_string()]);
        assert!(store.authenticate(Some(&test_key(12)), None).is_some());
    }

    #[test]
    fn file_line_format_with_expires_and_scopes() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("keys.txt");
        write_file(
            &f,
            &format!(
                "# comment\n\n{} expires=2999-01-01T00:00:00Z scopes=read,write key_id=whatever\n{}\n",
                test_key(20),
                test_key(21)
            ),
            0o600,
        );
        let p = f.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        let id = store.authenticate(Some(&test_key(20)), None).unwrap();
        assert_eq!(id.scopes, vec!["read".to_string(), "write".to_string()]);
        assert!(store.authenticate(Some(&test_key(21)), None).is_some());
    }

    #[test]
    fn declared_key_id_mismatch_uses_computed() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("k.json");
        write_file(
            &f,
            &format!("{{\"key\":\"{}\",\"key_id\":\"deadbeef\"}}", test_key(30)),
            0o600,
        );
        let p = f.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        let id = store.authenticate(Some(&test_key(30)), None).unwrap();
        // The computed id wins over the (wrong) declared one.
        assert_eq!(id.key_id.as_deref(), Some(key_id(&test_key(30)).as_str()));
        assert_ne!(id.key_id.as_deref(), Some("deadbeef"));
    }

    // --- 0600 enforcement ---

    #[test]
    #[cfg(unix)]
    fn group_or_world_readable_key_file_refuses_to_load() {
        let tmp = tempfile::tempdir().unwrap();
        for mode in [0o644u32, 0o640, 0o604, 0o777] {
            let f = tmp.path().join(format!("k{mode:o}.txt"));
            write_file(&f, &format!("{}\n", test_key(40)), mode);
            let p = f.to_string_lossy().into_owned();
            assert!(
                ApiKeyStore::load(fake_env(&[(ENV_API_KEY_FILE, &p)]), tmp.path()).is_err(),
                "mode {mode:o} must be refused"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn owner_only_key_file_modes_load() {
        let tmp = tempfile::tempdir().unwrap();
        for mode in [0o600u32, 0o400] {
            let f = tmp.path().join(format!("k{mode:o}.txt"));
            write_file(&f, &format!("{}\n", test_key(41)), mode);
            let p = f.to_string_lossy().into_owned();
            let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
            assert!(store.authenticate(Some(&test_key(41)), None).is_some());
        }
    }

    #[test]
    #[cfg(unix)]
    fn loose_file_in_convention_dir_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(KEY_DIR_NAME);
        fs::create_dir_all(&dir).unwrap();
        write_file(
            &dir.join("k.json"),
            &format!("{{\"key\":\"{}\"}}", test_key(42)),
            0o644,
        );
        assert!(ApiKeyStore::load(fake_env(&[]), tmp.path()).is_err());
    }

    // --- expiry ---

    #[test]
    fn expired_key_is_rejected_with_distinct_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("keys.txt");
        write_file(
            &f,
            &format!(
                "{} expires=2020-01-01T00:00:00Z\n{}\n",
                test_key(50),
                test_key(51)
            ),
            0o600,
        );
        let p = f.to_string_lossy().into_owned();
        let store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        match store.authenticate_verbose(Some(&test_key(50)), None) {
            Err(AuthFailure::Expired { key_id, expires_at }) => {
                assert_eq!(key_id, super::key_id(&test_key(50)));
                assert_eq!(expires_at.to_rfc3339(), "2020-01-01T00:00:00+00:00");
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        assert!(store.authenticate(Some(&test_key(50)), None).is_none());
        assert!(store.authenticate(Some(&test_key(51)), None).is_some());
        // Expired-but-loaded keys are reported separately.
        assert_eq!(store.expired_key_ids(), vec![key_id(&test_key(50))]);
        assert_eq!(store.active_key_ids(), vec![key_id(&test_key(51))]);
    }

    #[test]
    fn env_expires_list_aligns_positionally() {
        let tmp = tempfile::tempdir().unwrap();
        let list = format!("{},{},{}", test_key(60), test_key(61), test_key(62));
        // Aligned: first key expired, second entry empty (no expiry),
        // third in the future.
        let expires = "2020-01-01T00:00:00Z,,2999-01-01T00:00:00Z";
        let store = load_with(
            &[(ENV_API_KEY, &list), (ENV_API_KEY_EXPIRES, expires)],
            tmp.path(),
        );
        assert!(store.authenticate(Some(&test_key(60)), None).is_none());
        assert!(store.authenticate(Some(&test_key(61)), None).is_some());
        assert!(store.authenticate(Some(&test_key(62)), None).is_some());
    }

    // --- credential extraction ---

    #[test]
    fn bearer_scheme_and_bare_token_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(&[(ENV_API_KEY, &test_key(70))], tmp.path());
        let key = test_key(70);
        for form in [
            format!("Bearer {key}"),
            format!("bearer {key}"),
            format!("BEARER  {key}"),
            key.clone(), // bare token
        ] {
            assert!(
                store.authenticate(None, Some(&form)).is_some(),
                "rejected: {form:?}"
            );
        }
    }

    #[test]
    fn x_api_key_wins_over_bearer() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(
            &[(ENV_API_KEY, &format!("{},{}", test_key(71), test_key(72)))],
            tmp.path(),
        );
        let id = store
            .authenticate(
                Some(&test_key(71)),
                Some(&format!("Bearer {}", test_key(72))),
            )
            .unwrap();
        assert_eq!(id.key_id.as_deref(), Some(key_id(&test_key(71)).as_str()));
    }

    #[test]
    fn failure_reasons_are_distinguishable() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(&[(ENV_API_KEY, &test_key(80))], tmp.path());
        assert_eq!(
            store.authenticate_verbose(None, None),
            Err(AuthFailure::Missing)
        );
        assert_eq!(
            store.authenticate_verbose(Some("   "), Some("Bearer   ")),
            Err(AuthFailure::Missing)
        );
        assert_eq!(
            store.authenticate_verbose(Some("not-a-key"), None),
            Err(AuthFailure::Malformed)
        );
        // A *different* valid-format key is "unknown", not "malformed" —
        // and flipping one hex digit must not pass (constant-time compare
        // only ever returns true on a full match).
        let mut near_miss = test_key(80);
        let last = near_miss.len() - 1;
        near_miss.replace_range(last.., if near_miss.ends_with('0') { "1" } else { "0" });
        assert_eq!(
            store.authenticate_verbose(Some(&near_miss), None),
            Err(AuthFailure::Unknown)
        );
        assert_eq!(AuthFailure::Missing.reason(), "missing");
        assert_eq!(AuthFailure::Malformed.reason(), "malformed");
        assert_eq!(AuthFailure::Unknown.reason(), "unknown");
    }

    // --- fail closed & the dev hatch ---

    #[test]
    fn no_keys_configured_rejects_everything() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(&[], tmp.path());
        assert_eq!(store.mode(), AuthMode::Required);
        assert!(store.is_empty());
        assert!(store.authenticate(Some(&test_key(90)), None).is_none());
        assert!(store.authenticate(None, None).is_none());
    }

    #[test]
    fn disable_auth_hatch_passes_everyone() {
        let tmp = tempfile::tempdir().unwrap();
        let store = load_with(
            &[(ENV_DISABLE_AUTH, "true"), (ENV_API_KEY, &test_key(91))],
            tmp.path(),
        );
        assert_eq!(store.mode(), AuthMode::Disabled);
        assert!(store.is_disabled());
        let id = store.authenticate(None, None).unwrap();
        assert_eq!(id.key_id, None); // caller falls back to remote addr
        assert!(store.authenticate(Some("garbage"), None).is_some());
    }

    #[test]
    fn disable_auth_only_when_true() {
        let tmp = tempfile::tempdir().unwrap();
        for v in ["false", "0", "yes", "TRUEish"] {
            let store = load_with(
                &[(ENV_DISABLE_AUTH, v), (ENV_API_KEY, &test_key(92))],
                tmp.path(),
            );
            assert_eq!(store.mode(), AuthMode::Required, "value {v:?}");
        }
        for v in ["true", "TRUE", "1"] {
            let store = load_with(&[(ENV_DISABLE_AUTH, v)], tmp.path());
            assert_eq!(store.mode(), AuthMode::Disabled, "value {v:?}");
        }
    }

    #[test]
    fn from_env_honors_disable_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let saved: Vec<(&str, Option<OsString>)> = [
            ENV_DISABLE_AUTH,
            ENV_API_KEY,
            ENV_API_KEY_FILE,
            ENV_API_KEY_EXPIRES,
            "ULTRANIX_MCP_STATE_DIR",
        ]
        .iter()
        .map(|k| (*k, std::env::var_os(k)))
        .collect();
        // SAFETY: serialized by ENV_LOCK; all vars restored before unlock.
        unsafe {
            std::env::set_var(ENV_DISABLE_AUTH, "true");
            std::env::remove_var(ENV_API_KEY);
            std::env::remove_var(ENV_API_KEY_FILE);
            std::env::remove_var(ENV_API_KEY_EXPIRES);
            std::env::set_var("ULTRANIX_MCP_STATE_DIR", tmp.path());
        }
        let store = ApiKeyStore::from_env().unwrap();
        unsafe {
            for (k, v) in saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
        assert_eq!(store.mode(), AuthMode::Disabled);
    }

    // --- rotation ---

    #[test]
    fn rotate_keeps_old_until_expiry_and_issues_new() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = load_with(&[(ENV_API_KEY, &test_key(99))], tmp.path());
        let res = store.rotate(Duration::from_millis(30));
        assert!(is_valid_key(&res.new_key));
        assert_eq!(res.new_key_id, key_id(&res.new_key));
        // Both work during the overlap window.
        assert!(store.authenticate(Some(&test_key(99)), None).is_some());
        let id = store.authenticate(Some(&res.new_key), None).unwrap();
        assert_eq!(id.key_id.as_deref(), Some(res.new_key_id.as_str()));
        // Old self-revokes after the grace window; new keeps working.
        std::thread::sleep(Duration::from_millis(60));
        assert!(store.authenticate(Some(&test_key(99)), None).is_none());
        assert!(store.authenticate(Some(&res.new_key), None).is_some());
    }

    #[test]
    fn rotate_never_extends_an_earlier_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("keys.txt");
        write_file(
            &f,
            &format!("{} expires=2020-01-01T00:00:00Z\n", test_key(98)),
            0o600,
        );
        let p = f.to_string_lossy().into_owned();
        let mut store = load_with(&[(ENV_API_KEY_FILE, &p)], tmp.path());
        let res = store.rotate(Duration::from_secs(3600));
        // Already-expired key keeps its past expiry — rotate cannot
        // resurrect it.
        assert!(store.authenticate(Some(&test_key(98)), None).is_none());
        assert!(res.old_keys_expire_at > Utc::now());
        assert!(store.authenticate(Some(&res.new_key), None).is_some());
    }

    #[test]
    fn duplicate_keys_are_deduped() {
        let tmp = tempfile::tempdir().unwrap();
        let list = format!("{},{}", test_key(77), test_key(77));
        let store = load_with(&[(ENV_API_KEY, &list)], tmp.path());
        assert_eq!(store.len(), 1);
    }
}
