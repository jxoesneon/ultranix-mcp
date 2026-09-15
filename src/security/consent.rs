//! Consent gate for the destructive tool class — SECURITY.md "Consent gate
//! for destructive-class tools" and docs/TOOLS.md "Destructive-Action
//! Consent".
//!
//! Gated set (spec-frozen): `system_command`, `replay_action`,
//! `clear_action_history`, `window_control{action:"close"}`.
//!
//! Token semantics implemented here:
//! - CSPRNG, ≥128-bit (16 bytes), base64url-encoded, no padding.
//! - Single-use: consumed on the first `verify` attempt, pass or fail —
//!   a mismatched token returns `-32015` again with a *fresh* challenge.
//! - 60 s TTL (monotonic clock).
//! - Bound to `{caller_id, tool, args_hash}` where `caller_id` is the
//!   `key_id` on HTTP or the stdio session id; `args_hash` is SHA-256 over
//!   the canonical JSON of the arguments (sorted keys, insignificant
//!   whitespace removed, `consent_token` itself excluded).
//! - For calls whose target is resolved at execution time
//!   (`window_control{action:"close"}` with `window` omitted), the resolved
//!   target is folded into the token scope at challenge time — a change of
//!   the resolved target between challenge and retry invalidates the token.
//! - `--allow-destructive` bypass: `verify` then accepts anything; callers
//!   still stamp `"consent": "bypassed"` on the audit record.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Authoritative challenge TTL surfaced to clients (`expires_in_ms`).
pub const EXPIRES_IN_MS: u64 = 60_000;

/// Entropy carried by one token: 16 random bytes = 128 bits.
const TOKEN_BYTES: usize = 16;

/// The challenge handed back inside a `-32015 ConsentRequired` error's
/// `data` member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The `consent_token` string the client retries with.
    pub token: String,
    /// Always [`EXPIRES_IN_MS`].
    pub expires_in_ms: u64,
}

/// What a live token is bound to. Not serialized anywhere.
#[derive(Debug)]
struct TokenRecord {
    caller_id: String,
    tool: String,
    args_hash: String,
    resolved_target: Option<String>,
    issued: Instant,
}

/// The consent gate. One per server process; thread-safe.
pub struct ConsentGate {
    /// `--allow-destructive` operator opt-out.
    allow_destructive: bool,
    /// Token TTL — a constant in production, tunable for tests.
    ttl: Duration,
    /// token string → scope record. Bounded: entries are pruned on every
    /// mutation and self-expire after `ttl`.
    tokens: Mutex<HashMap<String, TokenRecord>>,
}

impl ConsentGate {
    /// Production constructor: 60 s TTL.
    pub fn new(allow_destructive: bool) -> Self {
        Self::with_ttl(allow_destructive, Duration::from_millis(EXPIRES_IN_MS))
    }

    /// Constructor with an explicit TTL — for tests and exotic deployments.
    pub fn with_ttl(allow_destructive: bool, ttl: Duration) -> Self {
        Self {
            allow_destructive,
            ttl,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `--allow-destructive` bypass is engaged. Callers must still
    /// write the audit record (stamped `"consent": "bypassed"`).
    pub fn allow_destructive(&self) -> bool {
        self.allow_destructive
    }

    /// Issue a challenge bound to `{caller, tool, args_hash}` with no
    /// resolved-target scope — for calls whose target is fully described by
    /// `args` (e.g. `window_control{action:"close", window:"0x…"}`).
    pub fn challenge(
        &self,
        key_id: Option<&str>,
        session_id: &str,
        tool: &str,
        args: &Value,
    ) -> Challenge {
        self.challenge_inner(key_id, session_id, tool, args, None)
    }

    /// Issue a challenge additionally bound to `resolved_target` — for
    /// calls whose target is resolved at execution time (e.g.
    /// `window_control{action:"close"}` with `window` omitted resolving to
    /// the *current* active window's address).
    pub fn challenge_for_target(
        &self,
        key_id: Option<&str>,
        session_id: &str,
        tool: &str,
        args: &Value,
        resolved_target: &str,
    ) -> Challenge {
        self.challenge_inner(key_id, session_id, tool, args, Some(resolved_target))
    }

    fn challenge_inner(
        &self,
        key_id: Option<&str>,
        session_id: &str,
        tool: &str,
        args: &Value,
        resolved_target: Option<&str>,
    ) -> Challenge {
        let mut tokens = self.tokens.lock().expect("consent gate poisoned");
        // Opportunistic GC — keeps the map bounded under challenge spam.
        let ttl = self.ttl;
        tokens.retain(|_, r| r.issued.elapsed() <= ttl);

        let token = generate_token();
        tokens.insert(
            token.clone(),
            TokenRecord {
                caller_id: caller_id(key_id, session_id).to_string(),
                tool: tool.to_string(),
                args_hash: args_hash(args),
                resolved_target: resolved_target.map(str::to_string),
                issued: Instant::now(),
            },
        );
        Challenge {
            token,
            expires_in_ms: EXPIRES_IN_MS,
        }
    }

    /// Consume and check `token` against the full scope. Single-use: the
    /// token is removed on *any* attempt, so an expired/mismatched token
    /// can never be retried — the client gets a fresh challenge instead.
    ///
    /// `resolved_target` must be `Some(_)` iff the challenge was issued via
    /// [`challenge_for_target`](Self::challenge_for_target), and must be the
    /// same value — a resolved-target change between challenge and retry
    /// invalidates the token.
    ///
    /// When `allow_destructive` is set, always returns `true` (the bypass
    /// is auditable via the `"consent": "bypassed"` record stamp).
    pub fn verify(
        &self,
        token: &str,
        key_id: Option<&str>,
        session_id: &str,
        tool: &str,
        args: &Value,
        resolved_target: Option<&str>,
    ) -> bool {
        if self.allow_destructive {
            return true;
        }
        let record = {
            let mut tokens = self.tokens.lock().expect("consent gate poisoned");
            tokens.remove(token) // single-use: consumed on attempt
        };
        let Some(rec) = record else {
            return false;
        };
        rec.issued.elapsed() <= self.ttl
            && rec.caller_id == caller_id(key_id, session_id)
            && rec.tool == tool
            && rec.args_hash == args_hash(args)
            && rec.resolved_target.as_deref() == resolved_target
    }
}

/// Caller identity: `key_id` on HTTP, stdio session id otherwise
/// (docs/TOOLS.md token binding).
fn caller_id<'a>(key_id: Option<&'a str>, session_id: &'a str) -> &'a str {
    key_id.unwrap_or(session_id)
}

/// Fresh stdio session id — CSPRNG, generated once at server start and
/// bound into consent-token caller identity (docs/TOOLS.md token binding).
pub fn new_session_id() -> String {
    generate_token()
}

/// 128 bits of CSPRNG entropy, base64url-encoded without padding.
fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::fill(&mut bytes);
    base64url(&bytes)
}

/// base64url (RFC 4648 §5), no padding — avoids a dependency for 16-byte
/// inputs.
fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// SHA-256 (hex) over the canonical JSON serialization of `args`:
/// sorted object keys at every depth, UTF-8, insignificant whitespace
/// removed, and the top-level `consent_token` member excluded — it carries
/// the challenge answer, not part of the consented-to call.
///
/// Also used by the audit layer so the record's `args_hash` matches exactly
/// what consent was bound to.
pub fn args_hash(args: &Value) -> String {
    let mut canonical = Vec::new();
    write_canonical(args, &mut canonical, true);
    let digest = Sha256::digest(&canonical);
    hex(&digest)
}

/// Canonical-JSON writer: object keys sorted, `,`/`:` without whitespace.
/// `strip_consent` applies only at the top level — a `consent_token` key
/// nested deeper in the structure is data, not the gate's parameter.
fn write_canonical(v: &Value, out: &mut Vec<u8>, strip_consent: bool) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(b.to_string().as_bytes()),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            // serde_json's string serialization is the canonical escaping.
            out.extend_from_slice(serde_json::to_string(s).expect("string escapes").as_bytes())
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out, false);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut first = true;
            for k in keys {
                if strip_consent && k == "consent_token" {
                    continue;
                }
                if !first {
                    out.push(b',');
                }
                first = false;
                out.extend_from_slice(serde_json::to_string(k).expect("key escapes").as_bytes());
                out.push(b':');
                write_canonical(&map[k], out, false);
            }
            out.push(b'}');
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SESSION: &str = "stdio-session-abc";

    #[test]
    fn token_shape_is_csprng_base64url() {
        let gate = ConsentGate::new(false);
        let c = gate.challenge(
            Some("key1"),
            SESSION,
            "system_command",
            &json!({"command":"slurp"}),
        );
        assert_eq!(c.expires_in_ms, EXPIRES_IN_MS);
        // 16 bytes → 22 base64url chars, URL-safe alphabet only.
        assert_eq!(c.token.len(), 22);
        assert!(
            c.token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // Tokens are random, never sequential.
        let c2 = gate.challenge(
            Some("key1"),
            SESSION,
            "system_command",
            &json!({"command":"slurp"}),
        );
        assert_ne!(c.token, c2.token);
    }

    #[test]
    fn challenge_then_verify_roundtrip() {
        let gate = ConsentGate::new(false);
        let args = json!({"command": "slurp", "args": ["-f", "%x"]});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &args);
        assert!(gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
    }

    #[test]
    fn token_is_single_use() {
        let gate = ConsentGate::new(false);
        let args = json!({"command": "slurp"});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &args);
        assert!(gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
        // Second attempt — token spent.
        assert!(!gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
    }

    #[test]
    fn failed_verify_consumes_token() {
        // A mismatched retry spends the token; replay with corrected args
        // cannot resurrect it.
        let gate = ConsentGate::new(false);
        let args = json!({"command": "slurp"});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &args);
        let wrong = json!({"command": "grim"});
        assert!(!gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &wrong,
            None
        ));
        assert!(!gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
    }

    #[test]
    fn binding_rejects_transplant() {
        let gate = ConsentGate::new(false);
        let args = json!({"command": "slurp"});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &args);
        // wrong key
        let gate2 = ConsentGate::new(false);
        let c2 = gate2.challenge(Some("key1"), SESSION, "system_command", &args);
        assert!(!gate2.verify(
            &c2.token,
            Some("key2"),
            SESSION,
            "system_command",
            &args,
            None
        ));
        // wrong tool
        let c3 = gate2.challenge(Some("key1"), SESSION, "system_command", &args);
        assert!(!gate2.verify(
            &c3.token,
            Some("key1"),
            SESSION,
            "replay_action",
            &args,
            None
        ));
        // wrong args
        let c4 = gate2.challenge(Some("key1"), SESSION, "system_command", &args);
        assert!(!gate2.verify(
            &c4.token,
            Some("key1"),
            SESSION,
            "system_command",
            &json!({"command": "grim"}),
            None
        ));
        // wrong session (key_id absent → session is the caller id)
        let c5 = gate2.challenge(None, SESSION, "system_command", &args);
        assert!(!gate2.verify(
            &c5.token,
            None,
            "other-session",
            "system_command",
            &args,
            None
        ));
        // a token from one gate is meaningless to another
        assert!(!gate2.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
    }

    #[test]
    fn consent_token_param_is_excluded_from_hash() {
        // The retry carries `consent_token` in args; the hash must match the
        // challenge-time args without it.
        let gate = ConsentGate::new(false);
        let base = json!({"command": "slurp", "args": ["-f", "%x"]});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &base);
        let mut with_token = base.clone();
        with_token["consent_token"] = json!(c.token);
        assert!(gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &with_token,
            None
        ));
    }

    #[test]
    fn key_order_and_whitespace_do_not_affect_hash() {
        let a = json!({"b": 2, "a": {"y": [1, 2], "x": true}});
        let b = json!({"a": {"x": true, "y": [1, 2]}, "b": 2});
        assert_eq!(args_hash(&a), args_hash(&b));
        // But different values hash differently.
        let c = json!({"a": 1});
        let d = json!({"a": 2});
        assert_ne!(args_hash(&c), args_hash(&d));
        // Hash is 64 lowercase hex chars.
        assert_eq!(args_hash(&c).len(), 64);
    }

    #[test]
    fn nested_consent_token_key_is_data() {
        // Only the top-level `consent_token` is excluded.
        let a = json!({"x": {"consent_token": "abc"}});
        let b = json!({"x": {}});
        assert_ne!(args_hash(&a), args_hash(&b));
    }

    #[test]
    fn resolved_target_binding() {
        let gate = ConsentGate::new(false);
        let args = json!({"action": "close"}); // window omitted
        let c = gate.challenge_for_target(None, SESSION, "window_control", &args, "0xaaa");
        // same resolved target → ok
        assert!(gate.verify(
            &c.token,
            None,
            SESSION,
            "window_control",
            &args,
            Some("0xaaa")
        ));
        // changed target → rejected
        let c2 = gate.challenge_for_target(None, SESSION, "window_control", &args, "0xaaa");
        assert!(!gate.verify(
            &c2.token,
            None,
            SESSION,
            "window_control",
            &args,
            Some("0xbbb")
        ));
        // target dropped → rejected
        let c3 = gate.challenge_for_target(None, SESSION, "window_control", &args, "0xaaa");
        assert!(!gate.verify(&c3.token, None, SESSION, "window_control", &args, None));
        // target added to an unscoped challenge → rejected
        let c4 = gate.challenge(None, SESSION, "window_control", &args);
        assert!(!gate.verify(
            &c4.token,
            None,
            SESSION,
            "window_control",
            &args,
            Some("0xaaa")
        ));
    }

    #[test]
    fn token_expires() {
        let gate = ConsentGate::with_ttl(false, Duration::from_millis(30));
        let args = json!({"command": "slurp"});
        let c = gate.challenge(Some("key1"), SESSION, "system_command", &args);
        std::thread::sleep(Duration::from_millis(60));
        assert!(!gate.verify(
            &c.token,
            Some("key1"),
            SESSION,
            "system_command",
            &args,
            None
        ));
    }

    #[test]
    fn unknown_and_garbage_tokens_rejected() {
        let gate = ConsentGate::new(false);
        let args = json!({"command": "slurp"});
        let long = "x".repeat(64);
        for tok in ["", "AAAA", "deadbeef", long.as_str()] {
            assert!(!gate.verify(tok, Some("key1"), SESSION, "system_command", &args, None));
        }
    }

    #[test]
    fn allow_destructive_bypasses() {
        let gate = ConsentGate::new(true);
        assert!(gate.allow_destructive());
        // Any token verifies — the bypass is real.
        assert!(gate.verify(
            "no-such-token",
            None,
            SESSION,
            "system_command",
            &json!({"command": "slurp"}),
            None
        ));
    }

    #[test]
    fn expired_tokens_are_pruned() {
        let gate = ConsentGate::with_ttl(false, Duration::from_millis(10));
        let args = json!({"command": "slurp"});
        let _ = gate.challenge(Some("k"), SESSION, "system_command", &args);
        std::thread::sleep(Duration::from_millis(30));
        let _ = gate.challenge(Some("k"), SESSION, "system_command", &args); // triggers GC
        assert_eq!(gate.tokens.lock().unwrap().len(), 1);
    }
}
