//! Per-identity token-bucket rate limiter - SECURITY.md "Request
//! pipeline" layer 2 and API_KEY_MANAGEMENT.md §5.
//!
//! One bucket per caller identity: the `key_id` of the authenticated
//! API key on HTTP (one key = one budget), or the remote socket address
//! as the defense-in-depth fallback. Default shape: **10 req/s**
//! sustained refill with a **20-token**burst capacity. Override the
//! rate with `ULTRANIX_MCP_RATE_LIMIT` (requests/second, float ok); the
//! burst floor stays 20, or `2 × rps` when the configured rate exceeds
//! that.
//!
//! Implementation notes:
//! - Monotonic clock ([`Instant`]) - wall-clock changes cannot refill
//!   or freeze buckets.
//! - `Mutex<HashMap>` - a single short critical section per check; no
//!   `DashMap` dependency.
//! - The map is bounded: stale buckets (idle > 10 min) are evicted by
//!   periodic GC, and a hard cap evicts the least-recently-active
//!   identities if an attacker sprays distinct identities.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Requests-per-second override, float (`ULTRANIX_MCP_RATE_LIMIT=25`).
pub const ENV_RATE_LIMIT: &str = "ULTRANIX_MCP_RATE_LIMIT";
/// Spec default sustained rate (SECURITY.md request pipeline).
pub const DEFAULT_RPS: f64 = 10.0;
/// Spec default burst capacity ("burst ~20").
pub const DEFAULT_BURST: f64 = 20.0;
/// Buckets idle longer than this are evicted - an inactive identity's
/// next request simply starts with a fresh full bucket.
const EVICT_AFTER: Duration = Duration::from_secs(600);
/// Hard bound on tracked identities; past it the least-recently-active
/// buckets are evicted.
const MAX_IDENTITIES: usize = 4096;
/// Run the stale-entry sweep every Nth check (bounded amortized cost).
const GC_EVERY_OPS: u64 = 256;

#[derive(Debug)]
struct Bucket {
    /// Whole + fractional tokens; a request costs exactly 1.0.
    tokens: f64,
    /// Last refill instant.
    last: Instant,
}

#[derive(Debug)]
struct Inner {
    buckets: HashMap<String, Bucket>,
    /// Total `check` calls - drives the periodic GC cadence.
    ops: u64,
}

/// Token-bucket rate limiter. One per server process; `Send + Sync`.
#[derive(Debug)]
pub struct RateLimiter {
    rps: f64,
    burst: f64,
    inner: Mutex<Inner>,
}

impl RateLimiter {
    /// `rps` sustained refill, `burst` bucket capacity. Non-positive or
    /// non-finite inputs are sanitized to the spec defaults.
    pub fn new(rps: f64, burst: f64) -> Self {
        let rps = if rps.is_finite() && rps > 0.0 {
            rps
        } else {
            DEFAULT_RPS
        };
        let burst = if burst.is_finite() && burst > 0.0 {
            burst
        } else {
            DEFAULT_BURST
        };
        Self {
            rps,
            burst,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                ops: 0,
            }),
        }
    }

    /// Resolve from the real environment: `ULTRANIX_MCP_RATE_LIMIT`
    /// sets the sustained rps; the burst floor is [`DEFAULT_BURST`] or
    /// `2 × rps`, whichever is larger.
    pub fn from_env() -> Self {
        Self::from_env_lookup(|k| std::env::var_os(k))
    }

    /// [`Self::from_env`] with an injected env lookup - for tests.
    pub fn from_env_lookup(get: impl Fn(&str) -> Option<OsString>) -> Self {
        match get(ENV_RATE_LIMIT).filter(|v| !v.is_empty()) {
            None => Self::default(),
            Some(v) => {
                let s = v.to_string_lossy();
                match s.trim().parse::<f64>() {
                    Ok(rps) if rps.is_finite() && rps > 0.0 => {
                        Self::new(rps, DEFAULT_BURST.max(2.0 * rps))
                    }
                    _ => {
                        tracing::warn!(
                            value = %s,
                            "invalid {ENV_RATE_LIMIT} - expected a positive number \
                             (requests/second); using {DEFAULT_RPS} req/s"
                        );
                        Self::default()
                    }
                }
            }
        }
    }

    /// Admit one request for `identity`. Refills the caller's bucket
    /// against the monotonic clock, then consumes one token if
    /// available. `false` = over budget - the caller should reject and
    /// emit `ratelimit.exceeded`.
    pub fn check(&self, identity: &str) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("rate limiter poisoned");
        inner.ops += 1;
        if inner.ops.is_multiple_of(GC_EVERY_OPS) || inner.buckets.len() > MAX_IDENTITIES {
            evict_stale(&mut inner.buckets, now);
        }
        let bucket = inner
            .buckets
            .entry(identity.to_string())
            .or_insert_with(|| Bucket {
                tokens: self.burst, // new identities start with a full burst
                last: now,
            });
        let allowed = take(bucket, now, self.rps, self.burst);
        if inner.buckets.len() > MAX_IDENTITIES {
            evict_oldest(&mut inner.buckets);
        }
        allowed
    }

    /// Configured sustained refill rate (requests/second).
    pub fn rps(&self) -> f64 {
        self.rps
    }

    /// Configured burst capacity (tokens).
    pub fn burst(&self) -> f64 {
        self.burst
    }

    /// Number of identities currently tracked - diagnostics/tests.
    pub fn tracked_identities(&self) -> usize {
        self.inner
            .lock()
            .expect("rate limiter poisoned")
            .buckets
            .len()
    }
}

impl Default for RateLimiter {
    /// Spec shape: 10 req/s, burst 20.
    fn default() -> Self {
        Self::new(DEFAULT_RPS, DEFAULT_BURST)
    }
}

/// Refill then consume: `tokens += elapsed × rps` (capped at `burst`),
/// then spend 1.0 if affordable. Pure over `(bucket, now)` so the refill
/// math is unit-testable without sleeping.
fn take(bucket: &mut Bucket, now: Instant, rps: f64, burst: f64) -> bool {
    let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rps).min(burst);
    bucket.last = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// Drop buckets idle longer than [`EVICT_AFTER`].
fn evict_stale(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    buckets.retain(|_, b| now.saturating_duration_since(b.last) <= EVICT_AFTER);
}

/// Trim to [`MAX_IDENTITIES`] by evicting least-recently-active buckets.
fn evict_oldest(buckets: &mut HashMap<String, Bucket>) {
    if buckets.len() <= MAX_IDENTITIES {
        return;
    }
    let mut by_last: Vec<(String, Instant)> =
        buckets.iter().map(|(k, b)| (k.clone(), b.last)).collect();
    by_last.sort_by_key(|(_, last)| *last);
    let excess = buckets.len() - MAX_IDENTITIES;
    for (key, _) in by_last.into_iter().take(excess) {
        buckets.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(v)))
            .collect();
        move |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    // --- bucket math ---

    #[test]
    fn burst_capacity_then_deny() {
        let rl = RateLimiter::new(10.0, 20.0);
        for i in 0..20 {
            assert!(rl.check("key-a"), "request {i} of the burst denied");
        }
        assert!(!rl.check("key-a"), "burst exhausted but still allowed");
    }

    #[test]
    fn refill_math_is_exact() {
        let now = Instant::now();
        // 5 tokens left, 1 s idle at 10 rps -> 15 available; one spend -> 14.
        let mut b = Bucket {
            tokens: 5.0,
            last: now - Duration::from_secs(1),
        };
        assert!(take(&mut b, now, 10.0, 20.0));
        assert!((b.tokens - 14.0).abs() < 1e-9, "tokens={}", b.tokens);
    }

    #[test]
    fn refill_is_capped_at_burst() {
        let now = Instant::now();
        let mut b = Bucket {
            tokens: 19.5,
            last: now - Duration::from_secs(60), // way over the cap
        };
        assert!(take(&mut b, now, 10.0, 20.0));
        assert!((b.tokens - 19.0).abs() < 1e-9, "tokens={}", b.tokens);
    }

    #[test]
    fn denial_spends_nothing() {
        let now = Instant::now();
        let mut b = Bucket {
            tokens: 0.5,
            last: now,
        };
        assert!(!take(&mut b, now, 10.0, 20.0));
        assert!((b.tokens - 0.5).abs() < 1e-9);
    }

    #[test]
    fn tokens_refill_over_wall_time() {
        let rl = RateLimiter::new(100.0, 5.0);
        for _ in 0..5 {
            assert!(rl.check("k"));
        }
        assert!(!rl.check("k"));
        // 30 ms at 100 rps ≈ 3 tokens back.
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.check("k"), "refill did not grant a token");
    }

    #[test]
    fn identities_have_independent_budgets() {
        let rl = RateLimiter::new(10.0, 3.0);
        for _ in 0..3 {
            assert!(rl.check("alice"));
        }
        assert!(!rl.check("alice"));
        // Exhausting alice must not touch bob's budget.
        for _ in 0..3 {
            assert!(rl.check("bob"));
        }
        assert!(!rl.check("bob"));
        assert_eq!(rl.tracked_identities(), 2);
    }

    // --- configuration ---

    #[test]
    fn env_override_sets_rps_and_scales_burst() {
        let rl = RateLimiter::from_env_lookup(fake_env(&[(ENV_RATE_LIMIT, "25")]));
        assert_eq!(rl.rps(), 25.0);
        assert_eq!(rl.burst(), 50.0); // 2 × rps beats the 20 floor
        let rl = RateLimiter::from_env_lookup(fake_env(&[(ENV_RATE_LIMIT, "2.5")]));
        assert_eq!(rl.rps(), 2.5);
        assert_eq!(rl.burst(), 20.0); // floor holds
    }

    #[test]
    fn invalid_or_absent_env_uses_defaults() {
        let rl = RateLimiter::from_env_lookup(fake_env(&[]));
        assert_eq!(rl.rps(), DEFAULT_RPS);
        assert_eq!(rl.burst(), DEFAULT_BURST);
        for bad in ["ten", "-5", "0", "NaN", ""] {
            let rl = RateLimiter::from_env_lookup(fake_env(&[(ENV_RATE_LIMIT, bad)]));
            assert_eq!(rl.rps(), DEFAULT_RPS, "value {bad:?}");
        }
    }

    #[test]
    fn constructor_sanitizes_bad_numbers() {
        let rl = RateLimiter::new(f64::NAN, -1.0);
        assert_eq!(rl.rps(), DEFAULT_RPS);
        assert_eq!(rl.burst(), DEFAULT_BURST);
    }

    // --- eviction ---

    #[test]
    fn stale_buckets_are_evicted_by_gc() {
        let rl = RateLimiter::default();
        {
            let mut inner = rl.inner.lock().unwrap();
            inner.buckets.insert(
                "stale".to_string(),
                Bucket {
                    tokens: 1.0,
                    last: Instant::now() - EVICT_AFTER - Duration::from_secs(1),
                },
            );
            inner.buckets.insert(
                "fresh".to_string(),
                Bucket {
                    tokens: 1.0,
                    last: Instant::now(),
                },
            );
            // Next check trips the GC cadence.
            inner.ops = GC_EVERY_OPS - 1;
        }
        rl.check("fresh");
        let inner = rl.inner.lock().unwrap();
        assert!(!inner.buckets.contains_key("stale"));
        assert!(inner.buckets.contains_key("fresh"));
    }

    #[test]
    fn identity_map_is_capped() {
        let rl = RateLimiter::new(1000.0, 1.0);
        {
            let mut inner = rl.inner.lock().unwrap();
            let now = Instant::now();
            for i in 0..(MAX_IDENTITIES + 10) {
                inner.buckets.insert(
                    format!("id-{i}"),
                    Bucket {
                        tokens: 0.0,
                        last: now - Duration::from_secs(i as u64 % 60),
                    },
                );
            }
        }
        assert!(rl.check("new-arrival"));
        assert!(rl.tracked_identities() <= MAX_IDENTITIES);
        // The just-admitted identity is freshest - it survives eviction.
        assert!(rl.inner.lock().unwrap().buckets.contains_key("new-arrival"));
    }

    #[test]
    fn evicted_identity_restarts_with_full_bucket() {
        // After eviction an old identity is indistinguishable from new -
        // it gets a fresh burst, never negative credit.
        let rl = RateLimiter::new(1.0, 2.0);
        {
            let mut inner = rl.inner.lock().unwrap();
            inner.buckets.insert(
                "gone".to_string(),
                Bucket {
                    tokens: -50.0, // deficit cannot persist across eviction
                    last: Instant::now() - EVICT_AFTER - Duration::from_secs(1),
                },
            );
            inner.ops = GC_EVERY_OPS - 1;
        }
        assert!(rl.check("gone"));
        assert!(rl.check("gone")); // two fresh burst tokens
        assert!(!rl.check("gone"));
    }
}
