//! Process-global Prometheus metrics - docs/ARCHITECTURE.md §7
//! "Observability" (canonical series names). The admin `metrics` tool and
//! the `GET /metrics` surface on :3010 serve [`exposition`] verbatim.
//!
//! Dependency-free by design: a `Mutex`-guarded registry of labelled
//! counters, one fixed-bucket histogram per tool, and gauges, rendered to
//! the Prometheus text exposition format (0.0.4). All state lives in a
//! process-global [`LazyLock`], so instrumentation call sites are plain
//! free functions with no context plumbing.
//!
//! Canonical series:
//! - `ultranix_mcp_tool_calls_total{tool,outcome}` - counter
//! - `ultranix_mcp_tool_duration_seconds{tool}` - histogram
//!   (`_bucket{le}` / `_sum` / `_count`)
//! - `ultranix_mcp_backend_calls_total{backend,outcome}` - counter
//! - `ultranix_mcp_build_info{version}` - gauge
//! - `ultranix_mcp_rate_limit_rejections_total{reason}` - counter
//! - `ultranix_mcp_auth_failures_total{reason}` - counter
//! - `ultranix_mcp_active_sessions{transport}` - gauge
//! - `ultranix_mcp_backend_active{backend}` - gauge
//! - `ultranix_mcp_action_history_size` - gauge
//! - `ultranix_mcp_ocr_cache_entries` - gauge

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

/// Fixed histogram bounds (seconds) for
/// `ultranix_mcp_tool_duration_seconds`. Tool latency spans sub-ms input
/// taps to multi-second whitelisted execs; the ladder covers the
/// docs/TOOLS.md latency budgets (<5 ms cached reads, <500 ms vision).
const BUCKETS: &[(f64, &str)] = &[
    (0.001, "0.001"),
    (0.005, "0.005"),
    (0.01, "0.01"),
    (0.025, "0.025"),
    (0.05, "0.05"),
    (0.1, "0.1"),
    (0.25, "0.25"),
    (0.5, "0.5"),
    (1.0, "1"),
    (2.5, "2.5"),
    (5.0, "5"),
    (10.0, "10"),
];

const N_BUCKETS: usize = BUCKETS.len();

/// Fixed-bucket latency histogram for one `tool` label value.
struct Histogram {
    /// Non-cumulative counts: `buckets[i]` holds observations
    /// `<= BUCKETS[i].0` and above `BUCKETS[i-1].0`. Observations past the
    /// last bound fall through to `+Inf` (`count` minus the bucket total).
    buckets: [u64; N_BUCKETS],
    /// Sum of observed seconds.
    sum: f64,
    /// Total observations (the `+Inf` bucket).
    count: u64,
}

impl Histogram {
    fn observe(&mut self, secs: f64) {
        if let Some(i) = BUCKETS.iter().position(|(b, _)| secs <= *b) {
            self.buckets[i] += 1;
        }
        self.sum += secs;
        self.count += 1;
    }
}

#[derive(Default)]
struct Registry {
    /// `ultranix_mcp_tool_calls_total` keyed by `(tool, outcome)`.
    calls: BTreeMap<(&'static str, &'static str), u64>,
    /// `ultranix_mcp_tool_duration_seconds` keyed by `tool`.
    durations: BTreeMap<&'static str, Histogram>,
    /// `ultranix_mcp_backend_calls_total` keyed by `(backend, outcome)`.
    backend_calls: BTreeMap<(&'static str, &'static str), u64>,
    /// Whether the process build-information gauge has been initialised.
    build_info: bool,
    /// `ultranix_mcp_rate_limit_rejections_total` keyed by `reason`.
    rate_rejections: BTreeMap<String, u64>,
    /// `ultranix_mcp_auth_failures_total` keyed by `reason`.
    auth_failures: BTreeMap<String, u64>,
    /// `ultranix_mcp_active_sessions` keyed by `transport`.
    sessions: BTreeMap<String, i64>,
    /// `ultranix_mcp_backend_active` keyed by `backend`.
    backends: BTreeMap<String, i64>,
    /// `ultranix_mcp_action_history_size` - retained history records.
    history_size: i64,
    /// `ultranix_mcp_ocr_cache_entries` - live OCR cache entries.
    ocr_cache_entries: i64,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

/// Lock the global registry, recovering from poisoning - a metrics sink
/// must never take down a tool call.
fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record one tool invocation: increments
/// `ultranix_mcp_tool_calls_total{tool,outcome}` and observes `duration`
/// in `ultranix_mcp_tool_duration_seconds{tool}`.
///
/// `outcome` uses the audit vocabulary: `ok`, `tool_error`,
/// `consent_required`, `denied`, `error`. All keys are `&'static` -
/// callers pass the catalog tool name (`metric_label`) and fixed
/// outcome literals - so a map hit allocates nothing.
pub fn record_call(tool: &'static str, duration: Duration, outcome: &'static str) {
    let mut reg = registry();
    record_tool_call(&mut reg, tool, duration, outcome);
}

/// Record one tool invocation and attribute it to its resolved provider
/// backend. This emits the existing per-tool counter and histogram as well as
/// `ultranix_mcp_backend_calls_total{backend,outcome}`.
pub fn record_call_with_backend(
    tool: &'static str,
    backend: &'static str,
    duration: Duration,
    outcome: &'static str,
) {
    let mut reg = registry();
    record_tool_call(&mut reg, tool, duration, outcome);
    *reg.backend_calls.entry((backend, outcome)).or_insert(0) += 1;
}

fn record_tool_call(
    reg: &mut Registry,
    tool: &'static str,
    duration: Duration,
    outcome: &'static str,
) {
    *reg.calls.entry((tool, outcome)).or_insert(0) += 1;
    reg.durations
        .entry(tool)
        .or_insert_with(|| Histogram {
            buckets: [0; N_BUCKETS],
            sum: 0.0,
            count: 0,
        })
        .observe(duration.as_secs_f64());
}

/// Initialise `ultranix_mcp_build_info` for this process. Repeated calls are
/// idempotent; the version label is fixed at compile time.
pub fn set_build_info() {
    registry().build_info = true;
}

/// Increment `ultranix_mcp_rate_limit_rejections_total{reason}` -
/// emitted by the HTTP token bucket on a 429 (Phase 4 wiring).
pub fn record_rate_rejection(reason: &str) {
    let mut reg = registry();
    *reg.rate_rejections.entry(reason.to_string()).or_insert(0) += 1;
}

/// Increment `ultranix_mcp_auth_failures_total{reason}` - emitted by the
/// HTTP gate on a rejected credential (`AuthFailure::reason()`:
/// `missing`, `malformed`, `unknown`, `expired_key`).
pub fn record_auth_failure(reason: &str) {
    let mut reg = registry();
    *reg.auth_failures.entry(reason.to_string()).or_insert(0) += 1;
}

/// Mark `ultranix_mcp_backend_active{backend}` = 1 - emitted once per
/// initialised backend at startup from `Providers::backend_names`
/// (e.g. `wlr-screencopy`, `atspi2`). Absent series = backend down.
pub fn set_backend_active(backend: &str) {
    registry().backends.insert(backend.to_string(), 1);
}

/// Set `ultranix_mcp_action_history_size` - the retained record count,
/// refreshed after each history append and reset to 0 on clear.
pub fn set_action_history_size(n: usize) {
    registry().history_size = n as i64;
}

/// Set `ultranix_mcp_ocr_cache_entries` - the live entry count of the
/// ONNX vision OCR cache (producer wired in `providers/onnx_vision.rs`).
pub fn set_ocr_cache_entries(n: usize) {
    registry().ocr_cache_entries = n as i64;
}

/// Set `ultranix_mcp_active_sessions{transport}` - the absolute count of
/// live sessions on `transport` (`stdio`, `http`).
pub fn set_sessions(transport: &str, n: i64) {
    registry().sessions.insert(transport.to_string(), n);
}

/// Render the registry in the Prometheus text exposition format -
/// `# HELP`/`# TYPE` blocks followed by labelled samples, one per line,
/// trailing newline. Series are emitted in sorted label order
/// (BTreeMap) for deterministic output.
pub fn exposition() -> String {
    let reg = registry();
    let mut out = String::new();

    out.push_str("# HELP ultranix_mcp_tool_calls_total Tool call count by outcome.\n");
    out.push_str("# TYPE ultranix_mcp_tool_calls_total counter\n");
    for ((tool, outcome), n) in &reg.calls {
        let _ = writeln!(
            out,
            "ultranix_mcp_tool_calls_total{{tool=\"{}\",outcome=\"{}\"}} {n}",
            esc(tool),
            esc(outcome)
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_tool_duration_seconds Per-tool execution latency in seconds.\n",
    );
    out.push_str("# TYPE ultranix_mcp_tool_duration_seconds histogram\n");
    for (tool, h) in &reg.durations {
        let mut cumulative = 0u64;
        for (i, (_, label)) in BUCKETS.iter().enumerate() {
            cumulative += h.buckets[i];
            let _ = writeln!(
                out,
                "ultranix_mcp_tool_duration_seconds_bucket{{tool=\"{}\",le=\"{label}\"}} {cumulative}",
                esc(tool)
            );
        }
        let _ = writeln!(
            out,
            "ultranix_mcp_tool_duration_seconds_bucket{{tool=\"{}\",le=\"+Inf\"}} {}",
            esc(tool),
            h.count
        );
        let _ = writeln!(
            out,
            "ultranix_mcp_tool_duration_seconds_sum{{tool=\"{}\"}} {}",
            esc(tool),
            h.sum
        );
        let _ = writeln!(
            out,
            "ultranix_mcp_tool_duration_seconds_count{{tool=\"{}\"}} {}",
            esc(tool),
            h.count
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_backend_calls_total Tool call count by resolved backend and outcome.\n",
    );
    out.push_str("# TYPE ultranix_mcp_backend_calls_total counter\n");
    for ((backend, outcome), n) in &reg.backend_calls {
        let _ = writeln!(
            out,
            "ultranix_mcp_backend_calls_total{{backend=\"{}\",outcome=\"{}\"}} {n}",
            esc(backend),
            esc(outcome)
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_build_info Build information for this UltraNix MCP binary.\n",
    );
    out.push_str("# TYPE ultranix_mcp_build_info gauge\n");
    if reg.build_info {
        let _ = writeln!(
            out,
            "ultranix_mcp_build_info{{version=\"{}\"}} 1",
            esc(env!("CARGO_PKG_VERSION"))
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_rate_limit_rejections_total Rate-limit (429) rejections by rejection reason.\n",
    );
    out.push_str("# TYPE ultranix_mcp_rate_limit_rejections_total counter\n");
    for (reason, n) in &reg.rate_rejections {
        let _ = writeln!(
            out,
            "ultranix_mcp_rate_limit_rejections_total{{reason=\"{}\"}} {n}",
            esc(reason)
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_auth_failures_total HTTP authentication failures by rejection reason.\n",
    );
    out.push_str("# TYPE ultranix_mcp_auth_failures_total counter\n");
    for (reason, n) in &reg.auth_failures {
        let _ = writeln!(
            out,
            "ultranix_mcp_auth_failures_total{{reason=\"{}\"}} {n}",
            esc(reason)
        );
    }

    out.push_str("# HELP ultranix_mcp_active_sessions Live sessions by transport.\n");
    out.push_str("# TYPE ultranix_mcp_active_sessions gauge\n");
    for (transport, n) in &reg.sessions {
        let _ = writeln!(
            out,
            "ultranix_mcp_active_sessions{{transport=\"{}\"}} {n}",
            esc(transport)
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_backend_active Backends that initialised at startup (1 = active).\n",
    );
    out.push_str("# TYPE ultranix_mcp_backend_active gauge\n");
    for (backend, n) in &reg.backends {
        let _ = writeln!(
            out,
            "ultranix_mcp_backend_active{{backend=\"{}\"}} {n}",
            esc(backend)
        );
    }

    out.push_str(
        "# HELP ultranix_mcp_action_history_size Records retained in the encrypted action history.\n",
    );
    out.push_str("# TYPE ultranix_mcp_action_history_size gauge\n");
    let _ = writeln!(out, "ultranix_mcp_action_history_size {}", reg.history_size);

    out.push_str(
        "# HELP ultranix_mcp_ocr_cache_entries Live entries in the ONNX vision OCR cache.\n",
    );
    out.push_str("# TYPE ultranix_mcp_ocr_cache_entries gauge\n");
    let _ = writeln!(
        out,
        "ultranix_mcp_ocr_cache_entries {}",
        reg.ocr_cache_entries
    );

    out
}

/// Escape a label value per the exposition spec: `\`, `"`, newline.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: the registry is process-global and shared across tests, so
    // every test uses label values unique to itself and asserts on its
    // own series lines rather than whole-output equality.

    #[test]
    fn counter_increments_per_tool_outcome_pair() {
        record_call("test_ctr_tool", Duration::from_millis(3), "ok");
        record_call("test_ctr_tool", Duration::from_millis(5), "ok");
        record_call("test_ctr_tool", Duration::from_millis(1), "error");
        let exp = exposition();
        assert!(
            exp.contains(
                "ultranix_mcp_tool_calls_total{tool=\"test_ctr_tool\",outcome=\"ok\"} 2\n"
            ),
            "{exp}"
        );
        assert!(exp.contains(
            "ultranix_mcp_tool_calls_total{tool=\"test_ctr_tool\",outcome=\"error\"} 1\n"
        ));
        assert!(exp.contains("# TYPE ultranix_mcp_tool_calls_total counter\n"));
    }

    #[test]
    fn backend_counter_increments_per_backend_outcome_pair() {
        record_call_with_backend(
            "test_backend_tool",
            "test-backend-counter",
            Duration::from_millis(2),
            "ok",
        );
        record_call_with_backend(
            "test_backend_tool",
            "test-backend-counter",
            Duration::from_millis(4),
            "ok",
        );
        record_call_with_backend(
            "test_backend_tool",
            "test-backend-counter",
            Duration::from_millis(1),
            "tool_error",
        );
        let exp = exposition();
        assert!(exp.contains(
            "ultranix_mcp_backend_calls_total{backend=\"test-backend-counter\",outcome=\"ok\"} 2\n"
        ));
        assert!(exp.contains(
            "ultranix_mcp_backend_calls_total{backend=\"test-backend-counter\",outcome=\"tool_error\"} 1\n"
        ));
        assert!(exp.contains("# TYPE ultranix_mcp_backend_calls_total counter\n"));
    }

    #[test]
    fn build_info_gauge_reports_package_version() {
        set_build_info();
        let exp = exposition();
        assert!(exp.contains(&format!(
            "ultranix_mcp_build_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(exp.contains("# TYPE ultranix_mcp_build_info gauge\n"));
    }

    #[test]
    fn duration_histogram_buckets_sum_count() {
        // 3 ms lands in le="0.005"; 700 ms in le="1".
        record_call("test_hist_tool", Duration::from_millis(3), "ok");
        record_call("test_hist_tool", Duration::from_millis(700), "ok");
        let exp = exposition();
        assert!(exp.contains(
            "ultranix_mcp_tool_duration_seconds_bucket{tool=\"test_hist_tool\",le=\"0.005\"} 1\n"
        ));
        // Buckets are cumulative: the 700 ms sample rolls up to le="1".
        assert!(exp.contains(
            "ultranix_mcp_tool_duration_seconds_bucket{tool=\"test_hist_tool\",le=\"1\"} 2\n"
        ));
        assert!(exp.contains(
            "ultranix_mcp_tool_duration_seconds_bucket{tool=\"test_hist_tool\",le=\"+Inf\"} 2\n"
        ));
        assert!(
            exp.contains("ultranix_mcp_tool_duration_seconds_count{tool=\"test_hist_tool\"} 2\n")
        );
        assert!(
            exp.contains("ultranix_mcp_tool_duration_seconds_sum{tool=\"test_hist_tool\"} 0.70")
        );
        assert!(exp.contains("# TYPE ultranix_mcp_tool_duration_seconds histogram\n"));
    }

    #[test]
    fn sessions_gauge_set_inc_dec() {
        set_sessions("test_transport", 3);
        set_sessions("test_transport", 2); // dec
        let exp = exposition();
        assert!(exp.contains("ultranix_mcp_active_sessions{transport=\"test_transport\"} 2\n"));
        assert!(exp.contains("# TYPE ultranix_mcp_active_sessions gauge\n"));
    }

    #[test]
    fn rate_rejection_counter_increments() {
        record_rate_rejection("test_cat");
        record_rate_rejection("test_cat");
        let exp = exposition();
        assert!(exp.contains("ultranix_mcp_rate_limit_rejections_total{reason=\"test_cat\"} 2\n"));
        assert!(exp.contains("# TYPE ultranix_mcp_rate_limit_rejections_total counter\n"));
    }

    #[test]
    fn exposition_is_well_formed_text_format() {
        record_call("test_fmt_tool", Duration::from_millis(1), "ok");
        let exp = exposition();
        assert!(exp.ends_with('\n'));
        for line in exp.lines() {
            if let Some(rest) = line.strip_prefix('#') {
                assert!(
                    rest.starts_with(" HELP") || rest.starts_with(" TYPE"),
                    "unexpected comment line: {line}"
                );
            } else {
                let (sample, value) = line
                    .rsplit_once(' ')
                    .unwrap_or_else(|| panic!("bad sample: {line}"));
                assert!(
                    sample.starts_with("ultranix_mcp_"),
                    "series outside the canonical prefix: {line}"
                );
                // Every sample value parses as a float (counters/gauges
                // are integers, which parse fine).
                value
                    .parse::<f64>()
                    .unwrap_or_else(|_| panic!("bad value: {line}"));
            }
        }
    }

    #[test]
    fn label_values_are_escaped() {
        set_sessions("te\"st\n\\x", 1);
        let exp = exposition();
        assert!(exp.contains("transport=\"te\\\"st\\n\\\\x\""));
    }

    #[test]
    fn auth_failure_counter_increments_per_reason() {
        record_auth_failure("test_missing");
        record_auth_failure("test_missing");
        record_auth_failure("test_expired_key");
        let exp = exposition();
        assert!(
            exp.contains("ultranix_mcp_auth_failures_total{reason=\"test_missing\"} 2\n"),
            "{exp}"
        );
        assert!(exp.contains("ultranix_mcp_auth_failures_total{reason=\"test_expired_key\"} 1\n"));
        assert!(exp.contains("# TYPE ultranix_mcp_auth_failures_total counter\n"));
    }

    #[test]
    fn backend_active_gauge_marks_registered_backends() {
        set_backend_active("test-backend-alpha");
        set_backend_active("test-backend-beta");
        // Re-registering the same backend stays at 1 (idempotent mark).
        set_backend_active("test-backend-alpha");
        let exp = exposition();
        assert!(
            exp.contains("ultranix_mcp_backend_active{backend=\"test-backend-alpha\"} 1\n"),
            "{exp}"
        );
        assert!(exp.contains("ultranix_mcp_backend_active{backend=\"test-backend-beta\"} 1\n"));
        assert!(exp.contains("# TYPE ultranix_mcp_backend_active gauge\n"));
    }

    #[test]
    fn unlabelled_gauges_emit_integer_series() {
        set_action_history_size(5);
        set_ocr_cache_entries(9);
        let exp = exposition();
        // These series carry no labels, so a parallel test can
        // legitimately overwrite the value between set and render -
        // assert the series exists, is typed a gauge, and carries an
        // integer rather than pinning the number.
        for name in [
            "ultranix_mcp_action_history_size",
            "ultranix_mcp_ocr_cache_entries",
        ] {
            let line = exp
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("missing series {name}:\n{exp}"));
            line.rsplit(' ')
                .next()
                .unwrap()
                .parse::<i64>()
                .unwrap_or_else(|_| panic!("bad gauge value: {line}"));
            assert!(exp.contains(&format!("# TYPE {name} gauge\n")), "{exp}");
        }
    }
}
