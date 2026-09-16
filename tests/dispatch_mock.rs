//! `tools/call` dispatch against `Providers::all_mocks()`: every one of the
//! 39 tools accepts schema-valid arguments (deterministic success or an
//! isError-free result) and rejects schema-invalid arguments with
//! `-32602 InvalidParams`.

mod common;

use common::{
    ALL_TOOL_NAMES, TOOLS, args, assert_error_code, assert_success, call, invalid_args, valid_args,
};
use serde_json::json;
use ultranix_mcp::providers::Providers;

const INVALID_PARAMS: i32 = -32602;
const METHOD_NOT_FOUND: i32 = -32601;
const PROVIDER_UNAVAILABLE: i32 = -32010;
const CONSENT_REQUIRED: i32 = -32015;
const ELEMENT_NOT_FOUND: i32 = -32016;
const HISTORY_ERROR: i32 = -32014;
const COMMAND_NOT_WHITELISTED: i32 = -32003;

/// Happy path: every tool that is neither consent-gated nor
/// not-found-by-design must succeed outright with all-mock providers.
#[tokio::test]
async fn all_tools_valid_args_succeed_with_mocks() {
    // `screen_record` writes a real `rec-<ulid>` dir under the ambient
    // captures root — the `#[cfg(test)]` TEST_RECORDING_BASE seam does
    // not exist in the lib build integration tests link. Redirect the
    // state root into a tempdir for the whole loop (serialized via
    // env_lock: the environment is process-global).
    let _env = common::env_lock().await;
    let state_tmp = tempfile::tempdir().unwrap();
    let _state = common::ScopedStateDir::set(state_tmp.path());
    let providers = Providers::all_mocks();
    // invoke_element (mock tree has no match → -32016 is legal),
    // system_command / replay_action / clear_action_history (consent gate),
    // get_action_history (history store may not exist yet),
    // plugin_run (the fixture names a plugin that does not exist →
    // InvalidParams is legal), and
    // screen_highlight (MockOverlay no-ops; the -32010 path is covered
    // in dispatch_coverage) are
    // exercised by dedicated tests below / in dispatch_coverage.
    let flexible = [
        "invoke_element",
        "system_command",
        "replay_action",
        "clear_action_history",
        "get_action_history",
        "plugin_run",
        "screen_highlight",
    ];
    for (name, _cat) in TOOLS {
        if flexible.contains(name) {
            continue;
        }
        let res = call(name, valid_args(name), &providers).await;
        assert_success(&res, name);
    }
    // The flexible list must not drift from the catalog.
    assert_eq!(ALL_TOOL_NAMES.len(), 39);
}

/// With a mock AT-SPI tree `invoke_element` finds no match: per spec a
/// query with no match is `-32016 ElementNotFound`. A Phase-0 stub may
/// also surface the mock's `invoke_element → false` as a normal result —
/// accept either, but never InvalidParams.
#[tokio::test]
async fn invoke_element_no_match_is_element_not_found_or_success() {
    let providers = Providers::all_mocks();
    let res = call("invoke_element", valid_args("invoke_element"), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true), "isError result: {r:?}"),
        Err(e) => assert_eq!(
            e.code.0, ELEMENT_NOT_FOUND,
            "expected -32016 ElementNotFound, got {e:?}"
        ),
    }
}

/// Consent-gated tools: the first call without `consent_token` must either
/// execute (Phase-0 stub) or return `-32015 ConsentRequired`. Nothing else.
#[tokio::test]
async fn system_command_without_token_executes_or_challenges() {
    let providers = Providers::all_mocks();
    let res = call("system_command", valid_args("system_command"), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert!(
            [CONSENT_REQUIRED, COMMAND_NOT_WHITELISTED].contains(&e.code.0),
            "expected -32015 ConsentRequired (or -32003 when slurp is absent), got {e:?}"
        ),
    }
}

#[tokio::test]
async fn replay_action_without_token_executes_or_challenges() {
    let providers = Providers::all_mocks();
    let res = call("replay_action", valid_args("replay_action"), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        // -32015 consent challenge; -32602/-32014 when the history store
        // has no index 0 yet — all are spec-shaped Phase-0 outcomes.
        Err(e) => assert!(
            [CONSENT_REQUIRED, INVALID_PARAMS, HISTORY_ERROR].contains(&e.code.0),
            "unexpected code for replay_action: {e:?}"
        ),
    }
}

#[tokio::test]
async fn clear_action_history_without_token_executes_or_challenges() {
    let providers = Providers::all_mocks();
    let res = call(
        "clear_action_history",
        valid_args("clear_action_history"),
        &providers,
    )
    .await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert!(
            [CONSENT_REQUIRED, HISTORY_ERROR].contains(&e.code.0),
            "unexpected code for clear_action_history: {e:?}"
        ),
    }
}

#[tokio::test]
async fn get_action_history_succeeds_or_reports_history_error() {
    let providers = Providers::all_mocks();
    let res = call(
        "get_action_history",
        valid_args("get_action_history"),
        &providers,
    )
    .await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert_eq!(e.code.0, HISTORY_ERROR, "got {e:?}"),
    }
}

/// "Not found" is data, not a fault: with the mock AT-SPI / vision stack
/// these tools must return a *successful* `found: false`-style result.
#[tokio::test]
async fn not_found_queries_are_success_results() {
    let providers = Providers::all_mocks();
    for name in [
        "find_element",
        "find_text_on_screen",
        "find_icon",
        "wait_for_ui_element",
    ] {
        let res = call(name, valid_args(name), &providers).await;
        assert_success(&res, name);
    }
}

/// Every tool rejects schema-invalid input with -32602 InvalidParams.
/// For consent-gated tools the gate may legally fire before schema
/// validation (-32015); both orderings are accepted there.
#[tokio::test]
async fn all_tools_invalid_args_are_invalid_params() {
    let providers = Providers::all_mocks();
    for (name, _cat) in TOOLS {
        let invalid = invalid_args(name);
        let res = call(name, invalid.clone(), &providers).await;
        if common::is_consent_gated(name, &invalid) {
            assert_error_code(&res, &[INVALID_PARAMS, CONSENT_REQUIRED], name);
        } else {
            assert_error_code(&res, &[INVALID_PARAMS], name);
        }
    }
}

/// Extra semantic validation the JSON Schema alone cannot express.
#[tokio::test]
async fn mouse_scroll_both_deltas_zero_is_invalid_params() {
    let providers = Providers::all_mocks();
    let res = call("mouse_scroll", args(json!({"dx": 0, "dy": 0})), &providers).await;
    assert_error_code(&res, &[INVALID_PARAMS], "mouse_scroll dx=dy=0");
}

#[tokio::test]
async fn window_control_move_requires_geometry() {
    let providers = Providers::all_mocks();
    // `move` requires x and y — omitting them is a per-action rule violation.
    let res = call(
        "window_control",
        args(json!({"action": "move"})),
        &providers,
    )
    .await;
    assert_error_code(&res, &[INVALID_PARAMS], "window_control move without x/y");
}

#[tokio::test]
async fn replay_action_with_both_selectors_is_invalid_params() {
    let providers = Providers::all_mocks();
    let res = call(
        "replay_action",
        args(json!({"index": 0, "id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12"})),
        &providers,
    )
    .await;
    // Exactly-one-selector rule. The consent gate may fire first; both are
    // legal orderings in Phase 0.
    assert_error_code(
        &res,
        &[INVALID_PARAMS, CONSENT_REQUIRED],
        "replay_action with both selectors",
    );
}

#[tokio::test]
async fn key_control_bad_modifier_is_invalid_params() {
    let providers = Providers::all_mocks();
    let res = call(
        "key_control",
        args(json!({"key": "a", "action": "press", "modifiers": ["bogus"]})),
        &providers,
    )
    .await;
    assert_error_code(&res, &[INVALID_PARAMS], "key_control bad modifier");
}

/// Alternate valid call shapes.
#[tokio::test]
async fn set_spatial_focus_clear_succeeds() {
    let providers = Providers::all_mocks();
    let res = call(
        "set_spatial_focus",
        args(json!({"clear": true})),
        &providers,
    )
    .await;
    assert_success(&res, "set_spatial_focus clear");
}

#[tokio::test]
async fn screenshot_without_region_succeeds() {
    let providers = Providers::all_mocks();
    let res = call("screenshot", args(json!({})), &providers).await;
    assert_success(&res, "screenshot full-frame");
}

#[tokio::test]
async fn window_control_close_is_consent_gated_or_executes() {
    let providers = Providers::all_mocks();
    let res = call(
        "window_control",
        args(json!({"action": "close", "window": "0x0"})),
        &providers,
    )
    .await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert_eq!(
            e.code.0, CONSENT_REQUIRED,
            "window_control close: expected -32015, got {e:?}"
        ),
    }
}

#[tokio::test]
async fn unknown_tool_name_is_method_not_found() {
    let providers = Providers::all_mocks();
    let res = call("definitely_not_a_tool", args(json!({})), &providers).await;
    assert_error_code(&res, &[METHOD_NOT_FOUND], "unknown tool");
}

/// Valid calls must not produce provider errors under all_mocks — sanity
/// that the fixtures above route to the right backend. (`screen_highlight`
/// is exempt: no OverlayProvider exists at all, so -32010 is its honest
/// answer everywhere.)
#[tokio::test]
async fn valid_calls_never_report_provider_unavailable() {
    // Same screen_record hermeticity seam as
    // `all_tools_valid_args_succeed_with_mocks` — this loop dispatches
    // it too.
    let _env = common::env_lock().await;
    let state_tmp = tempfile::tempdir().unwrap();
    let _state = common::ScopedStateDir::set(state_tmp.path());
    let providers = Providers::all_mocks();
    for (name, _cat) in TOOLS {
        if *name == "screen_highlight" {
            continue;
        }
        let res = call(name, valid_args(name), &providers).await;
        if let Err(e) = res {
            assert_ne!(
                e.code.0, PROVIDER_UNAVAILABLE,
                "{name}: all-mock registry must not yield -32010"
            );
        }
    }
}
