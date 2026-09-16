//! `tools/call` against `Providers::empty()`: every provider-backed tool
//! degrades to a typed `-32010 ProviderUnavailable` error instead of
//! panicking or failing silently (providers/mod.rs contract).

mod common;

use common::{
    TOOLS, args, assert_error_code, assert_success, call, is_provider_backed, valid_args,
};
use serde_json::json;
use ultranix_mcp::providers::Providers;

const PROVIDER_UNAVAILABLE: i32 = -32010;
const CONSENT_REQUIRED: i32 = -32015;
const HISTORY_ERROR: i32 = -32014;
const COMMAND_NOT_WHITELISTED: i32 = -32003;
const INVALID_PARAMS: i32 = -32602;

/// The 30 provider-backed tools must each return -32010 when their backend
/// slot is `None`.
#[tokio::test]
async fn provider_backed_tools_return_provider_unavailable() {
    let providers = Providers::empty();
    let mut covered = 0;
    for (name, _cat) in TOOLS {
        if !is_provider_backed(name) {
            continue;
        }
        covered += 1;
        // `screen_stream` lifecycle actions `status`/`stop` read server
        // state only; `start` is the action that resolves the capture slot.
        let a = if *name == "screen_stream" {
            args(json!({"action": "start"}))
        } else {
            valid_args(name)
        };
        let res = call(name, a, &providers).await;
        assert_error_code(&res, &[PROVIDER_UNAVAILABLE], name);
    }
    assert_eq!(
        covered, 30,
        "catalog drift: expected 30 provider-backed tools"
    );
}

/// Server-core tools never report -32010 — they have no provider slot.
#[tokio::test]
async fn server_core_tools_never_report_provider_unavailable() {
    let providers = Providers::empty();
    for (name, _cat) in TOOLS {
        if is_provider_backed(name) {
            continue;
        }
        // replay_action re-enters `call_tool` with the *recorded* tool, which
        // may be provider-backed — under an empty registry -32010 is the
        // honest outcome, so the core-only invariant does not apply to it.
        if *name == "replay_action" {
            continue;
        }
        let res = call(name, valid_args(name), &providers).await;
        if let Err(e) = res {
            assert_ne!(
                e.code.0, PROVIDER_UNAVAILABLE,
                "{name}: server-core tool must not yield -32010"
            );
        }
    }
}

/// The pure server-core tools succeed even with an empty registry.
#[tokio::test]
async fn sleep_metrics_spatial_focus_succeed_without_providers() {
    let providers = Providers::empty();
    for name in ["sleep", "metrics", "set_spatial_focus"] {
        let res = call(name, valid_args(name), &providers).await;
        assert_success(&res, name);
    }
}

/// Consent-gated server-core tools surface their gate, not a provider error.
#[tokio::test]
async fn gated_core_tools_challenge_or_run_without_providers() {
    let providers = Providers::empty();

    let res = call("system_command", valid_args("system_command"), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert!(
            [CONSENT_REQUIRED, COMMAND_NOT_WHITELISTED].contains(&e.code.0),
            "system_command: expected -32015/-32003, got {e:?}"
        ),
    }

    let res = call("clear_action_history", args(json!({})), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert!(
            [CONSENT_REQUIRED, HISTORY_ERROR].contains(&e.code.0),
            "clear_action_history: expected -32015/-32014, got {e:?}"
        ),
    }

    let res = call("replay_action", valid_args("replay_action"), &providers).await;
    match res {
        Ok(r) => assert!(r.is_error != Some(true)),
        Err(e) => assert!(
            [CONSENT_REQUIRED, INVALID_PARAMS, HISTORY_ERROR].contains(&e.code.0),
            "replay_action: unexpected code {e:?}"
        ),
    }
}

/// Invalid input still beats the provider check when schema validation
/// runs first — at minimum it must not be reported as -32010 success.
/// (Ordering is implementation-defined; we only pin that an invalid call
/// cannot succeed.)
#[tokio::test]
async fn invalid_args_with_empty_providers_do_not_succeed() {
    let providers = Providers::empty();
    for (name, _cat) in TOOLS {
        if !is_provider_backed(name) {
            continue;
        }
        let res = call(name, common::invalid_args(name), &providers).await;
        assert!(res.is_err(), "{name}: invalid args must not return Ok");
    }
}
