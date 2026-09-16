//! `UltraNixError::code()` mapping — every variant lands on the JSON-RPC
//! code declared by the docs/TOOLS.md error taxonomy.

use anyhow::anyhow;
use rmcp::model::ErrorCode;
use ultranix_mcp::error::{UltraNixError, codes};

#[test]
fn codes_module_constants_match_spec() {
    assert_eq!(codes::COMMAND_NOT_WHITELISTED, -32003);
    assert_eq!(codes::ARG_CONSTRAINT_VIOLATION, -32003);
    assert_eq!(codes::PATH_NOT_WHITELISTED, -32004);
    assert_eq!(codes::SANITIZATION_REJECTED, -32006);
    assert_eq!(codes::PROVIDER_UNAVAILABLE, -32010);
    assert_eq!(codes::CONSENT_REQUIRED, -32015);
    assert_eq!(codes::PLUGIN_ERROR, -32017);
}

#[test]
fn provider_unavailable_maps_to_32010() {
    let err = UltraNixError::ProviderUnavailable("capture");
    assert_eq!(err.code(), -32010);
    assert_eq!(err.code(), codes::PROVIDER_UNAVAILABLE);
}

#[test]
fn invalid_params_maps_to_jsonrpc_invalid_params() {
    let err = UltraNixError::InvalidParams("missing `x`".into());
    assert_eq!(err.code(), -32602);
    assert_eq!(err.code(), ErrorCode::INVALID_PARAMS.0);
}

#[test]
fn consent_required_maps_to_32015() {
    let err = UltraNixError::ConsentRequired("system_command".into());
    assert_eq!(err.code(), -32015);
    assert_eq!(err.code(), codes::CONSENT_REQUIRED);
}

#[test]
fn arg_constraint_violation_maps_to_32003() {
    let err = UltraNixError::ArgConstraintViolation("hyprctl dispatch exec".into());
    assert_eq!(err.code(), -32003);
    assert_eq!(err.code(), codes::ARG_CONSTRAINT_VIOLATION);
}

#[test]
fn backend_maps_to_jsonrpc_internal_error() {
    let err = UltraNixError::Backend(anyhow!("screencopy denied"));
    assert_eq!(err.code(), -32603);
    assert_eq!(err.code(), ErrorCode::INTERNAL_ERROR.0);
}

#[test]
fn anyhow_converts_into_backend_variant() {
    let err: UltraNixError = anyhow!("boom").into();
    assert!(matches!(err, UltraNixError::Backend(_)));
    assert_eq!(err.code(), -32603);
}

#[test]
fn display_messages_carry_context() {
    assert_eq!(
        UltraNixError::ProviderUnavailable("vision").to_string(),
        "provider unavailable: vision"
    );
    assert_eq!(
        UltraNixError::InvalidParams("bad enum".into()).to_string(),
        "invalid params: bad enum"
    );
    assert_eq!(
        UltraNixError::ConsentRequired("replay_action".into()).to_string(),
        "consent required: replay_action"
    );
    assert_eq!(
        UltraNixError::ArgConstraintViolation("dispatch exec".into()).to_string(),
        "argument constraint violation: dispatch exec"
    );
    assert_eq!(
        UltraNixError::Backend(anyhow!("dbus gone")).to_string(),
        "backend error: dbus gone"
    );
}
