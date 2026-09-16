//! Canonical error surface - mirrors docs/TOOLS.md error taxonomy.

use rmcp::model::ErrorCode;

/// JSON-RPC error codes used across the tool surface.
pub mod codes {
    /// Command outside the whitelist / argument constraint violation
    /// (docs/TOOLS.md error table - both share `-32003`).
    pub const COMMAND_NOT_WHITELISTED: i32 = -32003;
    /// Argument rejected by the command whitelist.
    pub const ARG_CONSTRAINT_VIOLATION: i32 = -32003;
    /// Path argument outside the path whitelist roots.
    pub const PATH_NOT_WHITELISTED: i32 = -32004;
    /// Input rejected by the sanitization layer (metachars, control bytes).
    pub const SANITIZATION_REJECTED: i32 = -32006;
    /// Backend present in the registry but unavailable at call time.
    pub const PROVIDER_UNAVAILABLE: i32 = -32010;
    /// Destructive tool invoked without a valid consent token.
    pub const CONSENT_REQUIRED: i32 = -32015;
    /// A `plugin_run` step failed at the tool level (`isError` result)
    /// or a post-validation template fault surfaced. JSON-RPC errors
    /// from the inner dispatch keep their own code (so `-32015
    /// ConsentRequired` survives intact).
    pub const PLUGIN_ERROR: i32 = -32017;
    /// Tool denied because the server is in `--readonly` mode.
    pub const READ_ONLY_MODE: i32 = -32018;
    /// Tool denied because it is outside the caller's per-tool allowlist
    /// or inside its denylist (docs/adr/0010-policy-controls.md).
    pub const NOT_IN_TOOL_LIST: i32 = -32019;
}

/// Tool-level failures that map onto MCP `CallToolResult` / JSON-RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum UltraNixError {
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(&'static str),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("consent required: {0}")]
    ConsentRequired(String),
    #[error("argument constraint violation: {0}")]
    ArgConstraintViolation(String),
    #[error("backend error: {0}")]
    Backend(#[from] anyhow::Error),
}

impl UltraNixError {
    /// Map onto the JSON-RPC error code declared for this failure class.
    pub fn code(&self) -> i32 {
        match self {
            Self::ProviderUnavailable(_) => codes::PROVIDER_UNAVAILABLE,
            Self::InvalidParams(_) => ErrorCode::INVALID_PARAMS.0,
            Self::ConsentRequired(_) => codes::CONSENT_REQUIRED,
            Self::ArgConstraintViolation(_) => codes::ARG_CONSTRAINT_VIOLATION,
            Self::Backend(_) => ErrorCode::INTERNAL_ERROR.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_maps_to_its_documented_code() {
        assert_eq!(
            UltraNixError::ProviderUnavailable("capture").code(),
            codes::PROVIDER_UNAVAILABLE
        );
        assert_eq!(
            UltraNixError::InvalidParams("missing `x`".into()).code(),
            ErrorCode::INVALID_PARAMS.0
        );
        assert_eq!(
            UltraNixError::ConsentRequired("system_command".into()).code(),
            codes::CONSENT_REQUIRED
        );
        assert_eq!(
            UltraNixError::ArgConstraintViolation("dispatch exec".into()).code(),
            codes::ARG_CONSTRAINT_VIOLATION
        );
        assert_eq!(
            UltraNixError::Backend(anyhow::anyhow!("screencopy denied")).code(),
            ErrorCode::INTERNAL_ERROR.0
        );
    }

    #[test]
    fn code_constants_match_tools_taxonomy() {
        // docs/TOOLS.md freezes these values on the wire.
        assert_eq!(codes::COMMAND_NOT_WHITELISTED, -32003);
        assert_eq!(codes::ARG_CONSTRAINT_VIOLATION, -32003);
        assert_eq!(codes::PATH_NOT_WHITELISTED, -32004);
        assert_eq!(codes::SANITIZATION_REJECTED, -32006);
        assert_eq!(codes::PROVIDER_UNAVAILABLE, -32010);
        assert_eq!(codes::CONSENT_REQUIRED, -32015);
        assert_eq!(codes::PLUGIN_ERROR, -32017);
        assert_eq!(codes::READ_ONLY_MODE, -32018);
        assert_eq!(codes::NOT_IN_TOOL_LIST, -32019);
    }

    #[test]
    fn display_strings_embed_the_context() {
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
            UltraNixError::ArgConstraintViolation("hyprctl exec".into()).to_string(),
            "argument constraint violation: hyprctl exec"
        );
        assert_eq!(
            UltraNixError::Backend(anyhow::anyhow!("dbus gone")).to_string(),
            "backend error: dbus gone"
        );
    }

    #[test]
    fn anyhow_converts_into_backend_variant() {
        let err: UltraNixError = anyhow::anyhow!("boom").into();
        assert!(matches!(err, UltraNixError::Backend(_)));
        assert_eq!(err.code(), ErrorCode::INTERNAL_ERROR.0);
        // Debug derive stays informative for log/metrics paths.
        assert!(format!("{err:?}").contains("Backend"));
    }
}
