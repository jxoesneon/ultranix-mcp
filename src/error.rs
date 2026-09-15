//! Canonical error surface — mirrors docs/TOOLS.md error taxonomy.

use rmcp::model::ErrorCode;

/// JSON-RPC error codes used across the tool surface.
pub mod codes {
    /// Backend present in the registry but unavailable at call time.
    pub const PROVIDER_UNAVAILABLE: i32 = -32010;
    /// Destructive tool invoked without a valid consent token.
    pub const CONSENT_REQUIRED: i32 = -32015;
    /// Argument rejected by the command/path whitelist.
    pub const ARG_CONSTRAINT_VIOLATION: i32 = -32020;
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
