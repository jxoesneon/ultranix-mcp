//! Tool registry: schemas, categories, dispatch. Canonical catalog lives in
//! docs/TOOLS.md — this module is its compiled mirror (32 tools).

use rmcp::model::{CallToolResult, ErrorData, Tool};
use serde_json::Value;

use crate::providers::Providers;

/// All advertised tools, filtered by enabled categories (`None` = all).
pub fn list_tools(_categories: Option<&[String]>) -> Vec<Tool> {
    todo!("phase-0: populated by tool registry")
}

/// Dispatch a `tools/call` request into the provider layer.
pub async fn call_tool(
    _name: &str,
    _args: serde_json::Map<String, Value>,
    _providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    todo!("phase-0: dispatch")
}
