//! Plugin tools (3) - `plugin_list` / `plugin_run` / `plugin_reload` over
//! the declarative tool-macros in `<state-root>/plugins/*.json`
//! ([`crate::plugins`]).
//!
//! `plugin_run` is **not**itself consent-gated: its steps re-enter the
//! normal dispatch path - [`super::call_tool_secured`] when a
//! `SecurityContext` exists, [`super::call_tool`] otherwise - exactly
//! like `replay_action` re-dispatches the recorded call (admin.rs).
//! Destructive steps therefore challenge the consent gate on their own
//! `{caller, tool, args_hash}` binding, are audited, and land in action
//! history; the consent granted to `plugin_run`'s caller never covers a
//! step. A manifest that wants to thread a challenge token through
//! declares a `consent_token` string param and references
//! `${consent_token}` in the step args.
//!
//! Scanning is always fresh - every call rescans the manifest dir
//! (manifests are tiny; a live view beats cache invalidation), and
//! `plugin_reload` exists to surface *what loaded* and *what was
//! skipped*, not to flush state.
//!
//! [`dispatch_ctx`]'s catch-all arm additionally resolves *non-catalog*
//! names against the live plugin-tool registry (manifest `tool`
//! sections - [`crate::plugins::ToolRegistry`]): `deploy_notes{...}`
//! routes into the same manifest executor as
//! `plugin_run{name, params}` - never a bypass, since it sits inside
//! `call_tool_secured`'s policy/consent/audit pipeline. Unresolved
//! names return `None` and the caller reports `-32601` as before.

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{SecRef, invalid_params, json_result, parse_args, tool};
use crate::error::codes::{self, PLUGIN_ERROR};
use crate::plugins::{self, ParamError, PluginManifest, PluginStore};
use crate::providers::Providers;
use crate::security::history::RESULT_SUMMARY_MAX;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PluginRunParams {
    /// Plugin name as reported by `plugin_list`
    name: String,
    /// Parameter values for the manifest's declared `params` (object);
    /// undeclared keys are rejected
    params: Option<Map<String, Value>>,
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<NoParams>(
            "plugin_list",
            "List plugin tool-macros loaded from <state>/plugins/*.json (name, version, params schema, step count).",
        ),
        tool::<PluginRunParams>(
            "plugin_run",
            "Run a plugin tool-macro: executes its catalog-tool steps in order through the secured dispatch path (per-step consent gates still apply); stops on the first failing step.",
        ),
        tool::<NoParams>(
            "plugin_reload",
            "Rescan <state>/plugins and report loaded manifests plus skipped files (scanning is always live; this surfaces the diagnostics).",
        ),
    ]
}

/// Borrowed security pipeline for the secured dispatch path - mirrors
/// admin.rs `Secured`: lets `plugin_run` pass each step back through
/// `call_tool_secured` (consent re-challenge, audit, real
/// `system_command` exec) instead of an ungated dispatch.
#[derive(Clone, Copy)]
struct Secured<'a> {
    /// [`SecRef`] (not a bare `&SecurityContext`) so a step re-entering
    /// `call_tool_secured` keeps the `Arc` shared handle and its
    /// `spawn_blocking` audit path.
    security: SecRef<'a>,
    session_id: &'a str,
    key_id: Option<&'a str>,
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    dispatch_ctx(name, args, providers, None).await
}

/// Secured variant for `call_tool_secured` (via `super::dispatch_secured`):
/// identical to [`dispatch`] but `plugin_run` re-enters the full security
/// pipeline per step - mirrors `admin::dispatch_secured`.
pub(super) async fn dispatch_secured(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    security: SecRef<'_>,
    session_id: &str,
    key_id: Option<&str>,
) -> Option<Result<CallToolResult, ErrorData>> {
    dispatch_ctx(
        name,
        args,
        providers,
        Some(Secured {
            security,
            session_id,
            key_id,
        }),
    )
    .await
}

async fn dispatch_ctx(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Option<Result<CallToolResult, ErrorData>> {
    match name {
        "plugin_list" => Some(plugin_list(args).await),
        "plugin_run" => Some(plugin_run(args, providers, secured).await),
        "plugin_reload" => Some(plugin_reload(args).await),
        // A name no catalog leg claimed may be a plugin-exposed tool
        // (a manifest `tool` section - crate::plugins::ToolRegistry).
        // `None` here falls through to `unknown_tool` (-32601) in the
        // caller, keeping the catalog-miss error shape unchanged.
        _ => run_exposed_tool(&ambient_store(), name, args, providers, secured).await,
    }
}

/// The manifest dir for tool calls - the ambient state root
/// (`ULTRANIX_MCP_STATE_DIR` -> `$HOME/.ultranix-mcp`). In production the
/// `SecurityContext` is built on this same root (main.rs), so the
/// secured path resolves the identical directory; the inner
/// `*_in(store)` functions take the store explicitly so tests stay
/// hermetic without env mutation.
fn ambient_store() -> PluginStore {
    PluginStore::ambient()
}

/// `PluginStore::scan` is blocking `std::fs` work - a directory listing
/// plus a read + JSON parse per manifest - so it runs on
/// `tokio::task::spawn_blocking` instead of a runtime worker, the same
/// EFF-1 convention as the secured history append and
/// `clear_action_history`. The store is recreated inside the closure
/// from its (cheap-to-clone) dir so `&self` borrows never cross the
/// spawn boundary; a `JoinError` means the scan task panicked and maps
/// to `-32603 InternalError`.
async fn scan_blocking(store: &PluginStore) -> Result<plugins::Scan, ErrorData> {
    let dir = store.dir().to_path_buf();
    tokio::task::spawn_blocking(move || PluginStore::at(dir).scan())
        .await
        .map_err(|e| {
            ErrorData::new(
                ErrorCode::INTERNAL_ERROR,
                format!("plugin scan task panicked: {e}"),
                None,
            )
        })
}

async fn plugin_list(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    plugin_list_in(&ambient_store(), args).await
}

async fn plugin_list_in(
    store: &PluginStore,
    args: &Map<String, Value>,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("plugin_list", args)?;
    let scan = scan_blocking(store).await?;
    Ok(json_result(&Value::Array(
        scan.plugins.iter().map(plugin_json).collect(),
    )))
}

async fn plugin_reload(args: &Map<String, Value>) -> Result<CallToolResult, ErrorData> {
    plugin_reload_in(&ambient_store(), args).await
}

async fn plugin_reload_in(
    store: &PluginStore,
    args: &Map<String, Value>,
) -> Result<CallToolResult, ErrorData> {
    let _p: NoParams = parse_args("plugin_reload", args)?;
    let scan = scan_blocking(store).await?;
    Ok(json_result(&json!({
        "loaded": scan.plugins.len(),
        "plugins": scan.plugins.iter().map(plugin_json).collect::<Vec<_>>(),
        "skipped": scan.skipped.iter().map(|s| json!({
            // Basename only - absolute paths leak host filesystem layout
            // to any caller that can reach plugin_list/plugin_reload.
            "file": s.file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| s.file.display().to_string()),
            "error": s.error,
        })).collect::<Vec<_>>(),
    })))
}

async fn plugin_run(
    args: &Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Result<CallToolResult, ErrorData> {
    let p: PluginRunParams = parse_args("plugin_run", args)?;
    run_by_name(
        &ambient_store(),
        &p.name,
        p.params.unwrap_or_default(),
        providers,
        secured,
    )
    .await
}

/// `plugin_list` entry shape: name, version, description, params
/// schema, steps count - plus the registered `tool` name when the
/// manifest exposes itself in `tools/list` (`null` otherwise).
fn plugin_json(p: &plugins::Plugin) -> Value {
    let m = &p.manifest;
    json!({
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "tool": m.tool.as_ref().map(|t| json!({
            "name": t.name,
            "description": t.description,
        })),
        "params": m.params.iter().map(|(k, s)| (k.clone(), json!({
            "type": s.ty.as_str(),
            "required": s.required,
            "description": s.description,
        }))).collect::<Map<String, Value>>(),
        "steps": m.steps.len(),
    })
}

/// Scan + resolve + run - the store-parameterized workhorse behind
/// `plugin_run` (tests inject a tempdir store here).
async fn run_by_name(
    store: &PluginStore,
    name: &str,
    params: Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Result<CallToolResult, ErrorData> {
    let scan = scan_blocking(store).await?;
    let plugin = scan
        .plugins
        .iter()
        .find(|p| p.manifest.name == name)
        .ok_or_else(|| invalid_params(format!("plugin_run: no plugin named {name:?}")))?;
    if let Some(s) = secured {
        // Symmetric deny: `deny_tools` naming the exposed tool
        // (`deploy_notes`) *or* the manifest name (`deploy-notes`) -
        // either address `plugin_list` shows must bite a
        // `plugin_run{name: "deploy-notes"}` call. Same manifest,
        // either spelling.
        let role = s.security.policy.resolve(s.key_id);
        let denied_by_manifest = role.deny_tools.contains(&plugin.manifest.name);
        let denied_by_tool = plugin
            .manifest
            .tool
            .as_ref()
            .is_some_and(|t| role.deny_tools.contains(&t.name));
        if denied_by_manifest || denied_by_tool {
            return Err(plugin_run_denied(&plugin.manifest.name, role));
        }
    }
    run_manifest(&plugin.manifest, params, providers, secured).await
}

/// Execute a validated manifest: bind params -> per-step `${...}`
/// substitution -> each step dispatched through the *same* path a direct
/// `tools/call` would take (`call_tool_secured` on the secured path,
/// `call_tool` otherwise - the `replay_action` mechanism), collecting
/// truncated per-step results. Stops on the first error.
async fn run_manifest(
    manifest: &PluginManifest,
    params: Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Result<CallToolResult, ErrorData> {
    let bound = plugins::bind_params(manifest, params)
        .map_err(|e| invalid_params(format!("plugin_run: {e}")))?;
    let mut results = Vec::with_capacity(manifest.steps.len());
    for (i, step) in manifest.steps.iter().enumerate() {
        let step_args = match plugins::substitute_args(&step.args, &bound) {
            Ok(a) => a,
            // Unsupplied optional refs are caller-fixable -> InvalidParams;
            // a Template fault is unreachable post-validation -> step error.
            Err(e) => {
                return Err(if matches!(e, ParamError::Template(_)) {
                    step_error(manifest, i, &step.tool, e.to_string())
                } else {
                    invalid_params(format!("plugin_run: {e}"))
                });
            }
        };
        // Boxed re-dispatch (mirrors replay_action): plugin_run ->
        // dispatch -> plugin_run is an async-recursion cycle - the
        // indirection keeps the future sized (E0733).
        let inner = match secured {
            Some(s) => {
                Box::pin(super::call_tool_secured(
                    &step.tool,
                    step_args,
                    providers,
                    s.security,
                    s.session_id,
                    s.key_id,
                ))
                .await
            }
            None => Box::pin(super::call_tool(&step.tool, step_args, providers)).await,
        };
        match inner {
            // The step's own JSON-RPC error keeps its code and data -
            // `-32015 ConsentRequired` (and its consent_token) must
            // survive for the client to retry - annotated with which
            // step produced it.
            Err(e) => return Err(step_dispatch_error(manifest, i, &step.tool, e)),
            Ok(r) if r.is_error == Some(true) => {
                return Err(step_error(manifest, i, &step.tool, first_text(&r)));
            }
            Ok(r) => results.push(json!({
                "step": i,
                "tool": step.tool,
                "result": truncate(&first_text(&r)),
            })),
        }
    }
    Ok(json_result(&json!({
        "plugin": manifest.name,
        "steps_run": results.len(),
        "results": results,
    })))
}

// ---------------------------------------------------------------------------
// Plugin-exposed tools (`tool` manifest sections)
// ---------------------------------------------------------------------------

/// Dispatch arm for non-catalog names: resolve `name` against the live
/// plugin-tool registry (a manifest `tool` section) and run the owning
/// manifest - identical to `plugin_run{name: <plugin>, params: args}`
/// but addressed by the advertised tool name. `None` when no plugin
/// registers `name`: the caller's `unknown_tool` (-32601) then
/// reports the catalog miss unchanged.
///
/// This is the tail of `dispatch`/`dispatch_secured`, so an exposed
/// call passes through *the same* secured pipeline as a catalog tool -
/// `call_tool_secured` already policy-checked the tool's own name and
/// will audit/metric/history it under that name. What remains here is
/// the plugin-specific conjuncts a catalog miss cannot express: the
/// tool lives in `plugin_run`'s category (`admin`) and requires the
/// caller's role to allow `plugin_run`.
async fn run_exposed_tool(
    store: &PluginStore,
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
    secured: Option<Secured<'_>>,
) -> Option<Result<CallToolResult, ErrorData>> {
    let scan = match scan_blocking(store).await {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    let plugin = scan
        .plugins
        .iter()
        .find(|p| p.manifest.tool.as_ref().is_some_and(|t| t.name == name))?;
    if let Some(s) = secured {
        // Plugin tools are uncatalogued, so `call_tool_secured`'s
        // category gate cannot classify them - they inherit the gate
        // of the plugin machinery itself (`plugin_run` -> `admin`). A
        // server filtered to `mouse`-only must not expose them.
        if let Some(err) = category_disabled(name, s.security.categories.as_deref()) {
            return Some(Err(err));
        }
        // Implicit rule: a plugin tool is allowed iff `plugin_run` is
        // allowed AND the tool name passes the role's allow/deny (the
        // name half already ran in `call_tool_secured`; an allowlist
        // role that does not list the tool never reaches dispatch).
        let role = s.security.policy.resolve(s.key_id);
        // Symmetric deny: `deny_tools` naming the *plugin* (`deploy-
        // notes`) must bite its exposed tool (`deploy_notes`) too -
        // the manifest is reachable under either name.
        if !s.security.policy.is_tool_allowed(role, "plugin_run")
            || role.deny_tools.contains(&plugin.manifest.name)
        {
            return Some(Err(plugin_run_denied(name, role)));
        }
    }
    // The call's argument object *is* the manifest's `params` map -
    // the advertised inputSchema and `bind_params` describe the same
    // declared set.
    Some(run_manifest(&plugin.manifest, args.clone(), providers, secured).await)
}

/// `-32601 MethodNotFound` for a plugin-exposed tool when the server's
/// category set excludes `plugin_run`'s category (`admin`). Same wire
/// shape as `super::category_gate`, which cannot produce it itself -
/// plugin tool names are uncatalogued, so that gate returns `None`
/// for them.
fn category_disabled(name: &str, categories: Option<&[String]>) -> Option<ErrorData> {
    let cats = categories?;
    let cat = crate::tools::category_of("plugin_run").unwrap_or("admin");
    if cats.iter().any(|c| c == cat) {
        return None;
    }
    Some(ErrorData::new(
        ErrorCode::METHOD_NOT_FOUND,
        format!("tool disabled by category filter: {name}"),
        Some(json!({
            "kind": "CategoryDisabled",
            "category": cat,
            "tool": name,
        })),
    ))
}

/// Denial for the `plugin_run` conjunct of an exposed-tool call -
/// mirrors `super::policy_denied`'s wire shape (private there, so
/// reconstructed here): `denial_reason` distinguishes a readonly role
/// from an allow/deny-list rejection, and the message names the
/// *called* tool.
fn plugin_run_denied(name: &str, role: &crate::security::policy::Role) -> ErrorData {
    let reason = if role.readonly
        && !crate::security::policy::readonly_allowlist().contains(&"plugin_run")
    {
        "readonly_mode"
    } else {
        "not_in_tool_list"
    };
    let (code, kind) = if reason == "readonly_mode" {
        (codes::READ_ONLY_MODE, "ReadOnlyMode")
    } else {
        (codes::NOT_IN_TOOL_LIST, "NotInToolList")
    };
    ErrorData::new(
        ErrorCode(code),
        format!("{name} denied: {reason} (plugin tools require plugin_run)"),
        Some(json!({"kind": kind, "denial_reason": reason})),
    )
}

/// A step's `Err(e)` re-wrapped with plugin/step context. The inner
/// code is preserved (consent challenges stay `-32015`) and `data`
/// gains `plugin`/`step`/`step_tool` - `kind`, `consent_token`, and
/// `expires_in_ms` pass through untouched.
fn step_dispatch_error(manifest: &PluginManifest, i: usize, tool: &str, e: ErrorData) -> ErrorData {
    let data = match e.data {
        Some(Value::Object(mut o)) => {
            o.insert("plugin".into(), json!(manifest.name));
            o.insert("step".into(), json!(i));
            o.insert("step_tool".into(), json!(tool));
            Some(Value::Object(o))
        }
        Some(other) => Some(json!({
            "plugin": manifest.name,
            "step": i,
            "step_tool": tool,
            "inner": other,
        })),
        None => Some(json!({
            "plugin": manifest.name,
            "step": i,
            "step_tool": tool,
        })),
    };
    ErrorData::new(
        e.code,
        format!(
            "plugin_run {:?} step {i} ({tool}): {}",
            manifest.name, e.message
        ),
        data,
    )
}

/// A step-level failure with no inner JSON-RPC error - `isError`
/// results and post-validation template faults.
fn step_error(manifest: &PluginManifest, i: usize, tool: &str, detail: String) -> ErrorData {
    ErrorData::new(
        ErrorCode(PLUGIN_ERROR),
        format!(
            "plugin_run {:?} step {i} ({tool}) failed: {detail}",
            manifest.name
        ),
        Some(json!({
            "kind": "PluginStepError",
            "plugin": manifest.name,
            "step": i,
            "tool": tool,
            "detail": detail,
        })),
    )
}

/// First text block of a tool result (mirrors `result_summary` in
/// tools/mod.rs).
fn first_text(r: &CallToolResult) -> String {
    r.content
        .first()
        .and_then(ContentBlock::as_text)
        .map(|t| t.text.clone())
        .unwrap_or_else(|| "<non-text result>".into())
}

/// Char-safe truncation to [`RESULT_SUMMARY_MAX`] - the history.rs
/// convention for per-step result summaries.
fn truncate(s: &str) -> String {
    if s.chars().count() <= RESULT_SUMMARY_MAX {
        s.to_string()
    } else {
        s.chars().take(RESULT_SUMMARY_MAX).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::PluginStore;
    use crate::security::SecurityContext;
    use std::fs;

    const INVALID_PARAMS: i32 = -32602;
    const CONSENT_REQUIRED: i32 = -32015;
    const SESSION: &str = "plugin-test-session";

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().expect("test args must be an object").clone()
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    /// Tempdir plugin root - hermetic, injected via `PluginStore::at`.
    fn store_with(files: &[(&str, &str)]) -> (tempfile::TempDir, PluginStore) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        for (name, body) in files {
            fs::write(dir.join(name), body).unwrap();
        }
        let store = PluginStore::at(&dir);
        (tmp, store)
    }

    const SLEEP_PLUGIN: &str = r#"{
        "name": "nap",
        "version": "1.0.0",
        "description": "sleep then report metrics",
        "params": {"ms": {"type": "number", "required": true}},
        "steps": [
            {"tool": "sleep", "args": {"ms": "${ms}"}},
            {"tool": "metrics"}
        ]
    }"#;

    #[tokio::test]
    async fn tools_advertise_three_object_schemas() {
        let ts = tools();
        assert_eq!(ts.len(), 3);
        for t in &ts {
            assert_eq!(t.input_schema["type"], "object", "{}", t.name);
        }
        assert_eq!(ts[0].name.as_ref(), "plugin_list");
        assert_eq!(ts[1].name.as_ref(), "plugin_run");
        assert_eq!(ts[2].name.as_ref(), "plugin_reload");
    }

    #[tokio::test]
    async fn dispatch_ignores_foreign_names() {
        assert!(
            dispatch_ctx("sleep", &Map::new(), &Providers::empty(), None)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_empty_and_populated() {
        let (_t, store) = store_with(&[]);
        let res = plugin_list_in(&store, &Map::new()).await.unwrap();
        assert_eq!(text_of(&res), "[]");

        let (_t2, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        let res = plugin_list_in(&store, &Map::new()).await.unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "nap");
        assert_eq!(arr[0]["version"], "1.0.0");
        assert_eq!(arr[0]["description"], "sleep then report metrics");
        assert_eq!(arr[0]["steps"], 2);
        assert_eq!(arr[0]["params"]["ms"]["type"], "number");
        assert_eq!(arr[0]["params"]["ms"]["required"], true);
    }

    #[tokio::test]
    async fn reload_reports_loaded_and_skipped() {
        let (_t, store) = store_with(&[
            ("nap.json", SLEEP_PLUGIN),
            ("broken.json", "{not json"),
            (
                "unknown-tool.json",
                r#"{"name":"z","version":"1.0.0",
                "steps":[{"tool":"no_such_tool"}]}"#,
            ),
        ]);
        let res = plugin_reload_in(&store, &Map::new()).await.unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["loaded"], 1);
        assert_eq!(body["plugins"][0]["name"], "nap");
        let skipped = body["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 2);
        assert!(
            skipped
                .iter()
                .any(|s| s["error"].as_str().unwrap().contains("unknown tool")),
            "the nonexistent-tool manifest must surface its reason: {body}"
        );
    }

    #[tokio::test]
    async fn run_executes_macro_end_to_end() {
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        let res = run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["plugin"], "nap");
        assert_eq!(body["steps_run"], 2);
        let results = body["results"].as_array().unwrap();
        assert_eq!(results[0]["tool"], "sleep");
        assert_eq!(results[0]["result"], "Slept 0 ms");
        assert_eq!(results[1]["tool"], "metrics");
        assert!(
            results[1]["result"]
                .as_str()
                .unwrap()
                .contains("ultranix_mcp_tool_calls_total"),
            "metrics step result: {body}"
        );
    }

    #[tokio::test]
    async fn run_typed_substitution_feeds_sleep_a_number() {
        // `"ms": "${ms}"` whole-string substitution keeps the JSON
        // number - a text-substituted "0" would fail sleep's schema.
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn run_stops_on_first_failing_step() {
        // Step 0 sleeps fine; step 1 violates sleep's ms bound ->
        // InvalidParams propagates with the step index.
        let manifest = r#"{
            "name": "two-step",
            "version": "1.0.0",
            "steps": [
                {"tool": "sleep", "args": {"ms": 0}},
                {"tool": "sleep", "args": {"ms": 99999}},
                {"tool": "metrics"}
            ]
        }"#;
        let (_t, store) = store_with(&[("m.json", manifest)]);
        let err = run_by_name(&store, "two-step", Map::new(), &Providers::empty(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        assert!(err.message.contains("step 1"), "{}", err.message);
        assert_eq!(err.data.unwrap()["step"], 1);
    }

    /// WindowProvider that reports no windows - drives
    /// `window_control{focus}` onto its `isError` "no active window"
    /// path so a step-level tool error can be exercised end-to-end.
    struct NoWindows;

    #[async_trait::async_trait]
    impl crate::traits::WindowProvider for NoWindows {
        async fn list_windows(&self) -> anyhow::Result<Vec<crate::traits::WindowInfo>> {
            Ok(vec![])
        }
        async fn active_window(&self) -> anyhow::Result<Option<crate::traits::WindowInfo>> {
            Ok(None)
        }
        async fn dispatch(
            &self,
            _action: &str,
            _window_id: &str,
            _args: &Value,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_tool_error_result_stops_chain() {
        // window_control{focus} on a provider with no windows ->
        // Ok(isError) -> the chain stops with -32017 PluginStepError
        // naming the step.
        let manifest = r#"{
            "name": "focus-nowhere",
            "version": "1.0.0",
            "steps": [
                {"tool": "window_control", "args": {"action": "focus"}},
                {"tool": "metrics"}
            ]
        }"#;
        let (_t, store) = store_with(&[("m.json", manifest)]);
        let mut providers = Providers::empty();
        providers.window = Some(std::sync::Arc::new(NoWindows));

        let err = run_by_name(&store, "focus-nowhere", Map::new(), &providers, None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, PLUGIN_ERROR);
        let data = err.data.unwrap();
        assert_eq!(data["kind"], "PluginStepError");
        assert_eq!(data["step"], 0);
        assert_eq!(data["tool"], "window_control");
        assert!(err.message.contains("no active window"), "{}", err.message);
    }

    #[tokio::test]
    async fn run_unknown_plugin_is_invalid_params() {
        let (_t, store) = store_with(&[]);
        let err = run_by_name(&store, "ghost", Map::new(), &Providers::empty(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        assert!(err.message.contains("ghost"));
    }

    #[tokio::test]
    async fn run_rejects_bad_call_params() {
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        // Missing required.
        let err = run_by_name(&store, "nap", Map::new(), &Providers::empty(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // Extra (undeclared) param - rejected, not ignored.
        let err = run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0, "evil": true})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // Wrong type.
        let err = run_by_name(
            &store,
            "nap",
            args(json!({"ms": "zero"})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn run_embedded_substitution_in_larger_string() {
        let manifest = r#"{
            "name": "typer",
            "version": "1.0.0",
            "params": {"who": {"type": "string", "required": true}},
            "steps": [{"tool": "type_text",
                       "args": {"text": "hi ${who} $${who}", "delay_ms": 0}}]
        }"#;
        let (_t, store) = store_with(&[("t.json", manifest)]);
        let res = run_by_name(
            &store,
            "typer",
            args(json!({"who": "bob"})),
            &Providers::all_mocks(),
            None,
        )
        .await
        .unwrap();
        // type_text reports the char count: "hi bob ${who}" is 13
        // chars - proves `${who}` was substituted and `$${who}` stayed
        // literal by the time the step reached dispatch.
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["results"][0]["result"], "Typed 13 characters");
    }

    // --- secured path ---------------------------------------------------------

    fn secured_in<'a>(sec: &'a SecurityContext) -> Secured<'a> {
        Secured {
            security: SecRef::Borrowed(sec),
            session_id: SESSION,
            key_id: None,
        }
    }

    #[tokio::test]
    async fn run_through_secured_dispatch_executes() {
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();

        let res = run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["steps_run"], 2);
    }

    #[tokio::test]
    async fn run_destructive_step_rechallenges_consent() {
        // A gated step inside a plugin is challenged by the secured
        // dispatch - the -32015 (and its token) must propagate through
        // plugin_run's step-error wrapper.
        let manifest = r#"{
            "name": "sniper",
            "version": "1.0.0",
            "steps": [
                {"tool": "system_command", "args": {"command": "slurp"}}
            ]
        }"#;
        let (_t, store) = store_with(&[("s.json", manifest)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();

        let err = run_by_name(
            &store,
            "sniper",
            Map::new(),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, CONSENT_REQUIRED);
        let data = err.data.unwrap();
        // Inner consent shape preserved + step context added.
        assert_eq!(data["kind"], "ConsentRequired");
        assert_eq!(data["plugin"], "sniper");
        assert_eq!(data["step"], 0);
        let token = data["consent_token"].as_str().unwrap().to_string();
        // The token binds to the *step* call, not plugin_run.
        assert!(sec.consent.verify(
            &token,
            None,
            SESSION,
            "system_command",
            &json!({"command": "slurp"}),
            None,
        ));
    }

    #[tokio::test]
    async fn run_secured_records_audit_for_each_step() {
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap();
        // Every step went through call_tool_secured -> audit.jsonl
        // carries one record per step.
        let audit = fs::read_to_string(sec_tmp.path().join("logs/audit.jsonl")).unwrap();
        let lines: Vec<&str> = audit.lines().collect();
        assert_eq!(lines.len(), 2, "one audit record per step: {audit}");
        assert!(audit.contains("\"tool\":\"sleep\""), "{audit}");
        assert!(audit.contains("\"tool\":\"metrics\""), "{audit}");
    }

    // --- no manifest-mutation surface ----------------------------------------

    #[tokio::test]
    async fn plugin_tools_cannot_write_manifests() {
        // The tool surface exposes only list/run/reload - read-only
        // scans. Assert the whole cycle leaves the dir byte-identical.
        let (_t, store) = store_with(&[("nap.json", SLEEP_PLUGIN)]);
        let before: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        plugin_list_in(&store, &Map::new()).await.unwrap();
        plugin_reload_in(&store, &Map::new()).await.unwrap();
        run_by_name(
            &store,
            "nap",
            args(json!({"ms": 0})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap();
        let after: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        // And a scan never materializes a missing dir.
        let tmp = tempfile::tempdir().unwrap();
        let missing = PluginStore::at(tmp.path().join("nope"));
        missing.scan();
        assert!(!missing.dir().exists());
    }

    // --- plugin-exposed tools (`tool` manifest sections) --------------------

    const EXPOSED_PLUGIN: &str = r#"{
        "name": "deploy-notes",
        "version": "1.0.0",
        "tool": {
            "name": "deploy_notes",
            "description": "Deploy the notes bundle",
            "params": {"ms": {"type": "number", "required": true}}
        },
        "steps": [
            {"tool": "sleep", "args": {"ms": "${ms}"}},
            {"tool": "metrics"}
        ]
    }"#;

    #[tokio::test]
    async fn exposed_tool_executes_manifest_steps() {
        // deploy_notes{ms} == plugin_run{name: "deploy-notes", params: {ms}}.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let res = run_exposed_tool(
            &store,
            "deploy_notes",
            &args(json!({"ms": 0})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap()
        .unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body["plugin"], "deploy-notes");
        assert_eq!(body["steps_run"], 2);
        assert_eq!(body["results"][0]["tool"], "sleep");
    }

    #[tokio::test]
    async fn exposed_tool_bind_errors_are_invalid_params() {
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        // Missing required param.
        let err = run_exposed_tool(
            &store,
            "deploy_notes",
            &Map::new(),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
        // Undeclared param - strict, same as plugin_run.
        let err = run_exposed_tool(
            &store,
            "deploy_notes",
            &args(json!({"ms": 0, "evil": true})),
            &Providers::empty(),
            None,
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code.0, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn unregistered_tool_name_falls_through() {
        // `None` -> the caller reports -32601 unknown tool, unchanged.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        assert!(
            run_exposed_tool(&store, "nope", &Map::new(), &Providers::empty(), None)
                .await
                .is_none()
        );
        // ...and a name that could never be a legal tool name too.
        assert!(
            run_exposed_tool(&store, "no-such", &Map::new(), &Providers::empty(), None)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn exposed_tool_requires_plugin_run_allowed() {
        // The implicit conjunct: a role that denies `plugin_run` cannot
        // call plugin tools even when the tool's own name passes.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.deny_tools.insert("plugin_run".to_string());
        sec.set_policy(p);
        let err = run_exposed_tool(
            &store,
            "deploy_notes",
            &args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }

    #[tokio::test]
    async fn exposed_tool_inherits_plugin_run_category_gate() {
        // Plugin tools live in `admin` - a `mouse`-only server must
        // not dispatch them (MethodNotFound + CategoryDisabled).
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        sec.categories = Some(vec!["mouse".to_string()]);
        let err = run_exposed_tool(
            &store,
            "deploy_notes",
            &args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::METHOD_NOT_FOUND);
        assert_eq!(err.data.unwrap()["kind"], "CategoryDisabled");
    }

    #[tokio::test]
    async fn secured_dispatch_routes_exposed_tool_by_name() {
        // End-to-end through call_tool_secured: the ambient store is
        // the registry - pin ULTRANIX_MCP_STATE_DIR to this test's
        // root. The env is process-wide, so keep the window tight and
        // restore it; scans are read-only, so a parallel test's ambient
        // read is at worst a listing of this dir.
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("d.json"), EXPOSED_PLUGIN).unwrap();
        let prev = std::env::var_os("ULTRANIX_MCP_STATE_DIR");
        unsafe { std::env::set_var("ULTRANIX_MCP_STATE_DIR", state.path()) };
        let sec_tmp = tempfile::tempdir().unwrap();
        let sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let res = crate::tools::call_tool_secured(
            "deploy_notes",
            args(json!({"ms": 0})),
            &Providers::empty(),
            &sec,
            SESSION,
            None,
        )
        .await;
        match prev {
            Some(v) => unsafe { std::env::set_var("ULTRANIX_MCP_STATE_DIR", v) },
            None => unsafe { std::env::remove_var("ULTRANIX_MCP_STATE_DIR") },
        }
        let body: Value = serde_json::from_str(&text_of(&res.unwrap())).unwrap();
        assert_eq!(body["plugin"], "deploy-notes");
        // Audited under the *tool* name; steps under their own.
        let audit = fs::read_to_string(sec_tmp.path().join("logs/audit.jsonl")).unwrap();
        assert!(audit.contains("\"tool\":\"deploy_notes\""), "{audit}");
        assert!(audit.contains("\"tool\":\"sleep\""), "{audit}");
    }

    #[tokio::test]
    async fn policy_denylist_denies_exposed_tool_name() {
        // `deny_tools: ["deploy_notes"]` bites in call_tool_secured's
        // primary policy check - before dispatch, so no manifest is
        // needed.
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.deny_tools.insert("deploy_notes".to_string());
        sec.set_policy(p);
        let err = crate::tools::call_tool_secured(
            "deploy_notes",
            Map::new(),
            &Providers::empty(),
            &sec,
            SESSION,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
        let audit = fs::read_to_string(sec_tmp.path().join("logs/audit.jsonl")).unwrap();
        assert!(audit.contains("\"tool\":\"deploy_notes\""), "{audit}");
        assert!(audit.contains("\"denied\""), "{audit}");
    }

    #[tokio::test]
    async fn allowlist_role_denies_unlisted_exposed_tool() {
        // `allow_tools` without the plugin tool's name -> denied by the
        // primary check, consistent with `Role::allows` semantics.
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.allow_tools = Some(
            ["plugin_run".to_string(), "metrics".to_string()]
                .into_iter()
                .collect(),
        );
        sec.set_policy(p);
        let err = crate::tools::call_tool_secured(
            "deploy_notes",
            Map::new(),
            &Providers::empty(),
            &sec,
            SESSION,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }

    #[tokio::test]
    async fn plugin_list_surfaces_exposed_tool_name() {
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let res = plugin_list_in(&store, &Map::new()).await.unwrap();
        let body: Value = serde_json::from_str(&text_of(&res)).unwrap();
        assert_eq!(body[0]["tool"]["name"], "deploy_notes");
        assert_eq!(body[0]["tool"]["description"], "Deploy the notes bundle");
    }

    #[tokio::test]
    async fn denylist_plugin_name_denies_exposed_tool() {
        // Symmetric deny: `deny_tools: ["deploy-notes"]` (the plugin
        // name) must bite the exposed `deploy_notes` tool - the
        // manifest is reachable under either name.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.deny_tools.insert("deploy-notes".to_string());
        sec.set_policy(p);
        let err = run_exposed_tool(
            &store,
            "deploy_notes",
            &args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }

    #[tokio::test]
    async fn denylist_exposed_name_denies_plugin_run() {
        // The other direction: `deny_tools: ["deploy_notes"]` blocks
        // the tool AND `plugin_run{name: "deploy-notes"}` - otherwise
        // the name-addressed path would bypass the tool deny.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.deny_tools.insert("deploy_notes".to_string());
        sec.set_policy(p);
        let err = run_by_name(
            &store,
            "deploy-notes",
            args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }

    #[tokio::test]
    async fn denylist_manifest_name_denies_plugin_run() {
        // Full symmetry: `deny_tools: ["deploy-notes"]` - the name
        // `plugin_list` shows - must bite the name-addressed
        // `plugin_run` call too, not only the exposed `deploy_notes`.
        let (_t, store) = store_with(&[("d.json", EXPOSED_PLUGIN)]);
        let sec_tmp = tempfile::tempdir().unwrap();
        let mut sec = SecurityContext::new(sec_tmp.path(), false, false).unwrap();
        let mut p = crate::security::policy::Policy::default();
        p.default_role.deny_tools.insert("deploy-notes".to_string());
        sec.set_policy(p);
        let err = run_by_name(
            &store,
            "deploy-notes",
            args(json!({"ms": 0})),
            &Providers::empty(),
            Some(secured_in(&sec)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code.0, codes::NOT_IN_TOOL_LIST);
    }
}
