//! Plugin tools (3) — `plugin_list` / `plugin_run` / `plugin_reload` over
//! the declarative tool-macros in `<state-root>/plugins/*.json`
//! ([`crate::plugins`]).
//!
//! `plugin_run` is **not** itself consent-gated: its steps re-enter the
//! normal dispatch path — [`super::call_tool_secured`] when a
//! `SecurityContext` exists, [`super::call_tool`] otherwise — exactly
//! like `replay_action` re-dispatches the recorded call (admin.rs).
//! Destructive steps therefore challenge the consent gate on their own
//! `{caller, tool, args_hash}` binding, are audited, and land in action
//! history; the consent granted to `plugin_run`'s caller never covers a
//! step. A manifest that wants to thread a challenge token through
//! declares a `consent_token` string param and references
//! `${consent_token}` in the step args.
//!
//! Scanning is always fresh — every call rescans the manifest dir
//! (manifests are tiny; a live view beats cache invalidation), and
//! `plugin_reload` exists to surface *what loaded* and *what was
//! skipped*, not to flush state.

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{SecRef, invalid_params, json_result, parse_args, tool};
use crate::error::codes::PLUGIN_ERROR;
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

/// Borrowed security pipeline for the secured dispatch path — mirrors
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
/// pipeline per step — mirrors `admin::dispatch_secured`.
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
    Some(match name {
        "plugin_list" => plugin_list(args).await,
        "plugin_run" => plugin_run(args, providers, secured).await,
        "plugin_reload" => plugin_reload(args).await,
        _ => return None,
    })
}

/// The manifest dir for tool calls — the ambient state root
/// (`ULTRANIX_MCP_STATE_DIR` → `$HOME/.ultranix-mcp`). In production the
/// `SecurityContext` is built on this same root (main.rs), so the
/// secured path resolves the identical directory; the inner
/// `*_in(store)` functions take the store explicitly so tests stay
/// hermetic without env mutation.
fn ambient_store() -> PluginStore {
    PluginStore::ambient()
}

/// `PluginStore::scan` is blocking `std::fs` work — a directory listing
/// plus a read + JSON parse per manifest — so it runs on
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
            "file": s.file.display().to_string(),
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
/// schema, steps count.
fn plugin_json(p: &plugins::Plugin) -> Value {
    let m = &p.manifest;
    json!({
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "params": m.params.iter().map(|(k, s)| (k.clone(), json!({
            "type": s.ty.as_str(),
            "required": s.required,
            "description": s.description,
        }))).collect::<Map<String, Value>>(),
        "steps": m.steps.len(),
    })
}

/// Scan + resolve + run — the store-parameterized workhorse behind
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
    run_manifest(&plugin.manifest, params, providers, secured).await
}

/// Execute a validated manifest: bind params → per-step `${…}`
/// substitution → each step dispatched through the *same* path a direct
/// `tools/call` would take (`call_tool_secured` on the secured path,
/// `call_tool` otherwise — the `replay_action` mechanism), collecting
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
            // Unsupplied optional refs are caller-fixable → InvalidParams;
            // a Template fault is unreachable post-validation → step error.
            Err(e) => {
                return Err(if matches!(e, ParamError::Template(_)) {
                    step_error(manifest, i, &step.tool, e.to_string())
                } else {
                    invalid_params(format!("plugin_run: {e}"))
                });
            }
        };
        // Boxed re-dispatch (mirrors replay_action): plugin_run →
        // dispatch → plugin_run is an async-recursion cycle — the
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
            // The step's own JSON-RPC error keeps its code and data —
            // `-32015 ConsentRequired` (and its consent_token) must
            // survive for the client to retry — annotated with which
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

/// A step's `Err(e)` re-wrapped with plugin/step context. The inner
/// code is preserved (consent challenges stay `-32015`) and `data`
/// gains `plugin`/`step`/`step_tool` — `kind`, `consent_token`, and
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

/// A step-level failure with no inner JSON-RPC error — `isError`
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

/// Char-safe truncation to [`RESULT_SUMMARY_MAX`] — the history.rs
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

    /// Tempdir plugin root — hermetic, injected via `PluginStore::at`.
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
        // number — a text-substituted "0" would fail sleep's schema.
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
        // Step 0 sleeps fine; step 1 violates sleep's ms bound →
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

    /// WindowProvider that reports no windows — drives
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
        // window_control{focus} on a provider with no windows →
        // Ok(isError) → the chain stops with -32017 PluginStepError
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
        // Extra (undeclared) param — rejected, not ignored.
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
        // chars — proves `${who}` was substituted and `$${who}` stayed
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
        // dispatch — the -32015 (and its token) must propagate through
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
        // Every step went through call_tool_secured → audit.jsonl
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
        // The tool surface exposes only list/run/reload — read-only
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
}
