//! Clipboard tools (3) - `ClipboardProvider` injection: `clipboard_get`
//! reads text (or enumerates MIME types), `clipboard_set`/`clipboard_clear`
//! overwrite or drop the user's clipboard.
//!
//! `clipboard_set` and `clipboard_clear` are in the destructive consent
//! class - overwriting a clipboard destroys user state and can inject
//! hostile content into the next paste. The gate lives upstream in
//! `super::is_destructive` (`call_tool_secured` challenges before
//! dispatch); by the time a call reaches this module the token is already
//! verified, and the params only carry `consent_token` so the challenged
//! schema matches what the client retries with.
//!
//! Reads are text-only by design - binary MIME payloads never move
//! through the provider boundary (see [`crate::traits::ClipboardProvider`]).

use rmcp::model::{CallToolResult, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    backend, invalid_params, json_result, parse_args, provider_unavailable, text_result, tool,
};
use crate::providers::Providers;
use crate::traits::ClipboardProvider;

/// `clipboard_set` payload cap - 1 MiB of UTF-8 (bytes). Bounds both the
/// MCP payload and what a pasted-secret sized blob can occupy.
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// X11 selection atoms that mean "text" - accepted in `clipboard_get`'s
/// `mime` alongside real `text/*` types (an X11 TARGETS list speaks
/// atoms, not MIME strings).
const X11_TEXT_ATOMS: &[&str] = &["UTF8_STRING", "STRING", "TEXT", "COMPOUND_TEXT"];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClipboardGetParams {
    /// MIME type to read - "text/plain" (default), another text/* type
    /// or X11 text atom, or "list" to enumerate offered types
    #[serde(default = "default_mime")]
    #[schemars(length(min = 1, max = 256))]
    mime: String,
}

fn default_mime() -> String {
    "text/plain".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClipboardSetParams {
    /// Text to place on the clipboard (max 1 MiB)
    #[schemars(length(max = 1048576))]
    text: String,
    /// Challenge token from a prior -32015 ConsentRequired response
    consent_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClipboardClearParams {
    /// Challenge token from a prior -32015 ConsentRequired response
    consent_token: Option<String>,
}

/// The category's `tools/list` entries - registered via
/// `super::all_tools`/`CATALOG` under the `clipboard` category.
pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<ClipboardGetParams>(
            "clipboard_get",
            "Read the clipboard's text, or list offered MIME types with mime \"list\".",
        ),
        tool::<ClipboardSetParams>(
            "clipboard_set",
            "Overwrite the clipboard with the given text (max 1 MiB; consent-gated).",
        ),
        tool::<ClipboardClearParams>(
            "clipboard_clear",
            "Clear the clipboard entirely (consent-gated).",
        ),
    ]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "clipboard_get" => clipboard_get(args, providers).await,
        "clipboard_set" => clipboard_set(args, providers).await,
        "clipboard_clear" => clipboard_clear(args, providers).await,
        _ => return None,
    })
}

/// `None` slot -> `-32010 ProviderUnavailable` (headless session, or no
/// clipboard helper pinned at startup).
fn clipboard_provider(p: &Providers) -> Result<&dyn ClipboardProvider, ErrorData> {
    p.clipboard
        .as_deref()
        .ok_or_else(|| provider_unavailable("ClipboardProvider"))
}

/// Whether `mime` names the text read channel: any `text/*` type or an
/// X11 text atom ([`X11_TEXT_ATOMS`]), case-insensitive. The provider
/// contract is text-first, so every accepted value reads the same
/// channel - `mime` is a selection/validation surface, not a decoder.
fn is_text_mime(mime: &str) -> bool {
    mime.len() <= 256
        && (mime
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("text/"))
            || X11_TEXT_ATOMS.iter().any(|a| a.eq_ignore_ascii_case(mime)))
}

async fn clipboard_get(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ClipboardGetParams = parse_args("clipboard_get", args)?;
    if p.mime.is_empty() {
        return Err(invalid_params("clipboard_get: mime must be non-empty"));
    }
    if p.mime == "list" {
        let clipboard = clipboard_provider(providers)?;
        let mimes = backend!(clipboard.list_mimes().await);
        return Ok(json_result(&json!({"mimes": mimes})));
    }
    if !is_text_mime(&p.mime) {
        return Err(invalid_params(format!(
            "clipboard_get: unsupported mime {:?} - use \"list\" or a text/* type",
            p.mime
        )));
    }
    let clipboard = clipboard_provider(providers)?;
    let text = backend!(clipboard.get_text().await);
    Ok(json_result(&json!({"mime": p.mime, "text": text})))
}

async fn clipboard_set(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ClipboardSetParams = parse_args("clipboard_set", args)?;
    if p.text.len() > MAX_CLIPBOARD_BYTES {
        return Err(invalid_params(format!(
            "clipboard_set: text exceeds the 1 MiB limit ({} bytes)",
            p.text.len()
        )));
    }
    // Consent is enforced upstream by `call_tool_secured` - the token is
    // already spent by the time dispatch reaches this leg.
    let _ = &p.consent_token;
    let clipboard = clipboard_provider(providers)?;
    backend!(clipboard.set_text(&p.text).await);
    Ok(text_result(format!(
        "Copied {} bytes to clipboard",
        p.text.len()
    )))
}

async fn clipboard_clear(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: ClipboardClearParams = parse_args("clipboard_clear", args)?;
    // Consent enforced upstream - see clipboard_set.
    let _ = &p.consent_token;
    let clipboard = clipboard_provider(providers)?;
    backend!(clipboard.clear().await);
    Ok(text_result("Clipboard cleared"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::mock::MockClipboard;
    use rmcp::model::{ContentBlock, ErrorCode};
    use std::sync::Arc;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().expect("test args must be an object").clone()
    }

    fn providers() -> Providers {
        Providers {
            clipboard: Some(Arc::new(MockClipboard)),
            ..Providers::empty()
        }
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(ContentBlock::as_text)
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    // ---- schema surface -------------------------------------------------

    #[test]
    fn tools_are_three_closed_schemas() {
        let all = tools();
        assert_eq!(all.len(), 3);
        let names: Vec<&str> = all.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, ["clipboard_get", "clipboard_set", "clipboard_clear"]);
        for t in &all {
            assert_eq!(t.input_schema["type"], json!("object"));
            assert_eq!(t.input_schema["additionalProperties"], json!(false));
        }
        // `mime` is optional; `text` is required; consent_token is
        // optional on the two gated tools.
        let required = |t: &Tool| {
            t.input_schema
                .get("required")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        assert!(!required(&all[0]).iter().any(|v| v == "mime"));
        assert!(required(&all[1]).iter().any(|v| v == "text"));
        assert!(required(&all[2]).iter().all(|v| v != "consent_token"));
    }

    #[test]
    fn is_text_mime_accepts_text_types_and_x11_atoms() {
        for m in [
            "text/plain",
            "TEXT/html",
            "text/plain;charset=utf-8",
            "UTF8_STRING",
            "utf8_string",
            "STRING",
            "TEXT",
            "text",
        ] {
            assert!(is_text_mime(m), "{m}");
        }
        for m in [
            "image/png",
            "application/octet-stream",
            "textx/plain",
            "textplain",
            "UTF8_STRIN",
        ] {
            assert!(!is_text_mime(m), "{m}");
        }
        assert!(!is_text_mime(&"x".repeat(300)));
    }

    // ---- dispatch against the mock --------------------------------------

    #[tokio::test]
    async fn get_returns_text_and_mime_list() {
        let p = providers();
        let r = dispatch("clipboard_get", &args(json!({})), &p)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.is_error, Some(false));
        let v: Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["mime"], "text/plain");
        assert_eq!(v["text"], "mock-clipboard");

        let r = dispatch("clipboard_get", &args(json!({"mime": "list"})), &p)
            .await
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["mimes"], json!(["text/plain", "UTF8_STRING"]));

        // X11 atom and other text/* types read the same text channel.
        for mime in ["UTF8_STRING", "text/html"] {
            let r = dispatch("clipboard_get", &args(json!({"mime": mime})), &p)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r.is_error, Some(false));
        }
    }

    #[tokio::test]
    async fn get_rejects_bad_mime_and_unknown_fields() {
        let p = providers();
        for a in [
            json!({"mime": ""}),
            json!({"mime": "image/png"}),
            json!({"mime": 42}),
            json!({"bogus": 1}),
        ] {
            let err = dispatch("clipboard_get", &args(a), &p)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{err:?}");
        }
    }

    #[tokio::test]
    async fn set_and_clear_run_against_mock() {
        let p = providers();
        let r = dispatch("clipboard_set", &args(json!({"text": "hello"})), &p)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(text_of(&r), "Copied 5 bytes to clipboard");

        let r = dispatch("clipboard_clear", &args(json!({})), &p)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(text_of(&r), "Clipboard cleared");

        // consent_token is an accepted field (the retry shape).
        let r = dispatch(
            "clipboard_clear",
            &args(json!({"consent_token": "tok"})),
            &p,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r.is_error, Some(false));
    }

    #[tokio::test]
    async fn set_rejects_oversized_and_missing_text() {
        let p = providers();
        // > 1 MiB rejected.
        let big = "x".repeat(MAX_CLIPBOARD_BYTES + 1);
        let err = dispatch("clipboard_set", &args(json!({"text": big})), &p)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // Missing text entirely.
        let err = dispatch("clipboard_set", &args(json!({})), &p)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        // Exactly 1 MiB passes validation.
        let ok = "x".repeat(MAX_CLIPBOARD_BYTES);
        let r = dispatch("clipboard_set", &args(json!({"text": ok})), &p)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.is_error, Some(false));
    }

    #[tokio::test]
    async fn absent_provider_is_32010() {
        let p = Providers::empty();
        for (name, a) in [
            ("clipboard_get", json!({})),
            ("clipboard_set", json!({"text": "x"})),
            ("clipboard_clear", json!({})),
        ] {
            let err = dispatch(name, &args(a), &p).await.unwrap().unwrap_err();
            assert_eq!(err.code.0, -32010, "{name}");
            assert!(err.message.contains("ClipboardProvider"));
        }
        // Unknown names fall through to the next category.
        assert!(dispatch("nope", &args(json!({})), &p).await.is_none());
    }

    #[tokio::test]
    async fn backend_failure_is_iserror_result() {
        struct Failing;
        #[async_trait::async_trait]
        impl ClipboardProvider for Failing {
            async fn get_text(&self) -> anyhow::Result<Option<String>> {
                anyhow::bail!("paste exploded")
            }
            async fn set_text(&self, _t: &str) -> anyhow::Result<()> {
                anyhow::bail!("copy exploded")
            }
            async fn clear(&self) -> anyhow::Result<()> {
                anyhow::bail!("clear exploded")
            }
            async fn list_mimes(&self) -> anyhow::Result<Vec<String>> {
                anyhow::bail!("types exploded")
            }
        }
        let p = Providers {
            clipboard: Some(Arc::new(Failing)),
            ..Providers::empty()
        };
        for (name, a) in [
            ("clipboard_get", json!({})),
            ("clipboard_get", json!({"mime": "list"})),
            ("clipboard_set", json!({"text": "x"})),
            ("clipboard_clear", json!({})),
        ] {
            let r = dispatch(name, &args(a), &p).await.unwrap().unwrap();
            assert_eq!(r.is_error, Some(true), "{name}");
            assert!(text_of(&r).contains("backend error"), "{name}");
        }
    }

    // ---- consent gate ---------------------------------------------------

    #[tokio::test]
    async fn set_and_clear_are_consent_gated_on_the_secured_path() {
        // The destructive-class listing lives in `super::is_destructive`:
        // both mutating tools must challenge without a token, accept the
        // retry bound to the same args, and leave `clipboard_get` ungated.
        let tmp = tempfile::tempdir().unwrap();
        let sec = crate::security::SecurityContext::new(tmp.path(), false, false).unwrap();
        let p = providers();
        const SESSION: &str = "clipboard-test-session";

        for (name, a) in [
            ("clipboard_set", json!({"text": "x"})),
            ("clipboard_clear", json!({})),
        ] {
            let err =
                super::super::call_tool_secured(name, args(a.clone()), &p, &sec, SESSION, None)
                    .await
                    .unwrap_err();
            assert_eq!(err.code.0, crate::error::codes::CONSENT_REQUIRED, "{name}");
            let token = err.data.as_ref().unwrap()["consent_token"]
                .as_str()
                .unwrap()
                .to_string();

            let mut retry = a.as_object().unwrap().clone();
            retry.insert("consent_token".into(), json!(token));
            let r = super::super::call_tool_secured(name, retry, &p, &sec, SESSION, None)
                .await
                .unwrap();
            assert_eq!(r.is_error, Some(false), "{name}");
        }

        // The read path is not in the destructive class.
        let r = super::super::call_tool_secured(
            "clipboard_get",
            args(json!({})),
            &p,
            &sec,
            SESSION,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.is_error, Some(false));
    }
}
