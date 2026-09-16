//! Keyboard tools (2) - `InputProvider` injection with focus safety.
//! Key names follow XKB keysym spelling (case-insensitive).

use std::time::Duration;

use rmcp::model::{CallToolResult, ErrorData, Tool};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    backend, input_provider, invalid_params, parse_args, sanitization_rejected, text_result, tool,
    tool_error,
};
use crate::providers::Providers;

/// XKB keysym names accepted in addition to any single printable character
/// and `F1`-`F24` (matched case-insensitively).
const KNOWN_KEYSYMS: &[&str] = &[
    "return",
    "escape",
    "tab",
    "space",
    "backspace",
    "delete",
    "insert",
    "home",
    "end",
    "page_up",
    "page_down",
    "left",
    "right",
    "up",
    "down",
    "print",
    "scroll_lock",
    "pause",
    "caps_lock",
    "num_lock",
    "menu",
    "shift_l",
    "shift_r",
    "control_l",
    "control_r",
    "alt_l",
    "alt_r",
    "super_l",
    "super_r",
    "meta_l",
    "meta_r",
    "hyper_l",
    "hyper_r",
    "minus",
    "equal",
    "comma",
    "period",
    "slash",
    "backslash",
    "semicolon",
    "apostrophe",
    "bracketleft",
    "bracketright",
    "grave",
    "kp_enter",
    "kp_add",
    "kp_subtract",
    "kp_multiply",
    "kp_divide",
    "kp_decimal",
    "kp_0",
    "kp_1",
    "kp_2",
    "kp_3",
    "kp_4",
    "kp_5",
    "kp_6",
    "kp_7",
    "kp_8",
    "kp_9",
];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TypeTextParams {
    /// Literal text to type
    #[schemars(length(min = 1, max = 65536))]
    text: String,
    /// Delay between key events in milliseconds
    #[serde(default)]
    #[schemars(range(min = 0, max = 1000))]
    delay_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum KeyAction {
    Press,
    Down,
    Up,
}

/// Canonical modifier order is the enum declaration order
/// (ctrl, shift, alt, super) - `Ord` sorts into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Modifier {
    Ctrl,
    Shift,
    Alt,
    Super,
}

impl Modifier {
    /// XKB keysym passed to `InputProvider::key_event`.
    fn key_name(self) -> &'static str {
        match self {
            Self::Ctrl => "Control_L",
            Self::Shift => "Shift_L",
            Self::Alt => "Alt_L",
            Self::Super => "Super_L",
        }
    }

    /// Spelling used in response text (`ctrl+shift+t`).
    fn as_str(self) -> &'static str {
        match self {
            Self::Ctrl => "ctrl",
            Self::Shift => "shift",
            Self::Alt => "alt",
            Self::Super => "super",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct KeyControlParams {
    /// XKB keysym name, e.g. "c", "Return", "F5", "Left"
    #[schemars(length(min = 1))]
    key: String,
    /// `press` = a full tap; `down`/`up` enable multi-call sequences
    action: KeyAction,
    /// Modifiers held for the duration of the action (max 4)
    #[serde(default)]
    #[schemars(length(max = 4))]
    modifiers: Vec<Modifier>,
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<TypeTextParams>(
            "type_text",
            "Type a literal UTF-8 string into the focused element, with optional inter-key delay.",
        ),
        tool::<KeyControlParams>(
            "key_control",
            "Press, hold, or release a single key, optionally chorded with modifiers.",
        ),
    ]
}

pub(super) async fn dispatch(
    name: &str,
    args: &Map<String, Value>,
    providers: &Providers,
) -> Option<Result<CallToolResult, ErrorData>> {
    Some(match name {
        "type_text" => type_text(args, providers).await,
        "key_control" => key_control(args, providers).await,
        _ => return None,
    })
}

/// Snapshot of the focused window id, when a `WindowProvider` is present.
/// Focus-safety failures are non-fatal to the snapshot itself - a missing
/// provider simply disables the check.
async fn focused_window_id(providers: &Providers) -> Option<String> {
    let window = providers.window.as_deref()?;
    window.active_window().await.ok().flatten().map(|w| w.id)
}

/// Post-action focus check; returns an `isError` result when the active
/// window changed while the sequence was being injected.
fn check_focus_unchanged(before: &Option<String>, after: Option<String>) -> Option<CallToolResult> {
    let before = before.as_ref()?;
    match after {
        Some(now) if &now != before => Some(tool_error(format!(
            "FocusChanged: active window changed mid-action (was {before}, now {now})"
        ))),
        _ => None,
    }
}

async fn type_text(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: TypeTextParams = parse_args("type_text", args)?;
    if p.text.is_empty() {
        return Err(invalid_params("type_text: text must be non-empty"));
    }
    let n_chars = p.text.chars().count();
    if n_chars > 65_536 {
        return Err(invalid_params("type_text: text exceeds maxLength 65536"));
    }
    if p.delay_ms > 1_000 {
        return Err(invalid_params(
            "type_text: delay_ms must be between 0 and 1000",
        ));
    }
    // Sanitization: NUL and control bytes other than \n / \t are rejected.
    if p.text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(sanitization_rejected(
            "type_text: text contains control bytes other than \\n and \\t",
        ));
    }

    let input = input_provider(providers)?;
    let focus_before = focused_window_id(providers).await;

    if p.delay_ms == 0 {
        backend!(input.type_text(&p.text).await);
    } else {
        // Delayed path types char-by-char: re-check the active window
        // between key events and abort the remaining sequence on a focus
        // change (docs/TOOLS.md §Focus Safety) instead of typing the tail
        // into the wrong window. Each re-check is a provider round-trip,
        // so it's throttled: the first inter-char gap is always checked
        // (short sequences must still abort mid-way), then every 16th
        // character or ≥100 ms since the last check. The post-loop check
        // below catches anything in the unchecked remainder.
        let mut chars = p.text.chars().peekable();
        let mut typed = 0usize;
        let mut last_focus_check = std::time::Instant::now();
        while let Some(ch) = chars.next() {
            backend!(input.type_text(&ch.to_string()).await);
            typed += 1;
            if chars.peek().is_some() {
                let check_due = focus_before.is_some()
                    && (typed == 1
                        || typed.is_multiple_of(16)
                        || last_focus_check.elapsed() >= Duration::from_millis(100));
                if check_due {
                    last_focus_check = std::time::Instant::now();
                    if let (Some(before), Some(now)) =
                        (focus_before.as_ref(), focused_window_id(providers).await)
                        && &now != before
                    {
                        return Ok(tool_error(format!(
                            "FocusChanged: active window changed mid-action \
                             (was {before}, now {now}); typed {typed} of \
                             {n_chars} characters, aborted the rest"
                        )));
                    }
                }
                tokio::time::sleep(Duration::from_millis(p.delay_ms)).await;
            }
        }
    }

    if let Some(err) = check_focus_unchanged(&focus_before, focused_window_id(providers).await) {
        return Ok(err);
    }
    Ok(text_result(format!("Typed {n_chars} characters")))
}

fn is_valid_key_name(key: &str) -> bool {
    if key.is_empty() || key.chars().any(|c| c.is_control()) {
        return false;
    }
    if key.chars().count() == 1 {
        return true; // any single printable character
    }
    let lower = key.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix('f')
        && let Ok(n) = rest.parse::<u32>()
    {
        return (1..=24).contains(&n);
    }
    KNOWN_KEYSYMS.contains(&lower.as_str())
}

async fn key_control(
    args: &Map<String, Value>,
    providers: &Providers,
) -> Result<CallToolResult, ErrorData> {
    let p: KeyControlParams = parse_args("key_control", args)?;
    if p.key.is_empty() {
        return Err(invalid_params("key_control: key must be non-empty"));
    }
    if p.modifiers.len() > 4 {
        return Err(invalid_params("key_control: at most 4 modifiers"));
    }
    if !is_valid_key_name(&p.key) {
        return Err(invalid_params(format!(
            "key_control: unknown key name {:?} (expected XKB keysym)",
            p.key
        )));
    }

    // Normalise modifier order to ctrl+shift+alt+super and drop duplicates.
    let mut mods = p.modifiers.clone();
    mods.sort();
    mods.dedup();

    let input = input_provider(providers)?;
    let focus_before = focused_window_id(providers).await;

    for m in &mods {
        backend!(input.key_event(m.key_name(), true).await);
    }
    let outcome = async {
        match p.action {
            KeyAction::Press => {
                input.key_event(&p.key, true).await?;
                input.key_event(&p.key, false).await?;
            }
            KeyAction::Down => input.key_event(&p.key, true).await?,
            KeyAction::Up => input.key_event(&p.key, false).await?,
        }
        anyhow::Ok(())
    }
    .await;
    // Always release held modifiers, even when the key event failed.
    for m in mods.iter().rev() {
        let _ = input.key_event(m.key_name(), false).await;
    }
    backend!(outcome);

    if let Some(err) = check_focus_unchanged(&focus_before, focused_window_id(providers).await) {
        return Ok(err);
    }

    let combo = mods
        .iter()
        .map(|m| m.as_str())
        .chain(std::iter::once(p.key.as_str()))
        .collect::<Vec<_>>()
        .join("+");
    Ok(text_result(match p.action {
        KeyAction::Press => format!("Pressed {combo}"),
        KeyAction::Down => format!("{combo} down"),
        KeyAction::Up => format!("{combo} up"),
    }))
}
