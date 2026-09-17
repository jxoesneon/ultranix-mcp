# ultranix-mcp - Tool API Reference

Complete API specification for every tool exposed by **ultranix-mcp**, the
Rust MCP server for Linux desktop automation. This document describes the
shipped **v1.4.0 tool surface - 40 tools in 6 categories**: v1.2.0 grew the
catalog to 39, v1.3.0 left it unchanged while adding runtime controls
around it (the `policy.toml` access-control policy with per-key role
scoping, the `--readonly`/`--allow-tools`/`--deny-tools` flags,
`-32018`/`-32019` policy denials, per-backend/build-info metrics, and
optional audit-log HMAC - see [Maturity Phases](#maturity-phases) and
[ADR 0010](adr/0010-policy-controls.md)), and v1.4.0 added `screen_stream`
(live rolling-window capture) plus **plugin-exposed dynamic tools**-
manifest `tool` sections that register first-class entries in `tools/list`
(see [Plugin Manifests](#plugin-manifests)).

- **Server**: `ultranix-mcp` (Rust 2024, tokio, `rmcp` SDK)
- **Transports**: stdio and streamable HTTP on `:3010` (canonical JSON-RPC
  endpoint `http://127.0.0.1:3010/mcp`)
- **Naming**: all tools are `snake_case`; category prefixes (`mouse_*`,
  `key_*`, `screen_*`, `get_*`) are part of the stable public contract
- **Auth (HTTP only)**: `X-API-Key: uxcp_<64-hex>` is the canonical header,
  supplied via `ULTRANIX_MCP_API_KEY` (`Authorization: Bearer uxcp_<64-hex>`
  is accepted as an equivalent header). Auth is **fail-closed**: when no key
  is configured the server refuses to bind `:3010` rather than listen
  unauthenticated, and no development key is ever generated.
  `ULTRANIX_MCP_DISABLE_AUTH=true` is an explicit operator opt-out for local
  development. The stdio transport is trusted-local and performs no key check.
- **Rate limit**: 10 requests/second token bucket per caller identity on
  the HTTP transport - the API key, or the remote address when auth is
  disabled (`ULTRANIX_MCP_DISABLE_AUTH`). See [Rate Limiting](#rate-limiting).
- **Consent gate**: destructive tools return `-32015 ConsentRequired` with a
  short-lived challenge token on first call; retry with `consent_token`.
  See [Destructive-Action Consent](#destructive-action-consent).
- **State directory**: `~/.ultranix-mcp/` - AES-256-GCM action history
  (`history.json`, `UNXHIST2` framed append format since v1.2.0), JSONL
  audit log (`audit.jsonl`), config, plugin manifests (`plugins/*.json`),
  `screen_record`/`screen_stream` output (`captures/rec-*`,
  `captures/stream-*`).

---

## Table of Contents

- [Provider Backends](#provider-backends)
- [Tool Summary](#tool-summary)
- [Conventions](#conventions)
  - [Request / Response Envelope](#request--response-envelope)
  - [Content Types](#content-types)
  - [Coordinate System](#coordinate-system)
  - [Spatial Focus](#spatial-focus)
  - [Focus Safety](#focus-safety)
  - [Capture Output Writes](#capture-output-writes)
  - [Rate Limiting](#rate-limiting)
  - [Destructive-Action Consent](#destructive-action-consent)
  - [Error Model](#error-model)
- [Mouse Tools](#mouse-tools)
- [Keyboard Tools](#keyboard-tools)
- [Vision & Screen Tools](#vision--screen-tools)
- [Automation Tools](#automation-tools)
- [Admin & Observability Tools](#admin--observability-tools)
- [Clipboard Tools](#clipboard-tools)
- [Plugin Manifests](#plugin-manifests)
- [Maturity Phases](#maturity-phases)

---

## Provider Backends

Each tool is implemented by exactly one primary provider. Providers are
pluggable backends selected at startup; each lists its Wayland-first mechanism
and its fallback chain. The fallback chains below are a summary - the
canonical normative fallback-chain table lives in
[ARCHITECTURE.md §5](ARCHITECTURE.md#5-backend-detection--fallback).

| Provider | Responsibility | Primary mechanism | Fallback chain |
| --- | --- | --- | --- |
| `CaptureProvider` | Screenshots, pixel reads | `wlr-screencopy` | `grim`/`slurp` -> XDG Desktop Portal `org.freedesktop.portal.Screenshot`; where a backend advertises `RemoteDesktop` but not `Screenshot`, frames come from an ephemeral RemoteDesktop session's PipeWire stream. On X11 sessions the chain is `scrot` (`X11Capture`, backend name `"scrot"`) -> portal |
| `OverlayProvider` | Highlight overlays | `wlr-layer-shell` (`zwlr_layer_shell_v1`, `overlay` layer) | - (returns `ProviderUnavailable` when the compositor lacks layer-shell) |
| `InputProvider` | Pointer and keyboard injection | `wlr-virtual-pointer` + `virtual-keyboard` (zwlr_virtual_pointer_manager_v1 / virtual-keyboard-unstable-v1) | `/dev/uinput` -> XDG Portal `RemoteDesktop`. On X11 sessions `xdotool` (`X11Input`, backend name `"xdotool"`) is tried first, then uinput -> portal |
| `UIAutomationProvider` | Accessibility tree, element search, AT-SPI action invocation | AT-SPI2 via the `atspi` crate over D-Bus | - (returns `ProviderUnavailable` when the AT-SPI bus is absent) |
| `WindowProvider` | Window enumeration and control | `hyprctl` IPC (`hyprctl -j`) over `$XDG_RUNTIME_DIR/hypr/` sockets | sway IPC over `$SWAYSOCK` (`SwayWindow`, backend name `"sway-ipc"`) on sway sessions; wayfire `ipc`/`ipc-rules` socket over `$WAYFIRE_SOCKET` (`WayfireWindow`, backend name `"wayfire-ipc"`, v1.4.0) on Wayfire sessions; `riverctl` subprocess + `zwlr_foreign_toplevel_manager_v1` composite (`RiverWindow`, backend name `"riverctl"`, v1.4.0/composite later) on river sessions - `riverctl` keeps focused-view `close` and relative `dx,dy`/`dw,dh` geometry while foreign-toplevel supplies enumeration and per-window `focus`/`close`/`min`/`max`/`fullscreen` via `wlr-toplevel-N` ids (without the protocol, `get_windows`/`get_active_window` keep their honest `isError` results and `window_control` is focused-view only; absolute `x,y`/`w,h` always error - river has no absolute form); `zwlr_foreign_toplevel_manager_v1` also serves directly as the shared `WlrToplevelWindow` fallback rung (backend name `"wlr-toplevel"`) behind the compositor-specific providers on Hyprland/sway/Wayfire and as the sole window rung on unknown wlroots sessions; GNOME "Window Calls" extension over D-Bus (`GnomeShellWindow`, backend name `"gnome-shell"`, v1.4.0) on GNOME sessions - requires the extension installed (`org.gnome.Shell.Extensions.Windows`); `kdotool` subprocess (`KdotoolWindow`, backend name `"kdotool"`) on KDE sessions (Wayland and X11 - it drives KWin on both); `wmctrl` + `xdotool`/`xprop` (`X11Window`, backend name `"wmctrl"`) on other X11 sessions - and as the GNOME-X11/KDE-X11 fallback rung behind `gnome-shell`/`kdotool`; `None` elsewhere |
| `VisionProvider` | OCR and open-vocabulary detection | ONNX Runtime (`ort`): text OCR model + OWL-ViT | - (tools fail closed with `ProviderUnavailable`) |
| `BrowserProvider` | DOM queries | Chrome DevTools Protocol at `127.0.0.1:9222` | - (requires the browser launched with `--remote-debugging-port=9222`) |
| `ClipboardProvider` | Clipboard read/write | `wl-copy`/`wl-paste` (`wl-clipboard`, backend name `"wl-clipboard"`) on Wayland | `xclip` (+ `xsel` for clear; backend name `"xclip"`) on X11 and as the XWayland rung on Wayland |
| Server core | Timing, session state, history, metrics, plugin macros | tokio timers, `~/.ultranix-mcp/` stores | - | ---

## Tool Summary

| Tool | Category | Backend | Phase |
| --- | --- | --- | --- |
| `mouse_click` | mouse | InputProvider | 1 |
| `mouse_double_click` | mouse | InputProvider | 1 |
| `mouse_move` | mouse | InputProvider | 1 |
| `mouse_get_position` | mouse | InputProvider + compositor IPC (`hyprctl cursorpos`) | 1 |
| `mouse_scroll` | mouse | InputProvider | 1 |
| `mouse_drag` | mouse | InputProvider | 1 |
| `mouse_button_control` | mouse | InputProvider | 1 |
| `type_text` | keyboard | InputProvider | 1 |
| `key_control` | keyboard | InputProvider | 1 |
| `screenshot` | vision | CaptureProvider | 1 |
| `screen_info` | vision | CaptureProvider + WindowProvider | 1 |
| `screen_highlight` | vision | OverlayProvider | 2 |
| `color_at` | vision | CaptureProvider | 1 |
| `set_spatial_focus` | vision | Server core (session state) | 2 |
| `get_ui_tree` | vision | UIAutomationProvider | 2 |
| `get_focused_element` | vision | UIAutomationProvider | 2 |
| `find_element` | vision | UIAutomationProvider | 2 |
| `invoke_element` | vision | UIAutomationProvider | 2 |
| `find_text_on_screen` | vision | VisionProvider + CaptureProvider | 3 |
| `find_icon` | vision | VisionProvider + CaptureProvider | 3 |
| `wait_for_ui_element` | vision | UIAutomationProvider | 2 |
| `screen_record` | vision | CaptureProvider | 6 |
| `screen_stream` | vision | CaptureProvider | 7 |
| `sleep` | automation | Server core | 1 |
| `mouse_move_path` | automation | InputProvider | 1 |
| `system_command` | automation | Server core (arg-constrained exec, consent-gated) | 1 |
| `web_query` | automation | BrowserProvider | 3 |
| `window_control` | admin | WindowProvider (`close` is consent-gated) | 1 |
| `get_windows` | admin | WindowProvider | 1 |
| `get_active_window` | admin | WindowProvider | 1 |
| `metrics` | admin | Server core | 4 |
| `get_action_history` | admin | Server core (encrypted history) | 4 |
| `replay_action` | admin | Server core (encrypted history, consent-gated) | 4 |
| `clear_action_history` | admin | Server core (encrypted history, consent-gated) | 4 |
| `plugin_list` | admin | Server core (plugin store) | 6 |
| `plugin_run` | admin | Server core (plugin store; per-step secured dispatch) | 6 |
| `plugin_reload` | admin | Server core (plugin store) | 6 |
| `clipboard_get` | clipboard | ClipboardProvider | 6 |
| `clipboard_set` | clipboard | ClipboardProvider (consent-gated) | 6 |
| `clipboard_clear` | clipboard | ClipboardProvider (consent-gated) | 6 | **Total: 40 tools**(mouse 7 - keyboard 2 - vision 14 - automation 4 -
admin 10 - clipboard 3). Plugin-exposed dynamic tools (manifest `tool`
sections, v1.4.0) are **not**counted here - they join `tools/list` at
runtime; see [Plugin Manifests](#plugin-manifests).

---

## Conventions

### Request / Response Envelope

Tools are invoked via the standard MCP `tools/call` JSON-RPC method:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "<tool_name>",
    "arguments": { }
  }
}
```

A successful call returns a `result` object containing a `content` array:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [
      { "type": "text", "text": "..." }
    ],
    "isError": false
  }
}
```

Two failure modes are distinguished:

1. **Protocol / validation failures**- malformed params, unknown tool,
   and security rejections are returned as JSON-RPC **error
   objects**(no `result`). On the HTTP transport, auth and rate-limit
   rejections surface earlier still - as HTTP `401`/`429` status codes
   before the JSON-RPC layer is reached. See [Error Model](#error-model).
2. **Execution failures**- the call was valid but the backend could not
   complete the action (e.g. capture failed mid-flight) - are returned as a
   normal `result` with `"isError": true` and a single `text` content item
   describing the failure. Callers MUST check `isError`.

"Not found" conditions (`find_element`, `find_text_on_screen`, `find_icon`,
`wait_for_ui_element` timeouts) are **successful results**carrying a
structured `found: false` payload, never errors - absence of an element is
data, not a fault. `invoke_element` is the exception: because it acts on the
match rather than reporting it, a query with no AT-SPI match is an error
(`-32016 ElementNotFound`).

### Content Types

| Content type | Shape | Used by |
| --- | --- | --- |
| `text` | `{ "type": "text", "text": "<string>" }` - either a human-readable sentence or a JSON document (documented per tool; JSON payloads are always parseable with `JSON.parse`/`serde_json`) | all tools |
| `image` | `{ "type": "image", "data": "<base64>", "mimeType": "image/png" }` | `screenshot`, `screen_stream` (`action: "latest"`) | Tools that return JSON text content always place it in a **single**`text`
item; clients should parse `content[0].text` as JSON when the tool's "Returns"
section specifies a JSON payload.

### Coordinate System

- All coordinates are **Hyprland logical coordinates**: compositor layout
  space in logical (post-scale) pixels, origin at the top-left of the
  workspace layout.
- **Multi-monitor**: `x`/`y` address the *global* layout, not a per-output
  frame. A monitor placed to the left of or above another contributes
  **negative**coordinate ranges; all tools that take `x`, `y` accept negative
  integers. Use `screen_info` to enumerate outputs and their layout rects.
- **Scale**: logical coordinates divide by each output's scale factor. A
  `1920x1080@1.5` output occupies `1280x720` logical units. `screenshot`
  returns *physical* pixels (PNG at native resolution); multiply logical
  regions by the target output's `scale` when cropping pixel data yourself.
- Bounds returned by AT-SPI tools (`get_ui_tree`, `find_element`, ...) are
  already in the same logical space and can be fed directly to mouse tools.

### Spatial Focus

`set_spatial_focus` installs a process-scoped rectangular region of
interest:

- `screenshot` with **no explicit `region`**captures the focus rect instead
  of the full layout (an explicit `region` argument always wins).
- `find_text_on_screen` and `find_icon` restrict capture and search to the
  focus rect (an explicit `region` argument on `find_text_on_screen` wins).
- `find_element` / `wait_for_ui_element` / `get_ui_tree` are **not**affected -
  they operate on the AT-SPI2 tree, not pixels.
- The focus rect is process-scoped (the dispatch layer carries no session
  handle yet, so it is shared by every caller), never persisted to
  `~/.ultranix-mcp/`, and is cleared by `set_spatial_focus { "clear": true }`
  or process end.

### Focus Safety

`type_text` and `key_control` snapshot the active window (via
`WindowProvider`) before injecting input. If the active window changes
mid-sequence, the remaining injection is aborted and the tool returns
`isError: true` with a `FocusChanged` explanation instead of typing into the
wrong window. Single-shot actions (`mouse_click`, ...) do not re-check focus.

The mid-sequence re-check is **throttled**, not per-character: on the
`delay_ms > 0` path, `type_text` re-reads focus at the first inter-key gap
(so short sequences still abort mid-way), then at most every 16th character
or when ≥100 ms have elapsed since the last check, plus a final post-loop
check. Focus changes between checks are caught at the next checkpoint, not
at the exact keystroke.

### Capture Output Writes

Capture tools and capture-adjacent whitelist binaries (`grim`, `scrot`)
never write to a caller-chosen path directly. The server creates a
**fresh `mktemp`-style directory**(mode `0700`) per capture under
`~/.ultranix-mcp/captures/` (preferred) - falling back to `/tmp` (also
`0700`) when the state directory is unavailable - and passes the spawned
binary a path inside that directory. Because the directory is freshly
created, unpredictable, and owner-only, a same-UID attacker cannot
pre-place a symlink inside it: this closes the canonicalize-then-write
TOCTOU window that spawned binaries cannot close themselves (`O_NOFOLLOW`
applies to server-side opens only). When the server itself opens the file
(e.g. to return image content), it uses `O_NOFOLLOW` and mode `0600`.
Files are unlinked after the tool returns, including on error paths;
systemd `PrivateTmp=yes` is recommended on top (see
[THREAT_MODEL.md §4.6](THREAT_MODEL.md)).

### Rate Limiting

- Token bucket: **10 requests/second**per caller identity on the HTTP
  transport - the API key (`key_id`), or the remote address when auth is
  disabled.
  The stdio transport is not rate-limited - it inherits the spawning
  client's trust boundary and its calls go straight to input sanitization
  (see the pipeline diagram in
  [ARCHITECTURE.md §2](ARCHITECTURE.md#2-security-layer)).
- Exceeding the bucket returns JSON-RPC error `-32005`
  (`RateLimitExceeded`), surfaced as **HTTP 429**with a `Retry-After: 1`
  header before the JSON-RPC layer is reached.
- `sleep`, `wait_for_ui_element`, and `metrics` count against the bucket like
  any other call; long-running waits are not exempt.
- Administrative calls (`clear_action_history`, `replay_action`) are
  additionally written to the JSONL audit log regardless of outcome.

### Destructive-Action Consent

Destructive or hard-to-reverse tools are gated behind an explicit consent
challenge. The gated set is:

- `system_command` (every invocation)
- `replay_action`
- `clear_action_history`
- `clipboard_set`
- `clipboard_clear`
- `window_control` **only**when `action` is `"close"`

The clipboard writes joined the class at v1.2.0: overwriting or clearing
the clipboard destroys user state and can plant hostile content into the
next paste. `clipboard_get` is a read and is **not**gated.

**Consent-class boundary.**The gate covers the *state/system-mutating*
class above and nothing else. UI-interaction tools (`mouse_click`,
`type_text`, `key_control`, `invoke_element`, and the rest of the
pointer/keyboard/AT-SPI surface) are **not**consent-gated: they are
physical-input-equivalent, in the same residual class as any input
injector on the session (see [THREAT_MODEL.md](THREAT_MODEL.md) R-7), so a
per-call challenge would add friction without adding a boundary. Note that
`invoke_element` can reach privileged dialogs (e.g. a polkit
"Authenticate" prompt) through the AT-SPI Action interface - that reach is
a registered residual risk (THREAT_MODEL.md R-13), not a gating miss.

The first call to a gated tool **without**a valid token is not executed;
the server returns JSON-RPC error `-32015` (`ConsentRequired`) whose `data`
carries a short-lived `consent_token` challenge:

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "error": {
    "code": -32015,
    "message": "Destructive action requires consent",
    "data": {
      "kind": "ConsentRequired",
      "tool": "system_command",
      "consent_token": "r9mK2vQx...",
      "expires_in_ms": 60000
    }
  }
}
```

Token semantics:

- Tokens are **single-use**and bound to
  `{key_id (or stdio session id), tool, args_hash}` - the caller identity
  (`key_id` on HTTP; on stdio, a CSPRNG session id generated at server
  start), the tool name, and a hash of the exact arguments. `args_hash`
  is SHA-256 over the canonical JSON serialization of the call arguments
  (sorted keys, UTF-8, insignificant whitespace removed, `consent_token`
  itself excluded). For calls whose target is resolved at execution
  time (e.g. `window_control {action:"close"}` with `window` omitted),
  the **resolved target identity**(window address) is folded into the
  token scope at challenge time - a change of the resolved target
  between challenge and retry invalidates the token. A token issued for
  one caller or one command authorises neither a different command nor a
  different caller.
- Tokens expire after **60 seconds**(`expires_in_ms` is authoritative).
- Tokens are **CSPRNG-generated**with at least 128 bits of entropy (e.g.
  16 random bytes, base64url-encoded) - *not* a bare ULID or other
  guessable/sequential identifier. The `{key_id, tool, args_hash}` binding
  means a forged or transplanted token is rejected even if the attacker
  can guess or capture another call's token.
- Retry the identical call with the token supplied as the optional
  `consent_token` parameter; on success the action executes normally.
- An expired, mismatched, or already-spent token returns `-32015` again with
  a fresh challenge.
- Launching the server with `--allow-destructive` disables the gate entirely
  (operator opt-out for trusted automation); every gated call is still
  written to `audit.jsonl` with `"consent": "bypassed"`.

`consent_token` is an optional parameter on each gated tool - omitting it is
never an `InvalidParams` violation; it simply routes the call through the
challenge flow above.

### Error Model

Standard JSON-RPC 2.0 codes plus server-defined codes in the
`-32000...-32099` range. Every error object carries a machine-readable
`data.kind` discriminator alongside the human message.

| Code | `data.kind` | Meaning | Typical trigger |
| --- | --- | --- | --- |
| `-32700` | `ParseError` | Request is not valid JSON | corrupt frame |
| `-32600` | `InvalidRequest` | Not a well-formed JSON-RPC request | missing `jsonrpc`/`method` |
| `-32601` | `MethodNotFound` | Unknown method or tool name | typo'd tool; tool hidden by `--category` filter |
| `-32602` | `InvalidParams` | Schema validation failed | missing required param, wrong type, enum violation, out-of-range |
| `-32603` | `InternalError` | Unclassified server fault | panic-free unexpected failure |
| `-32001` | `Unauthorized` | Missing/invalid API key | no `X-API-Key`, bad `uxcp_*` key |
| `-32002` | `Forbidden` | Authenticated but not permitted | reserved - category filtering surfaces as `-32601` + `kind:"CategoryDisabled"` |
| `-32003` | `CommandNotWhitelisted` **or**`ArgConstraintViolation` | Whitelist violation - `data.kind` discriminates: `CommandNotWhitelisted` = binary outside the allowed command set; `ArgConstraintViolation` = allowed binary invoked with a denied subcommand/argument | `system_command` outside `{grim, slurp, hyprctl, scrot, xdotool, wmctrl}`; `hyprctl dispatch exec ...`/`exec-once ...`; `xdotool`/`wmctrl` on a Wayland session |
| `-32004` | `PathNotWhitelisted` | Path outside allowed roots | path arg resolving outside `$XDG_RUNTIME_DIR`, `/tmp`, `~/.ultranix-mcp/**` |
| `-32005` | `RateLimitExceeded` | Token bucket empty | >10 req/s |
| `-32006` | `SanitizationRejected` | Argument failed input sanitization | shell metacharacters, oversized strings (>64 KiB), control bytes |
| `-32010` | `ProviderUnavailable` | Backend not reachable | AT-SPI bus absent, CDP not listening on `127.0.0.1:9222`, no screencopy support |
| `-32011` | `CaptureFailed` | Frame capture/encode failed | reserved - backend failures surface as `isError:true` results, not JSON-RPC codes |
| `-32012` | `InputInjectionFailed` | Virtual input device failed | reserved - backend failures surface as `isError:true` results |
| `-32013` | `FocusChanged` | Active window changed mid-action | delivered as `isError:true` result text (`FocusChanged: ...`), not a JSON-RPC code |
| `-32014` | `HistoryError` | Encrypted history store fault | corrupt `history.json`, bad `ULTRANIX_MCP_HISTORY_SECRET` |
| `-32015` | `ConsentRequired` | Destructive call lacks a valid consent token | first `system_command`, `replay_action`, `clear_action_history`, `clipboard_set`, `clipboard_clear`, or `window_control{action:"close"}` without `consent_token`; `data` carries the challenge token (see [Destructive-Action Consent](#destructive-action-consent)) |
| `-32016` | `ElementNotFound` | Action-targeted element query matched nothing | `invoke_element` query with no AT-SPI match |
| `-32017` | `PluginStepError` | A `plugin_run` step failed at the tool level (`isError` result) or hit a post-validation template fault | `plugin_run` whose step returned an `isError` result; `data` carries `plugin`, `step`, `tool`, `detail`. JSON-RPC errors from the inner dispatch keep their own code instead (a step's `-32015 ConsentRequired` survives intact) |
| `-32018` | `ReadOnlyMode` | Tool denied by a readonly role - the `--readonly` flag or `readonly = true` on the resolved role in `policy.toml` | a tool outside the 15-tool readonly preset (and not opted back in via `allow_tools`) called under a readonly role |
| `-32019` | `NotInToolList` | Tool denied by the runtime policy allowlist/denylist | a tool not in `allow_tools`, or present in `deny_tools`, for the resolved role | Example error response:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "error": {
    "code": -32003,
    "message": "Command not whitelisted",
    "data": { "kind": "CommandNotWhitelisted", "command": "curl" }
  }
}
```

---

## Mouse Tools

All mouse tools are implemented by `InputProvider`
(wlr-virtual-pointer -> uinput -> portal RemoteDesktop; `xdotool` first on
X11 sessions) and shipped in **Phase 1**.
Coordinates are logical layout-space integers (see
[Coordinate System](#coordinate-system)).

### `mouse_click`

Move the pointer to `(x, y)` and click a button.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer", "description": "Horizontal coordinate in logical layout space" },
    "y": { "type": "integer", "description": "Vertical coordinate in logical layout space" },
    "button": {
      "type": "string",
      "enum": ["left", "right", "middle"],
      "default": "left",
      "description": "Button to click"
    }
  },
  "required": ["x", "y"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Clicked <button> at (<x>, <y>)"`.

**Errors**

| Condition | Code / result |
| --- | --- |
| Missing/invalid `x`, `y`, bad enum | `-32602 InvalidParams` |
| Input device unavailable | `-32012 InputInjectionFailed` | **Example**

```json
// request
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "mouse_click", "arguments": { "x": 640, "y": 420, "button": "left" } } }
// response
{ "jsonrpc": "2.0", "id": 1, "result": {
    "content": [{ "type": "text", "text": "Clicked left at (640, 420)" }],
    "isError": false } }
```

### `mouse_double_click`

Move to `(x, y)` and double-click within the compositor's click-interval.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer" },
    "y": { "type": "integer" },
    "button": { "type": "string", "enum": ["left", "right", "middle"], "default": "left" }
  },
  "required": ["x", "y"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Double-clicked <button> at (<x>, <y>)"`.

**Errors**: same as `mouse_click`.

**Example**

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
  "params": { "name": "mouse_double_click", "arguments": { "x": 512, "y": 300 } } }
// -> "Double-clicked left at (512, 300)"
```

### `mouse_move`

Move the pointer without pressing buttons (hover).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer" },
    "y": { "type": "integer" }
  },
  "required": ["x", "y"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Pointer moved to (<x>, <y>)"`.

**Errors**: `InvalidParams`, `InputInjectionFailed`.

### `mouse_get_position`

Report the current pointer position in logical layout coordinates.

Reading the pointer position is a **compositor query, not an input
injection**: on Hyprland the position is read over compositor IPC
(`hyprctl cursorpos`, served from the same
`$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/` socket used by
`WindowProvider`); on X11 sessions `xdotool getmouselocation --shell`
supplies the read channel. Backends that expose no pointer-position read
channel (uinput, portal RemoteDesktop) cannot service this tool.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON - `{"x": 812, "y": 344, "display": "DP-1"}`
(`display` is the output under the pointer, or `null` between outputs).

**Errors**

| Condition | Code |
| --- | --- |
| No pointer-position read channel on the active backend | `-32010 ProviderUnavailable` |
| Compositor IPC socket absent / query failed | `-32010 ProviderUnavailable` | **Example**

```json
{ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "mouse_get_position", "arguments": {} } }
// -> {"x": 812, "y": 344, "display": "DP-1"}
```

### `mouse_scroll`

Emit scroll-wheel deltas at the current pointer position.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "dx": {
      "type": "integer", "default": 0,
      "description": "Horizontal wheel steps; positive scrolls right, negative left"
    },
    "dy": {
      "type": "integer", "default": 0,
      "description": "Vertical wheel steps; positive scrolls down, negative up"
    }
  },
  "additionalProperties": false
}
```

At least one of `dx`, `dy` must be non-zero. One step = one discrete
`wl_pointer.axis` detent (~15° wheel notch).

**Returns**: `text` - `"Scrolled dx=<n> dy=<n>"`.

**Errors**: `InvalidParams` (both zero), `InputInjectionFailed`.

### `mouse_drag`

Press a button at `(from_x, from_y)`, move to `(to_x, to_y)` over
`duration_ms`, then release.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "from_x": { "type": "integer" },
    "from_y": { "type": "integer" },
    "to_x": { "type": "integer" },
    "to_y": { "type": "integer" },
    "button": { "type": "string", "enum": ["left", "right", "middle"], "default": "left" },
    "duration_ms": {
      "type": "integer", "default": 250, "minimum": 0, "maximum": 10000,
      "description": "Interpolation time; 0 performs an instant drag"
    }
  },
  "required": ["from_x", "from_y", "to_x", "to_y"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Dragged <button> from (x1, y1) to (x2, y2) in <ms>ms"`.

**Errors**: `InvalidParams`, `InputInjectionFailed`.

### `mouse_button_control`

Hold or release a button without moving - building block for custom gestures.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "button": { "type": "string", "enum": ["left", "right", "middle"] },
    "action": { "type": "string", "enum": ["down", "up"] }
  },
  "required": ["button", "action"],
  "additionalProperties": false
}
```

`down` presses and holds; `up` releases. The server tracks button state per
session; releasing an unpressed button is a no-op success.

**Returns**: `text` - `"<button> button down"` / `"<button> button up"`.

**Errors**: `InvalidParams`, `InputInjectionFailed`.

---

## Keyboard Tools

Both tools use `InputProvider` (virtual-keyboard -> uinput -> portal
RemoteDesktop), Phase 1, and honour [Focus Safety](#focus-safety).

Key names follow **XKB keysym**spelling, case-insensitive: letters (`"a"`...),
digits, `Return`, `Escape`, `Tab`, `space`, `BackSpace`, `Delete`,
`Home`/`End`/`Page_Up`/`Page_Down`, arrows (`Left`, `Right`, `Up`, `Down`),
function keys `F1`-`F24`, and common symbols (`minus`, `equal`, `comma`, ...).

### `type_text`

Type a literal UTF-8 string into the focused element, with optional
inter-key delay. Newlines (`\n`) produce `Return` presses; characters with no
direct keysym are injected via the virtual keyboard's Unicode code-point path
on the wlr backend; on the uinput backend non-ASCII input is rejected
with `isError` (no Unicode fallback).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "text": {
      "type": "string", "minLength": 1, "maxLength": 65536,
      "description": "Literal text to type"
    },
    "delay_ms": {
      "type": "integer", "default": 0, "minimum": 0, "maximum": 1000,
      "description": "Delay between key events in milliseconds"
    }
  },
  "required": ["text"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Typed <n> characters"`. The typed text is **not**
echoed back (it may contain secrets); the count is the UTF-8 `chars()` count.

**Errors**

| Condition | Code |
| --- | --- |
| Empty/oversized `text`, `delay_ms` out of range | `-32602 InvalidParams` |
| Text failed sanitization (NUL/control bytes other than `\n`, `\t`) | `-32006 SanitizationRejected` |
| Active window changed while typing | `-32013 FocusChanged` (as `isError: true` result) |
| Keyboard injection failed | `-32012 InputInjectionFailed` | **Example**

```json
{ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
  "params": { "name": "type_text", "arguments": { "text": "ls -la\n", "delay_ms": 12 } } }
// -> "Typed 7 characters"
```

### `key_control`

Press (`down`+`up`), hold (`down`), or release (`up`) a single key, optionally
chorded with modifiers. `press` = a full tap; `down`/`up` enable custom
multi-key sequences across calls.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "key": {
      "type": "string",
      "description": "XKB keysym name, e.g. \"c\", \"Return\", \"F5\", \"Left\""
    },
    "action": { "type": "string", "enum": ["press", "down", "up"] },
    "modifiers": {
      "type": "array",
      "items": { "type": "string", "enum": ["ctrl", "shift", "alt", "super"] },
      "maxItems": 4,
      "description": "Modifiers held for the duration of the action"
    }
  },
  "required": ["key", "action"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Pressed ctrl+shift+t"` (modifier order normalised to
`ctrl+shift+alt+super`).

**Errors**: `InvalidParams` (unknown key name), `SanitizationRejected`,
`FocusChanged`, `InputInjectionFailed`.

**Example**

```json
{ "jsonrpc": "2.0", "id": 5, "method": "tools/call",
  "params": { "name": "key_control",
    "arguments": { "key": "t", "action": "press", "modifiers": ["ctrl", "shift"] } } }
// -> "Pressed ctrl+shift+t"
```

---

## Vision & Screen Tools

Capture-side tools use `CaptureProvider`; tree-side tools use
`UIAutomationProvider`; model-side tools use `VisionProvider`. All honour
[Spatial Focus](#spatial-focus) where noted.

### `screenshot`

Capture the screen as PNG. Without arguments it captures the whole layout (or
the spatial-focus rect when set); `region` crops to a rect and `display`
limits capture to one output.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "region": {
      "type": "object",
      "properties": {
        "x": { "type": "integer" },
        "y": { "type": "integer" },
        "w": { "type": "integer", "minimum": 1 },
        "h": { "type": "integer", "minimum": 1 }
      },
      "required": ["x", "y", "w", "h"],
      "additionalProperties": false,
      "description": "Crop rect in logical coordinates"
    },
    "display": {
      "type": "string",
      "description": "Output name from screen_info (e.g. \"eDP-1\", \"DP-2\"); omit for all outputs"
    }
  },
  "additionalProperties": false
}
```

**Returns**: two content items - `text` (`"Captured <w>x<h> PNG of <scope>"`)
then `image` (`image/png`, base64, physical pixels).

**Errors**

| Condition | Code |
| --- | --- |
| Bad region / unknown `display` | `-32602 InvalidParams` |
| No capture backend (non-wlroots compositor without portal) | `-32010 ProviderUnavailable` |
| Screencopy/portal denied or encode failed | `-32011 CaptureFailed` | **Example**

```json
{ "jsonrpc": "2.0", "id": 6, "method": "tools/call",
  "params": { "name": "screenshot",
    "arguments": { "region": { "x": 0, "y": 0, "w": 400, "h": 300 } } } }
// -> content: [
//     {"type":"text","text":"Captured 400x300 PNG of region (0,0,400,300)"},
//     {"type":"image","data":"iVBORw0KGgoAAA...","mimeType":"image/png"} ]
```

### `screen_info`

Enumerate outputs, layout bounds, and the focused output.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON:

```json
{
  "monitors": [
    {
      "name": "eDP-1",
      "x": 0, "y": 0,
      "width": 1280, "height": 720,
      "physical_width": 1920, "physical_height": 1080,
      "scale": 1.5,
      "refresh_hz": 60,
      "focused": true
    }
  ],
  "layout": { "x": 0, "y": 0, "width": 1280, "height": 720 }
}
```

Backend: `WindowProvider` (`hyprctl monitors -j`) cross-checked against
`CaptureProvider` output enumeration.

**Errors**: `ProviderUnavailable` when neither `hyprctl` nor the wlr output
manager responds.

### `screen_highlight`

Draw a translucent rectangle overlay at `(x, y, w, h)` for `duration_ms` -
a `zwlr_layer_shell_v1` surface on the `overlay` layer with an empty input
region, so clicks pass straight through. Purely visual feedback; it does
not affect capture or input. On multi-monitor layouts the overlay is
anchored to the output containing the rect's centre.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer" },
    "y": { "type": "integer" },
    "w": { "type": "integer", "minimum": 1, "maximum": 16384 },
    "h": { "type": "integer", "minimum": 1, "maximum": 16384 },
    "duration_ms": {
      "type": "integer", "default": 1500, "minimum": 100, "maximum": 30000
    }
  },
  "required": ["x", "y", "w", "h"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Highlighted (x, y, w, h) for <ms>ms"`.

**Errors**: `InvalidParams`, `ProviderUnavailable` (the `OverlayProvider`
slot is `None` - compositor lacks `zwlr_layer_shell_v1`, the session is
X11, or it is headless; `-32010` carries `data.provider = "OverlayProvider"`;
a no-op success is NOT returned, the call fails loudly).

### `color_at`

Sample the colour of the logical-space pixel at `(x, y)` via a 1×1
screencopy. The captured frame is decoded and the pixel's real RGBA is
returned (on HiDPI outputs the 1×1 logical region may capture larger - the
centre pixel is sampled).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer" },
    "y": { "type": "integer" }
  },
  "required": ["x", "y"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON -
`{"x":640,"y":420,"hex":"#3B82F6","r":59,"g":130,"b":246,"a":255}`.

**Errors**: `InvalidParams` (point outside layout bounds), `CaptureFailed`.

### `set_spatial_focus`

Set or clear the process-scoped region of interest (see
[Spatial Focus](#spatial-focus)). Two call shapes:

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "x": { "type": "integer" },
    "y": { "type": "integer" },
    "w": { "type": "integer", "minimum": 1 },
    "h": { "type": "integer", "minimum": 1 },
    "clear": { "type": "boolean" }
  },
  "anyOf": [
    { "required": ["x", "y", "w", "h"] },
    { "required": ["clear"], "properties": { "clear": { "const": true } } }
  ],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Spatial focus set to (x, y, w, h)"` or
`"Spatial focus cleared"`.

**Errors**: `InvalidParams` when neither a full rect nor `clear: true` is
given.

### `get_ui_tree`

Return the AT-SPI2 accessibility tree rooted at the desktop (the
registry root whose children are the running applications) as nested
JSON, pruned to `depth` levels.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "depth": {
      "type": "integer", "default": 3, "minimum": 1, "maximum": 16,
      "description": "Maximum tree depth below the focused application root"
    }
  },
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON:

```json
{
  "name": "Firefox",
  "role": "application",
  "bounds": { "x": 0, "y": 0, "w": 1280, "h": 720 },
  "children": [
    {
      "name": "New Tab", "role": "frame",
      "bounds": { "x": 0, "y": 0, "w": 1280, "h": 720 },
      "children": []
    }
  ]
}
```

Node fields: `name`, `role`, `states` (when non-default), `bounds` (logical
coords), `children`. Trees are capped at 5 000 nodes; deeper content sets
`"truncated": true` on the root.

**Errors**: `ProviderUnavailable` (no AT-SPI bus / assistive tech not
enabled), `InternalError` (D-Bus fault).

### `get_focused_element`

Return properties of the element that currently owns keyboard focus.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON:

```json
{
  "found": true,
  "name": "Search",
  "role": "entry",
  "states": ["focused", "editable"],
  "bounds": { "x": 412, "y": 118, "w": 480, "h": 32 },
  "center": { "x": 652, "y": 134 },
  "application": "Firefox",
  "pid": 2314
}
```

When nothing reports focus: `{"found": false}`.

**Errors**: `ProviderUnavailable`.

### `find_element`

Search the focused application's AT-SPI2 tree by case-insensitive substring
against `name`, `description`, and `role`.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string", "minLength": 1, "maxLength": 256,
      "description": "Substring matched against accessible name, description, or role"
    }
  },
  "required": ["query"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON - up to 10 matches in tree order,
each with its bounds, centre point, and whatever accessibility metadata
the backend reports:

```json
{
  "found": true,
  "count": 2,
  "matches": [
    {
      "name": "Reload",
      "role": "push-button",
      "states": ["focusable", "sensitive"],
      "bounds": { "x": 980, "y": 64, "w": 96, "h": 36 },
      "center": { "x": 1028, "y": 82 }
    },
    {
      "name": "",
      "role": "",
      "states": [],
      "bounds": { "x": 1090, "y": 64, "w": 96, "h": 36 },
      "center": { "x": 1138, "y": 82 }
    }
  ]
}
```

Backends that expose only geometry report `"name"`/`"role"` as `""` and
`"states"` as `[]`.

Not found: `{"found": false, "count": 0, "matches": []}` (a **success**
result - see [Conventions](#request--response-envelope)).

**Errors**: `InvalidParams` (empty query), `ProviderUnavailable`.

### `invoke_element`

Find an element in the focused application's AT-SPI2 tree (same matching
rules as `find_element`) and invoke an action on it **directly through the
AT-SPI Action interface**- no synthesized pointer event. This is the
preferred way to act on controls that expose accessible actions: it is
unaffected by occlusion, pointer position, or focus races, and reduces
reliance on coordinate-based `mouse_click` calls. UI-interaction class:
not consent-gated (physical-input-equivalent); can reach privileged
dialogs - see THREAT_MODEL.md residual R-13.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string", "minLength": 1, "maxLength": 256,
      "description": "Substring matched against accessible name, description, or role (same semantics as find_element)"
    },
    "action": {
      "type": "string",
      "enum": ["press", "focus", "expand", "collapse"],
      "default": "press",
      "description": "AT-SPI Action to invoke on the matched element"
    }
  },
  "required": ["query"],
  "additionalProperties": false
}
```

`press`/`focus`/`expand`/`collapse` map onto the AT-SPI Action interface's
named actions; when the matched element does not implement the requested
action, the tool reports it in `action_result` rather than falling back to
coordinates.

**Returns**: `text` containing JSON - the invoked element's bounding rect
plus the action result:

```json
{
  "found": true,
  "action": "press",
  "action_result": "ok",
  "element": {
    "bounds": { "x": 980, "y": 64, "w": 96, "h": 36 },
    "center": { "x": 1028, "y": 82 }
  }
}
```

`action_result` is `"ok"` on success or `"action_not_supported"` when the
element lacks the requested AT-SPI action (the `found`/`element` payload is
still returned so the caller can fall back to `mouse_click` on `center`).

**Errors**

| Condition | Code |
| --- | --- |
| Empty/oversized `query`, bad `action` enum | `-32602 InvalidParams` |
| Query matched no element | `-32016 ElementNotFound` |
| No AT-SPI bus / assistive tech not enabled | `-32010 ProviderUnavailable` | ### `find_text_on_screen`

OCR the screen (or a region) with the `VisionProvider` text model and return
bounding boxes for occurrences of `text`.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "text": {
      "type": "string", "minLength": 1, "maxLength": 256,
      "description": "Text to locate (case-insensitive)"
    },
    "region": {
      "type": "object",
      "properties": {
        "x": { "type": "integer" }, "y": { "type": "integer" },
        "w": { "type": "integer", "minimum": 1 }, "h": { "type": "integer", "minimum": 1 }
      },
      "required": ["x", "y", "w", "h"],
      "additionalProperties": false,
      "description": "Overrides the spatial-focus rect for this call"
    }
  },
  "required": ["text"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON:

```json
{
  "found": true,
  "count": 1,
  "matches": [
    {
      "text": "Sign in",
      "confidence": 0.97,
      "bounds": { "x": 980, "y": 64, "w": 96, "h": 36 },
      "center": { "x": 1028, "y": 82 }
    }
  ]
}
```

**Errors**: `InvalidParams`, `ProviderUnavailable` (ONNX model not loaded),
`CaptureFailed`.

### `find_icon`

Locate an icon or visual element from a natural-language description using
OWL-ViT open-vocabulary detection on the captured frame.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "description": {
      "type": "string", "minLength": 1, "maxLength": 256,
      "description": "Natural-language visual query, e.g. \"hamburger menu icon\", \"blue submit button\""
    }
  },
  "required": ["description"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON - up to 32 detections over the 0.10
confidence floor, score-descending:

```json
{
  "found": true,
  "count": 1,
  "detections": [
    {
      "label": "hamburger menu icon",
      "score": 0.83,
      "bounds": { "x": 24, "y": 16, "w": 28, "h": 28 },
      "center": { "x": 38, "y": 30 }
    }
  ]
}
```

**Errors**: `InvalidParams`, `ProviderUnavailable`, `CaptureFailed`.

### `wait_for_ui_element`

Poll `find_element` every 250 ms until the query matches or `timeout_ms`
elapses. Use after actions that trigger UI transitions.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "query": { "type": "string", "minLength": 1, "maxLength": 256 },
    "timeout_ms": {
      "type": "integer", "default": 10000, "minimum": 250, "maximum": 120000
    }
  },
  "required": ["query"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON - on success
`{"found": true, "count": 1, "matches": [<match>], "elapsed_ms": <n>}` where
the match entry is the same shape as `find_element`'s
(`{"name","role","states","bounds","center"}` - backends that expose only
geometry report `""`/`[]` for the metadata fields); on timeout
`{"found": false, "timed_out": true, "elapsed_ms": <n>}` (a success result,
not an error).

**Errors**: `InvalidParams`, `ProviderUnavailable`.

### `screen_record`

Record a bounded burst of screen captures: one PNG frame every
`interval_ms` for up to `duration_ms`. This is the bounded version of
capture - for a caller-driven live feed see
[`screen_stream`](#screen_stream) (v1.4.0). Frames are written to a fresh
`rec-<ulid>` directory (mode `0700`) under the captures root
(`~/.ultranix-mcp/captures/` preferred, `/tmp` fallback) together with a
`manifest.json`, and the directory is **kept**after the call returns.

Shipped at v1.2.0. Works on any backend that can capture frames -
wlr-screencopy and grim on wlroots sessions, the portal capture path on
KDE/GNOME, `scrot` on X11 - and returns `-32010 ProviderUnavailable`
where no `CaptureProvider` resolved.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "duration_ms": {
      "type": "integer", "minimum": 100, "maximum": 30000,
      "description": "Total recording length in milliseconds"
    },
    "interval_ms": {
      "type": "integer", "default": 250, "minimum": 50, "maximum": 5000,
      "description": "Capture interval in milliseconds"
    },
    "region": {
      "type": "object",
      "description": "Crop rect in logical coordinates (same convention as screenshot)",
      "properties": {
        "x": { "type": "integer" },
        "y": { "type": "integer" },
        "w": { "type": "integer", "minimum": 1 },
        "h": { "type": "integer", "minimum": 1 }
      },
      "required": ["x", "y", "w", "h"],
      "additionalProperties": false
    },
    "display": {
      "type": "string",
      "description": "Output name from screen_info (e.g. \"eDP-1\"); omit for all outputs"
    }
  },
  "required": ["duration_ms"],
  "additionalProperties": false
}
```

Scope precedence mirrors `screenshot`: explicit `region` wins, then
`display` resolves to that output's layout rect, else the full layout.
The session spatial-focus rect is **not**consulted.

Behaviour contract:

- Target frame count is `duration_ms / interval_ms` (at least 1), hard-
  capped at **600 frames**; total bytes written are hard-capped at
  **512 MiB**. A frame that would cross the byte cap is dropped and the
  recording ends with `truncated: true` / `stop_reason: "byte_cap"`.
- Missed ticks delay rather than burst - successive captures stay at
  least `interval_ms` apart even if a capture runs long.
- The call always runs to its bound (duration, frame cap, or byte cap);
  **mid-record cancellation is not supported**. For "live" UX, re-invoke
  with small `duration_ms` values.
- `manifest.json` is written on every exit path - including partial or
  failed recordings - so the output directory is self-describing.
- The `rec-<ulid>` dir is **kept**after the call returns - there is no
  auto-prune; the operator removes recordings. Each recording is bounded
  by the 512 MiB cap above.
- **Not consent-gated**: the tool reads pixels and writes only into a
  fresh server-owned `0700` directory - nothing caller-chosen is written
  or destroyed.

**Returns**: `text` containing JSON:

```json
{
  "dir": "/home/user/.ultranix-mcp/captures/rec-01J9XKQV0R6T4H2Y8ZQ3N0AB12",
  "frames": 40,
  "duration_ms": 10042,
  "truncated": false,
  "manifest": {
    "tool": "screen_record",
    "schema": 1,
    "backend": "wlr-screencopy",
    "frame_target": 40,
    "frames_written": 40,
    "total_bytes": 1843200,
    "byte_cap": 536870912,
    "stop_reason": "duration",
    "frames": [
      { "file": "frame_0001.png", "bytes": 46080, "width": 1920, "height": 1080, "t_ms": 251 }
    ]
  }
}
```

The manifest records `args`, `backend` (the resolved capture backend
name), `region`/`display`, `started_at`/`finished_at`/`elapsed_ms`,
`frames[]` (`file`, `bytes`, `width`, `height`, `t_ms`), `truncated`,
`stop_reason` (`duration` | `byte_cap` | `capture_error` | `io_error`),
and `error` when a failure occurred. A call that captures **zero**frames
because the backend faulted is an `isError` result, not a success.

**Errors**: `InvalidParams` (out-of-range `duration_ms`/`interval_ms`,
`region` w/h < 1, unknown `display` name - the error lists the known
outputs), `ProviderUnavailable` (no capture backend), `InternalError`
(recording-dir creation failure). Backend capture faults mid-run surface
as `isError` results with the partial manifest still on disk.

### `screen_stream`

Continuous live screen capture with a `start` / `status` / `latest` /
`stop` lifecycle - the live counterpart to `screen_record`'s bounded
burst. `start` spawns a background task on the server's
tokio runtime that captures one PNG frame per `fps` interval into a fresh
`stream-<ulid>` directory (mode `0700`) under the captures root
(`~/.ultranix-mcp/captures/` preferred, `/tmp` fallback), keeping a
bounded **rolling window**on disk: when `max_frames` or `max_bytes` would
be crossed the *oldest* frames are evicted and counted as
`dropped_frames`. `latest` returns the newest frame as image content so
clients can poll; `stop` cancels and joins the task and returns final
stats. This is a rolling-window disk capture, **not**an RTP/streaming
protocol - frames are pulled per `latest` call.

Shipped at v1.4.0. Works on any backend that can capture frames - same
`CaptureProvider` coverage as `screen_record` - and `start` returns
`-32010 ProviderUnavailable` where none resolved.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "action": {
      "type": "string",
      "enum": ["start", "status", "latest", "stop"],
      "description": "Lifecycle action"
    },
    "fps": {
      "type": "integer", "default": 2, "minimum": 1, "maximum": 10,
      "description": "Capture rate in frames/second; start only"
    },
    "max_frames": {
      "type": "integer", "default": 600, "minimum": 1, "maximum": 1800,
      "description": "Rolling window size in frames; start only"
    },
    "max_bytes": {
      "type": "integer", "default": 536870912, "minimum": 1, "maximum": 536870912,
      "description": "Rolling window byte budget (default and ceiling 512 MiB); start only"
    },
    "since": {
      "type": "integer",
      "description": "latest only: frames_written watermark - only frames newer than this seq count; every latest reply reports its seq"
    },
    "wait_ms": {
      "type": "integer", "default": 0, "minimum": 0, "maximum": 30000,
      "description": "latest only: long-poll up to this long for a frame newer than since (or the first frame) before answering"
    }
  },
  "required": ["action"],
  "additionalProperties": false
}
```

Behaviour contract:

- **Single stream server-wide.**The registry is process-global - HTTP
  and stdio callers share it. A second `start` while a task is alive is an
  `isError` result naming the active `stream_id`; a *dead* task
  (`stop_reason` `capture_error`/`io_error`) does not block a fresh
  `start` - its finished handle is displaced and its dir + manifest stay
  on disk.
- **Rolling eviction.**Eviction runs before each write: oldest frames
  are removed while the window is at `max_frames` or the byte budget would
  overflow; a frame larger than the whole `max_bytes` budget is dropped
  unwritten, so `buffered_bytes <= max_bytes` holds unconditionally.
  On-disk frames are `frame_NNNNN.png` (sequence-numbered).
- **`manifest.json` is written by the task on every exit path**- `stop`,
  `capture_error`, `io_error` - so a stream that died on its own is still
  self-describing on disk. The manifest records `tool`/`schema`/
  `stream: true`, the call `args`, `backend` (resolved capture backend
  name), `dir`, `fps`/`interval_ms`/`max_frames`/`max_bytes`,
  `started_at`/`finished_at`/`elapsed_ms`, the extant `frames[]` list
  (`file`, `bytes`, `width`, `height`, `t_ms`), `buffered_*`,
  `frames_written`/`bytes_written`, `dropped_frames`, `stop_reason`
  (`stopped` | `capture_error` | `io_error`), and `error` when a failure
  occurred.
- **Damage-driven sessions.**On capture backends that can hold a
  session - wlroots (`ext-image-copy-capture`, or
  `zwlr_screencopy` `copy_with_damage` elsewhere) and RemoteDesktop
  portals (one held PipeWire stream) - the capture task pushes **only
  changed frames**: `frames_written`/`seq` advance on real damage, an
  idle desktop produces no disk churn, and `fps` acts as a write-rate
  ceiling rather than a timer. Backends without a session mode (grim,
  X11, Screenshot-portal-only) keep the per-tick polling loop verbatim;
  the first frame still lands as soon as the backend produces one. On
  RemoteDesktop portals the session open raises **one** `Start` consent
  dialog per `start` - nothing is persisted, so the next `start`
  re-consents.
- **Ticking.**Missed ticks delay rather than burst (a slow backend
  never triggers a catch-up storm), and `stop` is checked before every
  tick; session-mode `stop` lands within one 200 ms poll slice.
- **`latest` long-polls.**`since` is a `frames_written` watermark (every
  `latest` reply reports its `seq` for chaining) and `wait_ms`
  (0..=30000, default 0) is how long the call parks for a newer frame -
  or the first frame at all on a cold start. On timeout it returns a
  text-only "no new frame" result (`isError` stays false - a quiet
  stream is not a fault); a stopped/dead stream answers the "no stream"
  error immediately rather than waiting out the deadline.
- **Retention.**The `stream-<ulid>` dir is **kept**after the stream
  ends, matching `screen_record` - there is no auto-prune; the operator
  removes stream dirs. Disk use while running is bounded by
  `max_frames`/`max_bytes`.
- **Not consent-gated**- same posture as `screen_record`: pixels are
  read and written only into a fresh server-owned `0700` directory;
  nothing caller-chosen is written or destroyed.
- **Not replayable**- `screen_stream` is in `NON_REPLAYABLE`: replaying
  a recorded `start` would spawn a background capture task, so
  `replay_action` refuses it (`InvalidParams`). Lifecycle calls
  (`start`/`stop`) are still recorded to audit/history; the polling
  actions (`status`/`latest`) are suppressed from history - they are
  per-frame reads that would flood the bounded store.
- **No shutdown drain.**There is no server-level cancel hook - dropping
  the runtime aborts the task; frames already on disk survive (the
  manifest may be absent on a hard kill).
- `fps`/`max_frames`/`max_bytes` are accepted on every action but only
  meaningful on `start` - `status`/`latest`/`stop` ignore them.

**Returns**- per action:

- `start`: `text` containing JSON -

  ```json
  {
    "stream_id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12",
    "dir": "stream-01J9XKQV0R6T4H2Y8ZQ3N0AB12",
    "fps": 2,
    "interval_ms": 500,
    "max_frames": 600,
    "max_bytes": 536870912,
    "started_at": "2026-09-16T08:00:00Z"
  }
  ```

  (`dir` is the basename only - the full path never crosses the wire.)

- `status`: `text` containing JSON - `{"active": false}` when no stream
  exists (ever ran); otherwise:

  ```json
  {
    "active": true,
    "stream_id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12",
    "dir": "stream-01J9XKQV0R6T4H2Y8ZQ3N0AB12",
    "fps": 2,
    "started_at": "2026-09-16T08:00:00Z",
    "frames_written": 41,
    "bytes_written": 1889280,
    "buffered_frames": 41,
    "buffered_bytes": 1889280,
    "dropped_frames": 0,
    "latest_frame": "frame_00041.png",
    "last_error": null,
    "stop_reason": null,
    "finished_at": null
  }
  ```

- `latest`: two content items - `text` (`"Latest frame frame_00041.png
  (1920x1080 PNG) of stream <id>"`) then `image` (`image/png`, base64) -
  the same wire shape as `screenshot`, so clients can poll frames.
- `stop`: `text` containing JSON - `{"stopped": true, "aborted": ...,
  "stream_id": ..., "dir": ..., "fps": ..., "started_at": ..., "finished_at": ...,
  "frames_written": ..., "bytes_written": ..., "buffered_frames": ...,
  "buffered_bytes": ..., "dropped_frames": ..., "latest_frame": ...,
  "stop_reason": ..., "last_error": ..., "manifest": "manifest.json"}`.
  `aborted` is `true` when the task did not exit within the 15 s join
  budget and was killed (stats are best-effort then; the manifest is
  still written by the task's drop guard with `stop_reason`
  `"terminated"`/`"panic"`). A dead-but-unreaped stream still reports
  its final stats (the task already wrote its own manifest).

**Errors**

|| Condition | Code / result |
|| --- | --- |
|| Missing `action`, unknown action, `fps`/`max_frames`/`max_bytes` out of range, unknown fields | `-32602 InvalidParams` |
|| No capture backend | `-32010 ProviderUnavailable` (`start` only) |
|| Stream-dir creation/rename failure | `-32603 InternalError` |
|| `start` while a stream is alive | `isError` result naming the active `stream_id` |
|| `latest`/`stop` with no stream, `latest` before the first frame | `isError` result |
|| Mid-stream capture/io fault | stream ends (`stop_reason` `capture_error`/`io_error`); `status`/`stop` report `last_error`, manifest still written | ---

## Automation Tools

### `sleep`

Block the call for `ms` milliseconds (tokio timer; other sessions are not
blocked).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "ms": { "type": "integer", "minimum": 0, "maximum": 60000 }
  },
  "required": ["ms"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Slept <ms> ms"`.

**Errors**: `InvalidParams` (`ms` > 60 000 - chain calls for longer waits).

### `mouse_move_path`

Move the pointer through a polyline of points over `duration_ms`
(evenly-timed interpolation; a hover, not a drag - no button is pressed).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "points": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "x": { "type": "integer" },
          "y": { "type": "integer" }
        },
        "required": ["x", "y"],
        "additionalProperties": false
      },
      "minItems": 2,
      "maxItems": 256
    },
    "duration_ms": {
      "type": "integer", "default": 500, "minimum": 0, "maximum": 30000
    }
  },
  "required": ["points"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Moved along <n>-point path in <ms>ms"`.

**Errors**: `InvalidParams` (<2 points), `InputInjectionFailed`.

### `system_command`

Execute a binary from the fixed, **arg-constrained**command set - the only
sanctioned escape hatch. This is a destructive tool: every invocation is
gated by the [consent challenge](#destructive-action-consent) unless the
server was launched with `--allow-destructive`.

Execution rules:

- **Direct spawn, no shell**- `Command::new` + an argument vector; never
  `sh -c`. Every argument is sanitised before spawn.
- **Absolute path pinning**- each allowed binary is resolved once at
  startup via `PATH` lookup to an absolute path; spawn always uses the
  pinned path, so a later `PATH` hijack cannot substitute a different
  binary.
- **Per-binary argument constraints**- an allowed binary may only be
  invoked with its sanctioned subcommands/flags; everything else is rejected
  with `-32003 ArgConstraintViolation`.
- **Path confinement**- any argument that resolves to a filesystem path
  must land under `$XDG_RUNTIME_DIR`, `/tmp`, or `~/.ultranix-mcp/**` (see
  [Error Model](#error-model)). `$HOME` at large is *not* an allowed root.

**Allowed commands and argument constraints**

| `command` | Permitted invocations | Denied |
| --- | --- | --- |
| `grim` | `grim`, `grim -o <output>`, `grim -g <geometry>` - no caller `[file]` argument; the server supplies a path inside a fresh `0700` mktemp dir under `~/.ultranix-mcp/captures/` and returns the image content directly | any caller-chosen path or other flag |
| `slurp` | `slurp [-f <format>] [-d] [-b <color>] [-c <color>]` - fixed flag set, no path arguments | everything else |
| `hyprctl` | `hyprctl [-j] clients`, `activewindow`, `monitors`, `workspaces`; `hyprctl [-j] dispatch focuswindow|movewindow|resizewindow|workspace|movetoworkspace <args>` - `-j` (JSON output) is a sanctioned global flag | `dispatch exec`, `dispatch exec-once`, `keyword`, `setprop`, `reload`, and every other flag, dispatcher, or subcommand |
| `scrot` | `scrot [-s] [-d <sec>]` - no caller `[file]` argument; same server-supplied captures-dir path as `grim` | any caller-chosen path or other flag |
| `xdotool` | X11/XWayland fallback sessions only - accepted when the session probe resolved an X11 backend (the `X11Input`/`X11Window` rungs); args pass through under sanitization | rejected with `ArgConstraintViolation` on native Wayland sessions |
| `wmctrl` | X11/XWayland fallback sessions only (same rule as `xdotool`) | rejected on native Wayland sessions | `xrandr` and `xprop` are pinned at startup alongside the command set but are
**provider-internal only**- they have no per-binary validation arm, so
`system_command` cannot invoke them (`CommandNotWhitelisted`). They exist to
give the X11 providers display geometry (`xrandr`) and `_NET_WM_STATE`
reads (`xprop`). The same pin-only posture covers `wl-copy`, `wl-paste`,
`xclip`, `xsel`, `kdotool` (v1.2.0 clipboard + KDE window rungs) and
`riverctl` (v1.4.0 river window rung).

`busctl` and `gdbus` are **not**in the command set: D-Bus interactions
(portals, AT-SPI2) are performed in-process via `zbus`/`atspi`, never
through a shell-out.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "command": {
      "type": "string",
      "enum": ["grim", "slurp", "hyprctl", "scrot", "xdotool", "wmctrl"],
      "description": "Allowed binary to execute (resolved to a pinned absolute path at startup)"
    },
    "args": {
      "type": "array",
      "items": { "type": "string", "maxLength": 512 },
      "maxItems": 16,
      "description": "Arguments passed verbatim (no shell expansion); validated against the per-binary constraints above"
    },
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response for this exact call"
    }
  },
  "required": ["command"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON -
`{"exit_code": 0, "stdout": "...", "stderr": "..."}` (stdout/stderr truncated to
64 KiB each). A non-zero exit is a successful result carrying the code, not a
protocol error. Commands time out at 15 s (`{"timed_out": true}`).

**Errors**

| Condition | Code |
| --- | --- |
| `command` outside the enum | `-32602 InvalidParams` |
| No `consent_token` supplied (or token expired/spent/mismatched) | `-32015 ConsentRequired` - `data.consent_token` carries the challenge |
| Binary absent from `PATH` at startup pin time | `-32003 CommandNotWhitelisted` (treated as unavailable) |
| Allowed binary invoked with a denied subcommand/flag (e.g. `hyprctl dispatch exec`, `xdotool` on Wayland) | `-32003 ArgConstraintViolation` |
| Path argument outside the path whitelist | `-32004 PathNotWhitelisted` |
| Metacharacters (`;`, `|`, `&`, `` ` ``, `$()`, NUL) in args | `-32006 SanitizationRejected` | **Example**

```json
{ "jsonrpc": "2.0", "id": 8, "method": "tools/call",
  "params": { "name": "system_command",
    "arguments": { "command": "slurp", "args": ["-f", "%x %y %w %h"] } } }
// -> {"exit_code": 0, "stdout": "320 180 640 400", "stderr": ""}
```

### `web_query`

Evaluate a CSS selector in the browser attached via CDP at
`127.0.0.1:9222` (Chromium/Firefox launched with remote debugging). Returns
the first match's element model.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "selector": {
      "type": "string", "minLength": 1, "maxLength": 1024,
      "description": "CSS selector, e.g. \"button.submit\", \"#main h1\""
    }
  },
  "required": ["selector"],
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON:

```json
{
  "found": true,
  "element": {
    "tag": "button",
    "id": "submit",
    "classes": ["submit", "primary"],
    "text": "Sign in",
    "bounds": { "x": 980, "y": 64, "w": 96, "h": 36 },
    "attributes": { "type": "submit", "aria-label": "Sign in" }
  }
}
```

Not found: `{"found": false}`. `bounds` are viewport CSS pixels mapped into
logical layout space when the browser window's position is known, otherwise
viewport-relative (field `bounds_space`: `"layout" | "viewport"`).

**Errors**: `InvalidParams`, `ProviderUnavailable` (nothing listening on
`127.0.0.1:9222`), `SanitizationRejected` (selector containing `javascript:`
or control bytes).

---

## Admin & Observability Tools

Window tools use `WindowProvider` - `hyprctl` IPC on Hyprland, `sway-ipc`
on sway, `wayfire-ipc` on Wayfire, `riverctl` + foreign-toplevel on river
(`riverctl` keeps focused-view `close` and relative `dx,dy`/`dw,dh`
geometry; `zwlr_foreign_toplevel_manager_v1` supplies `get_windows`,
`get_active_window`, and per-window `focus`/`close`/`min`/`max`/
`fullscreen` on `wlr-toplevel-N` ids - without the protocol the rung
degrades to focused-view-only and `get_windows`/`get_active_window`
return honest `isError` results), `wlr-toplevel` as the shared wlroots
fallback rung behind every compositor-specific provider and the sole rung
on unknown wlroots sessions, `kdotool`
on KDE, `gnome-shell` on GNOME (**requires the "Window Calls" Shell
extension**- `org.gnome.Shell.Extensions.Windows`; without it the rung
drops out and GNOME reports `ProviderUnavailable`), `wmctrl` + `xdotool`
on other X11 sessions; history/metrics tools are server core, Phase 4.

### `window_control`

Focus, move, resize, minimise, or close a window via the resolved window
backend (hyprctl dispatchers on Hyprland; the per-session rungs listed in
[Provider Backends](#provider-backends) elsewhere).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "action": {
      "type": "string",
      "enum": ["focus", "move", "resize", "minimize", "close"]
    },
    "window": {
      "type": "string",
      "description": "Backend window id (Hyprland \"0x...\" address, sway con_id, Wayfire view id, wlr-toplevel-N, GNOME window id, X11 window id) or unique title/class substring; omit for the active/focused window. On river \"focused\" - or an omitted selector - addresses the focused view directly, and wlr-toplevel-N ids address enumerated windows when the compositor advertises foreign-toplevel"
    },
    "x": { "type": "integer", "description": "Target x (move only)" },
    "y": { "type": "integer", "description": "Target y (move only)" },
    "w": { "type": "integer", "minimum": 1, "description": "Target width (resize only)" },
    "h": { "type": "integer", "minimum": 1, "description": "Target height (resize only)" },
    "dx": { "type": "integer", "description": "Relative x delta (move only; focused-view backends such as river)" },
    "dy": { "type": "integer", "description": "Relative y delta (move only; focused-view backends such as river)" },
    "dw": { "type": "integer", "description": "Relative width delta (resize only; focused-view backends such as river)" },
    "dh": { "type": "integer", "description": "Relative height delta (resize only; focused-view backends such as river)" },
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response (close only)"
    }
  },
  "required": ["action"],
  "additionalProperties": false
}
```

Per-action parameter rules (violations -> `InvalidParams`):

| `action` | Requires | Ignores |
| --- | --- | --- |
| `focus` | - | `x`, `y`, `w`, `h` |
| `move` | `x`, `y` *or* `dx`, `dy` | `w`, `h`, `dw`, `dh` |
| `resize` | `w`, `h` *or* `dw`, `dh` | `x`, `y`, `dx`, `dy` |
| `minimize`, `close` | - | all geometry | `dx`/`dy`/`dw`/`dh` are **relative deltas for river's focused-view geometry**
(v1.4.0): they are rejected with `InvalidParams` on any
list-capable backend, mixing absolute and relative pairs is rejected,
and deltas on non-geometry actions are rejected. On river they dispatch
`riverctl move <dir> <delta>` / `resize <axis> <delta>` against the
focused view.

`minimize` maps to Hyprland `movetoworkspacesilent special:...`; `close` maps
to `closewindow`. Other backends map honestly: sway `minimize` -> scratchpad,
Wayfire `minimize` -> `wm-actions/set-minimized`. On river,
`window:"focused"` (or an omitted selector) reaches `riverctl` directly -
`close` -> `riverctl close`, `move`/`resize` -> the delta forms above;
absolute `x,y`/`w,h` error honestly (river has no absolute form). With
foreign-toplevel advertised, `wlr-toplevel-N` ids from `get_windows`
address any window for `focus`/`close`/`minimize`/`maximize`/
`fullscreen` (and the un- variants where the protocol defines them);
the expected title/class are re-verified against a fresh enumeration
before dispatch so a stale index fails closed. Without the protocol,
non-focused selectors and verbs beyond `close`/geometry error honestly.
Ambiguous `window` substrings (>1 match) fail with
`InvalidParams` listing the candidate addresses.

`close` is a destructive action: it is consent-gated per
[Destructive-Action Consent](#destructive-action-consent). The first
`window_control { "action": "close" }` call without `consent_token` returns
`-32015 ConsentRequired` and does not close the window; retry the identical
call with the returned token. When `window` is omitted, the token binds the
window resolved at challenge time - if the active window changes before the
retry, the token is rejected and a fresh challenge is issued. `focus`,
`move`, `resize`, and `minimize` are not gated.

**Returns**: `text` - `"<action> applied to <address> (\"<title>\")"`.

**Errors**: `InvalidParams`, `ConsentRequired` (`action:"close"` without a
valid token), `ProviderUnavailable` (no window backend resolved for the
session - e.g. GNOME without the Window Calls extension),
`InternalError` (dispatcher rejected).

### `get_windows`

List all managed windows.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON array:

```json
[
  {
    "address": "0x5f3a21c0",
    "class": "firefox",
    "title": "ultranix-mcp - Mozilla Firefox",
    "workspace": { "id": 1, "name": "1" },
    "at": { "x": 0, "y": 0 },
    "size": { "w": 1280, "h": 720 },
    "focused": true,
    "floating": false,
    "fullscreen": false,
    "pid": 2314,
    "monitor": "eDP-1"
  }
]
```

**Errors**: `ProviderUnavailable`.

### `get_active_window`

Return the focused window (single object in `get_windows` shape) or
`{"focused": null}` when nothing is focused.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON (see above) or `{"focused": null}`.

**Errors**: `ProviderUnavailable`.

### `metrics`

Return the same Prometheus text exposition served at `GET /metrics` on
`:3010` - handy for stdio sessions that cannot reach the HTTP endpoint.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` - Prometheus 0.0.4 exposition using the canonical
`ultranix_mcp_*` metric set defined in
[ARCHITECTURE.md §7](ARCHITECTURE.md#7-observability):

```text
# HELP ultranix_mcp_tool_calls_total Tool call count by outcome
# TYPE ultranix_mcp_tool_calls_total counter
ultranix_mcp_tool_calls_total{tool="mouse_click",outcome="ok"} 41
# HELP ultranix_mcp_tool_duration_seconds Per-tool execution latency
# TYPE ultranix_mcp_tool_duration_seconds histogram
ultranix_mcp_tool_duration_seconds_bucket{tool="mouse_click",le="0.05"} 120
ultranix_mcp_rate_limit_rejections_total{reason="rate_limit"} 3
ultranix_mcp_active_sessions{transport="stdio"} 1
```

**Errors**: none beyond transport faults (always succeeds).

### `get_action_history`

Read the AES-256-GCM-encrypted action history
(`~/.ultranix-mcp/history.json`), newest-first.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "limit": {
      "type": "integer", "default": 50, "minimum": 1, "maximum": 1000
    },
    "action": {
      "type": "string",
      "description": "Case-insensitive substring filter over tool names (e.g. \"window\" matches window_control)"
    }
  },
  "additionalProperties": false
}
```

**Returns**: `text` containing JSON:

```json
{
  "count": 2,
  "actions": [
    {
      "id": "01J9XKQV0R6T4H2Y8ZQ3N0AB12",
      "index": 41,
      "timestamp": "2026-09-14T20:31:07.512Z",
      "tool": "mouse_click",
      "args": { "x": 640, "y": 420, "button": "left" },
      "success": true,
      "duration_ms": 8,
      "result_summary": "Clicked left at (640, 420)"
    }
  ]
}
```

`result_summary` is truncated to 200 chars; arguments are stored verbatim
except sensitive values: `type_text.text`, `clipboard_set.text`, and
`plugin_run.params` are redacted to `<redacted:N chars>` / `<redacted:N params>`,
and `clipboard_get` summaries keep only the MIME type and payload length.

**Errors**: `HistoryError` (decrypt/read failure).

### `replay_action`

Re-execute a recorded action by ULID `id` or by `index` from
`get_action_history`. Exactly one selector is required. The replayed call runs
through the full middleware stack (rate limit on HTTP, sanitization, audit)
and is itself appended to history. Replay is destructive - the tool is consent-gated
per [Destructive-Action Consent](#destructive-action-consent): the first call
without `consent_token` returns `-32015 ConsentRequired`. Consent tokens
never authorize replay beyond the `replay_action` call itself: when the
*replayed* action belongs to the destructive class (e.g. replaying a
recorded `system_command` or `window_control{action:"close"}`), the
replayed invocation passes back through the full consent gate and
re-challenges on its own `{key_id/session, tool, args_hash}` binding - the
consent granted for the original recorded call is never inherited.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "index": { "type": "integer", "minimum": 0 },
    "id": { "type": "string", "minLength": 26, "maxLength": 26 },
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response for this exact call"
    }
  },
  "anyOf": [
    { "required": ["index"], "not": { "required": ["id"] } },
    { "required": ["id"], "not": { "required": ["index"] } }
  ],
  "additionalProperties": false
}
```

Non-replayable tools are refused with `InvalidParams`: `metrics`,
`get_action_history`, `replay_action`, `clear_action_history` (recursion and
no-op guards), `plugin_list`, `plugin_reload` (read-only catalog/rescan
operations - nothing to replay), and `screen_stream` (a `start` replay
would spawn a background capture task - the record is kept, replay is
refused).

**Returns**: `text` containing JSON -
`{"replayed": "<tool>", "id": "<ulid>", "result": <original result content>}`.

**Errors**: `InvalidParams` (no/ambiguous selector, unknown id/index,
non-replayable tool), `ConsentRequired` (no valid `consent_token` - replay is
a destructive, consent-gated action; see
[Destructive-Action Consent](#destructive-action-consent)), `HistoryError`,
plus any error the replayed tool itself raises.

### `clear_action_history`

Securely wipe `history.json` (overwrite + delete) and reset the in-memory
index. The wipe itself is recorded to `audit.jsonl` - audit is never
cleared by this tool. This is a destructive, consent-gated action (see
[Destructive-Action Consent](#destructive-action-consent)).

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response"
    }
  },
  "additionalProperties": false
}
```

**Returns**: `text` - `"Action history cleared (<n> records removed)"`.

**Errors**: `ConsentRequired` (no valid `consent_token`), `HistoryError`
(filesystem failure; partial wipes are reported).

### `plugin_list`

List the plugin tool-macros loaded from `~/.ultranix-mcp/plugins/*.json`
(see [Plugin Manifests](#plugin-manifests)). Shipped at v1.2.0.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing a JSON array - one entry per loaded plugin:

```json
[
  {
    "name": "focus-firefox",
    "version": "1.0.0",
    "description": "Focus the Firefox window",
    "params": {
      "title": { "type": "string", "required": true, "description": "title substring" }
    },
    "steps": 1
  }
]
```

The manifest dir is rescanned on **every**call (manifests are tiny; a live
view beats cache invalidation), so edits are visible immediately.

**Errors**: `InvalidParams` (any argument supplied).

### `plugin_run`

Execute a plugin tool-macro: bind `params` against the manifest's declared
parameter spec, substitute `${param}` placeholders into each step's args,
and run the steps in order. Shipped at v1.2.0.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Plugin name as reported by plugin_list"
    },
    "params": {
      "type": "object",
      "description": "Parameter values for the manifest's declared params; undeclared keys are rejected"
    }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

Execution semantics:

- `plugin_run` is **not**itself consent-gated. Each step re-enters the
  normal dispatch path - `call_tool_secured` when a `SecurityContext`
  exists (the production path), `call_tool` otherwise - exactly like
  `replay_action` re-dispatches the recorded call. Destructive steps
  therefore challenge the consent gate on their own
  `{caller, tool, args_hash}` binding, are audited, and land in action
  history; consent granted to `plugin_run`'s caller never covers a step.
  A manifest that wants to thread a challenge token through declares a
  `consent_token` string param and references `${consent_token}` in the
  step args.
- Steps run in manifest order and execution **stops on the first failing
  step**. A step's `isError` result surfaces as `-32017 PluginStepError`;
  a step's JSON-RPC error keeps its own code - a `-32015 ConsentRequired`
  from a destructive step passes through intact (with `plugin`, `step`,
  and `step_tool` added to `data`) so the client can retry with the
  challenge token.
- Steps can only name real catalog tools - `plugin_*` tools are rejected
  at manifest load, so plugins cannot compose into unbounded macro
  recursion.
- `plugin_run` calls are themselves recorded in action history and are
  replayable like any non-meta tool.
- A manifest `tool` section (v1.4.0) makes the plugin callable by its own
  `tools/list` name - that call *is* `plugin_run` through the same secured
  path with an extra policy check on the exposed name; see
  [Plugin-exposed tools](#plugin-exposed-tools-v140).

**Returns**: `text` containing JSON:

```json
{
  "plugin": "focus-firefox",
  "steps_run": 1,
  "results": [
    { "step": 0, "tool": "window_control", "result": "focus applied to 0x5f3a21c0 (\"ultranix-mcp - Mozilla Firefox\")" }
  ]
}
```

Per-step `result` text is truncated to 200 chars (the action-history
`result_summary` convention).

**Errors**: `InvalidParams` (unknown plugin name, missing required param,
undeclared param supplied, wrong param type, a step referencing an
unsupplied optional param), `PluginStepError` (step `isError`), plus any
JSON-RPC error a step raises (e.g. `ConsentRequired`,
`ProviderUnavailable`).

### `plugin_reload`

Rescan `~/.ultranix-mcp/plugins/` and report what loaded and what was
skipped. Scanning is always live - this tool exists to surface the
diagnostics, not to flush state. Shipped at v1.2.0.

**inputSchema**

```json
{ "type": "object", "properties": {}, "additionalProperties": false }
```

**Returns**: `text` containing JSON:

```json
{
  "loaded": 1,
  "plugins": [ { "name": "focus-firefox", "version": "1.0.0", "description": "...", "params": {}, "steps": 1 } ],
  "skipped": [
    { "file": "/home/user/.ultranix-mcp/plugins/broken.json", "error": "invalid name \"Bad_Name\": must match ^[a-z][a-z0-9-]{0,63}$" }
  ]
}
```

**Errors**: `InvalidParams` (any argument supplied).

---

## Clipboard Tools

Clipboard tools read and write the desktop clipboard through
`ClipboardProvider` (shipped at v1.2.0). The backend ladder is
`wl-copy`/`wl-paste` (the `wl-clipboard` package) on Wayland sessions -
with `xclip` (+ `xsel` for `clear`) as the XWayland rung behind it - and
`xclip`/`xsel` on X11 sessions. Helpers are spawned through the pinned,
env-scrubbed whitelist path (`wl-copy`, `wl-paste`, `xclip`, `xsel` are
provider-internal pins - `system_command` cannot invoke them); write
payloads are fed over **stdin, never argv**, so copied secrets cannot leak
through the process list.

Reads are **text-first by design**: `clipboard_get` surfaces UTF-8 text
only - binary MIME payloads never cross the provider boundary. A
non-text or empty clipboard reads as `text: null`.

When no clipboard backend resolved (headless session, or no helper pinned
at startup) all three tools return `-32010 ProviderUnavailable` with
`data.provider = "ClipboardProvider"`.

### `clipboard_get`

Read the clipboard's text, or enumerate the MIME types the clipboard owner
currently offers.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "mime": {
      "type": "string", "default": "text/plain", "minLength": 1, "maxLength": 256,
      "description": "MIME type to read - \"text/plain\" (default), another text/* type or X11 text atom (UTF8_STRING, STRING, TEXT, COMPOUND_TEXT), or \"list\" to enumerate offered types"
    }
  },
  "additionalProperties": false
}
```

`mime` is a selection/validation surface, not a decoder: the provider
contract is text-first, so every accepted text type reads the same text
channel. Non-`text/*` values (e.g. `image/png`) are rejected -
use `"list"` to see what is offered.

**Returns**: `text` containing JSON - `{"mime": "text/plain", "text": "..."}`
(`"text": null` when the clipboard is empty or holds no text), or
`{"mimes": ["text/plain", "UTF8_STRING", ...]}` for `mime: "list"`.

**Errors**: `InvalidParams` (empty/unsupported `mime`, unknown fields),
`ProviderUnavailable`.

### `clipboard_set`

Overwrite the clipboard with the given text (max **1 MiB**of UTF-8).
This is a destructive, consent-gated action - see
[Destructive-Action Consent](#destructive-action-consent): the first call
without `consent_token` returns `-32015 ConsentRequired`; retry the
identical call with the returned token.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "text": {
      "type": "string", "maxLength": 1048576,
      "description": "Text to place on the clipboard (max 1 MiB)"
    },
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response"
    }
  },
  "required": ["text"],
  "additionalProperties": false
}
```

**Returns**: `text` - `"Copied <n> bytes to clipboard"`.

**Errors**: `InvalidParams` (missing `text`, payload over 1 MiB),
`ConsentRequired`, `ProviderUnavailable`.

### `clipboard_clear`

Clear the clipboard entirely (drop the selection so subsequent reads
report empty). Destructive and consent-gated like `clipboard_set`.

**inputSchema**

```json
{
  "type": "object",
  "properties": {
    "consent_token": {
      "type": "string",
      "description": "Challenge token from a prior -32015 ConsentRequired response"
    }
  },
  "additionalProperties": false
}
```

**Returns**: `text` - `"Clipboard cleared"`.

**Errors**: `ConsentRequired`, `ProviderUnavailable`. On the X11 rung
the real clear primitive is `xsel --clipboard --clear`; when `xsel` was
absent at pin time the call falls back to an `xclip -i` empty write and
still succeeds - `xclip` cannot disown a selection, so the fallback
leaves an empty-string owner and subsequent reads report an empty
clipboard.

---

## Plugin Manifests

Plugins are **declarative tool-macros**, not code: a JSON manifest in
`~/.ultranix-mcp/plugins/` (i.e. `<state-root>/plugins/*.json`) declaring
an ordered list of calls to real catalog tools with `${param}`
placeholders in string arguments. The `plugin_*` tools (above) list, run,
and diagnose them. Scanning is strictly read-only - no directory is
created and no file is written - and happens fresh on every `plugin_*`
call. Duplicate `name`s across files resolve to the first file in lexical
filename order; later duplicates are skipped. Since v1.4.0 a manifest may
also carry a `tool` section that registers the plugin as a first-class
`tools/list` entry - see
[Plugin-exposed tools](#plugin-exposed-tools-v140) below.

**Manifest shape**

```json
{
  "name": "focus-firefox",
  "version": "1.0.0",
  "description": "Focus the Firefox window",
  "params": {
    "title": { "type": "string", "required": true, "description": "title substring" }
  },
  "steps": [
    { "tool": "window_control", "args": { "action": "focus", "window": "${title}" } }
  ]
}
```

**Validation**- every rule failure skips the file with a `tracing::warn`
(never fatal; `plugin_reload` reports the skip):

- `manifest_version` (optional, unsigned integer) declares the manifest
  schema revision. Absent means `1` - the only revision this server
  reads. Any other value skips the file with a warning: format
  versioning is fail-closed, so a future-format manifest is never
  interpreted under a schema it did not declare.
- `name` must match `^[a-z][a-z0-9-]{0,63}$` and must not collide with a
  catalog tool name (a plugin named `sleep` would shadow the real tool).
- `version` is semver-ish: `MAJOR.MINOR.PATCH` with optional
  `-prerelease` / `+build` suffixes.
- `params` keys match `^[a-z][a-z0-9_]{0,63}$`; each declares a `type`
  (`string` | `number` | `boolean`), `required` (default `false`), and an
  optional `description`. Cap: 64 params.
- `steps` is non-empty, capped at **32 steps**(each step is a full
  secured dispatch + audit record - the cap keeps one `plugin_run`
  bounded).
- `step.tool` must be a real catalog tool; `plugin_*` names are rejected
  so plugins cannot compose into unbounded macro recursion, and
  `replay_action` is likewise rejected (since v1.3.0) - it re-enters the
  secured dispatch layer and could chain a recorded `plugin_run` back
  into plugin execution.
- Every `${ref}` inside a step's string args must reference a declared
  param.
- `tool` (optional; `expose_as_tool` alias accepted, v1.4.0) declares a
  `tools/list` registration - `name` `^[a-z][a-z0-9_]{0,63}$`,
  `description` ≤256 chars, `params` in the same shape as top-level
  `params` (merged; a name declared in both is an authoring error). Full
  rules below.

**Template rules**(`${...}` in `args` string values, at any depth):

- A string that is *exactly* `${name}` substitutes the typed JSON value -
  a `number`/`boolean` param lands as a JSON number/bool, so
  `"ms": "${ms}"` feeds `sleep` a real number. Inside a larger string the
  value is stringified.
- `$$` escapes a literal `$`, so `$${x}` renders as `${x}`; a lone `$`
  not followed by `$`/`{` is literal text.
- Referencing a declared-but-unsupplied (optional) param is a run-time
  `InvalidParams` - manifests cannot declare defaults.
- Supplied params not declared by the manifest are **rejected**(strict -
  mirrors `deny_unknown_fields` across the tool surface).

### Plugin-exposed tools (v1.4.0)

A manifest may add an optional `tool` section (`expose_as_tool` is an
accepted alias spelling) that registers the plugin as a **first-class
entry in `tools/list`**- a dynamic tool alongside the static catalog:

```json
{
  "name": "deploy-notes",
  "version": "1.0.0",
  "tool": {
    "name": "deploy_notes",
    "description": "Deploy the notes bundle",
    "params": { "env": { "type": "string", "required": true, "description": "target env" } }
  },
  "steps": [
    { "tool": "type_text", "args": { "text": "${env}" } }
  ]
}
```

Validation and shape:

- `tool.name` uses the tool grammar `^[a-z][a-z0-9_]{0,63}$` and is
  advertised **verbatim**- no `plugin_` prefix. It must not collide with
  a catalog tool name (the grammar reaches every catalog name, so the
  existing collision check keeps them disjoint); two manifests claiming
  the same tool name resolve to the first loaded, and the later manifest
  is skipped with a `plugin_reload` diagnostic.
- `tool.description` is a human-readable string capped at **256 chars**.
- `tool.params` declares *additional* params in the same shape as
  top-level `params` (`type` `string` | `number` | `boolean`,
  `required`, optional `description`); they merge into the manifest's
  param set, so `${ref}` resolution and `plugin_run` binding treat them
  identically. A param declared in **both**`params` and `tool.params` is
  an authoring error (the bindable set can never diverge from the
  advertised schema).
- The advertised `inputSchema` is generated from the merged param set:
  `type: "object"`, one property per param (`type` + optional
  `description`), a `required` array (omitted when empty), and
  `additionalProperties: false` - the same shape the static catalog's
  schemars-generated schemas produce.

Dispatch semantics - an exposed tool is *sugar over `plugin_run`*, never a
bypass:

- Calling `deploy_notes{env: "prod"}` is exactly
  `plugin_run{name: "deploy-notes", params: {env: "prod"}}` through the
  same secured pipeline: `call_tool_secured` policy-checks the tool's
  **own name**and audits/metrics/history under it; the call's argument
  object *is* the manifest `params` map; every step then re-enters the
  full dispatch - per-step consent re-challenge, audit, history, metrics,
  `-32017 PluginStepError` on a step `isError`, and `-32015` pass-through
  on a destructive step.
- **Dual policy gate**: a plugin-exposed tool is advertised and callable
  iff the caller's role allows `plugin_run` **and**the tool's own name
  passes the role's allow/deny. A `readonly` role denies them
  (`-32018 ReadOnlyMode`); an allowlist role that does not name the tool
  denies `-32019 NotInToolList`; a role that denies `plugin_run` sees none
  of them. Denials carry `denial_reason` like catalog denials.
- **Category**: plugin tools are uncatalogued - they inherit
  `plugin_run`'s category (`admin`). A `--category` filter that excludes
  `admin` removes them from `tools/list` and gates calls with `-32601`
  `CategoryDisabled`, same wire shape as catalog tools.
- **No `tools/list_changed` notification**- the server does not
  advertise that capability. The registry rescans the manifest dir on
  every `tools/list`/`tools/call` (the always-fresh model `plugin_list`
  already uses), so dropping in a manifest registers its tool on the next
  request and `plugin_reload` needs no cache flush - but clients must
  re-list themselves after `plugin_reload` or a manifest change; nothing
  is pushed.
- History summaries treat an exposed tool like `plugin_run`: step payloads
  are never persisted - only `plugin=<name> steps=<n>` is recorded (the
  check is on the result shape, not the dispatch name).

---

## Maturity Phases

| Phase | Scope | Tools landed |
| --- | --- | --- |
| 0 - Scaffold | Transports (stdio + streamable HTTP on `:3010`), mock providers, `tools/list` + `tools/call` dispatch | none (health/initialize only) |
| 1 - Hyprland I/O + security scaffolding | wlr capture+input, hyprctl windowing, arg-constrained exec; input sanitization, path whitelist, audit skeleton, consent gate | all mouse & keyboard tools; `screenshot`, `screen_info`, `color_at`; `sleep`, `mouse_move_path`, `system_command`; `window_control`, `get_windows`, `get_active_window` |
| 2 - AT-SPI2 | Accessibility tree + action invocation | `set_spatial_focus`, `get_ui_tree`, `get_focused_element`, `find_element`, `invoke_element`, `wait_for_ui_element`, `screen_highlight` |
| 3 - Vision + CDP | ONNX models, browser bridge | `find_text_on_screen`, `find_icon`, `web_query` |
| 4 - Enterprise | HTTP auth surface (`uxcp_*` enforcement on `:3010`, fail-closed bind), rate limiting, AES-256-GCM history, replay, metrics; opt-in Sentry via `ULTRANIX_MCP_SENTRY_DSN` (wired at v1.1.0) | `metrics`, `get_action_history`, `replay_action`, `clear_action_history` |
| 5 - Portability | Non-Hyprland backends (KDE/GNOME via portal+uinput; X11 via `scrot`/`xdotool`/`wmctrl` - shipped at v1.1.0; portal RemoteDesktop->PipeWire capture - v1.1.0) | no new tools - widens where existing ones work |
| 6 - v1.2.0 breadth wave | Clipboard providers (wl-clipboard/xclip), plugin tool-macros (`<state>/plugins/*.json`), bounded recording, compositor breadth (sway IPC window provider; KDE/GNOME portal routing; `kdotool` window provider on KDE), per-backend cargo features | `screen_record`; `plugin_list`, `plugin_run`, `plugin_reload`; `clipboard_get`, `clipboard_set`, `clipboard_clear` |
| 7 - v1.4.0 reach wave | Wayfire (`wayfire-ipc`), river (`riverctl`, focused-view-only rung - `window_control` on `"focused"`/`close` + relative deltas), and GNOME Window Calls (`gnome-shell`) window providers; live rolling-window capture; plugin-exposed dynamic tools (manifest `tool` sections); OCI/-bin distribution | `screen_stream`; plugin-exposed tools join `tools/list` dynamically (not catalogued); `window_control` gains `dx,dy`/`dw,dh` delta params |
| 8 - unreleased wlroots-breadth wave | Shared `wlr-toplevel` rung (`zwlr_foreign_toplevel_manager_v1`) behind every wlroots window provider and as the sole rung on unknown wlroots sessions; stable `ext_foreign_toplevel_list_v1` identifiers where advertised; river composite provider (foreign-toplevel enumeration + `riverctl` geometry); `screen_stream` damage-driven capture sessions (ext-image-copy-capture / `copy_with_damage` / held portal PipeWire) + `latest` long-poll | `screen_stream` gains `since`/`wait_ms` and damage-driven writes; `window_control` accepts `wlr-toplevel-<id>` selectors |

Tools advertised in `tools/list` always reflect the *currently available*
providers: a Phase-2 tool on a system without an AT-SPI bus is still listed
(it is part of the stable surface) but returns `ProviderUnavailable` when
called. Deployment-time `--category` filters (see
[API_VERSIONING.md](API_VERSIONING.md#category-filters)) remove tools from the
listing entirely. Since v1.4.0, plugin manifests with a `tool` section can
add entries to the listing at runtime - the server emits no
`tools/list_changed` notification, so clients should re-list after
`plugin_reload` (see [Plugin-exposed tools](#plugin-exposed-tools-v140)).

A second, finer-grained filter was added at v1.3.0: the runtime
access-control policy (`docs/adr/0010-policy-controls.md`). The server can
be started with `--readonly` (advertises only the non-mutating catalog),
`--allow-tools=tool1,tool2`, `--deny-tools=tool3`, or `--policy=/path/to/policy.toml`
for per-key role scoping. Policy-hidden tools are removed from
`tools/list` *and* rejected in `tools/call` - a caller cannot guess a
hidden tool into existence. Denied calls return `-32018 ReadOnlyMode`
or `-32019 NotInToolList` and are audited with an explicit
`denial_reason` field.
