# ADR 0010: Runtime Access-Control Policy

- **Status:** Accepted
- **Date:** v1.3.0 wave
- **Deciders:** ultranix-mcp architecture council
- **Related:** ENTERPRISE_PLAN §6 "Policy knobs roadmap", SECURITY.md

## Context

The server shipped with a coarse `--category` capability cap and a
consent gate for individual destructive calls. Enterprise deployments need
finer control:

- Read-only daemons that only expose observation tools.
- Per-tool allow/deny lists for least-privilege client roles.
- Per-API-key scoping so one HTTP server can serve an analyst key
  (screenshots + UI tree) and an automation key (full input) simultaneously.
- A fleet-managed config file rather than ever-longer CLI flags.

## Decision

- Introduce a `Policy` object loaded once at startup from an optional TOML
  file (`~/.config/ultranix-mcp/policy.toml` or `--policy=...`) layered with
  CLI overrides (`--readonly`, `--allow-tools=...`, `--deny-tools=...`).
- A `Policy` contains:
  - `default_role`: applied to stdio sessions and unmapped HTTP keys.
  - `roles`: named `Role` definitions.
  - `keys`: mapping from key fingerprint (`key_id`) to role name.
- A `Role` contains:
  - `readonly: bool` — shortcut that allows only the non-mutating tool set.
  - `allow_tools: Option<HashSet<String>>` — explicit allowlist.
  - `deny_tools: HashSet<String>` — explicit denylist.
- Evaluation order for a tool under a role:
  1. If tool is in `deny_tools` → deny (deny always wins).
  2. If `readonly` → allow only when the tool is in the readonly preset
     **or** in `allow_tools` — the allowlist *unions* with the preset, so
     operators can opt individual mutating tools back in; otherwise deny.
  3. If `allow_tools` is `Some` (and `readonly` is false) and tool is not
     in it → deny.
  4. Otherwise allow.
- Policy loading is **fail-closed**:
  - An explicit `--policy` path that is missing or malformed aborts
    startup — a typo'd path must never silently grant the permissive
    default. The auto-discovered default
    `~/.config/ultranix-mcp/policy.toml` is loaded only when the file
    exists.
  - `#[serde(deny_unknown_fields)]` on `Policy` and `Role` turns
    misspelled TOML keys into startup errors rather than silently
    ignored directives.
  - Every `keys` entry must reference a defined role — a dangling
    `keys` → role reference aborts startup (a typo'd role name would
    otherwise silently grant `default_role`).
- Readonly allowlist (non-mutating catalog, 15 tools): `screenshot`,
  `screen_info`, `color_at`, `get_ui_tree`, `get_focused_element`,
  `find_element`, `find_text_on_screen`, `find_icon`,
  `wait_for_ui_element`, `sleep`, `mouse_get_position`, `get_windows`,
  `get_active_window`, `metrics`, `plugin_list`. The preset is strictly
  observation-only; the excluded tools are denied because they mutate or
  disclose state: all mouse/keyboard input, `invoke_element` (performs
  AT-SPI actions — equivalent to input), `screen_highlight` (draws a
  visible overlay), `set_spatial_focus` (writes process-global state),
  `screen_record` (writes files), `clipboard_get` and
  `get_action_history` (cross-caller disclosure of clipboard/history
  contents), `plugin_reload` (server-state mutation), `plugin_run`,
  `clipboard_set`, `clipboard_clear`, `window_control`,
  `system_command`, `web_query`, `replay_action`,
  `clear_action_history`, `mouse_move_path`.
- Policy is applied in both `tools/list` (so the advertised surface matches the
  caller's role) and `tools/call` (so a forged `tools/call` request for a hidden
  tool is denied). The denial is audited with `denial_reason=readonly_mode` or
  `not_in_tool_list` and returned as `data.denial_reason` alongside
  `data.kind` (`ReadOnlyMode`/`NotInToolList`, codes `-32018`/`-32019`).
- Per-key scoping for HTTP: the `key_id` recovered from the request
  extensions is looked up in `policy.keys`; missing keys fall back to
  `default_role`. Stdio sessions always use `default_role`.
  `key_id` fingerprints are 8 hex chars (32 bits) — sufficient for tens of
  keys; deployments planning hundreds of mapped keys should note the
  birthday bound (a collision silently assigns the wrong role).
- Startup warnings surface the remaining silent-degradation cases:
  CLI policy flags (`--readonly`/`--allow-tools`/`--deny-tools`)
  coexisting with named `roles` (the flags scope to `default_role`
  only); a configured `keys` map while `default_role` is unrestricted
  (unmapped keys then get the full tool surface); and a configured
  `keys` map under stdio or disabled auth (per-key scoping never
  resolves without a caller identity).

## Consequences

- Fleet/enterprise policy can be declared in a config file and versioned.
- Least-privilege keys can coexist on one HTTP transport.
- Read-only mode makes it safe to expose the server to less-trusted clients.
- The deny/readonly/allow precedence is simple and fail-closed: any ambiguity
  resolves to deny.
- Plugin re-entry (`plugin_run` step dispatch) uses the same caller identity,
  so per-key scoping applies to plugin steps too.
