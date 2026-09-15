# ADR 0006: snake_case Tool Naming and `--category` Token Filtering

- **Status:** Accepted
- **Date:** Phase 0 (tool catalog freeze)
- **Deciders:** ultranix-mcp architecture council

## Context

MCP clients pay for every tool definition in the `tools/list` payload — name,
description, and JSON schema all consume the agent's context window on every
session. ultramac established the family convention: `snake_case` tool names
grouped into categories, exposed selectively via a `--category=` startup filter.

ultranix-mcp must decide its tool surface. Requirements:

- **Cross-sibling parity:** an agent prompt or playbook written against
  ultramac/ultrawin (`mouse_click`, `get_ui_tree`, `find_element`,
  `type_text`, `web_query`, …) should transfer to Linux unchanged.
- **Token economy:** 32 tool definitions in one listing is wasteful when a
  workflow only needs mouse + keyboard; a category filter is required at
  startup, before any client connects.
- **Stable contract:** names are part of the MCP public API — churn breaks
  saved agent workflows, golden fixtures, and the `replay_action` history.

The full approved catalog (32 tools, 5 categories — canonical catalog in
[TOOLS.md](../TOOLS.md); this table records the decision):

| Category | Tools |
| -------- | ----- |
| mouse (7) | `mouse_click`, `mouse_double_click`, `mouse_move`, `mouse_get_position`, `mouse_scroll`, `mouse_drag`, `mouse_button_control` |
| keyboard (2) | `type_text`, `key_control` |
| vision (12) | `screenshot`, `screen_info`, `screen_highlight`, `color_at`, `set_spatial_focus`, `get_ui_tree`, `get_focused_element`, `find_element`, `find_text_on_screen`, `find_icon`, `wait_for_ui_element`, `invoke_element` |
| automation (4) | `sleep`, `mouse_move_path`, `system_command`, `web_query` |
| admin (7) | `window_control`, `get_windows`, `get_active_window`, `metrics`, `get_action_history`, `replay_action`, `clear_action_history` |

Alternatives considered:

- **camelCase (FastMCP/TS idiom)** — diverges from the sibling catalogs and
  reads unnaturally beside `get_ui_tree` parity tools; rejected.
- **Flat 32-tool listing, no filter** — simplest, but wastes agent context on
  irrelevant tools; rejected on token-economy grounds.
- **Dynamic per-request tool filtering** — not supported by the MCP capability
  model cleanly and would complicate client caching; rejected.

## Decision

- All tools are named in **`snake_case`**, matching the sibling projects' public
  contract; the catalog above is frozen as the Phase 0–5 target.
- The binary accepts **`--category=<name>`** (repeatable / comma-separated) to
  restrict `tools/list` to the selected categories at startup; omitting the flag
  exposes all 32 tools.
- Category membership is static and versioned with the tool catalog; `metrics`,
  `get_action_history`, `replay_action`, and `clear_action_history` live in
  `admin` so minimal-agent deployments can exclude them entirely.

## Consequences

**Positive:**

- **Prompt/playbook portability** across ultramac, ultrawin, and ultranix — the
  flagship reason for the family.
- **Measurable context savings:** `--category=mouse,keyboard` exposes 9 tools
  instead of 32 — a ~72% reduction in tool-definition tokens for input-only
  agents.
- **Safe API evolution:** new tools enter a category rather than a flat list;
  the `--category` flag is a stable operator contract for least-exposure
  deployments (e.g., serve only `vision` to a read-only observer agent).

**Negative / accepted trade-offs:**

- **Category is a startup decision** — changing exposed tools requires a service
  restart (`systemctl --user restart ultranix-mcp`); accepted because MCP
  capability negotiation is session-scoped anyway.
- **Naming collisions are permanent** — once published, `system_command` can't
  be renamed; mitigated by freezing the 32-name catalog (canonical in
  [TOOLS.md](../TOOLS.md)) and covering the exact list with `tools/list`
  golden tests.
- **Cross-category dependencies are implicit** — e.g., `wait_for_ui_element`
  (vision) semantically pairs with `mouse_click` (mouse); operators must select
  coherent category sets — documented in the deployment guide.

**Follow-ups:**

- Emit an explicit `tracing::info!` line at startup: `serving 9 tools
  (categories: mouse,keyboard)`.
- Golden `tools/list` fixtures per category combination exercised in CI (see
  TESTING_STRATEGY.md) to prevent accidental schema/name drift.
