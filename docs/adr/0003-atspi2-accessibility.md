# ADR 0003: AT-SPI2 as the UI-Introspection Backbone

- **Status:** Accepted
- **Date:** Phase 2 (semantic UI)
- **Deciders:** ultranix-mcp architecture council
- **Related:** ADR 0004 (graceful `None` degradation when the bus is absent)

## Context

ultramac uses the macOS Accessibility API and ultrawin uses UIA3 with
`CacheRequests` to expose a semantic UI tree — the foundation of
`get_ui_tree`, `get_focused_element`, `find_element`, and `wait_for_ui_element`.
ultranix-mcp needs a Linux analog. Options:

1. **AT-SPI2 (Assistive Technology Service Provider Interface)** — the standard
   Linux accessibility framework, exposed over the session D-Bus, consumable from
   Rust via the `atspi` crate. Supported by GTK, Qt, Electron/Chromium
   (`--force-renderer-accessibility`), and Firefox.
2. **Vision-only element finding** — screenshot + OCR + OWL-ViT icon detection,
   inferring "elements" from pixels with no accessibility bus.
3. **hyprctl / compositor window metadata** — gives window geometry and titles,
   but nothing below the window level (no buttons, fields, or text roles).

Requirements:

- `get_ui_tree` must return a recursive, role-annotated tree in <500ms.
- `find_element` must locate an element by name/role and return bounds usable by
  `mouse_click` — AT-SPI2 components expose absolute screen extents directly.
- The verified environment already runs AT-SPI2 live (confirmed on CachyOS +
  Hyprland), so no additional service is required of the user.

Vision-only was rejected as the *primary* mechanism: it is probabilistic
(confidence-scored guesses), costs a full capture + inference cycle per lookup
(~2s), and cannot distinguish a button from a label that merely looks clickable.
It remains essential as the *fallback* — `find_text_on_screen` and `find_icon`
already exist for sessions/apps where AT-SPI2 yields nothing.

## Decision

- **`UIAutomationProvider` is implemented by `AtspiUi`** over the session
  D-Bus using the `atspi` crate.
- The provider exposes `get_root_json` (recursive tree), `get_focused_json`, and
  `find_element(query) -> Option<bounds>` semantics matching ultrawin's trait
  shape, extended for Linux coordinate space.
- When the AT-SPI2 bus is absent or an application exports no accessibility
  tree, `UIAutomationProvider` resolves to `None` at startup (ADR 0004) and the
  vision tools (`find_text_on_screen`, `find_icon`, `color_at`) remain the
  documented degradation path — tools return a structured
  capability-unavailable error rather than silently falling back mid-call.
- `set_spatial_focus` + screenshot region capture remain usable to scope vision
  fallbacks, mirroring ultramac's flow.

## Consequences

**Positive:**

- **Deterministic semantics:** roles, names, states, and bounds come from the
  toolkit's own accessibility data — no inference error bars, and
  `wait_for_ui_element` can subscribe to AT-SPI2 events instead of polling
  pixels.
- **Performance:** a recursive tree snapshot over D-Bus meets the <500ms
  `get_ui_tree` target without image capture or GPU/CPU inference.
- **Parity:** the trait surface stays structurally identical to ultrawin's
  `UIAutomationProvider`, so tool handlers and tests port almost verbatim.

**Negative / accepted trade-offs:**

- **Application opt-in:** apps that don't export an AT-SPI2 tree (some Electron
  builds, games, minimal toolkits) are invisible — accepted, with vision tools
  as the sanctioned fallback.
- **D-Bus dependency:** the provider requires a session bus and the
  `at-spi2-core`/`at-spi-bus-launcher` stack running; hardened/minimal sessions
  degrade to `None`.
- **Depth/size control:** recursive trees can be large; `get_ui_tree` must bound
  depth/child-count and `find_element` must short-circuit on first match to hold
  the latency target.

**Follow-ups:**

- Define tree-size caps (depth 12, 5k nodes) and the JSON node schema
  (`name`, `role`, `states`, `bounds`) in the tool contract.
- Integration test on the live session: launch a known GTK app, assert
  `find_element` returns correct bounds; nested-compositor fixture per
  TESTING_STRATEGY.md.
