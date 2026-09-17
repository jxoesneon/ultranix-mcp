# ADR 0012: Shared wlroots foreign-toplevel Rung and Stream Long-Poll

- **Status:**Accepted
- **Date:**post-v1.4.0 wave
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0004 (backend ladder), ADR 0007 (compositor breadth),
  ADR 0011 (reach wave)

## Context

ADR 0011 gave every named compositor an honest window rung but left two
classes of debt:

1. **wlroots coverage was compositor-specific.** river had only the
   focused-view `riverctl` rung (no enumeration), Wayfire's rung dropped
   out without `$WAYFIRE_SOCKET`, and unknown wlroots sessions (niri,
   labwc, ...) got an empty window ladder. Yet every wlroots compositor
   optionally advertises `zwlr_foreign_toplevel_manager_v1` - one
   protocol that enumerates toplevels (title/app-id/state) and dispatches
   activate/close/minimize/maximize/fullscreen.
2. **`screen_stream` forced busy-polling.** `latest` answered
   immediately or errored; an agent waiting for change had to call in a
   sleep loop.

## Decision

### `WlrToplevelWindow` - the shared wlroots window rung

`providers/wlr_toplevel.rs` implements `WindowProvider` over
`zwlr_foreign_toplevel_manager_v1` with the codebase's stateless
per-call convention: each operation opens a short-lived Wayland
connection, binds the manager, collects `title`/`app_id`/`state`/`done`
events for every toplevel until the first roundtrip completes, then
answers or issues the request and flushes before disconnecting.

- Synthetic ids are `wlr-toplevel-N` in enumeration order; `"focused"`
  selects the activated toplevel.
- Verb map: `focus` -> `activate`; `close` -> `close`;
  `minimize`/`maximize`/`fullscreen` and the `un-` variants -> the
  matching `set_`/`unset_` requests; `move`/`resize` error honestly -
  the protocol has no geometry verbs.
- The protocol does not expose geometry, workspace, monitor, PID, or
  floating state - `WindowInfo` reports zero/`None` rather than
  inventing values.
- **Index drift fails closed.** `window_control` resolves a selector to
  a window, then dispatches on a fresh connection - a stale
  `wlr-toplevel-N` could silently retarget. The tool layer therefore
  passes the expected title/app-id from its own resolution, and the
  provider re-verifies them against the fresh enumeration before
  dispatching.

Ladder placement (`WindowBackend::WlrToplevel`, backend name
`"wlr-toplevel"`): Hyprland `Hyprctl -> WlrToplevel`, sway
`SwayIpc -> WlrToplevel`, Wayfire `WayfireIpc -> WlrToplevel`, river
`Riverctl -> WlrToplevel`, Other-Wayland `[WlrToplevel]`. KDE and GNOME
keep their existing rungs (KWin and Mutter are not wlroots).

### `RiverWindow` becomes a composite

river keeps `riverctl` for what it can prove - `close` on the focused
view and relative `move`/`resize` deltas - and delegates enumeration
plus per-window verbs to foreign-toplevel when the protocol probes at
construction. `wlr-toplevel-N` selectors route to the toplevel path;
`"focused"`/empty keep the `riverctl` path; anything else fails closed.
Without the protocol the provider degrades to the v1.4.0 posture:
`isError` enumeration, focused-view-only dispatch.

### `screen_stream` `latest` long-polls

`action:"latest"` gains `since` (a `frames_written` watermark - every
reply reports its `seq` so clients can chain) and `wait_ms`
(0..=30000, default 0). The call snapshots the registry under the lock,
drops it, and re-polls at 50 ms intervals until a qualifying frame
exists or the deadline expires. Timeout returns a text-only "no new
frame" result - `isError` false, since a quiet stream is a normal
outcome. `stop` or task death removes the registry entry, which wakes
parked calls immediately with the "no stream" error instead of waiting
out the deadline. No mutex is held across an await.

## Consequences

- Every wlroots session - named or unknown - can enumerate and control
  windows when the compositor advertises the protocol; niri/labwc gain
  coverage for free.
- river graduates from "focused view only" to a full window backend
  (enumeration + per-window verbs) while `riverctl` remains the
  geometry authority.
- Wayfire without the IPC socket, and Hyprland/sway with a broken IPC
  rung, still enumerate via the shared fallback.
- `latest` replies are self-describing (`seq` in the text block), so
  agents can long-poll a screen diff loop with one tool call per frame
  instead of a poll loop.
- The wlr-toplevel index is snapshot-order, not compositor-stable -
  the expected-title/class check makes drift a failure, not a wrong
  target. Long-lived references should use title/class substrings where
  a compositor-native id is unavailable.

## Alternatives considered

- **Keeping enumeration compositor-specific**: rejected - foreign-
  toplevel is the one protocol wlroots desktops share; per-compositor
  enumeration would leave river and unknown sessions permanently blind.
- **Push notifications / `tokio::sync::watch` on frames**: rejected -
  the stream registry already uses `watch` for cancellation, but
  `latest` needs only "seq advanced" semantics; a 50 ms re-poll loop is
  simpler, bounded, and wakes correctly on stop/removal without a new
  notification channel.
- **Stable toplevel handles across calls**: rejected - the stateless
  per-call convention (one connection per operation) matches every
  other provider and avoids a long-lived event pump; synthetic ids plus
  the title/class re-check cover the drift risk.
