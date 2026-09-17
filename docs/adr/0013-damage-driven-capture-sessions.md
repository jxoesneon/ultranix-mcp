# ADR 0013: Damage-Driven Capture Sessions and Stable Toplevel Ids

- **Status:**Accepted
- **Date:**post-v1.4.0 wave (continuation of ADR 0012)
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0004 (capture ladder), ADR 0012 (wlroots toplevel rung)

## Context

ADR 0012 left three known gaps:

1. **`screen_stream` still captured blind.** The long-poll consumer
   side landed, but the producer still ran `capture_frame` on a timer -
   every tick did a GPU copy and PNG encode regardless of whether the
   screen changed, and `latest` could only poll for `seq` movement.
2. **Toplevel ids were snapshot-order.** `wlr-toplevel-N` selectors
   depended on enumeration order; the expected-title/class re-check
   contained the drift risk but could not eliminate it.
3. **Portal-backed sessions had no viable stream path.** On portals
   advertising only `RemoteDesktop`, `capture_frame` creates an
   ephemeral session per call - at stream fps that is a consent dialog
   per frame, i.e. unusable.

## Decision

### `StreamCapture` - a session-scoped frame source

`traits.rs` gains a small trait beside `CaptureProvider`:

```rust
pub trait StreamCapture: Send {
    fn next_frame(&mut self, wait: Duration) -> Result<Option<Frame>>;
}
```

`Ok(None)` means "the deadline passed with no screen damage" - the
stream task must not advance `seq` or write. Providers opt in with a
cheap `stream_sessions_supported()` hint (no I/O - construction-time
knowledge only) plus `stream_capture()`, which opens a session on the
caller's thread.

`run_stream` gives session-capable providers a dedicated blocking
thread that pushes changed frames over a bounded channel; the async
loop keeps its eviction/write/manifest path unchanged. When the hint
is false - or the open fails and the thread reports `Unsupported` -
the stream runs the original ticker + `capture_frame` loop verbatim.
In session mode `fps` becomes a **rate ceiling** on writes rather than
a capture timer.

### wlroots: ext-image-copy-capture preferred, `copy_with_damage` fallback

`providers/wlr_stream.rs` implements `StreamCapture` twice, chosen at
open by advertised globals:

- **`ext_image_copy_capture_manager_v1` +
  `ext_output_image_capture_source_manager_v1`** (staging protocols;
  Hyprland >= 0.54, wlroots >= 0.20). The compositor holds `capture`
  open until the source changes, so an idle screen costs literally
  nothing - no polling, no GPU work. One persistent `wl_shm` buffer is
  attached per frame and client damage is tracked so the compositor
  only rewrites what changed. `stopped` sessions (output off) report
  idle, not death.
- **`zwlr_screencopy_manager_v1` `copy_with_damage`** (every wlroots
  compositor). The compositor answers immediately; a `ready` with no
  `damage` events means "unchanged", so the client polls - but an idle
  poll is one roundtrip with no buffer writes and no PNG encode, ~20
  Hz worst case and cheap.

Both share one persistent shm pool/buffer, recreated only when the
compositor's buffer description changes.

### Portal: one held PipeWire stream per `screen_stream`

`providers/portal_stream.rs` opens a RemoteDesktop session per stream:
`CreateSession -> SelectSources -> Start` (one consent dialog) ->
`OpenPipeWireRemote`, then holds the PipeWire stream and lets the
compositor push buffers. `stop` closes the session.

**No `persist_mode`/`restore_token` is sent or stored** - the consent
policy is identical to `portal_input`/`portal_capture`
(THREAT_MODEL.md §4.2). The consent boundary simply moves from "per
frame" (unusable) to "per stream" (one dialog per `start`), which is
the strongest consent posture that still allows streaming at all.

PipeWire and zbus objects are `!Send`, so the entire session - D-Bus
handshake, mainloop pump, `Session.Close` teardown - lives inside one
worker thread; the `PortalStream` handle crossing into the session
driver is `Arc` state + a shutdown flag + a join handle, all `Send`.

### Stable toplevel ids via `ext_foreign_toplevel_list_v1`

ADR 0012 rejected "stable handles across calls" because handles cannot
outlive a stateless connection. `ext_foreign_toplevel_list_v1`
supplies the missing piece without one: a compositor-assigned
`identifier` string per toplevel. The provider now binds the ext list
beside the wlr manager, correlates entries by title/app-id in
occurrence order, and reports `wlr-toplevel-<identifier>` as the id -
stable across calls and process restarts. Identifier lookup precedes
numeric-index parsing (Hyprland mints all-digit identifiers, so
parse-first ordering would misread them), and index ids remain the
fallback where the ext protocol is absent. `monitor` populates from
`output_enter`/`output_leave` where the compositor emits them;
Hyprland currently does not, so it reports `None` honestly.

### `ext-workspace-v1` evaluated - not implemented

The protocol enumerates workspace objects (id/name/coordinates/state)
but exposes **no toplevel-to-workspace association**: `assign` is a
request, not a query, and neither toplevel protocol reports workspace
membership. `WindowInfo.workspace` therefore stays `-1` on this
backend rather than fabricating data.

## Consequences

- `screen_stream` on wlroots is event-driven end-to-end: idle desktops
  produce zero disk churn, `latest` long-polls wake on real damage,
  and `seq` is a true change counter.
- On portal-only desktops (GNOME/KDE without Screenshot), streaming
  works for the first time with exactly one consent dialog per stream.
- Toplevel selectors are compositor-stable where advertised; stale
  selectors still fail closed through the expected-title/class check.
- A provider returning `Unsupported` mid-handshake, a session dying,
  or a compositor without either protocol all degrade to the unchanged
  polled path - no new failure mode reaches the tool surface.
- `stop` latency is bounded by the session poll slice (200 ms driver /
  50 ms PipeWire pump), not by any in-flight copy.

## Alternatives considered

- **`persist_mode` + `restore_token` for portal streams**: rejected -
  storing a restore credential would let later streams bypass consent
  entirely, which the threat model explicitly forbids. One dialog per
  stream is the correct boundary.
- **DMA-BUF capture on the ext path**: deferred - `wl_shm` covers every
  compositor today and keeps the decode path single-sourced with
  `wlr_capture`; dmabuf negotiation can land behind the same trait
  later without changing `screen_stream`.
- **WebRTC/SSE push transport**: deferred (still) - long-poll plus
  damage-driven production covers the agent diff-loop use case without
  a second authenticated surface.
- **`ext-workspace-v1` anyway**: rejected - without a toplevel mapping
  it would populate a workspace *list*, not the `workspace` field this
  work targeted.
