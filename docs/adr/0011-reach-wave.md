# ADR 0011: Reach Wave - Compositor Coverage, Live Streaming, Dynamic Tools

- **Status:**Accepted
- **Date:**v1.4.0 wave
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0004 (backend ladder), ADR 0007 (compositor breadth),
  ADR 0009 (plugin tools), ADR 0010 (policy controls)

## Context

The post-v1.3 backlog held four gaps the earlier waves deferred as "no
IPC exists" or "bounded version shipped":

1. **GNOME window management**- Mutter/gnome-shell exposes no public
   client-window IPC.
2. **Wayfire / river window management**- Wayfire's IPC was assessed as
   plugin-scoped; river's `riverctl` manages layout, not windows.
3. **True live streaming**- `screen_record` is a bounded burst
   recorder; remote-control UX wants a caller-driven start/stop feed.
4. **Dynamic third-party tool registration**- plugins shipped as
   macros over the fixed catalog; tools with their own schemas were out
   of scope.

Each item was re-examined for a *real* implementation path rather than a
continued deferral.

## Decision

### Window backends - every compositor gets its honest rung

- **Wayfire**(`WindowBackend::WayfireIpc`, `providers/wayfire_window.rs`):
  the `ipc` plugin (enabled by default in wayfire sessions that ship it)
  listens on `$WAYFIRE_SOCKET` with a length-prefixed JSON protocol.
  `list-views` enumerates windows; ipc-rules view methods (`view/*`)
  cover focus/close/move/resize. Short-lived connection per request,
  2 s bound, capped reply read - the `sway_window.rs` shape.
- **river**(`WindowBackend::Riverctl`, `providers/river_window.rs`):
  river genuinely has no window-list IPC. `riverctl` operates on the
  *focused* view: `close`, `move`, `resize`, `send-to-output`, float
  toggles. The provider maps `dispatch` ops for `window_id="focused"`
  and returns honest errors for `list_windows`/`active_window` (the tool
  layer surfaces `ProviderUnavailable`). To make the rung reachable the
  trait gains `focused_view_selector()` (default `None`; river returns
  `Some("focused")`): `window_control` skips list/active resolution for
  the `"focused"` selector - and for an omitted selector on such a
  backend, where the focused view is the only addressable target - and
  accepts relative `dx,dy`/`dw,dh` params for `move`/`resize` (rejected
  on list-capable backends). `close` consent binds the `"focused"`
  pseudo-id. `riverctl` joins the pin set -
  provider-internal only, no `validate_command` arm.
- **GNOME**(`WindowBackend::GnomeShell`, `providers/gnome_window.rs`):
  the community-standard **Window Calls**Shell extension exposes
  `org.gnome.Shell.Extensions.Windows` on the session bus - `List`,
  `Activate`, `Close`, `Move`, `Resize`, `Minimize`, `Maximize` over
  window ids. `org.gnome.Shell.Eval` is deliberately *not* used: it is
  disabled in most builds and is an arbitrary-JS hazard. When the
  extension is absent the rung fails detection and the ladder reports
  `ProviderUnavailable` - same posture as every optional rung.

Ladder rows: Wayfire `[WayfireIpc]`, river `[Riverctl]`, GNOME Wayland
`[GnomeShell]`, GNOME X11 `[GnomeShell, Wmctrl]`.

### Live streaming - `screen_stream`, bounded and rolling

`screen_stream{action}` = `start|status|latest|stop`. `start` spawns a
background task capturing at `fps` (1-10) into a server-owned
`stream-<ulid>` `0700` dir under the captures root; the rolling window
evicts oldest frames at `max_frames`/`max_bytes`; `latest` returns the
newest frame in the same image shape `screenshot` uses; `stop` joins the
task and writes the manifest. Single active stream per server -
concurrency is a policy question, not an implementation gap.

### Dynamic tool registration - manifests can expose tools

Plugin manifests gain an optional `tool` section (`name`, `description`,
typed `params` with `required`/`description`). A manifest with a `tool`
section registers that name in `tools/list` with a generated JSON
`inputSchema`; calling it routes through the same secured dispatch as
`plugin_run` - policy applies to the tool's own name, consent
re-challenges per step, audit/history/metrics unchanged. Names are
`[a-z][a-z0-9_]{0,63}` and must not collide with the static catalog or
sibling plugin tools - collisions skip the manifest with a `plugin_reload`
diagnostic. `listChanged` notification is not emitted (documented
limitation).

## Consequences

- The backend ladder now has a real implementation at every compositor
  rung; "no IPC exists" survives only where it is *literally* true
  (river list, GNOME without the extension) and the error path says so.
- `screen_stream` adds one tool to the catalog (39 -> 40) and introduces
  server-owned background task state - bounded by the same captures
  discipline as `screen_record`.
- Dynamic tools keep the security invariants: no code execution, policy
  enforcement per tool name, per-step consent, collision-safe.
- Distribution: `Dockerfile` + `oci.yml` publish
  `ghcr.io/jxoesneon/ultranix-mcp` on tags; `.SRCINFO` files keep the AUR
  PKGBUILDs submission-ready.

## Alternatives considered

- **GNOME `Eval` / `gdbus` scripting**: rejected - `Eval` is disabled by
  default for exactly the reasons we would use it (arbitrary JS in the
  compositor), and `gdbus` was removed from the whitelist in v1.1.
- **Unbounded stream until client disconnects**: rejected - a dropped
  MCP connection must not leak a writer; the rolling cap plus explicit
  `stop` keeps disk use provable.
- **WASM plugin runtime for dynamic tools**: still rejected (ADR 0009) -
  schemas-over-manifests deliver the ask without a second interpreter.
