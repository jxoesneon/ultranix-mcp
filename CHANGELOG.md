# Changelog

All notable changes to ultranix-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The compositor-breadth wave, part two: every wlroots compositor now gets
window enumeration and per-window control through
`zwlr_foreign_toplevel_manager_v1` (with stable
`ext_foreign_toplevel_list_v1` identifiers where advertised), and
`screen_stream` becomes damage-driven - wlroots sessions capture through
a persistent `ext-image-copy-capture`/`copy_with_damage` session,
portal-backed sessions hold one RemoteDesktop PipeWire stream per
stream, and `latest` learns to long-poll so agents stop busy-polling
for frames.

### Added

- **`WlrToplevelWindow` provider** - `WindowProvider` over
  `zwlr_foreign_toplevel_manager_v1` (`src/providers/wlr_toplevel.rs`),
  the shared wlroots window rung. Stateless per call: one short-lived
  Wayland connection binds the manager, collects title/app-id/state for
  every tracked toplevel, then answers or dispatches. Verbs:
  `focus` -> `activate`, `close`, `minimize`/`unminimize`,
  `maximize`/`unmaximize`, `fullscreen`/`unfullscreen`; `move`/`resize`
  error honestly - the protocol carries no geometry. Geometry,
  workspace, monitor, PID, and floating state are reported as
  zero/unknown where the compositor does not expose them. Backend name
  `"wlr-toplevel"`.
- **Stable toplevel identifiers** - `ext_foreign_toplevel_list_v1` is
  bound alongside the wlr manager where advertised (Hyprland, wlroots
  >= 0.20); its compositor-assigned `identifier` becomes the window id
  (`wlr-toplevel-<identifier>`), surviving enumeration-order drift
  across calls. Entries are correlated to dispatch handles by
  title/app-id in occurrence order; numeric suffixes still parse as
  index fallbacks, but identifier lookup wins first so all-digit ids
  are never misread as positions. `monitor` populates from
  `output_enter`/`output_leave` on compositors that emit them
  (Hyprland currently does not - it reports `None` honestly).
- **`StreamCapture` sessions** - a damage-driven frame source
  (`crate::traits::StreamCapture`) that `screen_stream` prefers over
  per-tick polling: a dedicated thread pushes only *changed* frames, so
  `seq`/`frames_written` advance on real damage, `latest` long-polls
  wake on actual screen updates, and idle screens cost no GPU copy and
  no PNG encode. `fps` becomes a rate ceiling rather than a timer.
  Providers opt in via `stream_sessions_supported()`/`stream_capture()`;
  anything else keeps the ticker loop unchanged.
- **wlroots capture session** (`src/providers/wlr_stream.rs`) -
  prefers `ext_image_copy_capture_manager_v1` +
  `ext_output_image_capture_source_manager_v1` (staging; Hyprland >=
  0.54, wlroots >= 0.20), whose `capture` request the compositor holds
  until the source changes - genuinely event-driven with zero polling.
  Falls back to `zwlr_screencopy_manager_v1` `copy_with_damage`, where
  a `ready` with no damage events means "unchanged" and idle polling
  costs one roundtrip per ~50 ms. Both reuse one persistent `wl_shm`
  buffer so only damaged regions are rewritten.
- **Held portal PipeWire session** (`src/providers/portal_stream.rs`) -
  on RemoteDesktop-capable portals, `screen_stream` opens one
  RemoteDesktop session per stream: a single `Start` consent dialog at
  start, then pushed frames for the session's lifetime (versus the
  ephemeral path which would re-consent per frame). Nothing is
  persisted - no `persist_mode`/`restore_token`, same policy as
  `portal_input`; `stop` closes the session and the next `start`
  re-consents.
- **Shared wlroots fallback rung** - `WlrToplevel` now sits behind the
  compositor-specific window rungs on every wlroots session: Hyprland
  `Hyprctl -> WlrToplevel`, sway `SwayIpc -> WlrToplevel`, Wayfire
  `WayfireIpc -> WlrToplevel` (so Wayfire without the IPC socket still
  enumerates), river `Riverctl -> WlrToplevel`. Unknown/other Wayland
  sessions (niri, labwc, ...) that previously got an empty window
  ladder now get `WlrToplevel` when the compositor advertises the
  protocol.
- **`RiverWindow` composite** - river sessions keep `riverctl` for
  focused-view geometry (relative `move`/`resize`, `close` on
  `"focused"`/empty) and delegate enumeration plus per-window
  `focus`/`close`/`minimize`/`maximize`/`fullscreen` to
  foreign-toplevel (`wlr-toplevel-N` ids). `get_windows` and
  `get_active_window` now return real data on river when the protocol
  is advertised; without it they keep their honest `isError` results.
- **`screen_stream` long-poll** - `action:"latest"` accepts `since`
  (a `frames_written` watermark - every `latest` reply reports its
  `seq`) and `wait_ms` (0..=30000, default 0). With them set the call
  parks until a newer frame lands, the first frame exists, or the
  deadline expires - on timeout it returns a text-only "no new frame"
  result (`isError` stays false). No mutex is held across the wait.
- **Per-window capture** - `screenshot` gains `window` and
  `screen_stream` gains `window` on `start`: a session scoped to one
  toplevel through `ext_foreign_toplevel_image_capture_source_manager_v1`
  (Hyprland >= 0.54 / wlroots >= 0.20). Selectors resolve through the
  `get_windows` id namespace - compositor ids like Hyprland `0x...`
  addresses resolve to the window's title; `wlr-toplevel-<id>` stable
  identifiers and exact unique titles also match. Unknown or ambiguous
  selectors fail - window capture never falls back to a full-screen
  capture. Backends without the ext source report
  `"backend does not support per-window capture"`.
- **Frame notifications** - `screen_stream` `start {notify: true}`
  emits an `ultranix/stream_frame` server notification to the calling
  session on every written frame, carrying `{stream_id, seq, file,
  width, height}` (metadata only - pixels still come from `latest`).
  Delivery uses MCP server->client notifications, so no second auth
  surface: stdio delivers inline; streamable HTTP delivers on the
  client's standalone SSE stream when open.

### Changed

- `screen_stream` on session-capable backends now writes frames only
  when the screen actually changes: `frames_written`/`seq` advance on
  compositor-reported damage, and `fps` acts as a maximum write rate.
  Streams on idle desktops produce no disk churn; `stop` still lands
  within one 200 ms session poll.

- `window_control`'s `window` selector on wlroots sessions now also
  accepts `wlr-toplevel-N` ids wherever the foreign-toplevel rung
  resolved; the expected title/class travel with the dispatch so a
  stale index fails closed instead of hitting a different window.

## [1.4.0] - 2026-09-16

The reach wave: every compositor now gets its honest window rung
(Wayfire IPC, river `riverctl`, GNOME Window Calls), `screen_stream`
lands as the live counterpart to `screen_record`, plugin manifests can
register first-class dynamic tools, and the distribution artifacts
(OCI image, `-bin` package) ship. Tool surface grows from 39 to **40
tools in 6 categories**(additive MINOR changes; no schema or response
shape changed - `toolSurfaceVersion` stays `"2.0"`). See
[ADR 0011](docs/adr/0011-reach-wave.md).

### Added

- **`WayfireWindow` provider**- `WindowProvider` over Wayfire's `ipc`/
  `ipc-rules` plugins on `$WAYFIRE_SOCKET`
  (`src/providers/wayfire_window.rs`): length-prefixed JSON transport
  (4-byte LE length + UTF-8 JSON), `window-rules/list-views` for
  list/geometry, `window-rules/get-focused-view` for the active window,
  `view-info`/`focus-view`/`close-view`/`configure-view` for dispatch,
  `wm-actions/set-minimized` for minimize (honest compositor `error`
  reply on builds without `wm-actions`). Only `toplevel` views are
  listed; `floating` reports `None` (Wayfire has no floating-vs-tiled
  class - `tiled-edges` is a snap bitmask); `workspace` maps from
  `wset-index`. Short-lived connection per request, 2 s bound, capped
  reply read - the `sway_window.rs` shape. Backend name `"wayfire-ipc"`.
- **`RiverWindow` provider**- `WindowProvider` over the pinned
  `riverctl` subprocess (`src/providers/river_window.rs`), the river
  rung of the window ladder - **partial by design**: river exposes no
  window-list IPC, so `list_windows`/`active_window` return
  `ProviderUnavailable` honestly, and `dispatch` operates on the focused
  view only (`window_id` must be `"focused"` or empty). Closed verb set:
  `close` -> `riverctl close`; `move`/`resize` -> relative
  `move <dir> <delta>` / `resize <axis> <delta>` (deltas clamped
  ±8192, floating-view ops - no-op on tiled focus); absolute
  `x,y`/`w,h`, `focus`, and `minimize` have no riverctl form and error
  honestly. At the tool surface, `window_control` reaches the focused
  view through `window:"focused"` or an omitted selector (the provider's
  `focused_view_selector()` bypasses `list_windows`/`active_window`
  resolution), and `move`/`resize` accept the new relative `dx,dy`/
  `dw,dh` params - `close` and delta-form move/resize are live on river;
  `get_windows`/`get_active_window` still return `isError` results
  (river genuinely cannot enumerate or identify views). Backend name
  `"riverctl"`.
- **`GnomeShellWindow` provider**- `WindowProvider` over the community
  "Window Calls" GNOME Shell extension on the session D-Bus
  (`src/providers/gnome_window.rs`): `org.gnome.Shell`'s
  `/org/gnome/Shell/Extensions/Windows` object (`List`, `Activate`,
  `Close`, `Minimize`, `Move`, `Resize`, `MoveResize`,
  `MoveToWorkspace`, ...). `org.gnome.Shell.Eval` is deliberately **not**
  used - it is an arbitrary-JS primitive, commonly disabled, and a
  security hazard. Requires the extension installed
  (`gnome-extensions install <window-calls zip>`, EGO extension 4724);
  without it the rung fails detection and GNOME reports
  `ProviderUnavailable` as before. `floating`/`fullscreen` report `None`
  (the `List()` payload does not carry them). Backend name
  `"gnome-shell"`. GNOME-X11 ladders try `GnomeShell` then `wmctrl`.
- **`screen_stream` (vision)**- continuous live capture with a
  `start`/`status`/`latest`/`stop` lifecycle
  (`src/tools/stream.rs`): `start` spawns a background task capturing
  one PNG frame per `fps` interval (1-10, default 2) into a fresh
  `stream-<ulid>` `0700` dir under the captures root, keeping a rolling
  window bounded by `max_frames` (1-1800, default 600) and `max_bytes`
  (default and ceiling 512 MiB) - oldest frames are evicted and counted
  as `dropped_frames`; a frame larger than the whole budget is dropped
  unwritten. `latest` returns the newest frame in `screenshot`'s
  two-block image shape for polling; `status` reports live counters;
  `stop` joins the task and returns final stats. The task writes
  `manifest.json` on every exit path (`stopped` | `capture_error` | `io_error`). Single active stream server-wide (the registry is
  process-global; a second `start` while alive is an `isError`, a dead
  task does not block a fresh start). Not consent-gated - same posture
  as `screen_record` (server-owned `0700` output only). This is a
  rolling-window disk capture, not an RTP/streaming protocol.
- **Dynamic plugin tool registration**- manifests gain an optional
  `tool` (alias `expose_as_tool`) section (`src/plugins.rs`
  `ToolRegistry`, `src/server.rs` `advertised_tools`,
  `src/tools/plugin.rs` `run_exposed_tool`): `{name
  ^[a-z][a-z0-9_]{0,63}$, description ≤256 chars, params}` registers the
  plugin as a first-class `tools/list` entry with a generated
  `inputSchema` (per-param `type`/`description`, `required` array,
  `additionalProperties: false`). `tool.params` merge into the
  manifest's param set (declaring the same name in both sites is an
  authoring error); names are advertised verbatim and must not collide
  with the catalog or a sibling plugin's tool name (later claims are
  skipped with a `plugin_reload` diagnostic). Calling the tool is
  exactly `plugin_run{name, params}` through the secured dispatch:
  policy is applied to the tool's **own name***and* the call requires
  the role to allow `plugin_run` (denials are `-32018`/`-32019` with
  `denial_reason`); steps keep per-step consent/audit/history/metrics.
  Plugin tools inherit `plugin_run`'s `admin` category for
  `--category` filtering, and **no `tools/list_changed` notification is
  emitted**- the registry rescans per request, so clients see new
  tools on their next `tools/list`.
- **Distribution artifacts**- root `Dockerfile` (bookworm builder +
  distroless-style runtime; verified runtime linkage documented in the
  header comment) and `.github/workflows/oci.yml` publish
  `ghcr.io/jxoesneon/ultranix-mcp` on `v*` tags and `workflow_dispatch`
  (the `server.json` `packages[]` identifier already points there). New
  `packaging/ultranix-mcp-bin/` PKGBUILD (prebuilt-binary package) plus
  `.SRCINFO` files for `ultranix-mcp` and `ultranix-mcp-git` keep the
  AUR set submission-ready. `docs/HEADLESS.md` documents
  `SessionType::Headless` semantics and headless-compositor operation.
  `flake.nix` fixes.

### Security

- `riverctl` joined the startup pin set as **provider-internal only**-
  pinned to an absolute path, spawned under the scrubbed environment and
  bounded wait, but with no `validate_command` arm: `system_command`
  cannot invoke it.
- `screen_stream` writes only inside a fresh server-owned `stream-<ulid>`
  `0700` directory (the same `fresh_recording_dir` discipline as
  `screen_record`, renamed atomically in the same parent); the rolling
  byte cap (`buffered_bytes <= max_bytes <= 512 MiB`) holds
  unconditionally. The tool is in `NON_REPLAYABLE` - replaying a
  recorded `start` would spawn a background capture task, so
  `replay_action` refuses it; `start`/`stop` are still recorded to
  audit/history while the `status`/`latest` polls are suppressed from
  history (per-frame reads would flood the bounded store).
- Plugin-exposed tools add no new code-exec surface: they route through
  `plugin_run`'s secured dispatch with **dual policy**(the tool's own
  name must pass the role's allow/deny *and* `plugin_run` must be
  allowed), per-step consent re-challenge, and result-shape-based
  history redaction identical to `plugin_run`. History redaction is
  symmetric the other way too: a non-catalog (plugin-exposed) tool's
  args collapse to `<redacted:N params>` before they can persist into
  the queryable, replayable store, and `deny_tools` is likewise
  symmetric - naming either the plugin (`deploy-notes`) or its exposed
  tool (`deploy_notes`) denies the manifest under both addresses.
- `screen_stream` leaf I/O opens frames and `manifest.json` with
  `O_NOFOLLOW` at `0600` (async mirror of `open_nofollow`), and the
  plugin scanner bounds itself - ≤256 KiB per manifest, ≤256 files per
  scan.
- `WAYFIRE_SOCKET` is confined to wayfire's own socket root
  (`XDG_RUNTIME_DIR`, or `/tmp` when unset) - an out-of-root socket
  declines the provider instead of connecting.
- GNOME `Eval` remains deliberately unused - the Window Calls extension
  is the only GNOME window channel; its `List()` reply is bounded at
  1 MiB.

### Still deferred (honest notes)

- river has no window-list IPC - `get_windows`/`get_active_window`
  return an `isError` result on river; only the focused-view ops are
  reachable (`window_control` on `"focused"`/omitted selector: `close`,
  delta `move`/`resize`).
- GNOME window management requires the Window Calls extension installed
  and enabled; without it the rung drops out of detection (nothing to
  fall back to on GNOME-Wayland).
- `screen_stream` is rolling-window capture with polled `latest`
  frames - not RTP/WebRTC streaming; there is no push channel.
- `tools/list_changed` is not advertised - dynamic plugin tools appear
  on the next `tools/list`; clients must re-list after `plugin_reload`.
- crates.io publish and the AUR submissions themselves are still
  pending (PKGBUILDs + `.SRCINFO` are ready; see
  docs/REGISTRY_SUBMISSION.md).

## [1.3.0] - 2026-09-16

The policy wave: runtime access-control, per-key scoping, telemetry
hardening, and audit tamper evidence land on top of v1.2.0. Tool surface
is unchanged (**39 tools / 6 categories**); the changes are additive
security/ops knobs with fail-closed defaults.

### Added

- **Runtime access-control policy**(`src/security/policy.rs`,
  `docs/adr/0010-policy-controls.md`) - a `Policy` loaded once at startup
  from an optional TOML file (`~/.config/ultranix-mcp/policy.toml` or
  `--policy=...`) and layered with CLI overrides. It resolves every
  `tools/list` and `tools/call` through a named `Role` that carries a
  `readonly` preset, an `allow_tools` allowlist, and a `deny_tools`
  denylist. Deny-first evaluation: explicit denies always win; a
  `readonly` role permits the union of the readonly preset and
  `allow_tools` (so individual mutating tools can be opted back in);
  otherwise a set `allow_tools` restricts the callable set. Loading is
  **fail-closed**: an explicit `--policy` path that is missing or
  malformed aborts startup (the auto-discovered default path is read
  only when it exists), `deny_unknown_fields` turns misspelled TOML keys
  into startup errors, and `keys` entries referencing undefined roles
  abort startup rather than silently granting `default_role`.
- **`--readonly` mode**- advertises and allows only the non-mutating
  catalog (15 tools: `screenshot`, `screen_info`, `color_at`,
  `get_ui_tree`, `get_focused_element`, `find_element`,
  `find_text_on_screen`, `find_icon`, `wait_for_ui_element`, `sleep`,
  `mouse_get_position`, `get_windows`, `get_active_window`, `metrics`,
  `plugin_list`). Everything else is denied with `-32018 ReadOnlyMode` -
  including the observation-adjacent exclusions `invoke_element` (AT-SPI
  actions), `screen_highlight` (visible overlay), `set_spatial_focus`
  (process-global state), `screen_record` (file output),
  `clipboard_get`/`get_action_history` (cross-caller disclosure), and
  `plugin_reload` (server-state mutation).
- **`--allow-tools=` / `--deny-tools=`**- comma-separated per-tool
  allow/deny lists applied to the default role. When an allowlist is
  present, unlisted tools are denied with `-32019 NotInToolList`.
  `deny_tools` wins over `allow_tools` and `readonly`.
- **Per-key scoping**- the policy `keys` map binds API-key fingerprints
  (`key_id`) to named roles; HTTP sessions then see and can call only the
  tools their role allows. Unknown key IDs fall back to `default_role`.
- **Audit HMAC**- setting `ULTRANIX_MCP_AUDIT_SECRET` signs every
  `audit.jsonl` line with HMAC-SHA256 over its canonical JSON (the
  `prev_hash` chain still covers the final line). `verify_hmac_at()`
  returns `false` for any missing or mismatched signature when a secret
  is supplied. Rollout caveat: enable the secret on a fresh or rotated
  log - every pre-secret unsigned line in an existing file fails
  verification.
- **New metrics**- `ultranix_mcp_backend_calls_total{backend,outcome}`
  per-backend invocation counter and `ultranix_mcp_build_info{version}`
  gauge. The backend label is `"core"` for server-managed tools and the
  resolved provider name for provider-backed tools.

### Security

- `tools/list` now filters the advertised catalog by the caller's policy
  role, so a hidden tool is both unlisted and uncallable.
- `replay_action` is denied as a `plugin_run` step (new
  `ManifestError::DispatchReentry`), preventing plugin recursion through
  the secured dispatch layer.
- `clipboard_get` payloads are suppressed from action-history summaries;
  `plugin_run` results record only the plugin name and step count, not
  step payloads.
- Every `tools/call` **policy**denial now records an explicit
  `denial_reason` field (`readonly_mode`, `not_in_tool_list`) in
  `audit.jsonl` and returns it in the error `data` alongside `kind`.
  HTTP gate rejections (auth/rate-limit) are unaffected - they still
  record only `outcome` (`auth_rejected`/`rate_limited`) and carry no
  `denial_reason`.

### Still deferred (honest notes)

- GNOME window management remains unimplemented (no usable compositor IPC).
- Wayfire/river window management and GNOME-Wayland window/overlay rungs
  remain empty (no compositor IPC exists).
- True continuous live streaming capture is still open; `screen_record`
  is the bounded burst version.
- Third-party tool registration remains declarative macros over the
  existing catalog; no new tool schemas are loaded at runtime.
- The OCI image, crates.io publish, and AUR submissions are still pending
  packaging work.

## [1.2.0] - 2026-09-15

The breadth wave: the remaining post-v1 backlog items with a real
implementation path - clipboard tools, plugin tool-macros, bounded screen
recording, wider compositor detection, the per-backend cargo-feature
split, and the framed history format - landed together. Tool surface grows
from 32 to **39 tools in 6 categories**(additive MINOR changes; no
schema or response shape changed).

### Added

- **Clipboard category (3 tools)**- `clipboard_get`, `clipboard_set`,
  `clipboard_clear` over a new `ClipboardProvider` trait
  (`src/traits.rs`, `src/providers/clipboard.rs`, `src/tools/clipboard.rs`).
  `WlClipboard` drives `wl-copy`/`wl-paste` on Wayland (requires
  `WAYLAND_DISPLAY` + both helpers pinned at startup); `XclipClipboard`
  drives `xclip` (+ `xsel` for `clear`) on X11 and serves as the XWayland
  rung on Wayland (requires `DISPLAY`). Reads are text-first - binary
  MIME payloads never cross the provider boundary; `mime: "list"`
  enumerates offered types; `text/*` and the X11 text atoms
  (`UTF8_STRING`, `STRING`, `TEXT`, `COMPOUND_TEXT`) are accepted.
  `clipboard_set` is capped at 1 MiB; writes feed the payload over stdin,
  never argv. `clipboard_set`/`clipboard_clear` joined the destructive
  consent class (`-32015 ConsentRequired`); `clipboard_get` is ungated.
  Backend names: `"wl-clipboard"`, `"xclip"`.
- **Plugin tool-macros (3 admin tools)**- `plugin_list`, `plugin_run`,
  `plugin_reload` over declarative manifests in
  `<state-root>/plugins/*.json` (`src/plugins.rs`,
  `src/tools/plugin.rs`). A plugin is a macro, not code: an ordered list
  of catalog-tool calls with `${param}` templating (`$$` escapes a
  literal `$`; an exact-`${name}` arg substitutes the typed value).
  Manifest validation: `name` `^[a-z][a-z0-9-]{0,63}$` and no catalog
  collision; semver-ish `version`; typed params
  (`string`/`number`/`boolean`, ≤64); 1-32 steps; `step.tool` must be a
  real catalog tool - `plugin_*` steps are rejected so plugins cannot
  compose into unbounded recursion. `plugin_run` binds params strictly
  (undeclared keys rejected) and re-enters the secured dispatch path per
  step - consent re-challenge, audit, history, and metrics apply per
  step; a step's `-32015` passes through annotated with
  `plugin`/`step`/`step_tool`. New error code `-32017 PluginStepError`
  for step-level `isError` results. Scanning is fresh on every call;
  `plugin_reload` surfaces loaded-vs-skipped diagnostics.
- **`screen_record` (vision)**- bounded screen recording
  (`src/tools/record.rs`): one PNG frame per `interval_ms`
  (default 250, 50-5000) for up to `duration_ms` (100-30000), optional
  `region`/`display` scoping mirroring `screenshot`. Hard caps: 600
  frames and 512 MiB written - the frame that would cross the byte cap is
  dropped and the run ends `truncated: true`. Frames plus a
  `manifest.json` (schema 1: backend name, args, per-frame
  file/bytes/geometry/timestamp, `stop_reason`) land in a fresh
  `rec-<ulid>` `0700` dir under the captures root (`/tmp` fallback) and
  are kept after the call. Runs to its bound - no mid-record
  cancellation; not consent-gated (nothing caller-chosen is written).
- **`SwayWindow` provider**- `WindowProvider` over sway's i3-flavoured
  IPC on `$SWAYSOCK` (`src/providers/sway_window.rs`): `GET_TREE` for
  list/active/geometry, `RUN_COMMAND` scoped to `[con_id=N]` criteria
  with a closed command set (`focus`, `kill`, `move scratchpad`,
  `move absolute position`, `resize set|grow|shrink` - `exec` is
  unreachable). `minimize` honestly maps to the scratchpad; move/resize
  are floating-window ops (no-op on tiled nodes). Backend name
  `"sway-ipc"`.
- **`KdotoolWindow` provider**- `WindowProvider` over the `kdotool` CLI
  (`src/providers/kdotool_window.rs`), the KDE rung of the window ladder
  on Wayland *and* X11 Plasma sessions (it drives KWin through its
  scripting API either way). `search ""` lists every managed window; a
  single chained spawn per window gathers title/class/geometry/pid/
  desktop, best-effort like `x11_window`'s enrichment. Window ids are
  KWin `internalId`s (`{uuid}`, never XIDs) and are shape-validated
  before reuse. Dispatch is a closed set (`windowactivate`,
  `windowmove`/`--relative`, `windowsize`, `windowminimize`,
  `windowclose`) - `kwinscript`'s arbitrary-JS primitive is unreachable.
  `floating`/`fullscreen`/`monitor` report `None` (no kdotool readout);
  `onAllDesktops` windows report `workspace = -1`. Constructs only on a
  KDE session marker + the pinned binary. Backend name `"kdotool"`.
- **Compositor breadth**- `SessionKind` now resolves `Hyprland`, `Sway`,
  `Wayfire`, `River`, `Kde`, `Gnome`, `Other`
  (`src/backend/detect.rs`), detected signature-first:
  `HYPRLAND_INSTANCE_SIGNATURE` -> `SWAYSOCK`/`sway` ->
  `WAYFIRE_SOCKET`/`Wayfire` -> `river` -> `KDE_SESSION_VERSION`/`KDE`/
  `Plasma` -> `GNOME`. The wlroots family (Hyprland/sway/Wayfire/river)
  keeps the `wlr-*` capture/input/overlay rungs; KDE and GNOME Wayland
  route to the portal backends they actually implement (wlr probing can
  never succeed there); X11 keeps `Scrot`/`Xdotool`/`Wmctrl`. Window
  ladders: `Hyprctl` (Hyprland), `SwayIpc` (sway), `Kdotool` (KDE -
  `KdotoolWindow`, driving KWin on Wayland and X11 alike; falls through
  when the session marker or pinned binary is absent), `Wmctrl`
  (GNOME/Other X11). Wayfire, river, and GNOME-Wayland honestly get an
  empty window ladder.
- **Per-backend Cargo features**- `default = ["wayland", "uinput",
  "a11y", "pipewire", "vision", "browser", "sentry"]`; each feature gates
  its provider modules, so `--no-default-features` builds a lean core
  (mock + subprocess providers) that compiles clean with the gated
  backends honestly unregistered (`ProviderUnavailable`, not build
  failure). `vision-rocm` joins `vision-cuda`/`vision-openvino` on the EP
  ladder (all imply `ort/load-dynamic`; `ORT_DYLIB_PATH` required).
- **Nix flake**- `flake.nix` at the repo root: `packages.default` via
  `rustPlatform.buildRustPackage` (pkg-config + clang native inputs,
  pipewire/wayland/libxkbcommon build inputs, `LIBCLANG_PATH` +
  `ORT_LIB_LOCATION` pinned for the sandboxed build), `devShells.default`
  with the Rust toolchain + session helpers, `apps.default`.
  **Unverified**- nix is not in the maintainer toolchain; the flake was
  written by review and has not been evaluated. Contributions welcome.
- **History format v2**- `history.json` is now a framed append log
  (`src/security/history.rs`): 8-byte `UNXHIST2` magic + one
  AES-256-GCM-sealed frame per record, so `record()` appends in O(1)
  instead of rewriting the whole blob. Full rewrites happen only for
  FIFO-cap eviction and the automatic v1->v2 migration (v1 files are
  detected by the absent magic, read normally, and rewritten on next
  append). Encryption, redaction, and cap semantics are unchanged.
- **AT-SPI element-scan cache**- `find_element`/`find_elements`/
  `invoke_element`/`wait_for_ui_element` now evaluate their query against
  a cached whole-desktop `TreeScan` (300 ms TTL measured from scan
  completion) instead of re-walking the D-Bus tree per call -
  `wait_for_ui_element`'s 250 ms polls share one scan per TTL window
  rather than rescanning every poll. Staleness is bounded by TTL + one
  poll (~550 ms + scan time); `path:/i/j` index queries bypass the cache
  (direct navigation is cheaper and stays exact).
- **`wl-copy`, `wl-paste`, `xclip`, `xsel`, `kdotool`**joined the
  startup pin set as provider-internal helpers - like `xrandr`/`xprop`
  they have no `validate_command` arm, so `system_command` still cannot
  invoke them.

### Changed

- Sentry wiring is feature-gated (`sentry` cargo feature) - building
  without it compiles out the DSN parsing, the `sentry-tracing` layer,
  and the panic guard entirely.
- Portal capture probes honour the `pipewire` feature: a RemoteDesktop-
  only portal no longer counts as a capture source when the feature is
  compiled out.

### Notes on verification

- Clipboard, sway IPC, plugin, and `screen_record` paths are implemented
  and covered by hermetic tests (mock providers, fake IPC responders,
  tempdir stores); live-session smoke evidence remains Hyprland/wlr-only
  from earlier waves.
- `toolSurfaceVersion` still reports `"2.0"` - the wave is purely
  additive (new tools, new category, new error code); no existing name,
  schema, or response shape changed.

### Still deferred (honest notes)

- GNOME window management: no provider module exists (gnome-shell's only
  window channel is an arbitrary-JS primitive we do not use) - window
  tools report `ProviderUnavailable` on GNOME. KDE is covered:
  `KdotoolWindow` drives KWin via the pinned `kdotool` helper on Wayland
  and X11 alike.
- Wayfire/river window management and GNOME-Wayland window/overlay rungs:
  no usable compositor IPC - intentionally empty ladders.
- Live streaming capture: `screen_record` is the bounded version; true
  continuous streaming remains open.
- Dynamic third-party tool registration: plugins are manifest macros over
  the existing catalog, not new tool schemas.

## [1.1.0] - 2026-09-15

The post-v1 backlog wave: every item the v1.0.0 docs flagged as "planned /
post-v1" that had a real implementation path has now landed.

### Breaking (tool-surface `1.0` -> `2.0`)

- `find_element` and `wait_for_ui_element` changed response structure:
  the single-match envelope is now `{found, count, matches[]}` where each
  match carries `{name, role, states, bounds, center}`.
  `capabilities.ultranix.toolSurfaceVersion` reports `"2.0"`.

### Added

- `OverlayProvider` + real `screen_highlight` - `src/providers/overlay.rs`
  draws a short-lived `zwlr_layer_shell_v1` overlay surface (translucent
  fill + opaque border, click-through empty input region, per-output
  placement by rect centre, bounded 5 s configure wait). On X11, headless,
  or layer-shell-less compositors the tool returns `-32010
  ProviderUnavailable` with `data.provider = "OverlayProvider"`.
- `find_element` is now multi-match: it returns up to 10 matches
  (`name`/`role`/`states`/`bounds`/`center` each) via
  `UIAutomationProvider::find_elements`. `wait_for_ui_element` emits the
  same match-entry shape.
- X11-native providers: `x11_capture.rs` (`scrot` frames, `xdotool
  getmouselocation`, `xrandr`/`xdotool` geometry), `x11_input.rs`
  (`xdotool`), `x11_window.rs` (`wmctrl` + `xdotool` + `xprop`). Detect
  ladders on X11: capture `Scrot -> Portal`, input `Xdotool -> UInput ->
  Portal`, window `Wmctrl` (non-Hyprland X11). Backend names: `"scrot"`,
  `"xdotool"`, `"wmctrl"`. `xrandr`/`xprop` joined the startup pin set as
  provider-internal helpers - they have no `validate_command` arm, so
  `system_command` still cannot invoke them.
- PipeWire stream consumption in `PortalCapture`: when a portal backend
  advertises `RemoteDesktop` but not `Screenshot`, capture runs
  `CreateSession -> SelectSources -> Start -> OpenPipeWireRemote` and pulls
  one video buffer over the granted fd (BGRx/BGRA/RGBx/RGBA, 5 s bounded
  grab, session always closed). `Screenshot` remains preferred when
  advertised.
- Opt-in Sentry error reporting via `ULTRANIX_MCP_SENTRY_DSN`: parsed
  before tracing init; the `sentry-tracing` layer attaches only when the
  DSN parses; a malformed DSN logs a warning and continues without Sentry.
- Four new Prometheus series - `ultranix_mcp_auth_failures_total{reason}`,
  `ultranix_mcp_backend_active{backend}`,
  `ultranix_mcp_action_history_size`, `ultranix_mcp_ocr_cache_entries` -
  for 8 shipped series total (canonical catalog: docs/ARCHITECTURE.md §7).
- OCR/icon result cache in `onnx_vision.rs`: `DashMap`, blake3-keyed
  (`ocr:{frame_hash}` / `icon:{frame_hash}:{desc}`), 10 s TTL, 64-entry
  cap with oldest-first eviction - `find_text_on_screen`'s cached path is
  real.
- `server.json` registry manifest at repo root (schema 2025-09-29,
  camelCase fields; passes `mcp-publisher validate`).
- `providers/common.rs` - shared hyprctl degraded-read helpers, the evdev
  key/button table, and `wl_output` geometry records deduplicated out of
  the individual backends.

### Changed

- AT-SPI traversal is parallelized: `atspi.rs` uses `join_all` for child
  proxy builds and per-app active-window scans; `MAX_SEARCH_NODES`/
  `MAX_TREE_NODES` budgets and ordering semantics are unchanged.
- Audit appends and history `clear()` moved onto `spawn_blocking` - no
  blocking store work on the async executor.
- `type_text` focus re-checks are throttled on the delayed path: first
  inter-key gap, then every 16th char or ≥100 ms, plus the post-loop check
  (see TOOLS.md §Focus Safety).

### Still deferred (honest notes)

- `wait_for_ui_element` still repeats a full AT-SPI scan per 250 ms poll -
  no element cache.
- Clipboard tools (`wl-copy`/`wl-paste`), the Nix flake, and the
  per-backend cargo-feature split remain post-v1.

## [1.0.0] - 2026-09-15

First stable release - the union of [0.1.0]-[0.5.0] plus a
spec-vs-implementation audit remediation pass that closed the
remaining drift before tagging.

### Added

- `capabilities.ultranix` extension block on `initialize`
  (`toolSurfaceVersion`, enabled `categories`, live `providers`,
  `features`) and `result._meta` server identity on every `tools/call`
  (docs/API_VERSIONING.md contract is now emitted).
- Authenticated HTTP `key_id` propagates to the tool layer via request
  extensions - consent tokens bind `{key_id, tool, args_hash}` and audit
  records carry per-key attribution on the HTTP transport.
- `WindowInfo` carries `floating`/`fullscreen`/`pid`/`monitor` (hyprctl
  supplies all four); `mouse_get_position` resolves the output under the
  pointer; `invoke_element` honours named AT-SPI actions via
  `GetActions`; `screenshot` resolves `display` to per-output bounds;
  `color_at` decodes the real captured pixel; `set_spatial_focus` scopes
  `screenshot`/`find_text_on_screen`/`find_icon`.
- `--category` is enforced at dispatch (`-32601` +
  `kind:"CategoryDisabled"`), not merely at `tools/list`.
- `get_action_history` gains an `action` substring filter and returns
  verbatim `args` (minus `consent_token`); `replay_action` validates
  ULIDs and refuses redacted records.
- `security::spawn` - every subprocess (whitelist exec + provider
  helpers) runs env-scrubbed on a pinned, once-resolved absolute path
  with a bounded wait; stdout drained concurrently to avoid pipe
  deadlock.

### Fixed

- Error taxonomy aligned to the documented codes: `-32003`
  (command/arg whitelist), `-32004` (path), `-32006` (sanitize),
  `-32015` (consent), `-32016` (element not found) - `-32020` is gone.
- Consent challenge `data` now carries the `tool` field and binds
  `window_control{close}` to the resolved window id (TOCTOU-safe).
- HTTP gate audits `auth_rejected`/`rate_limited` into the hash-chained
  log; 429 carries `Retry-After`; `/health` returns `{status, version}`.
- Portal `RemoteDesktop` no longer requests persisted tokens (per-session
  re-consent, matching THREAT_MODEL §4.2).
- History recording runs on `spawn_blocking` without the double clone;
  all D-Bus calls are wrapped in 5s timeouts; ONNX model downloads are
  bounded by a 300s total timeout.
- `type_text` aborts mid-sequence on focus change; `mouse_button_control`
  tracks held-button state; `web_query` returns the documented
  `{found, element, bounds_space}` envelope.
- Rate-limit rejection metric label renamed `category` -> `reason`
  (`auth`/`rate_limit` values).

### Scope notes (honest limitations)

- `screen_highlight` validates arguments then returns `-32010
  ProviderUnavailable` (`OverlayProvider` absent); the layer-shell
  overlay is post-v1.
- `ULTRANIX_MCP_SENTRY_DSN` is documented but not wired (planned, post-v1).
- Portal `RemoteDesktop` is input-only - the granted PipeWire stream is
  deliberately not consumed.
- X11-native providers (`xdotool`/`wmctrl`/`scrot` backends) are post-v1;
  the whitelist entries for them apply to `system_command` on X11
  sessions only.
- The unsecured `call_tool` path retains a labelled `phase0_stub`
  `system_command` response - production always attaches a
  `SecurityContext`, so real exec is the production path.

## [0.5.0] - 2026-09-15

### Added

- HTTP security gate on `/mcp`: `ApiKeyStore` (`uxcp_*` keys; env ->
  file -> `~/.ultranix-mcp/api-keys/` precedence; sha256-digest store,
  constant-time compare, expiry + `rotate(grace)`, `0600`-enforced key
  files; `ULTRANIX_MCP_DISABLE_AUTH` dev hatch) -> 401, and a
  token-bucket `RateLimiter` (10 rps / 20 burst per `key_id` or remote
  addr) -> 429. `/health`, `/readyz`, `/metrics` open on loopback.
- `HistoryStore` - AES-256-GCM-encrypted action history at
  `history.json` (`ULTRANIX_MCP_HISTORY_SECRET` or generated 0600
  `history.key`; ULID ids, 10k FIFO cap, `type_text` arg redaction,
  atomic writes). Lazy `SecurityContext::history()` scopes the store to
  the context's state root.
- Real admin tools: `get_action_history`, `replay_action` (exactly-one
  selector, consent re-challenge through `call_tool_secured`),
  `clear_action_history`; `metrics` now serves the live Prometheus
  exposition.
- `metrics.rs` - dependency-free Prometheus registry:
  `ultranix_mcp_tool_calls_total`, `ultranix_mcp_tool_duration_seconds`
  (histogram), `ultranix_mcp_rate_limit_rejections_total`,
  `ultranix_mcp_active_sessions`.
- Audit completion: every invocation records
  `{tool, args_hash, outcome, duration_ms, key_id, caller, consent?,
  prev_hash}`; day-rollover rotation (`audit-YYYY-MM-DD.jsonl`) +
  `ULTRANIX_MCP_AUDIT_RETENTION_DAYS` pruning (default 30).
- `ultranix-mcp keygen` CLI subcommand.

### Fixed

- `Cargo.toml` version synced to the release train.

## [0.4.0] - 2026-09-15

### Added

- `OnnxVision` - `VisionProvider` on `ort` 2.0-rc (ONNX Runtime,
  prebuilt CPU EP; `vision-cuda`/`vision-openvino` cargo features):
  RapidOCR `ch_PP-OCRv4` det+rec pipeline for `find_text_on_screen`
  (connected-components det, CTC greedy decode over
  `ppocr_keys_v1.txt`) and quantized OWL-ViT-base for `find_icon`
  (sigmoid + cxcywh->xyxy + NMS). Models download on first use into
  `~/.ultranix-mcp/models/` with pinned URL+sha256, `.part` temp +
  atomic rename + `0600`.
- `CdpBrowser` - `BrowserProvider` on Chrome DevTools Protocol
  (`tokio-tungstenite`, loopback `127.0.0.1:9222` only):
  `query_selector` via `Runtime.evaluate` with JSON-encoded selector
  (no string splicing), debugger-URL loopback revalidation, lazy
  reconnect. Hermetic WS/HTTP stub test suite.
- `VisionBackend::Onnx` + `BrowserBackend::Cdp` detection rungs -
  all six provider slots now have real backends.

## [0.3.0] - 2026-09-15

### Added

- `AtspiUi` - `UIAutomationProvider` on AT-SPI2 (`atspi` 0.30 / zbus 5):
  `get_ui_tree` (5000-node-capped serialized tree: role/name/states/
  bounds/children), `get_focused_element`, `find_element`
  (`role:`/`name:`/`desc:`/`path:` query prefixes -> screen bounding
  rect), `wait_for_ui_element`, `invoke_element` (Action do_action(0)).
  Lazy zbus connection bound to the server runtime; session-agnostic
  rung applied on Wayland and X11. Live-verified against the real
  a11y bus; `invoke_element` never exercised live.
- `UinputInput` - `/dev/uinput` evdev `InputProvider` fallback
  (display-agnostic): EV_ABS absolute pointer moves, REL wheel scroll
  with sub-detent accumulator, full `key_binding` table (chars, mods,
  nav, keypad, F1-F24, media), probe-only `new()`; udev rule expects
  dedicated `ultranix-input` group.
- `UiAutomationBackend::Atspi` rung in `backend::detect`
  (`Wlr -> Grim`, `Wlr -> UInput`, `Hyprctl`, `Atspi` ladders).

## [0.2.0] - 2026-09-15

### Added

- Hyprland I/O backends (live-verified on CachyOS/Hyprland):
  `WlrCapture` (in-process wlr-screencopy -> PNG), `GrimCapture`
  fallback, `WlrInput` (zwlr_virtual_pointer_v1 +
  zwp_virtual_keyboard_v1 with uploaded XKB keymap), and
  `HyprctlWindow` (IPC socket / `hyprctl -j` window control)
- `backend::detect` - session probing (`XDG_SESSION_TYPE`,
  `XDG_CURRENT_DESKTOP`, `HYPRLAND_INSTANCE_SIGNATURE`) with the
  wlroots-native -> uinput -> portal fallback ladder
- `security/` scaffolding: input sanitization, arg-constrained +
  startup-pinned command whitelist (`grim`/`slurp`/`hyprctl`/`scrot`/
  `xdotool`/`wmctrl`), canonicalized path whitelist, CSPRNG consent gate
  (`-32015 ConsentRequired`, 60 s single-use tokens bound to
  caller+tool+args_hash+resolved target), hash-chained JSONL audit log,
  `0700` capture dirs with `O_NOFOLLOW` server opens
- `state.rs` - `~/.ultranix-mcp/` bootstrap (canonical root, `0700`)
- `system_command` real exec: pinned binaries, no shell, 15 s timeout,
  64 KiB output truncation
- `--allow-destructive` and `--mock` CLI flags

### Fixed

- `delegate_noop!` panics on event-emitting Wayland objects (`wl_seat`,
  `zwp_virtual_keyboard_v1`, `wl_shm`) - replaced with swallowing
  `Dispatch` impls
- wlr-screencopy `ready` race: fixed-count roundtrips -> 5 s deadline loop

## [0.1.0] - 2026-09-15

### Added

- Phase 0 scaffold (delivered): Rust 2024 edition crate on `rmcp` with
  stdio and streamable-HTTP transports, provider-trait layer with mock
  providers, 32-tool schema registry, session detection, and `tracing`
  logging - see [ROADMAP.md](ROADMAP.md) for the per-phase plan
- GitHub Actions CI (`rust_ci.yml`): `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, headless
  `cargo test --all-targets`, `cargo llvm-cov` coverage uploaded to
  Codecov, and a non-blocking `cargo audit` job
- Security scanning workflow (`security-scan.yml`): `cargo audit` plus
  `cargo deny check` with a permissive `deny.toml` (advisories deny on
  vulnerabilities, warn on unmaintained/yanked; no bans; license
  allowlist covering ISC/MIT/Apache-2.0/BSD/Zlib/Unicode/MPL/CC0)
- Repository hygiene: `.gitignore` (Rust target, `~/.ultranix-mcp`
  runtime artifacts, editor dirs; `Cargo.lock` kept committed),
  GitHub issue templates (bug report, feature request), and a pull
  request template with a tests/clippy/docs checklist

---

## Version History

- **1.2.0**: Breadth wave - clipboard category, plugin tool-macros,
  `screen_record`, sway/Wayfire/river/KDE/GNOME detection + sway window
  provider, per-backend cargo features (incl. `vision-rocm`), Nix flake
  (unverified), history v2 framed appends, AT-SPI scan cache. 39 tools.
- **1.1.0**: Post-v1 wave - layer-shell overlay, X11-native providers,
  PipeWire portal capture, Sentry, OCR cache, 4 new metrics.
- **1.0.0**: First stable release - all six delivery phases
  landed across 0.1.0-0.5.0.
- **0.1.0-0.5.0**(2026-09-15): Phase-by-phase delivery on the verified
  target environment - CachyOS (Arch) + Hyprland on Wayland, PipeWire,
  `xdg-desktop-portal-hyprland`, live AT-SPI2 bus, Rust 1.98.1.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/jxoesneon/ultranix-mcp/issues)
- **Security**: See [SECURITY.md](SECURITY.md)
- **Documentation**: [docs/](docs/)
