# Roadmap

ultranix-mcp's delivery plan for **v1.0.0** and beyond. Work proceeded in six
phases, each with concrete deliverables, exit criteria, dependencies, and
risk callouts — **Phases 0–5 are delivered as of v1.0.0, the v1.1.0 wave
shipped the post-v1 items that had a real implementation path, the
v1.2.0 breadth wave landed the rest, and the v1.3.0 policy-and-governance
wave added the runtime access-control surface** (see
[CHANGELOG.md](CHANGELOG.md), [v1.1.0 — Post-v1 Wave](#v110--post-v1-wave-shipped),
[v1.2.0 — Breadth Wave](#v120--breadth-wave-shipped), and
[v1.3.0 — Policy & Governance Wave](#v130--policy--governance-wave-shipped)
below). This is a living document — update it as direction shifts.

Legend: `[x]` done · `[ ]` planned · phases are strictly ordered; a phase's
exit criteria gate the next.

**Verified target environment:** CachyOS (Arch), Hyprland on Wayland,
PipeWire, `xdg-desktop-portal-hyprland`, live AT-SPI2 bus, Rust 1.98.1.
Installed session tools: `hyprctl`, `grim`, `slurp`. X11 sessions use the
shipped `scrot`/`xdotool`/`wmctrl` rungs (`xrandr`/`xprop` are pinned as
provider-internal helpers, not `system_command`-invocable). Optional:
`wl-clipboard` (`wl-copy`/`wl-paste` — clipboard tools on Wayland),
`xclip`/`xsel` (clipboard tools on X11/XWayland; all four are likewise
provider-internal pins, unreachable by `system_command`). Not required:
`gdbus`/`busctl` — removed from the command whitelist. Absent by design:
`wtype`, `ydotool`, `tesseract` — ultranix-mcp does not depend on them.

---

## Phase 0 — Scaffold & Mocks

Foundation: a compiling, test-covered skeleton with the full provider-trait
surface and zero real backends.

### Deliverables

- [x] Cargo project: `ultranix-mcp` binary, Rust 2024 edition, `tokio`
      runtime
- [x] `rmcp` (official `modelcontextprotocol/rust-sdk`) server core with
      stdio and streamable-HTTP (`:3010`) transports
- [x] `src/traits.rs`: `CaptureProvider`, `InputProvider`,
      `UIAutomationProvider`, `WindowProvider`, `VisionProvider`,
      `BrowserProvider` — all held as `Option<Arc<dyn Trait>>` in a provider
      registry
- [x] Mock implementations of all six traits; tool dispatch returns typed
      "provider unavailable" errors when a backend is `None`
- [x] Tool schema registration for the complete 32-tool surface and
      `--category=` filtering (`mouse`, `keyboard`, `vision`, `automation`,
      `admin`)
- [x] Session detection: `XDG_CURRENT_DESKTOP` +
      `HYPRLAND_INSTANCE_SIGNATURE`
- [x] `tracing`/`tracing-subscriber` logging; `~/.ultranix-mcp/` data-dir
      bootstrap
- [x] CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`
- [x] Specification documentation set (README, LICENSE, CHANGELOG, ROADMAP,
      CONTRIBUTING, CODE_OF_CONDUCT)

### Exit criteria

- `cargo test` is green with mock providers on headless CI (no Wayland, no
  AT-SPI bus)
- `ultranix-mcp --transport stdio` (`--stdio` alias) serves the tool list;
  `--category=mouse,keyboard` narrows it correctly
- Every tool invoked against mocks produces either a deterministic mock
  result or a structured provider-unavailable error

### Dependencies

`rmcp`, `tokio`, `serde`/`serde_json`, `anyhow`, `thiserror`, `tracing`,
`tracing-subscriber`, `async-trait`

### Risks

- **Low.** The main trap is schema drift — tool schemas are the contract, so
  they are frozen in Phase 0 and reviewed via ADR afterwards.

---

## Phase 1 — Hyprland I/O

Real capture, input, and window control on the primary compositor — no
root, no portals.

### Deliverables

- [x] `wayland-client` integration with `wlr-screencopy-unstable-v1` for
      in-process frame capture (`screenshot`, `screen_info`, `color_at`)
- [x] `grim`/`slurp` fallback capture path for region selection and compositor
      edge cases
- [x] `InputProvider` on `zwlr_virtual_pointer_v1` (pointer motion, buttons,
      scroll) and `virtual-keyboard-unstable-v1` (text, key states,
      modifiers, keymap upload) — powers all `mouse_*`, `type_text`,
      `key_control`, `mouse_move_path`, `sleep`
- [x] `WindowProvider` on the `hyprctl` IPC socket, parsing `hyprctl -j`
      JSON (`clients`, `activewindow`, `dispatch`, `workspaces`) for
      `get_windows`, `get_active_window`, `window_control`
- [x] Backend-selection logic implementing the wlroots-native →
      uinput/evdev → portal priority ladder
- [x] Security scaffolding — the server ships protected from day one:
      input sanitization (shell-metacharacter stripping, identifier
      length/charset validation); arg-constrained, absolute-path-pinned
      command whitelist for `system_command` (`grim`, `slurp`, `scrot`,
      `hyprctl` without `dispatch exec`/`exec-once`; `xdotool`/`wmctrl`
      X11-only); narrowed path whitelist (`$XDG_RUNTIME_DIR`, `/tmp`,
      `~/.ultranix-mcp/**`); JSONL audit skeleton (`key_id`, `args_hash`,
      `prev_hash` chaining); and the destructive-tool consent gate
      (`-32015 ConsentRequired` + `consent_token` retry;
      `--allow-destructive` bypass)

### Exit criteria

- On a live Hyprland session: every `mouse`, `keyboard`, and
  `window_control`-family tool works end-to-end; `screenshot` returns a
  correct full-frame capture; `get_windows` enumerates real clients
- `system_command` ships protected: whitelisted binaries resolve via pinned
  absolute paths, exec-capable subcommands (`hyprctl dispatch exec`,
  `exec-once`) are denied, and destructive tools answer `-32015
  ConsentRequired` until retried with a `consent_token`
- Tools degrade cleanly when a provider is unavailable (structured error,
  logged, no panic)

### Dependencies

`wayland-client`, `wayland-protocols-wlr`, `calloop` (or equivalent event
loop), `image`, Hyprland running with `HYPRLAND_INSTANCE_SIGNATURE` set

### Risks

- **Protocol drift**: Hyprland is a moving target; wlroots protocol versions
  are pinned and negotiated at bind time, with version mismatches reported
  as provider-unavailable rather than fatal.
- **Keymap handling**: `virtual-keyboard-unstable-v1` requires uploading an
  XKB keymap; correctness for non-QWERTY layouts is a named test case.
- **Screencopy damage/scale**: HiDPI outputs and damage tracking are handled
  explicitly; full-frame capture is the correctness baseline.

---

## Phase 2 — AT-SPI2 UI Automation

Semantic access to application UI through the accessibility bus.

### Deliverables

- [x] `UIAutomationProvider` on AT-SPI2 via the `atspi` crate: tree
      traversal, role/state/name extraction, bounding boxes
- [x] `get_ui_tree`, `get_focused_element`, `find_element`,
      `wait_for_ui_element`, `invoke_element`, `set_spatial_focus`
      (process-global rect scoping `screenshot`/`find_text_on_screen`/
      `find_icon`) — `screen_highlight` validates args then returns
      `-32010 ProviderUnavailable` when no overlay backend exists; the
      `zwlr_layer_shell_v1` `Overlay` backend landed at v1.1.0
- [x] Focus tracking across window/app switches (`get_focused_element`
      re-scans the live tree for `State::Focused`, so focus resolution
      follows window/app switches)
- [x] Documented element-query semantics (role, name, path) shared with
      `find_element` and `wait_for_ui_element`

### Exit criteria

- UI tree dumps succeed for GTK and Qt applications on the target desktop
- `find_element` resolves an element to a screen bounding box usable by the
  `mouse_*` tools
- `wait_for_ui_element` blocks until match or a clean, configurable timeout

### Dependencies

`atspi` crate, live AT-SPI2 bus (`org.a11y.Bus` on the session bus)

### Risks

- **App coverage gaps**: Electron/Chromium apps frequently expose no a11y
  tree unless launched with `--force-renderer-accessibility`; games and some
  toolkits expose partial trees. Mitigation: documented per-app flags, plus
  OCR/`find_element`-by-image fallbacks via the vision pipeline.
- **Bus availability**: session detection reports a11y-bus status at
  startup; the provider stays `None` (graceful degradation) when absent.

---

## Phase 3 — Vision & Browser

Local inference for OCR and icon finding, plus browser automation over CDP.

### Deliverables

- [x] `VisionProvider` on the `ort` crate (ONNX Runtime): OCR model for
      `find_text_on_screen`; OWL-ViT zero-shot detection for `find_icon`
- [x] Execution providers: CPU default; OpenVINO and CUDA behind cargo
      features (`vision-openvino`, `vision-cuda`)
- [x] `BrowserProvider`: CDP bridge on `127.0.0.1:9222` driving `web_query`
      (attach to an existing browser or launch with
      `--remote-debugging-port=9222`)
- [x] Model-artifact management: versioned download-on-first-use with
      checksum verification into `~/.ultranix-mcp/models/`

### Exit criteria

- `find_text_on_screen` locates real desktop text on the target environment
- `find_icon` locates a known icon via OWL-ViT with a confidence score
- `web_query` drives a CDP-enabled browser end-to-end

### Dependencies

`ort` (ONNX Runtime), model artifacts, `tokio-tungstenite`/CDP client,
Chromium-family browser for `web_query`

### Risks

- **ONNX model bundling size**: bundling models in the binary or repo is
  rejected — artifacts are fetched on first use with verified checksums, and
  the `vision` category can be excluded via `--category=` on model-free
  installs.
- **CPU latency for OWL-ViT**: icon finding is seconds-scale on CPU; EP
  features and result caching are the mitigation path.
- **CDP port collisions**: the bridge binds `127.0.0.1` only and reports the
  bound port in `screen_info`/`metrics`.

---

## Phase 4 — Enterprise Hardening

The governance surface: auth, audit completion, observability. (Sanitization,
the arg/path whitelists, the audit skeleton, and the consent gate are Phase-1
security scaffolding — this phase finishes the enterprise surface on top of
them.)

### Deliverables

- [x] `uxcp_*` API-key auth middleware on HTTP (`ULTRANIX_MCP_API_KEY` or
      `ULTRANIX_MCP_API_KEY_FILE`; fail-closed — `X-API-Key` header
      canonical, `Authorization: Bearer` accepted);
      `ULTRANIX_MCP_DISABLE_AUTH=true` escape hatch for dev; stdio never
      requires auth
- [x] Token-bucket rate limiter: 10 req/s per client
- [x] AES-256-GCM-encrypted action history at
      `~/.ultranix-mcp/history.json` (`ULTRANIX_MCP_HISTORY_SECRET` or a
      per-install generated secret under `~/.ultranix-mcp/`, mode `0700`)
- [x] Full JSONL audit log at `~/.ultranix-mcp/logs/` — extends the Phase-1
      skeleton to every tool invocation: `key_id`, `args_hash` (never raw
      args), duration, outcome, `prev_hash` chaining; 30-day rotation
      (configurable via `ULTRANIX_MCP_AUDIT_RETENTION_DAYS`)
- [x] Prometheus `/metrics` (4 series at v1.0.0; 8 as of v1.1.0; 10 since
      v1.3.0 — see ARCHITECTURE.md §7); `/health` and `/readyz` endpoints;
      `ultranix-mcp keygen` CLI
- [x] Optional Sentry error reporting via `ULTRANIX_MCP_SENTRY_DSN` —
      **shipped at v1.1.0** (opt-in; the `sentry-tracing` layer attaches
      only when the DSN parses, malformed DSN warns and disables)
- [x] Admin tools: `metrics`, `get_action_history`, `replay_action`,
      `clear_action_history`

### Exit criteria

- Unauthenticated HTTP requests are rejected (401); rate-limited clients get
  429; stdio requires no key
- `history.json` is unreadable at rest without the secret; audit JSONL
  records every call
- Error responses contain no stack traces or absolute paths
- Security review against [SECURITY.md](SECURITY.md)'s threat model is
  complete and documented under `docs/`

### Dependencies

`aes-gcm` (or `ring`), the dependency-free Prometheus text exporter in
`src/metrics.rs` (no `prometheus` crate), HTTP middleware on the rmcp
streamable-HTTP transport

### Risks

- **Key management UX**: `ULTRANIX_MCP_HISTORY_SECRET` (or the per-install
  generated secret) needs a documented rotation path; a lost secret means
  lost history — called out in docs.
- **Audit retention**: 30-day JSONL rotation is the spec'd default
  (configurable); fine-tuning rotation boundaries and shipped policy remains
  a Phase-4 hardening task.

---

## Phase 5 — Portability & Packaging

Off-Hyprland fallback paths and real distribution.

### Deliverables

- [x] `uinput`/`evdev` `InputProvider` fallback for non-wlroots compositors,
      with a packaged, opt-in udev rule for `/dev/uinput`
      (`SUBSYSTEM=="uinput", MODE="0660", GROUP="ultranix-input"` — a
      dedicated group holding only the service user, never `input`)
- [x] XDG Desktop Portal backend over `zbus`: `Screenshot` and
      `RemoteDesktop` portals (universal last resort). `RemoteDesktop`
      drives portal input; as of v1.1.0 the capture path also consumes the
      granted PipeWire stream when `Screenshot` is not advertised
- [x] PipeWire stream consumption for portal `RemoteDesktop` sessions —
      **shipped at v1.1.0** (`CreateSession → SelectSources → Start →
      OpenPipeWireRemote` → one video buffer, BGRx/BGRA/RGBx/RGBA, 5 s
      bounded grab, session always closed)
- [x] Nested-Hyprland integration test rig for real-Wayland CI
      (`tests/nested.rs` + `scripts/nested-test.sh`, gated behind
      `ULTRANIX_MCP_LIVE_TESTS=1`)
- [x] Packaging artifacts: AUR PKGBUILDs (`ultranix-mcp`,
      `ultranix-mcp-git`) under `packaging/`, `cargo install` support,
      systemd user unit, GitHub release binaries via `release.yml` —
      AUR/crates.io submission itself is tracked in
      [docs/REGISTRY_SUBMISSION.md](docs/REGISTRY_SUBMISSION.md)
- [x] Distro notes covering non-Arch packaging requirements
      ([docs/PACKAGING.md](docs/PACKAGING.md) §9)

### Exit criteria

- Server runs end-to-end on a non-Hyprland wlroots compositor via the portal
  path
- AUR package builds in a clean chroot; `cargo install ultranix-mcp` works
- Integration tests pass in a nested compositor on CI

### Dependencies

`zbus`, `evdev`/`uinput` crates, `xdg-desktop-portal-hyprland` (or the
session's portal impl), `pkgbuild` tooling

### Risks

- **uinput udev rule**: `/dev/uinput` access requires an elevated,
  persistent system change — packaged as an explicit opt-in rule
  (`GROUP="ultranix-input"`, dedicated group) with copy-paste setup
  instructions; never auto-installed.
- **Portal consent UX**: portal backends trigger per-app consent dialogs
  that block unattended automation; restore tokens are persisted where the
  portal version allows, and the docs steer primary installs toward the
  native wlroots path.
- **Portal implementation variance**: behavior differs across
  `xdg-desktop-portal-*` backends; the verified target pins
  `xdg-desktop-portal-hyprland`.

---

## v1.1.0 — Post-v1 Wave (shipped)

The items the v1.0.0 docs marked post-v1 that had a real implementation
path — all delivered:

- [x] **Layer-shell overlay** — `OverlayProvider` on `zwlr_layer_shell_v1`
      powers a real `screen_highlight` (translucent, click-through,
      per-output placement); `ProviderUnavailable` off-Wayland
- [x] **Multi-match `find_element`** — `find_elements` returns up to 10
      matches with name/role/states/bounds/center
- [x] **X11 session support** — `scrot`/`xdotool`/`wmctrl` provider rungs
      (`xrandr`/`xprop` pinned as provider-internal helpers only)
- [x] **PipeWire stream consumption** — portal `RemoteDesktop` capture path
      consumes the granted PipeWire fd when `Screenshot` is absent
- [x] **Sentry** — opt-in via `ULTRANIX_MCP_SENTRY_DSN`
- [x] **Four additional metrics** — `auth_failures_total`,
      `backend_active`, `action_history_size`, `ocr_cache_entries`
- [x] **OCR result cache** — blake3-keyed `DashMap`, 10 s TTL, 64-entry cap
- [x] **Parallel AT-SPI traversal** — `join_all` child-proxy builds and
      per-app scans (budgets/ordering unchanged)
- [x] **`spawn_blocking` audit/history** — blocking store work moved off
      the async executor
- [x] **Throttled `type_text` focus checks** — first gap, then every 16th
      char or ≥100 ms, plus post-loop
- [x] **`server.json` registry manifest** — `mcp-publisher validate`-clean

## v1.2.0 — Breadth Wave (shipped)

The rest of the post-v1 backlog with a real implementation path — the tool
surface grew from 32 to **39 tools in 6 categories**:

- [x] **Clipboard tools** — `clipboard_get`/`clipboard_set`/
      `clipboard_clear` over a new `ClipboardProvider`: `wl-copy`/
      `wl-paste` on Wayland (backend `"wl-clipboard"`), `xclip` + `xsel`
      on X11/XWayland (`"xclip"`). Text-first reads (`mime: "list"`
      enumerates), 1 MiB write cap, payloads over stdin; `set`/`clear`
      are consent-gated destructive actions
- [x] **Plugin tool-macros** — `plugin_list`/`plugin_run`/`plugin_reload`
      over declarative `<state>/plugins/*.json` manifests (`${param}`
      templating, `$$` escape, typed string/number/boolean params, 1–32
      steps). Steps re-enter the secured dispatch — per-step consent,
      audit, history, metrics; `plugin_*` steps rejected (no macro
      recursion); new `-32017 PluginStepError`
- [x] **Bounded screen recording** — `screen_record` (vision): one frame
      per `interval_ms` up to `duration_ms`, 600-frame + 512 MiB caps,
      `rec-<ulid>` output dir + `manifest.json`; not consent-gated
- [x] **Compositor breadth** — `SessionKind` detects Hyprland, sway,
      Wayfire, river, KDE, GNOME, Other; wlroots family shares the
      `wlr-*` rungs, KDE/GNOME route to portal backends; `SwayWindow`
      (`sway-ipc` over `$SWAYSOCK`) is the sway window provider; a
      `KdotoolWindow` (`kdotool` subprocess) is the KDE window provider —
      it drives KWin on Wayland and X11 alike
- [x] **Per-backend cargo features** — `wayland`/`uinput`/`a11y`/
      `pipewire`/`vision`/`browser`/`sentry` (all default-on);
      `--no-default-features` builds a lean core that reports
      `ProviderUnavailable` honestly; `vision-rocm` joins the EP ladder
- [x] **Nix flake** — `flake.nix` (package + devShell + app).
      **Unverified** — written by review, never evaluated; contributions
      welcome
- [x] **History v2** — `UNXHIST2` framed append format: O(1) encrypted
      appends; full rewrite only on FIFO eviction or v1→v2 migration
- [x] **AT-SPI scan cache** — `wait_for_ui_element` & friends reuse a
      cached `TreeScan` (300 ms TTL) instead of re-walking the tree every
      250 ms poll; staleness bounded by TTL + one poll

## v1.3.0 — Policy & Governance Wave (shipped)

Runtime access control and audit hardening — the tool surface is
unchanged (39 tools / 6 categories); every item is an additive
security/ops knob ([ADR 0010](docs/adr/0010-policy-controls.md)):

- [x] **`policy.toml` runtime policy** — TOML file
      (`~/.config/ultranix-mcp/policy.toml`, or `--policy=PATH`)
      declaring `default_role`, named `roles` (`readonly` /
      `allow_tools` / `deny_tools`), and a `keys` map binding API-key
      fingerprints to roles for per-key scoping on HTTP (stdio and
      unmapped keys resolve to `default_role`). Loading is fail-closed:
      a missing/malformed explicit `--policy`, misspelled TOML keys
      (`deny_unknown_fields`), and `keys` → undefined-role references
      all abort startup
- [x] **`--readonly`** — restricts the default role to the 15-tool
      non-mutating preset; `allow_tools` unions with the preset, so
      operators can opt individual mutating tools back in
- [x] **`--allow-tools` / `--deny-tools`** — per-tool lists scoped to
      `default_role` only: `--allow-tools` replaces the file's
      default-role allowlist (unioning with the preset under
      `--readonly`), `--deny-tools` adds to it; denials surface as
      `-32018 ReadOnlyMode` / `-32019 NotInToolList` with an audited
      `denial_reason`
- [x] **Backend metrics + build info** —
      `ultranix_mcp_backend_calls_total{backend,outcome}` and
      `ultranix_mcp_build_info{version}` (10 shipped series); `denied`
      joined the tool-call outcome vocabulary
- [x] **Audit HMAC** — `ULTRANIX_MCP_AUDIT_SECRET` signs every
      `audit.jsonl` line (HMAC-SHA256 over the canonical record;
      `prev_hash` covers the signed line). Rollout caveat: enable on a
      fresh/rotated log — pre-secret unsigned lines fail verification
- [x] **Startup policy warnings** — CLI policy flags coexisting with
      named roles, a `keys` map under an unrestricted `default_role`,
      and a `keys` map on stdio/disabled auth all log loud warnings

## Post-v1 Ideas

Exploration backlog — not committed, priority by demand.

- **GNOME native window backend** — a Mutter / gnome-shell provider
  behind `WindowProvider` (the KDE side shipped: `KdotoolWindow` drives
  KWin via `kdotool`)
- **Wayfire/river window backends** — no general window IPC exists today
  (Wayfire's IPC is plugin-scoped; `riverctl` manages layout, not client
  windows) — needs upstream capability or a protocol-level approach
- **GPU EP acceleration** — CUDA/OpenVINO/ROCm features are wired
  (`ort/load-dynamic` + `ORT_DYLIB_PATH`); remaining work is validated
  EP-packaged ONNX Runtime builds in CI/packaging
- **Streaming capture** — `screen_record` shipped the bounded version;
  true continuous/live streaming for remote-control UX remains open
- **Headless operation** — running under a nested or headless compositor for
  CI and server-side automation
- **Dynamic tool registration** — plugins shipped as manifest macros over
  the fixed catalog; third-party tools with their own schemas remain open

---

## Definition of Done for New Work

- [ ] Fixes applied (not just findings), with a report under `docs/` when an
      audit is involved
- [ ] Mock-provider tests green for all changed tools; live-session
      verification on Hyprland for backend changes
- [ ] `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` all clean
      before merge
- [ ] ADR under `docs/adr/` for any change to the backend priority ladder,
      provider-trait surface, or security model
