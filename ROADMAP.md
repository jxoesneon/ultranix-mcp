# Roadmap

ultranix-mcp's delivery plan for **v0.1.0** and beyond. Work proceeds in six
phases, each with concrete deliverables, exit criteria, dependencies, and
risk callouts. This is a living document — update it as direction shifts.

Legend: `[x]` done · `[ ]` planned · phases are strictly ordered; a phase's
exit criteria gate the next.

**Verified target environment:** CachyOS (Arch), Hyprland on Wayland,
PipeWire, `xdg-desktop-portal-hyprland`, live AT-SPI2 bus, Rust 1.98.1.
Installed session tools: `hyprctl`, `grim`, `slurp`. Post-v1/optional:
`wl-copy` (planned clipboard tools). Not required: `gdbus`/`busctl` —
removed from the command whitelist. Absent by design: `wtype`, `ydotool`,
`tesseract` — ultranix-mcp does not depend on them.

---

## Phase 0 — Scaffold & Mocks

Foundation: a compiling, test-covered skeleton with the full provider-trait
surface and zero real backends.

### Deliverables

- [ ] Cargo project: `ultranix-mcp` binary, Rust 2024 edition, `tokio`
      runtime
- [ ] `rmcp` (official `modelcontextprotocol/rust-sdk`) server core with
      stdio and streamable-HTTP (`:3010`) transports
- [ ] `src/traits.rs`: `CaptureProvider`, `InputProvider`,
      `UIAutomationProvider`, `WindowProvider`, `VisionProvider`,
      `BrowserProvider` — all held as `Option<Arc<dyn Trait>>` in a provider
      registry
- [ ] Mock implementations of all six traits; tool dispatch returns typed
      "provider unavailable" errors when a backend is `None`
- [ ] Tool schema registration for the complete 32-tool surface and
      `--category=` filtering (`mouse`, `keyboard`, `vision`, `automation`,
      `admin`)
- [ ] Session detection: `XDG_CURRENT_DESKTOP` +
      `HYPRLAND_INSTANCE_SIGNATURE`
- [ ] `tracing`/`tracing-subscriber` logging; `~/.ultranix-mcp/` data-dir
      bootstrap
- [ ] CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`
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

- [ ] `wayland-client` integration with `wlr-screencopy-unstable-v1` for
      in-process frame capture (`screenshot`, `screen_info`, `color_at`)
- [ ] `grim`/`slurp` fallback capture path for region selection and compositor
      edge cases
- [ ] `InputProvider` on `zwlr_virtual_pointer_v1` (pointer motion, buttons,
      scroll) and `virtual-keyboard-unstable-v1` (text, key states,
      modifiers, keymap upload) — powers all `mouse_*`, `type_text`,
      `key_control`, `mouse_move_path`, `sleep`
- [ ] `WindowProvider` on the `hyprctl` IPC socket, parsing `hyprctl -j`
      JSON (`clients`, `activewindow`, `dispatch`, `workspaces`) for
      `get_windows`, `get_active_window`, `window_control`
- [ ] Backend-selection logic implementing the wlroots-native →
      uinput/evdev → portal priority ladder
- [ ] Security scaffolding — the server ships protected from day one:
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

- [ ] `UIAutomationProvider` on AT-SPI2 via the `atspi` crate: tree
      traversal, role/state/name extraction, bounding boxes
- [ ] `get_ui_tree`, `get_focused_element`, `find_element`,
      `wait_for_ui_element`, `set_spatial_focus`, `screen_highlight`,
      `invoke_element`
- [ ] Focus tracking across window/app switches
- [ ] Documented element-query semantics (role, name, path) shared with
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

- [ ] `VisionProvider` on the `ort` crate (ONNX Runtime): OCR model for
      `find_text_on_screen`; OWL-ViT zero-shot detection for `find_icon`
- [ ] Execution providers: CPU default; OpenVINO and CUDA behind cargo
      features
- [ ] `BrowserProvider`: CDP bridge on `127.0.0.1:9222` driving `web_query`
      (attach to an existing browser or launch with
      `--remote-debugging-port=9222`)
- [ ] Model-artifact management: versioned download-on-first-use with
      checksum verification into `~/.ultranix-mcp/`

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

- [ ] `uxcp_*` API-key auth middleware on HTTP (`ULTRANIX_MCP_API_KEY` or
      `ULTRANIX_MCP_API_KEY_FILE`; fail-closed — `X-API-Key` header
      canonical, `Authorization: Bearer` accepted);
      `ULTRANIX_MCP_DISABLE_AUTH=true` escape hatch for dev; stdio never
      requires auth
- [ ] Token-bucket rate limiter: 10 req/s per client
- [ ] AES-256-GCM-encrypted action history at
      `~/.ultranix-mcp/history.json` (`ULTRANIX_MCP_HISTORY_SECRET` or a
      per-install generated secret under `~/.ultranix-mcp/`, mode `0700`)
- [ ] Full JSONL audit log at `~/.ultranix-mcp/logs/` — extends the Phase-1
      skeleton to every tool invocation: `key_id`, `args_hash` (never raw
      args), duration, outcome, `prev_hash` chaining; 30-day rotation
      (configurable)
- [ ] Prometheus `/metrics`; `/health` and `/readyz` endpoints;
      optional Sentry via `ULTRANIX_MCP_SENTRY_DSN`
- [ ] Admin tools: `metrics`, `get_action_history`, `replay_action`,
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

`aes-gcm` (or `ring`), `metrics`/`prometheus` exporter crates, HTTP
middleware on the rmcp streamable-HTTP transport

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

- [ ] `uinput`/`evdev` `InputProvider` fallback for non-wlroots compositors,
      with a packaged, opt-in udev rule for `/dev/uinput`
      (`SUBSYSTEM=="uinput", MODE="0660", GROUP="ultranix-input"` — a
      dedicated group holding only the service user, never `input`)
- [ ] XDG Desktop Portal backend over `zbus`: `Screenshot` and
      `RemoteDesktop` portals (universal last resort)
- [ ] Nested-Hyprland integration test rig for real-Wayland CI
- [ ] AUR packages (`ultranix-mcp`, `ultranix-mcp-git`), `cargo install`
      support, systemd user unit, GitHub release binaries
- [ ] Distro notes covering non-Arch packaging requirements

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

## Post-v1 Ideas

Exploration backlog — not committed, priority by demand.

- **KDE/GNOME native backends** — KWin scripting and Mutter RemoteDesktop /
  gnome-shell providers behind the existing traits
- **X11 session support** — XCB/XTest input plus `scrot`/`xdotool`/`wmctrl`
  (already on the command whitelist) for legacy sessions
- **GPU EP acceleration** — extend `ort` beyond CPU to CUDA/OpenVINO/ROCm
  for interactive-latency icon finding
- **Broader wlroots coverage** — Sway, Wayfire, river via the same
  compositor protocols
- **Streaming capture** — continuous/region capture for remote-control UX
- **Headless operation** — running under a nested or headless compositor for
  CI and server-side automation
- **Clipboard tools** — `wl-copy`-backed clipboard read/write (post-v1)
- **Plugin tools** — third-party tool registration against the same typed
  schema contract

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
