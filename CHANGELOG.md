# Changelog

All notable changes to ultranix-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-15

### Added

- Phase 0 scaffold (delivered): Rust 2024 edition crate on `rmcp` with
  stdio and streamable-HTTP transports, provider-trait layer with mock
  providers, 32-tool schema registry, session detection, and `tracing`
  logging — see the `[Unreleased]` phase breakdown below for the full plan
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

## [Unreleased]

Planned scope for the initial **0.1.0** release, organized by delivery phase.
See [ROADMAP.md](ROADMAP.md) for per-phase deliverables, exit criteria, and
risk callouts.

### Phase 0 — Scaffold & Mocks

#### Added

- Project scaffold: Rust 2024 edition, `tokio` async runtime, `rmcp` (official
  `modelcontextprotocol/rust-sdk`) server core with native stdio and
  streamable-HTTP (`:3010`) transports
- Provider-trait layer (`src/traits.rs`): `CaptureProvider`, `InputProvider`,
  `UIAutomationProvider`, `WindowProvider`, `VisionProvider`,
  `BrowserProvider` — all injected as `Option<Arc<dyn Trait>>` for graceful
  degradation
- Mock providers for every trait, enabling the full tool surface to be tested
  on headless CI without a Wayland session
- Tool schema registry for the 32-tool surface with `--category=` filtering
  (`mouse`, `keyboard`, `vision`, `automation`, `admin`)
- Session detection via `XDG_CURRENT_DESKTOP` and
  `HYPRLAND_INSTANCE_SIGNATURE`
- `tracing`-based structured logging; data directory at `~/.ultranix-mcp/`
- CI pipeline: `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test`
- Specification documentation set: README, LICENSE (ISC), CHANGELOG, ROADMAP,
  CONTRIBUTING, CODE_OF_CONDUCT

### Phase 1 — Hyprland I/O

#### Added

- `CaptureProvider` backend: in-process `wlr-screencopy-unstable-v1` capture
  (`screenshot`, `screen_info`, `color_at`); `grim`/`slurp` fallback path
- `InputProvider` backend: `zwlr_virtual_pointer_v1` pointer control and
  `virtual-keyboard-unstable-v1` keyboard control — no root required on
  Hyprland (`mouse_click`, `mouse_double_click`, `mouse_move`,
  `mouse_get_position`, `mouse_scroll`, `mouse_drag`, `mouse_button_control`,
  `type_text`, `key_control`, `mouse_move_path`, `sleep`)
- `WindowProvider` backend: `hyprctl` IPC socket with `hyprctl -j` JSON
  (`clients`, `activewindow`, `dispatch`, `workspaces`) powering
  `get_windows`, `get_active_window`, `window_control`
- Security scaffolding — the server ships protected from day one: input
  sanitization (shell-metacharacter stripping, identifier validation);
  arg-constrained, absolute-path-pinned command whitelist for
  `system_command` (`grim`, `slurp`, `scrot`, `hyprctl` without `dispatch
  exec`/`exec-once`; `xdotool`/`wmctrl` X11-only); narrowed path whitelist
  (`$XDG_RUNTIME_DIR`, `/tmp`, `~/.ultranix-mcp/**`); JSONL audit skeleton
  (`key_id`, `args_hash`, `prev_hash` chaining); destructive-tool consent
  gate (`-32015 ConsentRequired` + `consent_token` retry;
  `--allow-destructive` bypass)

### Phase 2 — AT-SPI2 UI Automation

#### Added

- `UIAutomationProvider` backend over the AT-SPI2 accessibility bus via the
  `atspi` crate
- `get_ui_tree`, `get_focused_element`, `find_element`,
  `wait_for_ui_element`, `set_spatial_focus`, `screen_highlight`,
  `invoke_element`

### Phase 3 — Vision & Browser

#### Added

- `VisionProvider` backend on the `ort` crate (ONNX Runtime): OCR for
  `find_text_on_screen`, OWL-ViT zero-shot detection for `find_icon`; CPU
  execution provider by default, OpenVINO/CUDA behind cargo features
- `BrowserProvider` backend: CDP bridge on `127.0.0.1:9222` powering
  `web_query`

### Phase 4 — Enterprise Hardening

#### Security

- `uxcp_*` API-key authentication on the HTTP transport via
  `ULTRANIX_MCP_API_KEY` / `ULTRANIX_MCP_API_KEY_FILE` (fail-closed;
  `X-API-Key` canonical, `Authorization: Bearer` accepted);
  `ULTRANIX_MCP_DISABLE_AUTH=true` escape hatch (stdio never requires auth)
- Token-bucket rate limiting: 10 req/s per client
- AES-256-GCM-encrypted action history at `~/.ultranix-mcp/history.json`
  (per-install generated secret or `ULTRANIX_MCP_HISTORY_SECRET`)
- JSONL audit log at `~/.ultranix-mcp/logs/` covering every tool invocation
  — `key_id` + `args_hash` (never raw args) + `prev_hash` chaining; 30-day
  rotation (configurable)

#### Added

- Prometheus `/metrics` endpoint; `/health` and `/readyz` health endpoints
- `metrics`, `get_action_history`, `replay_action`, `clear_action_history`
  admin tools
- Optional Sentry error tracking via `ULTRANIX_MCP_SENTRY_DSN`

### Phase 5 — Portability & Packaging

#### Added

- `uinput`/`evdev` `InputProvider` fallback for non-wlroots sessions
  (documented, opt-in udev rule for `/dev/uinput`, `GROUP="ultranix-input"` —
  a dedicated group, never `input`)
- XDG Desktop Portal backend over `zbus`: `Screenshot` and `RemoteDesktop`
  portals as the universal last-resort path
- Nested-Hyprland integration test rig for end-to-end CI on real Wayland
- AUR packaging (`ultranix-mcp`, `ultranix-mcp-git`), `cargo install` path,
  systemd user unit, release binaries

---

## Version History

- **0.1.0** (unreleased): Initial release — verified target environment
  CachyOS (Arch) + Hyprland on Wayland, PipeWire,
  `xdg-desktop-portal-hyprland`, live AT-SPI2 bus, Rust 1.98.1

---

## Support

- **Issues**: [GitHub Issues](https://github.com/jxoesneon/ultranix-mcp/issues)
- **Security**: See [SECURITY.md](SECURITY.md)
- **Documentation**: [docs/](docs/)
