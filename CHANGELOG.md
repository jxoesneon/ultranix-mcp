# Changelog

All notable changes to ultranix-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-15

First stable release — the union of [0.1.0]–[0.5.0] plus the Council-of-Five
audit remediation pass that closed the remaining spec-vs-implementation
drift before tagging.

### Added

- `capabilities.ultranix` extension block on `initialize`
  (`toolSurfaceVersion`, enabled `categories`, live `providers`,
  `features`) and `result._meta` server identity on every `tools/call`
  (docs/API_VERSIONING.md contract is now emitted).
- Authenticated HTTP `key_id` propagates to the tool layer via request
  extensions — consent tokens bind `{key_id, tool, args_hash}` and audit
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
- `security::spawn` — every subprocess (whitelist exec + provider
  helpers) runs env-scrubbed on a pinned, once-resolved absolute path
  with a bounded wait; stdout drained concurrently to avoid pipe
  deadlock.

### Fixed

- Error taxonomy aligned to the documented codes: `-32003`
  (command/arg whitelist), `-32004` (path), `-32006` (sanitize),
  `-32015` (consent), `-32016` (element not found) — `-32020` is gone.
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
- Rate-limit rejection metric label renamed `category` → `reason`
  (`auth`/`rate_limit` values).

### Scope notes (honest limitations)

- `screen_highlight` validates arguments then returns `-32010
  ProviderUnavailable` (`OverlayProvider` absent); the layer-shell
  overlay is post-v1.
- `ULTRANIX_MCP_SENTRY_DSN` is documented but not wired (planned, post-v1).
- Portal `RemoteDesktop` is input-only — the granted PipeWire stream is
  deliberately not consumed.
- X11-native providers (`xdotool`/`wmctrl`/`scrot` backends) are post-v1;
  the whitelist entries for them apply to `system_command` on X11
  sessions only.
- The unsecured `call_tool` path retains a labelled `phase0_stub`
  `system_command` response — production always attaches a
  `SecurityContext`, so real exec is the production path.

## [0.5.0] — 2026-09-15

### Added

- HTTP security gate on `/mcp`: `ApiKeyStore` (`uxcp_*` keys; env →
  file → `~/.ultranix-mcp/api-keys/` precedence; sha256-digest store,
  constant-time compare, expiry + `rotate(grace)`, `0600`-enforced key
  files; `ULTRANIX_MCP_DISABLE_AUTH` dev hatch) → 401, and a
  token-bucket `RateLimiter` (10 rps / 20 burst per `key_id` or remote
  addr) → 429. `/health`, `/readyz`, `/metrics` open on loopback.
- `HistoryStore` — AES-256-GCM-encrypted action history at
  `history.json` (`ULTRANIX_MCP_HISTORY_SECRET` or generated 0600
  `history.key`; ULID ids, 10k FIFO cap, `type_text` arg redaction,
  atomic writes). Lazy `SecurityContext::history()` scopes the store to
  the context's state root.
- Real admin tools: `get_action_history`, `replay_action` (exactly-one
  selector, consent re-challenge through `call_tool_secured`),
  `clear_action_history`; `metrics` now serves the live Prometheus
  exposition.
- `metrics.rs` — dependency-free Prometheus registry:
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

## [0.4.0] — 2026-09-15

### Added

- `OnnxVision` — `VisionProvider` on `ort` 2.0-rc (ONNX Runtime,
  prebuilt CPU EP; `vision-cuda`/`vision-openvino` cargo features):
  RapidOCR `ch_PP-OCRv4` det+rec pipeline for `find_text_on_screen`
  (connected-components det, CTC greedy decode over
  `ppocr_keys_v1.txt`) and quantized OWL-ViT-base for `find_icon`
  (sigmoid + cxcywh→xyxy + NMS). Models download on first use into
  `~/.ultranix-mcp/models/` with pinned URL+sha256, `.part` temp +
  atomic rename + `0600`.
- `CdpBrowser` — `BrowserProvider` on Chrome DevTools Protocol
  (`tokio-tungstenite`, loopback `127.0.0.1:9222` only):
  `query_selector` via `Runtime.evaluate` with JSON-encoded selector
  (no string splicing), debugger-URL loopback revalidation, lazy
  reconnect. Hermetic WS/HTTP stub test suite.
- `VisionBackend::Onnx` + `BrowserBackend::Cdp` detection rungs —
  all six provider slots now have real backends.

## [0.3.0] — 2026-09-15

### Added

- `AtspiUi` — `UIAutomationProvider` on AT-SPI2 (`atspi` 0.30 / zbus 5):
  `get_ui_tree` (5000-node-capped serialized tree: role/name/states/
  bounds/children), `get_focused_element`, `find_element`
  (`role:`/`name:`/`desc:`/`path:` query prefixes → screen bounding
  rect), `wait_for_ui_element`, `invoke_element` (Action do_action(0)).
  Lazy zbus connection bound to the server runtime; session-agnostic
  rung applied on Wayland and X11. Live-verified against the real
  a11y bus; `invoke_element` never exercised live.
- `UinputInput` — `/dev/uinput` evdev `InputProvider` fallback
  (display-agnostic): EV_ABS absolute pointer moves, REL wheel scroll
  with sub-detent accumulator, full `key_binding` table (chars, mods,
  nav, keypad, F1–F24, media), probe-only `new()`; udev rule expects
  dedicated `ultranix-input` group.
- `UiAutomationBackend::Atspi` rung in `backend::detect`
  (`Wlr → Grim`, `Wlr → UInput`, `Hyprctl`, `Atspi` ladders).

## [0.2.0] — 2026-09-15

### Added

- Hyprland I/O backends (live-verified on CachyOS/Hyprland):
  `WlrCapture` (in-process wlr-screencopy → PNG), `GrimCapture`
  fallback, `WlrInput` (zwlr_virtual_pointer_v1 +
  zwp_virtual_keyboard_v1 with uploaded XKB keymap), and
  `HyprctlWindow` (IPC socket / `hyprctl -j` window control)
- `backend::detect` — session probing (`XDG_SESSION_TYPE`,
  `XDG_CURRENT_DESKTOP`, `HYPRLAND_INSTANCE_SIGNATURE`) with the
  wlroots-native → uinput → portal fallback ladder
- `security/` scaffolding: input sanitization, arg-constrained +
  startup-pinned command whitelist (`grim`/`slurp`/`hyprctl`/`scrot`/
  `xdotool`/`wmctrl`), canonicalized path whitelist, CSPRNG consent gate
  (`-32015 ConsentRequired`, 60 s single-use tokens bound to
  caller+tool+args_hash+resolved target), hash-chained JSONL audit log,
  `0700` capture dirs with `O_NOFOLLOW` server opens
- `state.rs` — `~/.ultranix-mcp/` bootstrap (canonical root, `0700`)
- `system_command` real exec: pinned binaries, no shell, 15 s timeout,
  64 KiB output truncation
- `--allow-destructive` and `--mock` CLI flags

### Fixed

- `delegate_noop!` panics on event-emitting Wayland objects (`wl_seat`,
  `zwp_virtual_keyboard_v1`, `wl_shm`) — replaced with swallowing
  `Dispatch` impls
- wlr-screencopy `ready` race: fixed-count roundtrips → 5 s deadline loop

## [0.1.0] — 2026-09-15

### Added

- Phase 0 scaffold (delivered): Rust 2024 edition crate on `rmcp` with
  stdio and streamable-HTTP transports, provider-trait layer with mock
  providers, 32-tool schema registry, session detection, and `tracing`
  logging — see [ROADMAP.md](ROADMAP.md) for the per-phase plan
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

- **1.0.0** (in progress): First stable release — all six delivery phases
  landed across 0.1.0–0.5.0.
- **0.1.0–0.5.0** (2026-09-15): Phase-by-phase delivery on the verified
  target environment — CachyOS (Arch) + Hyprland on Wayland, PipeWire,
  `xdg-desktop-portal-hyprland`, live AT-SPI2 bus, Rust 1.98.1.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/jxoesneon/ultranix-mcp/issues)
- **Security**: See [SECURITY.md](SECURITY.md)
- **Documentation**: [docs/](docs/)
