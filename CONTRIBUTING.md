# Contributing to ultranix-mcp

Thank you for your interest in contributing! ultranix-mcp is a Rust 2024
Model Context Protocol server for Wayland-native Linux desktop automation.
This guide covers the development environment, testing pattern, and review
conventions.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be
respectful, inclusive, and constructive.

## Development Environment

### Prerequisites

- **Rust 1.98+**(2024 edition) via [rustup](https://rustup.rs/) - verified
  toolchain: 1.98.1
- **A Wayland session for live testing**- Hyprland is the verified target
  (CachyOS/Arch). A *nested* Hyprland instance is sufficient for most
  integration work: run `Hyprland` inside your session to get an isolated
  compositor with its own `HYPRLAND_INSTANCE_SIGNATURE`.
- **AT-SPI2 accessibility bus**- `org.a11y.Bus` on the session bus
  (required for `get_ui_tree`, `find_element`, and friends)
- **Session tools**used by backends and `system_command`: `hyprctl`,
  `grim`, `slurp`
- **Optional**:
  - `wl-clipboard` (`wl-copy`/`wl-paste`) - clipboard tools on Wayland
    (v1.2.0+); `xclip`/`xsel` - clipboard tools on X11/XWayland
  - `xdg-desktop-portal-hyprland` - portal fallback backend
  - `/dev/uinput` access (udev rule granting the dedicated
    `ultranix-input` group - never the broad `input` group) - uinput/evdev
    fallback backend
  - A Chromium-family browser with `--remote-debugging-port=9222` -
    `web_query` / `BrowserProvider`
  - ONNX Runtime libraries - only when building with vision features

> **No Wayland session?**All unit tests run against mock providers and pass
> on a headless CI box. You can meaningfully contribute without a desktop.

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/ultranix-mcp.git
cd ultranix-mcp
cargo build
cargo test
./target/debug/ultranix-mcp --transport stdio   # `--stdio` works as an alias
```

## Commands

```bash
cargo build                          # debug build
cargo build --release                # release binary at target/release/ultranix-mcp
cargo test                           # full test suite (mock providers, no Wayland needed)
cargo clippy --all-targets -- -D warnings   # lints - CI enforces zero warnings
cargo fmt --check                    # formatting - run `cargo fmt` to apply
cargo doc --no-deps                  # API docs
ultranix-mcp --transport stdio --category=mouse,keyboard   # narrow the tool surface
```

Live-session tests (real Hyprland, real AT-SPI bus) are gated behind the
`ULTRANIX_MCP_LIVE_TESTS=1` environment variable and skipped automatically
when no compositor is detected.

## The Mock-Provider Testing Pattern

Every OS capability lives behind a provider trait in `src/traits.rs`
(`CaptureProvider`, `InputProvider`, `UIAutomationProvider`,
`WindowProvider`, `VisionProvider`, `BrowserProvider`). The server holds
each as `Option<Arc<dyn Trait>>`.

**Rules for new code:**

1. **Tools never talk to the OS directly.**A tool handler calls a provider
   trait; a `None` provider must produce a structured
   provider-unavailable error, never a panic.
2. **Every trait ships a `Mock*` implementation.**New trait methods need a
   mock counterpart in the same PR.
3. **Unit tests inject mocks.**Construct the tool/server with mock
   providers and assert on recorded calls - no Wayland connection, no
   `hyprctl`, no D-Bus.
4. **Live tests are opt-in.**Put compositor/bus-dependent assertions behind
   `ULTRANIX_MCP_LIVE_TESTS=1` or a nested-compositor fixture.
5. **Degradation is tested.**At least one test per provider covers the
   `None` path.

## Contribution Workflow

### 1. Create a branch

```bash
git checkout -b feature/my-feature
```

**Branch naming:**`feature/` new features - `fix/` bug fixes -
`docs/` documentation - `refactor/` restructuring - `test/` test
improvements

### 2. Make changes

- `tokio` for all async work; offload CPU-bound work (image processing,
  inference) to a blocking pool
- Avoid `unsafe`; where Wayland/evdev FFI makes it unavoidable, isolate and
  document it
- Structured errors via `thiserror`/`anyhow` - sanitize before returning to
  the client (no stack traces, no absolute paths)

### 3. Architecture Decision Records

Non-trivial design decisions get an ADR under `docs/adr/`. **Required**
for: changes to the backend priority ladder (wlroots-native -> uinput/evdev
-> portal), the provider-trait surface, the tool schema, or the security
model (auth, whitelists, encryption).

File naming: `docs/adr/NNNN-short-title.md` (next sequential number).

Template:

```markdown
# NNNN. Short title

- Status: proposed | accepted | superseded by NNNN
- Date: YYYY-MM-DD

## Context
What forces the decision?

## Decision
What was decided?

## Consequences
What becomes easier/harder? What was rejected and why?
```

### 4. Test, lint, document

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Update docs with the change: new tool -> README tool reference +
CHANGELOG; schema/API change -> ADR + docs; security-surface change ->
SECURITY.md.

### 5. Commit

Conventional Commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat` `fix` `docs` `style` `refactor` `test` `chore`.
Scopes: `traits` `providers` `tools` `security` `server` `docs`.

Example:

```bash
git commit -m "feat(providers): add uinput InputProvider fallback

- Implement InputProvider over evdev/uinput
- Gate on /dev/uinput access; document udev rule
- Add MockInputProvider coverage for None path

Closes #42"
```

### 6. Pull request

PR checklist:

- [ ] `cargo test` green (including mock coverage for changed traits)
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo fmt` applied
- [ ] ADR included if the change touches architecture/security decisions
- [ ] Documentation updated; CHANGELOG entry for user-facing changes
- [ ] Commit messages follow convention

Reviews require at least one maintainer approval; CI must pass; squash
merge by maintainer.

## Project Structure (planned)

```
ultranix-mcp/
├── src/
│   ├── main.rs            # binary entry: transports, CLI flags, bootstrap
│   ├── server.rs          # rmcp server wiring, tool dispatch
│   ├── traits.rs          # the eight provider traits
│   ├── providers/         # backend implementations (wlroots, uinput, portal...)
│   ├── tools/             # one module per tool category (+ clipboard, plugin, record)
│   ├── plugins.rs         # plugin tool-macro manifest store (v1.2.0)
│   └── security/          # auth, rate limiting, sanitization, audit, history
├── tests/                 # integration + live-session tests
├── docs/
│   └── adr/               # architecture decision records
└── Cargo.toml
```

## Security

**Always:**sanitize tool input, respect the arg-constrained,
absolute-path-pinned command whitelist (`grim`, `slurp`, `scrot`, `hyprctl`
without `dispatch exec`/`exec-once`; `xdotool`/`wmctrl` X11-only) and path
whitelist (`$XDG_RUNTIME_DIR`, `/tmp`, `~/.ultranix-mcp/**`), keep the
destructive-tool consent gate (`-32015 ConsentRequired` + `consent_token`)
intact, and log security events to the audit log (`key_id` + `args_hash`,
`prev_hash`-chained - never raw args).

**Never:**execute arbitrary shell commands, trust client input, expose
stack traces to clients, commit API keys or `history.json`, or disable
security features silently.

**Reporting vulnerabilities:**do not open public issues - follow the
process in [SECURITY.md](SECURITY.md).

## Getting Help

- **Questions**: GitHub Discussions
- **Bugs**: GitHub Issues (environment, `ultranix-mcp --version`, steps to
  reproduce, expected vs. actual)
- **Security**: [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions are licensed under the
[ISC License](LICENSE).

---

**Thank you for contributing!**
