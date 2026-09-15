# ADR 0001: Rust 2024 + rmcp as the Implementation Substrate

- **Status:** Accepted
- **Date:** Phase 0 (project scaffold)
- **Deciders:** ultranix-mcp architecture council
- **Supersedes:** ultramac's TypeScript/Bun + FastMCP substrate (for the Linux sibling only)

## Context

ultranix-mcp is the Linux sibling of two existing desktop-automation MCP servers:

- **ultramac-mcp** — TypeScript on Bun, FastMCP framework, mature and feature-rich,
  but tied to a garbage-collected runtime and npm distribution.
- **ultrawin-mcp** — Rust rewrite proving the trait-provider architecture
  (`Option<Arc<dyn Trait>>` dependency injection, per-capability degradation), but
  built on `mcp-sdk-rs` — a community MCP crate — plus a hand-rolled
  `lsp_transport.rs` for JSON-RPC framing.

The Linux sibling must choose a language/runtime and an MCP SDK. Constraints:

- Desktop automation is latency-sensitive (click dispatch <10ms, screenshot <50ms)
  and interface-heavy at the syscall boundary (Wayland protocols, evdev ioctls,
  D-Bus, Unix sockets).
- The server must run as a per-user systemd service with a small resident footprint.
- Hermetic unit tests require trait-based mocking — ultrawin's `server.rs` test
  module (MockCapture/MockUIA/MockInput/MockVision/MockBrowser) demonstrated the
  pattern works.
- The MCP ecosystem's Rust SDK landscape has consolidated: `rmcp`
  (`modelcontextprotocol/rust-sdk`) is the official SDK and ships maintained
  stdio and streamable-HTTP transports, eliminating the need to own JSON-RPC
  framing code.

Alternatives considered:

1. **TypeScript/Bun + FastMCP (ultramac parity)** — maximal doc/tool parity, but
   adds a second runtime to a Wayland/evdev/ioctl codebase where every
   dependency (screencopy, uinput, zbus, ort) already has mature Rust crates.
2. **Rust + mcp-sdk-rs (ultrawin parity)** — proven in-family, but requires
   maintaining a bespoke transport and tracks the spec less closely than the
   official SDK.
3. **Rust + rmcp** — official SDK, spec-aligned, transports included.

## Decision

- Implement ultranix-mcp in **Rust, 2024 edition**, on the **tokio** runtime
  (verified toolchain: Rust 1.98.1).
- Use **`rmcp`** as the MCP SDK with **stdio + streamable-HTTP on `:3010`**
  transports — no hand-rolled transport code.
- Retain ultrawin's **trait-provider architecture** (`CaptureProvider`,
  `InputProvider`, `UIAutomationProvider`, `WindowProvider`, `VisionProvider`,
  `BrowserProvider`) injected as `Option<Arc<dyn Trait>>`.

## Consequences

**Positive:**

- Zero-GC, predictable latency for the input-dispatch hot path; single static
  binary distribution (no runtime install) fits the systemd `--user` deployment.
- rmcp provides spec-conformant `tools/list`/`tools/call` handling, typed
  `CallToolResult`, and maintained streamable-HTTP — deleting ultrawin's
  `lsp_transport.rs` and the associated maintenance surface.
- `Option<Arc<dyn Trait>>` DI carries over directly: mock providers give ≥90%
  coverage without a display server; missing backends degrade to `None`.
- Full access to the Linux-native crate ecosystem: `wayland-client`,
  `wayland-protocols-wlr`, `zbus`, `atspi`, `evdev`, `ort`, `tokio-tungstenite`.

**Negative / accepted trade-offs:**

- Divergence from ultramac's TypeScript codebase — tool *names* and *schemas*
  are kept in snake_case parity (ADR 0006), but implementation sharing is
  impossible; bug fixes don't flow between siblings.
- rmcp is younger than FastMCP; macro-generated schemas must be audited against
  golden `tools/list` fixtures in CI (see TESTING_STRATEGY.md).
- Rust compile times slow the iterate-test loop vs. Bun; mitigated by the mock
  layer making most tests display-free and `cargo check`-friendly.

**Follow-ups:**

- Pin rmcp version in `Cargo.toml` at Phase 0 and add a renovate-style bump gate
  that runs the protocol golden tests.
- Document the `tools/call` error mapping (provider `None` → structured
  capability-unavailable error) in the tool-router contract.
