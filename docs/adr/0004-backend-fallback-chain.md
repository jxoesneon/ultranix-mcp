# ADR 0004: Capability-Probed Backend Fallback Chains with Option-Degradation

- **Status:** Accepted
- **Date:** Phase 0 → refined through Phase 5
- **Deciders:** ultranix-mcp architecture council
- **Related:** ADR 0002 (input chain), ADR 0003 (`None` for AT-SPI2)

## Context

Linux desktop automation has no single API surface: capability depends on the
compositor family (wlroots vs. KWin/Mutter vs. X11), session type, device-node
permissions, and whether portal backends and the AT-SPI2 bus are running. Two
extremes were considered:

1. **Single-backend assumption** — target Hyprland only, fail hard elsewhere.
   Simple, but abandons every non-wlroots session and all X11 users.
2. **Runtime-selected backend per provider** — each of the six provider traits
   resolves independently at startup through a probe → fallback chain, landing
   on the best available implementation or `None`.

ultrawin already proved the `Option<Arc<dyn Trait>>` pattern: `main.rs` attempts
each engine, logs failures, and constructs the server with whatever resolved —
so a missing DXGI device or UIA failure degrades one capability, not the process.

Requirements:

- The server must **boot on any Linux session** — Hyprland, generic wlroots,
  KDE/GNOME Wayland, X11, even a bare Xvfb — and serve `tools/list` plus every
  tool whose providers resolved.
- Backend choice must be **capability-based**, not just env-name-based: a
  wlroots session missing `wlr-screencopy` globals must fall through to portal,
  not crash.
- Degradation must be **visible and structured**: `/readyz` reports which
  providers are `Some`, and tools on `None` providers return a typed
  capability-unavailable MCP error.

## Decision

- **Probe order at startup:** read `XDG_CURRENT_DESKTOP` +
  `HYPRLAND_INSTANCE_SIGNATURE` + `XDG_SESSION_TYPE`/`DISPLAY` to *order* the
  candidates, then attempt binding each backend in turn — actual protocol/device
  availability decides.
- **Per-provider fallback chains:**

  | Provider | Chain |
  | -------- | ----- |
  | Capture | `wlr-screencopy-unstable-v1` (in-process) → `grim`/`slurp` → portal `Screenshot` (zbus) → `scrot`/X11 *(post-v1)* → `None` |
  | Input | `zwlr_virtual_pointer_v1` + `virtual-keyboard-unstable-v1` → `/dev/uinput` evdev → portal `RemoteDesktop` → `xdotool` *(post-v1)* → `None` |
  | Window | `hyprctl` IPC socket → `wmctrl` (X11) *(post-v1)* → `None` |
  | UI Automation | AT-SPI2 via `atspi` → `None` |
  | Vision | `ort` ONNX: CPU EP → OpenVINO EP → CUDA EP → `None` |
  | Browser | CDP WebSocket `127.0.0.1:9222` → `None` |

  *Canonical chain table: [ARCHITECTURE.md](../ARCHITECTURE.md) §5 (Backend
  Detection & Fallback) — this ADR is the decision record; the architecture
  doc carries the live table.*

- **`None` is a first-class outcome.** A tool whose provider is `None` returns
  `ErrorData` with a capability-unavailable message naming the missing backend;
  the process never panics on absence.
- **Detection is one-shot at startup** in `src/backend/detect.rs`; the resolved
  registry is immutable for the process lifetime (re-probing is an admin-level
  concern, not a per-call cost).

## Consequences

**Positive:**

- **Maximum reach:** one binary serves Hyprland fast paths, generic Wayland via
  portal/uinput, and (post-v1) X11 via scrot/xdotool/wmctrl.
- **Honest failure modes:** `None` surfaces as a structured MCP error plus a
  `/readyz` signal, so agents and operators can see exactly which capabilities a
  session offers — no half-working tools.
- **Testability:** each chain element is a small `try_new() -> Result<Self>`;
  unit tests inject mocks directly, and integration tests exercise real chains
  (Hyprland, Xvfb, headless weston) per TESTING_STRATEGY.md.
- **Predictable hot path:** chains resolve once; per-call dispatch is a direct
  `Arc<dyn Trait>` invocation with zero probing overhead.

**Negative / accepted trade-offs:**

- **Chain maintenance:** each provider carries N implementations; a compositor
  or portal behavioral change is caught per-element, and matrix CI must cover
  the realistic permutations.
- **Probe latency at startup:** portal D-Bus checks can block; probes run
  concurrently with per-backend timeouts (~2s each) so startup stays <5s.
- **Capability skew between sessions:** the same tool behaves differently across
  environments (e.g., `get_windows` is rich on Hyprland, would be coarse under
  the post-v1 `wmctrl` rung); the tool contract documents per-backend
  fidelity differences.

**Follow-ups:**

- Emit a startup `tracing` table listing each provider's resolved backend (or
  `None`) — the single most useful support artifact.
- `/readyz` payload: `{ready: true, providers: {capture: true, input: true,
  window: false, ...}}` (booleans per provider, as shipped)
  consumed by the systemd unit's readiness story and CI smoke tests.
