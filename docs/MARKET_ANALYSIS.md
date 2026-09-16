# ultranix-mcp — Market Analysis

**Product scope:** ultranix-mcp — a Model Context Protocol (MCP) server for
Linux desktop automation (mouse, keyboard, screen capture, OCR/vision,
window management, semantic UI inspection) built on Rust 2024 + the `rmcp`
SDK, Wayland-native with a Hyprland-first backend ladder.

**Position:** the Linux sibling of `ultramac-mcp` (macOS, TypeScript) and
`UltraWin-MCP` (Windows, Rust) — completing a tri-OS, single-governance-model
desktop-automation family.

> **Confidence note.** Sibling-project facts come from direct codebase review
> of ultramac/ultrawin. Ecosystem figures reuse the mid-2026 MCP landscape
> synthesis from `ultramac/docs/MARKET_ANALYSIS.md`; treat counts as
> directional estimates, not investment-grade sizing.

---

## 1. Executive summary

- The MCP ecosystem is the de-facto standard for letting agents act on
  desktops (97M+ monthly SDK downloads; 12k–21k unique public servers), and
  the **desktop-automation niche is proven** by Playwright-MCP (~33k⭐) and
  chrome-devtools-mcp (~40k⭐).
- That niche is contested on **macOS** (Peekaboo, ToolPiper, LMCP),
  **Windows** (UltraWin, community servers) — **and Linux**: real
  Wayland-capable MCP servers already ship, led by **hypruse** on Hyprland
  (PyPI-listed, with AT-SPI `click_ui` actions) plus kde-mcp, screen-mcp,
  gnome-ui-mcp, linux-desktop-mcp, and smaller community servers. What none
  of them combines is a cross-compositor capability-probed fallback ladder,
  a governance surface (auth/audit/encryption/consent), and a tri-OS
  sibling tool contract. **Contested but differentiated** is the honest
  frame — the win condition is the bundle, not being first to the platform.
- Wayland broke the old automation stack (`xdotool`/`scrot` do not work
  under Wayland compositors), and the fragmentation (per-compositor
  protocols, portals, a11y variance) kept what did ship single-compositor.
  **That fragmentation is still the moat**: whoever solves the backend
  ladder correctly owns the category.
- ultranix-mcp's positioning: **the first Linux desktop MCP combining a
  cross-compositor capability-probed fallback ladder, a full governance
  surface (auth/audit/encryption/consent), and a tri-OS sibling tool
  contract** — compositor protocols where they exist (Hyprland needs *zero*
  privilege), portal/uinput fallbacks everywhere else, AT-SPI2 for
  deterministic semantic targeting (`invoke_element` ships at v1.0.0), and
  the Ultra\*-family governance surface (audit JSONL, `uxcp_*` auth, rate
  limiting, AES-256-GCM history, Prometheus).

---

## 2. Landscape

Axes: **Wayland-native** (works without XWayland, no root), **Hyprland IPC
depth** (window/workspace ops via `hyprctl` socket), **security layers**
(auth, rate limit, sanitization, audit, encryption), **enterprise
observability** (Prometheus, SIEM-able logs), **AT-SPI semantic UI**
(deterministic element targeting vs pure-vision clicking).

| Server / approach | Wayland-native | Hyprland IPC | Security layers | Observability | AT-SPI semantic UI | Notes |
| --- | :-: | :-: | :-: | :-: | :-: | --- |
| **ultranix-mcp** (this) | ✅ wlr protocols + portal + uinput | ✅ `hyprctl` + `sway-ipc` + `wayfire-ipc` + `gnome-shell` (Window Calls) + `kdotool` + `wmctrl`, window/workspace control (river is a focused-view-only rung — no list IPC) | ✅ auth/bucket-limit/sanitize/arg-constrained whitelists/AES-256-GCM/audit/consent gate | ✅ Prometheus + audit JSONL | ✅ AT-SPI2 (Phase 2, incl. `invoke_element`) + ONNX vision fallback | Rust 2024, `rmcp`, 40 snake_case tools in 6 categories (+ dynamic plugin-exposed tools), stdio + HTTP :3010 |
| **ultramac-mcp** (macOS sibling) | n/a | n/a | ✅ `umcp_*`, rate limit, sanitize, AES-256-GCM, audit | ✅ Prometheus, Winston logs | ✅ macOS AX tree + OCR/icon-find | Proves the governance model; TypeScript/Bun |
| **UltraWin-MCP** (Windows sibling) | n/a | n/a | ✅ `uwcp_*` keys, audit, encrypted history | ✅ metrics | ✅ UIA3 cached tree | Proves the Rust trait-provider architecture ultranix-mcp adopts |
| **hypruse** (IlyasKhallouki/hypruse) | ✅ `zwlr_virtual_pointer` + `wtype` + `grim` | ✅ `hyprctl` IPC window ops | ❌ none — no auth, audit, rate limit, encryption | ❌ | ✅ AT-SPI via `busctl`, incl. `click_ui` element actions | **Direct incumbent on the Hyprland wedge** — PyPI-listed; already ships AT-SPI actions and cursor-position workarounds; Hyprland-only, no governance |
| **kde-mcp** (atassis) | ✅ Plasma Wayland | ❌ KDE-scoped | ❌ | ❌ | ✅ AT-SPI-first | Rust; KDE/Plasma only, no fallback ladder or governance |
| **screen-mcp** (88plug) | ✅ GNOME portal RemoteDesktop + PipeWire | ❌ | ❌ | ❌ | ⚠️ ONNX/OmniParser visual grounding (not AT-SPI) | GNOME-oriented portal path; no governance |
| **gnome-ui-mcp** (asattelmaier) | ✅ Mutter RemoteDesktop | ❌ | ❌ | ❌ | ✅ AT-SPI discovery + activation | GNOME-only; no governance |
| **linux-desktop-mcp** (BeckhamLabsLLC) | ⚠️ X11 + Wayland | ❌ | ❌ | ❌ | ✅ AT-SPI2 element refs | Cross-session coverage without the probed ladder or governance |
| **linux-control-mcp** | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | Community desktop-control server |
| **desk-mcp** | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | Community desktop server |
| **Peekaboo** (macOS) | n/a | n/a | ❌ | ❌ | ✅ AX-driven see/click | The focused-screen-automator benchmark (4.7k⭐); no Linux build, no governance |
| **xdotool/scrot/wmctrl community MCP wrappers** | ❌ X11 only (dead under Wayland) | ❌ | ❌ none — no auth, no audit, no rate limit | ❌ | ❌ pure coordinates/screenshot | The incumbent pattern; breaks on the fastest-growing Linux desktop segment |
| **KDE/GNOME-specific scripts** (qdbus, gdbus, kdotool, wtype, grim) | ⚠️ partial — compositor-locked | ❌ single-DE each | ❌ | ❌ | ⚠️ GNOME has a11y; scripts don't expose it to agents | Fragmented per-DE glue; none is an MCP server with a security model |
| **ydotool / uinput DIY daemons** | ⚠️ input only | ❌ | ❌ needs root or `input` group | ❌ | ❌ | Injection-only; no capture, no windows, no tools |
| **Anthropic "computer use" (X11 reference)** | ❌ ships X11 VM | ❌ | ⚠️ sandbox-by-VM only | ❌ | ❌ pure-vision screenshot loop | Validated demand but heavyweight: full VM + vision-only + X11 |
| **Browser MCPs** (playwright-mcp, chrome-devtools-mcp) | n/a (browser sandbox) | n/a | ⚠️ | ⚠️ | DOM (better than a11y, but browser-only) | Category bellwethers; ultranix-mcp's CDP bridge *borrows* their strength instead of competing |

**Reading the table:** the Linux field is no longer empty — **hypruse is a
real incumbent on the Hyprland wedge** (Wayland input, `hyprctl` IPC, AT-SPI
`click_ui` actions, PyPI distribution), and single-DE servers already cover
KDE (`kde-mcp`) and GNOME (`gnome-ui-mcp`, `screen-mcp`). What remains
unclaimed is the *bundle*: no competitor pairs a cross-compositor,
capability-probed fallback ladder with a governance surface (auth, rate
limit, sanitization, arg-constrained whitelists, AES-256-GCM history, JSONL
audit, Prometheus, consent gate) *and* a tri-OS sibling tool contract. The
siblings prove both halves of ultranix-mcp's design: ultramac proves the
governance surface sells; UltraWin proves the Rust trait-provider backend
ladder architecture.

---

## 3. Why the differentiated opening exists

1. **Wayland reset the board.** `xdotool`/`scrot`/`wmctrl` — the entire
   scriptable-desktop canon — do not function under Wayland. Incumbent
   "Linux desktop automation" repos are quietly X11-fossils; their MCP
   wrappers inherit the limitation.
2. **Fragmentation tax.** Correct Linux coverage needs a *ladder*:
   wlr protocols → portal → uinput → X11 (scrot/xdotool/wmctrl, shipped at
   v1.1.0) — plus per-compositor
   IPC. That is
   real engineering (a trait-provider architecture like UltraWin's), not a
   weekend wrapper — which is why the servers that *did* ship
   (hypruse, kde-mcp, gnome-ui-mcp, screen-mcp) are each locked to one
   compositor or one mechanism instead of probing and degrading.
3. **Security asymmetry.** macOS agents got Peekaboo-without-governance and
   ultramac-with-governance; on Linux, every shipped server — hypruse
   included — has no auth, no audit, no rate limit, no encrypted history.
   Enterprise buyers who would never run an unaudited input injector now
   have a compliant option.
4. **Hyprland's rise.** The ricing/WM community skews exactly toward
   early-adopter MCP users (Arch/CachyOS, terminal-centric, agentic
   workflows). Hyprland-first is still the right wedge — but it is *held*,
   not open: hypruse already ships `hyprctl` IPC depth, wlr input, and
   AT-SPI actions there. The differentiation must therefore be the ladder
   plus governance, not Hyprland support alone.

---

## 4. Competitive threats & honest weaknesses

- **hypruse is still ahead on some semantic-action ergonomics.** ultranix-mcp
  v1.0.0 ships `invoke_element` (AT-SPI action invocation) and
  `mouse_get_position` (via `hyprctl cursorpos` on Hyprland,
  `ProviderUnavailable` elsewhere), closing the Phase-2 gap — but
  hypruse's cursor-position workarounds and element-action depth remain
  the reference to beat. The counters that differentiate are the
  governance surface and the cross-compositor ladder.
- **Pure-vision commoditization.** If "computer use" models get good enough
  to click screenshots blind, semantic-UI advantage shrinks. Counter:
  ultranix-mcp keeps both — ONNX `ort` vision *and* AT-SPI2 — and
  deterministic targeting + auditability matter to enterprises regardless.
- **Portal consent UX.** On GNOME/KDE the `Screenshot`/`RemoteDesktop`
  portals prompt on first use (per portal token lifetime); a poor first-run
  experience could sour users vs the zero-prompt Hyprland path. Mitigate
  with clear startup probe logging, `/readyz` provider reporting, and token
  persistence (see `docs/PACKAGING.md` §5).
- **Compositor coverage reality.** "Linux" is N compositors; the session
  detector resolves Hyprland/sway/Wayfire/river/KDE/GNOME with the wlroots
  `wlr-*` rungs shared across the family, and every compositor now has its
  window rung: `hyprctl`, `sway-ipc`, `wayfire-ipc` (`$WAYFIRE_SOCKET`),
  `riverctl` (river — focused-view-only rung: no list IPC, so
  `get_windows`/`get_active_window` return `isError` results while
  `window_control` drives the focused view), `gnome-shell` (Window Calls
  extension required), `kdotool` on KDE, and `wmctrl` on X11 —
  portal-routed capture/input still covers KDE/GNOME Wayland. Still do
  not overclaim in launch messaging — non-Hyprland
  paths are implemented + hermetically tested; only Hyprland/wlr has live
  smoke evidence.
- **No community signal yet** — same pre-distribution state ultramac
  documented. All value is currently latent.
- **Copycat risk is low but real** — a compositor vendor (e.g. a KDE/GNOME
  project) could ship an official MCP; the defense is the cross-compositor
  ladder + governance surface, which a single-DE tool won't replicate.

---

## 5. Positioning statement

> **ultranix-mcp is the first Linux desktop MCP combining a
> cross-compositor capability-probed fallback ladder, a full governance
> surface (auth, audit, encryption, consent), and a tri-OS sibling tool
> contract.** It gives MCP clients real control of a Linux session —
> compositor-grade input injection and capture on Hyprland with zero
> privilege, portal/uinput fallbacks on GNOME/KDE, AT-SPI2 semantic
> targeting plus ONNX vision — wrapped in the enterprise governance surface
> (API keys, rate limiting, sanitization, AES-256-GCM history, JSONL audit,
> Prometheus) proven by its macOS and Windows siblings. Individual
> competitors beat single axes — hypruse on Hyprland depth, kde-mcp /
> gnome-ui-mcp on their DEs — but no single one offers the bundle.

Tagline: *"Peekaboo for Linux, built like an enterprise product."*

---

## 6. Market sizing & audience

The addressable audience is the intersection of three growing sets:
**Linux desktop developers** (~3–5% of the ~28M+ professional developers
worldwide, over-indexed in infra/security/AI roles — the exact teams buying
agentic tooling), **MCP client users** (every Claude/Cursor/Windsurf user is
a potential installer; desktop automation is a top-5 MCP category by
registry traffic), and **the tiling-WM community** (Hyprland alone sustains
a large, vocal, Arch-centric user base that drives early adoption and
content). This is a **contested-but-differentiated** market, not a
greenfield: installs are earned against hypruse and the single-DE servers on
capability coverage, and against the whole field on governance — the
audience above is the pool, not a captured base. Realistic near-term TAM:
**tens of thousands of individual installs** on the OSS tier; the
enterprise tier targets the smaller set of
organizations standardizing Linux workstations/VDI for AI-augmented dev
teams — where governance, not tool count, is the buying criterion. Pricing
bands follow the family analysis: free OSS core; **$19–49/mo enterprise**
(priority support, policy knobs, audit-export, per-key scoping) once the
post-v1 policy surface lands — the v1.0.0 governance core (auth, consent,
audit, rate limiting) is already shipped.

---

## 7. Adoption strategy (0–6 months)

1. **Own the Arch channel.** Publish `ultranix-mcp`, `-bin`, `-git` to the
   AUR at Phase-1 release (`docs/PACKAGING.md` §3) — the target user lives
   on `pacman -S`/`paru`, not npm.
2. **Registry sweep.** Submit to the official MCP Registry, PulseMCP, Glama,
   Smithery, mcp.so, and `awesome-mcp-servers` — the distribution funnel
   ultramac's analysis proved is highest-ROI.
3. **Hyprland community seeding.** Presence where the users are: Hyprland
   Discord/forums, r/hyprland, CachyOS community channels, dotfiles repos.
   Demo asset: a screen recording of an agent driving a real Hyprland
   session with zero privilege and a live `audit.jsonl` tail.
4. **Family cross-promotion.** Link the tri-OS story in all three READMEs —
   "one governance model across macOS/Windows/Linux" is a differentiator
   none of the single-OS competitors can claim.
5. **Docs-as-marketing.** The runtime permission matrix
   (`docs/PACKAGING.md` §5), the provider fallback chains, and the honest
   Wayland-portability story are the content that earns trust in this
   audience.
6. **Enterprise lane.** The governance docs + SIEM snippets are shipped
   (`docs/ENTERPRISE_PLAN.md` §5); the SOC2-posture language differentiates
   against every Linux alternative even before the paid tier exists.

---

## 8. Key metrics

- AUR popularity/votes, crates.io weekly downloads, release-asset hits.
- Registry listings count + referral traffic; `awesome-mcp` merge.
- Community: Hyprland/Arch channel mentions, stars, third-party dotfiles
  adopting the service unit.
- Enterprise: policy-knob feature requests (leading indicator of post-v1
  pull), SIEM-config questions, read-only-mode deployments.

---

*Companion to `docs/PACKAGING.md` (distribution) and
`docs/ENTERPRISE_PLAN.md` (governance). Ecosystem figures inherited from
`ultramac/docs/MARKET_ANALYSIS.md` — verify before external citation.*
