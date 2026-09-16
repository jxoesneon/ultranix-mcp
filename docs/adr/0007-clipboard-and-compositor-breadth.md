# ADR 0007: Clipboard Provider, Compositor Breadth, and Per-Backend Cargo Features

- **Status:**Accepted
- **Date:**v1.2.0 wave
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0004 (fallback chains), ADR 0006 (tool categories)

## Context

Three post-v1.1 roadmap items share one architectural seam - the provider
registry and backend ladders:

1. **Clipboard tools.**`ultramac`/`ultrawin` expose clipboard read/write;
   Linux has no clipboard API - only `wl-clipboard`, `xclip`/`xsel`
   subprocesses, or a raw `wl_data_device` seat grab. Clipboard writes are
   destructive (they silently replace user state), so they need the consent
   boundary, and clipboard reads can carry secrets, so payloads must be
   bounded.
2. **Compositor breadth.**v1.1 detection ordered Hyprland -> generic wlroots
   -> X11 -> portal, but Sway, Wayfire, river, KDE, and GNOME sessions each
   have distinct IPC surfaces (`SWAYSOCK`, `WAYFIRE_SOCKET`, `kdotool`,
   `gdbus`) that the flat `Other` bucket ignored.
3. **Lean builds.**Every backend dep (`wayland-client`, `uinput`, `atspi`,
   `pipewire`, `ort`, `tokio-tungstenite`, `sentry`) compiled
   unconditionally - headless/CI/embedded consumers paid for a full GUI
   stack to get the core MCP server.

## Decision

- **`ClipboardProvider` trait**joins the registry (`src/traits.rs`):
  `get_text`, `set_text`, `clear`, `list_mimes`. Text-first: binary
  clipboard payloads do not cross the provider boundary; text is capped at
  **1 MiB**. `clipboard_set`/`clipboard_clear` are consent-gated like every
  other state-destroying tool.
- **Clipboard ladder**(ADR 0004 extension): Wayland -> `wl-copy`/`wl-paste`
  -> `xclip` (still serves the selection through XWayland) -> `None`; X11 ->
  `xclip` (`xsel` fallback for clear inside the provider) -> `None`.
- **`SessionKind` detection**expands to Hyprland, Sway, Wayfire, river,
  KDE, GNOME, Other - detected from instance signatures and socket env vars,
  not just `XDG_CURRENT_DESKTOP`. New rungs: `SwayWindow` over raw sway
  IPC on `$SWAYSOCK` (i3-flavoured protocol, backend name `"sway-ipc"` -
  not the `swaymsg` binary), plus a `kdotool` window rung on KDE -
  `KdotoolWindow` (src/providers/kdotool_window.rs) drives KWin on
  Wayland and X11 alike, gated on the KDE session marker + pinned binary;
  wlroots-family compositors share the wlr capture/input/overlay rungs;
  KDE/GNOME route through portal providers where wlroots protocols are
  absent.
- **Per-backend Cargo features:**`wayland`, `uinput`, `a11y`, `pipewire`,
  `vision`, `browser`, `sentry` - all default-on, so `cargo install` is
  unchanged. `--no-default-features` yields a lean core (mock +
  subprocess providers). Provider construction arms are `#[cfg]`-gated;
  detection still plans candidates, but unavailable features simply skip
  registration and tools answer `ProviderUnavailable` honestly.
  `vision-cuda`/`vision-openvino`/`vision-rocm` add `ort` execution
  providers with `load-dynamic` (runtime `ORT_DYLIB_PATH`, no build-time
  SDK).

## Consequences

- Registry grows to eight provider slots; `Providers::empty()` and mock
  registries gain a clipboard arm, keeping every test hermetic.
- Lean builds must compile **warning-free**- `providers/common.rs` helpers
  are `dead_code`-allowed because every consumer is feature-gated.
- Feature-combo correctness is a release gate: `--no-default-features`,
  each feature alone, and `vision-rocm` are all `cargo check`-verified.
