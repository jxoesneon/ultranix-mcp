# syntax=docker/dockerfile:1
# ultranix-mcp - OCI image (ghcr.io/jxoesneon/ultranix-mcp)
#
# This image is a *co-session* deployment vehicle: ultranix-mcp is a
# desktop-automation server, so the container only does anything useful when
# it can reach a real (or headless-nested) Wayland/X11 session. See the
# "RUNNING" comment block at the bottom for the required mounts.
#
# Verified runtime linkage (readelf -d on the v1.4.0 release binary):
#   NEEDED: libxkbcommon.so.0, libpipewire-0.3.so.0, libstdc++.so.6,
#           libgcc_s.so.1, libm, libc
#   * wayland-client uses the pure-Rust `rs` backend of wayland-backend -
#     no libwayland-client NEEDED entry (no dlopen either).
#   * ONNX Runtime is statically linked by ort's `download-binaries`
#     prebuilt archive - no libonnxruntime.so to ship (that static link is
#     also why libstdc++/libgcc_s appear).
#   * zbus is pure Rust - no libdbus linkage.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# Native build inputs (mirrors .github/workflows/release.yml):
#   pkg-config + libpipewire-0.3-dev - pipewire-sys resolves the lib via
#     pkg-config and binds it with bindgen (hence clang/libclang-dev).
#   libxkbcommon-dev - xkbcommon-sys (virtual-keyboard keymaps).
#   wayland-client's `rs` backend needs no wayland headers; the -dev
#   packages are still installed so a future `client_system` switch
#   keeps working.
#   ca-certificates - ort-sys `download-binaries` fetches the prebuilt
#     ONNX Runtime over HTTPS at build time.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config \
      clang \
      libclang-dev \
      libxkbcommon-dev \
      libpipewire-0.3-dev \
      libwayland-dev \
      wayland-protocols \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependency-caching layer: manifests + a stub main compile all deps (incl.
# the ort `download-binaries` ONNX fetch) into a layer that only rebuilds
# when Cargo.toml/Cargo.lock change - not on every source edit.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src target/release/ultranix-mcp target/release/ultranix_mcp-*

COPY . .
RUN cargo build --release --locked \
 && strip target/release/ultranix-mcp

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# Shared-library deps verified against `readelf -d` (see header), plus the
# whitelisted helper binaries the providers shell out to at RUNTIME (they
# are resolved on PATH / pinned at startup - missing ones simply drop that
# backend rung):
#   grim, slurp           - wlroots capture/region (system_command whitelist)
#   scrot                 - X11 capture (whitelist)
#   xdotool, wmctrl       - X11 input / EWMH window management (whitelist)
#   wl-clipboard          - wl-copy/wl-paste (Wayland clipboard)
#   xclip, xsel           - X11 clipboard get/set/clear
#   x11-xserver-utils     - xrandr output-geometry enrichment
#   x11-utils             - xprop _NET_WM_STATE enrichment
#   dbus                  - session bus for zbus (AT-SPI2 / portals) when the
#                           host bus socket is not mounted
#   ca-certificates       - HTTPS: ONNX model downloads, CDP /json, Sentry
# NOT packaged in Debian (documented gaps): hyprctl (ships with Hyprland -
# mount it or run the container on a Hyprland host with the host binary
# bind-mounted), kdotool (KDE helper, not in bookworm), riverctl (ships
# with river - river itself is not in bookworm). GNOME window ops need
# the host-side Window Calls extension (D-Bus, not a binary).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libxkbcommon0 \
      libpipewire-0.3-0 \
      libstdc++6 \
      ca-certificates \
      dbus \
      grim \
      slurp \
      scrot \
      xdotool \
      wmctrl \
      wl-clipboard \
      xclip \
      xsel \
      x11-xserver-utils \
      x11-utils \
 && rm -rf /var/lib/apt/lists/*

# Non-root service user. A real HOME is required: StateDir::bootstrap()
# creates ~/.ultranix-mcp (history, audit, api-keys) at startup.
RUN useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin ultranix

COPY --from=builder /src/target/release/ultranix-mcp /usr/local/bin/ultranix-mcp

USER ultranix
WORKDIR /home/ultranix

LABEL org.opencontainers.image.title="ultranix-mcp" \
      org.opencontainers.image.description="Rust MCP server for Linux desktop automation - Wayland/Hyprland-first" \
      org.opencontainers.image.source="https://github.com/jxoesneon/ultranix-mcp" \
      org.opencontainers.image.url="https://github.com/jxoesneon/ultranix-mcp" \
      org.opencontainers.image.licenses="ISC" \
      io.modelcontextprotocol.server.name="io.github.jxoesneon/ultranix-mcp"

# Default: print help (smoke-test friendly). Real deployments pass e.g.
#   --transport http --bind 127.0.0.1:3010
# or use stdio by passing `--transport stdio` (the default) to an MCP client.
ENTRYPOINT ["/usr/local/bin/ultranix-mcp"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# RUNNING - co-session deployment (honest requirements)
# ---------------------------------------------------------------------------
# Desktop automation cannot work in an isolated container. The container
# must share the desktop session's sockets, which is --privileged-adjacent:
#
#   docker run --rm \
#     --network host \                                   # HTTP :3010 + CDP loopback :9222
#     -e WAYLAND_DISPLAY="$WAYLAND_DISPLAY" \
#     -e XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
#     -v "$XDG_RUNTIME_DIR:$XDG_RUNTIME_DIR" \           # wayland-N, hypr/, sway-ipc, bus
#     -e HYPRLAND_INSTANCE_SIGNATURE="$HYPRLAND_INSTANCE_SIGNATURE" \
#     -e DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus" \
#     --device /dev/uinput \                             # evdev fallback input only
#     -v "$HOME/.ultranix-mcp:/home/ultranix/.ultranix-mcp" \  # persistent state
#     ghcr.io/jxoesneon/ultranix-mcp:latest \
#       --transport http --bind 127.0.0.1:3010
#
# Notes:
#   * /dev/uinput is only needed for the evdev fallback rung; wlroots
#     virtual-input needs no device. The container user must have write
#     permission (host udev rule / group, or --group-add).
#   * The HTTP transport has NO TLS - keep it on loopback (--network host
#     + --bind 127.0.0.1) and set ULTRANIX_MCP_API_KEY. See
#     docs/HEADLESS_AUTH.md.
#   * stdio transport (default) is the simplest: `docker run -i` with the
#     same socket mounts, driven by an MCP client over the container's
#     stdin/stdout.
#   * For a fully disposable session, pair with a headless wlroots
#     compositor (WLR_BACKENDS=headless sway/Hyprland) - see
#     docs/HEADLESS.md.
