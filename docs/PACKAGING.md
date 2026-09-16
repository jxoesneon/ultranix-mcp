# ultranix-mcp - Packaging & Distribution Specification

**Status:**Implemented (v1.4.0) - the packaging artifacts described here ship
under `packaging/` plus `flake.nix` at the repo root; registry/AUR/crates.io
submissions are pending (see
[REGISTRY_SUBMISSION.md](REGISTRY_SUBMISSION.md)).
**Applies to:**ultranix-mcp ≥ 1.0.0 (Rust 2024, `rmcp` SDK)
**Primary target:**CachyOS / Arch Linux + Hyprland (wlroots), with XDG-portal
and uinput fallbacks covering GNOME / KDE / other desktops. X11-native
providers (`scrot`/`xdotool`/`wmctrl`) shipped at v1.1.0 and resolve on X11
sessions; v1.2.0 added the clipboard helper providers
(`wl-copy`/`wl-paste`/`xclip`/`xsel`), the `sway-ipc` window provider, the
per-backend cargo-feature split, and the Nix flake (**unverified**- see §4).

This document defines every supported install path, the runtime permission
model, the systemd integration, and the post-install verification procedure.
It is the single source of truth for packagers (crates.io, AUR, Nix) and for
MCP client wiring.

---

## 1. Distribution matrix

| Channel | Artifact | Audience | Status |
| --- | --- | --- | --- |
| crates.io | `cargo install ultranix-mcp` | Rust toolchain users, all distros | publish pending |
| AUR `ultranix-mcp` | source build (PKGBUILD) | Arch/CachyOS users | PKGBUILD shipped; submission pending |
| AUR `ultranix-mcp-bin` | prebuilt release binary | fast install, no toolchain | pending |
| AUR `ultranix-mcp-git` | builds `main` HEAD | bleeding-edge testers | PKGBUILD shipped; submission pending |
| Nix flake | `github:jxoesneon/ultranix-mcp` | NixOS / nixpkgs users | `flake.nix` shipped at v1.2.0 - **unverified**(never evaluated; §4) |
| GitHub Releases | `x86_64-unknown-linux-gnu` tarball + `.deb`-less raw binary | generic distros, CI | live via `release.yml` |
| OCI image | `ghcr.io/jxoesneon/ultranix-mcp:<tag>` | headless tooling, CI smoke tests | shipped at v1.4.0 - root `Dockerfile` + `.github/workflows/oci.yml` publish on `v*` tags and `workflow_dispatch` | The OCI image exists for the **documented degraded container mode**only:
desktop automation is inherently single-seat - the server must share the
user's live Wayland session, seat, and session D-Bus. The image requires
bind-mounting `$XDG_RUNTIME_DIR`, the session bus, and `/dev/uinput`, and
yields portal/`None` providers with reduced tool coverage - see
`docs/ARCHITECTURE.md` (Deployment Architecture) and
`docs/HEADLESS.md`. That is a documented
limitation, not a supported production topology: the **native install is
primary**. The Prometheus scrape
config and HTTP transport exist for the *supervision* of a host-native
process. (Contrast with ultramac's Dockerfile, which serves its HTTP tooling
mode.)

---

## 2. crates.io - `cargo install ultranix-mcp`

The canonical install for users who already have a Rust toolchain.

```bash
# Stable Rust 2024 (verified toolchain: 1.98.1)
rustup default stable

cargo install ultranix-mcp --locked
# Binary lands at ~/.cargo/bin/ultranix-mcp
```

> **Build-time caveat:**the `ort` crate's `download-binaries` feature
> fetches the prebuilt ONNX Runtime shared library **during the build**-
> `cargo install` therefore needs network access mid-build (and fails on
> offline builders). Packagers may instead set `ORT_STRATEGY=system` to
> link a distro `onnxruntime` package.

Publish requirements (enforced in `Cargo.toml` before `cargo publish`):

- `license = "ISC"`, `edition = "2024"`, `rust-version` pinned to the MSRV.
- `readme`, `repository`, `homepage`, `keywords = ["mcp","wayland","automation",
  "hyprland","desktop"]`, `categories = ["command-line-utilities"]`.
- `--locked` is documented because `Cargo.lock` is committed to the repo and
  reproducibility is part of the security story.
- Native dependencies must remain pure-Rust or `pkg-config`-detectable at
  install time: `wayland-client`/`wayland-protocols` (system `libwayland`),
  `zbus` (pure Rust D-Bus), `pipewire` (`pipewire-sys`/`libspa-sys` resolve
  `libpipewire-0.3` via pkg-config at build time - unconditional since
  v1.1.0; Debian/Ubuntu `libpipewire-0.3-dev`, Fedora `pipewire-devel`,
  Arch `libpipewire`), `ort` (downloads the ONNX Runtime prebuilt shared
  library at build time - document that `cargo install` performs a network
  fetch of `libonnxruntime`; packagers may set
  `ORT_STRATEGY=system` to link a distro `onnxruntime` package instead).

Build-time feature flags - **as shipped at v1.2.0**the crate has a
per-backend feature split (`default = ["wayland", "uinput", "a11y",
"pipewire", "vision", "browser", "sentry"]`):

| Flag | Default | Effect |
| --- | --- | --- |
| `wayland` | on | native Wayland providers - wlr-screencopy capture, virtual-pointer/keyboard input, layer-shell overlay |
| `uinput` | on | `/dev/uinput` evdev input fallback |
| `a11y` | on | AT-SPI2 `UIAutomationProvider` + portal providers |
| `pipewire` | on | PipeWire portal-stream consumption (implies `a11y`) |
| `vision` | on | ONNX `VisionProvider` (`ort` + model deps) |
| `browser` | on | CDP `BrowserProvider` (`web_query`) |
| `sentry` | on | optional Sentry error reporting wiring |
| `vision-cuda` | off | CUDA execution provider for `ort` (implies `vision` + `ort/cuda` + `ort/load-dynamic` - a matching ONNX Runtime build must be provided via `ORT_DYLIB_PATH`) |
| `vision-openvino` | off | OpenVINO execution provider (same `load-dynamic` caveat) |
| `vision-rocm` | off | ROCm execution provider (same `load-dynamic` caveat) | `cargo install ultranix-mcp --locked --no-default-features` builds a lean
core (mock + subprocess providers: `grim`/`scrot`/`xdotool`/`wmctrl`/
`hyprctl`): feature-gated backends compile out and the tools that need
them report `ProviderUnavailable` at runtime rather than failing the
build - the minimal install is meaningful as of v1.2.0.
The clipboard providers are unconditional (their helpers are optional
runtime binaries, not build deps).

---

## 3. AUR packaging plan

Three AUR entries, following Arch Rust-packaging conventions.

### 3.1 `ultranix-mcp` (source build) - PKGBUILD outline

The shipped file lives at `packaging/ultranix-mcp/PKGBUILD` (with
`ultranix-mcp.install` alongside it); the outline below is kept in sync:

```bash
# Maintainer: <name> <email>
pkgname=ultranix-mcp
pkgver=1.2.0
pkgrel=1
pkgdesc="Wayland-native, security-first MCP server for Linux desktop automation (Hyprland-first)"
arch=('x86_64' 'aarch64')
url="https://github.com/jxoesneon/ultranix-mcp"
license=('ISC')
depends=(
  'libxkbcommon'      # virtual-keyboard keymap handling
  'dbus'              # zbus / portals / AT-SPI2 session bus
  'libpipewire'       # pipewire-sys links libpipewire-0.3 (portal RemoteDesktop stream consumer)
)
makedepends=('cargo' 'pkgconf' 'wayland' 'wayland-protocols')
optdepends=(
  'xdg-desktop-portal-hyprland: screen-capture consent path on Hyprland'
  'xdg-desktop-portal-wlr: portal backend for other wlroots compositors'
  'xdg-desktop-portal-gnome: portal backend under GNOME'
  'pipewire: PipeWire daemon for the portal RemoteDesktop capture stream (v1.1.0+ consumes the video fd when Screenshot is not advertised)'
  'wl-clipboard: clipboard tools on Wayland (wl-copy/wl-paste) - v1.2.0+'
  'xclip: clipboard tools on X11/XWayland - v1.2.0+'
  'xsel: clipboard_clear helper on X11/XWayland - v1.2.0+'
  'at-spi2-core: semantic UI tree (a11y backend)'
  'onnxruntime: system ONNX Runtime for ORT_STRATEGY=system builds'
  'grim: whitelisted system_command capture helper (wlroots)'
  'slurp: whitelisted system_command region-picker (wlroots)'
  'xdotool: X11 input fallback + pointer position (X11 sessions only)'
  'scrot: X11 capture fallback (X11 sessions only)'
  'wmctrl: X11 window-management fallback (X11 sessions only)'
  'xorg-xrandr: X11 output-geometry enrichment for the capture backend (X11 sessions only)'
  'xorg-xprop: X11 _NET_WM_STATE enrichment for the window backend (X11 sessions only)'
  'kdotool: window-management rung on KDE (Wayland + X11) - v1.2.0+'
  'river: riverctl for the river window rung (focused-view window_control only - no list IPC) - v1.4.0+'
)
install=ultranix-mcp.install
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/v${pkgver}.tar.gz")
sha256sums=('...')

prepare() {
  cd "${pkgname}-${pkgver}"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
  cd "${pkgname}-${pkgver}"
  export RUSTUP_TOOLCHAIN=stable CARGO_TARGET_DIR=target
  cargo build --release --locked
}

check() {
  cd "${pkgname}-${pkgver}"
  cargo test --release --locked
}

package() {
  cd "${pkgname}-${pkgver}"
  install -Dm0755 "target/release/ultranix-mcp" "${pkgdir}/usr/bin/ultranix-mcp"
  install -Dm0644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  install -Dm0644 "packaging/ultranix-mcp.service" \
    "${pkgdir}/usr/lib/systemd/user/ultranix-mcp.service"
  install -Dm0644 "packaging/99-ultranix-mcp-uinput.rules" \
    "${pkgdir}/usr/lib/udev/rules.d/99-ultranix-mcp-uinput.rules"
}
```

The `ultranix-mcp.install` script prints the permission notes from §5
(uinput udev rule activation, AT-SPI bus check) on first install - packagers
must not silently `udevadm trigger` inside `.install`; prompt the user.

### 3.2 `ultranix-mcp-bin` - prebuilt binary

- `source_x86_64=("ultranix-mcp-${pkgver}-x86_64-unknown-linux-gnu.tar.gz::.../releases/download/v${pkgver}/ultranix-mcp-${pkgver}-x86_64-unknown-linux-gnu.tar.gz")`;
  `release.yml` also attaches a per-file `<asset>.tar.gz.sha256`
  sidecar (not a combined `sha256sums.txt`) - plus detached `.sig`
  when signing lands.
- `provides=('ultranix-mcp')`, `conflicts=('ultranix-mcp' 'ultranix-mcp-git')`.
- Same `depends`/`optdepends`; ships the same service unit and udev rule
  extracted from the release tarball.
- `options=('!strip')` is NOT set - release artifacts are already
  stripped by `release.yml`, so there is nothing left for the package
  to strip.

### 3.3 `ultranix-mcp-git` - VCS build

- `pkgname=ultranix-mcp-git`, `source=('git+https://github.com/jxoesneon/ultranix-mcp.git')`.
- `pkgver()` derives from `git describe --tags --long` ->
  `1.1.0.rNN.g<sha>`; `provides=('ultranix-mcp')`,
  `conflicts=('ultranix-mcp' 'ultranix-mcp-bin')`.
- Builds with `cargo build --release` (no `--frozen`; lockfile still honored).
- Standard `-git` disclaimer applies: for testers; `main` may be between
  phases.

---

## 4. Optional Nix flake - shipped at v1.2.0, **unverified**

`flake.nix` at the repo root exposes:

- `packages.<system>.default` - `rustPlatform.buildRustPackage` with
  `cargoLock.lockFile = ./Cargo.lock`, `pkg-config` + `clang` native
  inputs, `pipewire`/`wayland`/`libxkbcommon` build inputs, and
  `LIBCLANG_PATH` / `ORT_STRATEGY=system` / `ORT_LIB_LOCATION` pinned so
  `bindgen` finds libclang and `ort-sys` links the nixpkgs `onnxruntime`
  instead of downloading a prebuilt lib inside the offline sandbox
  (`doCheck = false`, matching most Rust nixpkgs builds - the suite needs
  a live session).
- `devShells.default` - Rust toolchain (`cargo`/`rustc`/`rustfmt`/
  `clippy`/`rust-analyzer`) plus the session helpers the providers shell
  out to (`hyprland`, `grim`, `slurp`, `wl-clipboard`, `xclip`, `xsel`,
  `sway`, `kdotool`, `xdotool`, `scrot`, `wmctrl`).
- `apps.default` - `nix run` straight at the built binary.

> **Unverified:**nix is not in the maintainer toolchain - the flake was
> written by review and has never been evaluated (`nix build`,
> `nix develop`, `nix flake check` are all untried). Treat it as a
> starting point; fixes and confirmations are welcome contributions.
> There is no `nixosModules` output - NixOS consumers should wire the
> shipped systemd `--user` unit (§6) into their home-manager/system
> config.

The flake is optional and must never become the only install path -
crates.io and AUR remain canonical.

---

## 5. Runtime permission model (REQUIRED reading)

ultranix-mcp is designed for **least privilege**: on its primary target it
needs *no* elevated permissions at all. Backends are attempted in priority
order; the permission requirements below are per-backend.

| Backend | Capability used | Privilege required | Setup |
| --- | --- | --- | --- |
| **wlroots-native**(wlr-screencopy-unstable-v1) | screen capture | **None.**Compositor-granted to any client on the socket. | Hyprland/wlroots session; `WAYLAND_DISPLAY` set. |
| **wlroots-native**(wlr-virtual-pointer-unstable-v1, virtual-keyboard-unstable-v1) | mouse + keyboard injection | **None.**No root, no group, no portal prompt on Hyprland. | Same as above. |
| **uinput/evdev**(input fallback) | `/dev/uinput` event injection | Write access to `/dev/uinput` - per the documented rule (`docs/ARCHITECTURE.md` §5): `MODE="0660", GROUP="ultranix-input"` with the service user in the **dedicated**`ultranix-input` group. A seat-scoped `uaccess` variant is also supported. **Never**reuse `GROUP="input"` - that group can read *real* input devices, i.e. it is a keylogger permission (see `docs/THREAT_MODEL.md` §4.1). | Install rule `99-ultranix-mcp-uinput.rules` (§5.1), `udevadm control --reload`, `groupadd ultranix-input`, `usermod -aG ultranix-input $USER`, re-login. Add **only**the service user to the group. No root daemon, no `ydotoold`. |
| **XDG portal**(`org.freedesktop.portal.Screenshot` + `RemoteDesktop` via `zbus`) | capture + input fallback | **None**, but the user must accept the compositor/portal **consent dialog**on first use. Portal session tokens are persisted to avoid repeated prompts; failures degrade to `None`, never escalate. | `xdg-desktop-portal` + a backend (`-hyprland`, `-wlr`, `-gnome`, `-kde`) installed; PipeWire for the `RemoteDesktop` stream. |
| **AT-SPI2**| semantic UI tree, accessible-name targeting | Accessibility bus must be enabled; no extra privileges. | `at-spi2-core` installed; `org.a11y.Bus` reachable on the session bus (usually via `at-spi-bus-launcher` autostart or D-Bus activation). Under GNOME also: `gsettings set org.gnome.desktop.interface toolkit-accessibility true`. Under Hyprland ensure `exec-once = dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP` so the a11y bus inherits the session. |
| **hyprctl IPC**| window list/focus/move/resize | **None**- `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock` is user-owned. | Hyprland session. |
| **sway IPC**(v1.2.0+) | window list/focus/move/resize on sway | **None**- `$SWAYSOCK` is user-owned; `GET_TREE`/`RUN_COMMAND` over the i3-flavoured protocol. | sway session (`$SWAYSOCK` set). |
| **Clipboard helpers**(v1.2.0+) | `clipboard_get`/`clipboard_set`/`clipboard_clear` | Runs as the session user; helpers spawned with scrubbed env, payload over stdin, bounded exec. | `wl-clipboard` (`wl-copy`/`wl-paste`) on Wayland; `xclip` (+`xsel` for `clear`) on X11/XWayland. |
| **CDP bridge**| browser automation (`web_query`) | **None**beyond a browser launched with `--remote-debugging-port=9222`; the bridge connects to `127.0.0.1:9222`. | Chromium-family browser. |
| **X11 fallback**(v1.1.0+) | capture + input + window control on Xorg sessions | Runs as the session user; `DISPLAY` + `XAUTHORITY`. | `xdotool`, `scrot`, `wmctrl` installed (`xrandr`/`xprop` optional extras). | ### 5.1 Shipped udev rule - `packaging/99-ultranix-mcp-uinput.rules`

Documented rule (per `docs/ARCHITECTURE.md` §5, group-based):

```
# ultranix-mcp - uinput access for the evdev input fallback.
# Dedicated group: create `ultranix-input` and add ONLY the service user.
# Never GROUP="input" - `input` membership grants read of real devices
# (a keylogger permission; see docs/THREAT_MODEL.md §4.1).
SUBSYSTEM=="uinput", MODE="0660", GROUP="ultranix-input", OPTIONS+="static_node=uinput"
```

Setup: `groupadd ultranix-input` (a dedicated group used by nothing else),
`usermod -aG ultranix-input <service-user>` for the single account that runs
the server, then re-login (or `udevadm control --reload` + `udevadm trigger`
for the node). No other user or service belongs in this group.

Alternative seat-scoped variant for single-seat workstations (no group
membership; grants the seat's *active* user via logind):

```
SUBSYSTEM=="uinput", TAG+="uaccess", OPTIONS+="static_node=uinput"
```

Also ensure the `uinput` module loads: `echo uinput > /etc/modules-load.d/uinput.conf`.

### 5.2 Optional dependencies

| Package | Needed for | Required? |
| --- | --- | --- |
| `wl-clipboard` (`wl-copy`/`wl-paste`) | `clipboard_get`/`clipboard_set`/`clipboard_clear` on Wayland (v1.2.0+) | No - clipboard tools return `ProviderUnavailable` without it |
| `xclip` (+ `xsel` for `clipboard_clear`) | clipboard tools on X11/XWayland (v1.2.0+) | No - X11/XWayland sessions only |
| `xdg-desktop-portal-*` + `pipewire` (daemon; the `libpipewire` client lib is a hard `depends`, not optional) | portal `Screenshot`/`RemoteDesktop` fallback + consent UX | Recommended |
| `grim` / `slurp` | whitelisted `system_command` helpers on wlroots | Recommended |
| `at-spi2-core` | AT-SPI2 backend | Recommended |
| `onnxruntime` | system ONNX lib instead of bundled download | No |
| `xdotool` / `scrot` / `wmctrl` (+ `xorg-xrandr`/`xorg-xprop`) | X11 fallback rungs (shipped at v1.1.0) | No - X11 sessions only | ### 5.3 Environment & data directory

| Variable | Purpose | Default |
| --- | --- | --- |
| `ULTRANIX_MCP_API_KEY` | `uxcp_*` API key(s) for HTTP transport auth (comma-separated for rotation overlap) | unset - HTTP **fails closed**: the server refuses to bind `:3010` without a configured key; stdio is unaffected |
| `ULTRANIX_MCP_API_KEY_FILE` | Path to a file holding one `uxcp_*` key per line (must be mode `0600` or the server refuses to start) - preferred over the env var under systemd/credential layouts | unset |
| `ULTRANIX_MCP_API_KEY_EXPIRES` | Optional key-expiry metadata - comma-separated RFC 3339 timestamps aligned positionally with `ULTRANIX_MCP_API_KEY`; key files take a per-line `expires=` suffix (see `docs/API_KEY_MANAGEMENT.md` §6) | unset - keys do not expire |
| `ULTRANIX_MCP_DISABLE_AUTH` | Dev-only auth bypass (`true`) - startup warning + `auth.disabled` audit event | `false` |
| `ULTRANIX_MCP_HISTORY_SECRET` | AES-256-GCM key for `history.json` | per-install generated at first run (stored `0600` under `~/.ultranix-mcp/`); a dev fallback warns loudly |
| `ULTRANIX_MCP_LOG_LEVEL` / `RUST_LOG` | tracing verbosity | `info` |
| `ULTRANIX_MCP_SENTRY_DSN` | Optional Sentry error reporting - opt-in; unset/empty/malformed disables it (malformed warns at startup) | unset |
| `ULTRANIX_MCP_BIND` | HTTP bind address (or `--bind` flag) | `127.0.0.1:3010` | Key-source precedence: `ULTRANIX_MCP_API_KEY` -> `ULTRANIX_MCP_API_KEY_FILE`
-> `~/.ultranix-mcp/api-keys/*.json` (convention fallback - a directory of
key-record files, JSON or line format, mode `0600` enforced per file; see
`docs/API_KEY_MANAGEMENT.md` §3).

Startup flags (the other half of configuration): `--transport stdio|http`
(the canonical selector; `--stdio` is an accepted alias), `--bind <addr:port>`,
`--category=<csv>` to cap the served tool surface, and
`--allow-destructive` to bypass the destructive-tool consent gate (§5.4).

ONNX models are *not* packaged: the vision provider lazily downloads
SHA-256-pinned weights into `~/.ultranix-mcp/models/` on the first vision
call (see `docs/ARCHITECTURE.md` §6), so packages must not ship model blobs.

All state lives under `~/.ultranix-mcp/`: `logs/` (incl. `audit.jsonl`),
`history.json` (AES-256-GCM-encrypted action history - `UNXHIST2` framed
append log since v1.2.0), `models/` (ONNX), `plugins/` (declarative
tool-macro manifests for `plugin_*` tools, v1.2.0+), and `captures/`
(`screen_record` `rec-<ulid>` output dirs, v1.2.0+ - falls back to a
`0700` `/tmp` dir when the state dir is unusable).
Permissions are created `0700`/file `0600` at first run.
`rec-<ulid>` recording dirs under `captures/` are **kept until the
operator removes them**- there is no auto-prune; each recording is
individually bounded by the 512 MiB write cap.

### 5.4 Whitelisted helpers & the consent gate

`system_command` may only invoke the arg-constrained command whitelist
(canonical definition: `docs/ARCHITECTURE.md` §2): `grim`, `slurp`,
`hyprctl`, `scrot`, `xdotool`, `wmctrl`. Constraints that packagers and
operators must not weaken:

- **Absolute binary pinning.**Each whitelist entry resolves to a pinned
  absolute path at startup (e.g. `/usr/bin/grim`); `PATH` tricks and
  same-name shims elsewhere cannot satisfy the whitelist. If the pinned
  binary is absent, that entry is simply unavailable.
- **Per-command argument constraints.**`hyprctl` may not be invoked with
  `dispatch exec` / `dispatch exec-once` (arbitrary code execution - the
  sharpest edge flagged in `docs/THREAT_MODEL.md` §4.4). `xdotool` and
  `wmctrl` are accepted **only**when the session probe resolved an X11
  backend. `busctl`/`gdbus` are **not**whitelisted (free-form D-Bus calls
  are out of scope for v1).
- **No shell.**Arguments pass as an `exec` argv vector, never through
  `sh -c`; sanitization strips metacharacters before dispatch.
- **Path whitelist.**File arguments must canonicalize beneath
  `$XDG_RUNTIME_DIR`, `/tmp`, or `~/.ultranix-mcp/**`; anything else returns
  `-32004 PathNotWhitelisted`.

**Consent gate (Phase 1).**Destructive tools - `system_command`,
`clear_action_history`, `replay_action`, `window_control` with
`action: "close"`, and (v1.2.0+) `clipboard_set`/`clipboard_clear` -
return `-32015 ConsentRequired` with a single-use
challenge token on first invocation; the client retries the identical call
with `consent_token` attached. `plugin_run` steps re-enter the gate
individually - consent for the plugin call does not authorize a
destructive step. Passing `--allow-destructive` at startup
bypasses the gate (operator opt-out, logged as a startup warning and an
audit event).

---

## 6. systemd `--user` service (HTTP transport)

For daemonized operation - e.g. a long-running HTTP endpoint on :3010 scraped
by Prometheus and shared by several MCP clients - install the unit to
`~/.config/systemd/user/ultranix-mcp.service` (or use the packaged
`/usr/lib/systemd/user/` unit). The canonical unit lives in
`docs/ARCHITECTURE.md` (Deployment Architecture); the copy below is identical
to it and must not diverge:

```ini
# ~/.config/systemd/user/ultranix-mcp.service (packaged at /usr/lib/systemd/user/)
[Unit]
Description=ultranix-mcp - MCP server for Linux desktop automation (HTTP :3010)
After=graphical-session.target
PartOf=graphical-session.target
ConditionEnvironment=WAYLAND_DISPLAY

[Service]
Type=simple
# API key: prefer systemd-creds / EnvironmentFile over inline secrets.
EnvironmentFile=-%h/.config/ultranix-mcp/env
Environment=ULTRANIX_MCP_LOG_LEVEL=info
ExecStart=/usr/bin/ultranix-mcp --transport http --bind 127.0.0.1:3010
Restart=on-failure
RestartSec=3

# --- Hardening (must NOT break the session-level backends) ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.ultranix-mcp
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
# Deliberately NOT set:
# PrivateDevices=yes        - would hide /dev/uinput from the evdev fallback.
# MemoryDenyWriteExecute=yes - ONNX Runtime JIT may need W+X.
# RestrictNamespaces=yes    - portals spawn helper sockets via userns.

[Install]
WantedBy=graphical-session.target
```

Enable:

```bash
mkdir -p ~/.config/ultranix-mcp
printf 'ULTRANIX_MCP_API_KEY=uxcp_<generated>\nULTRANIX_MCP_HISTORY_SECRET=<generated>\n' \
  > ~/.config/ultranix-mcp/env && chmod 600 ~/.config/ultranix-mcp/env

systemctl --user daemon-reload
systemctl --user enable --now ultranix-mcp.service
journalctl --user -u ultranix-mcp -f
```

**Transport note:**for single-client desktop use, prefer **stdio**(the MCP
client spawns the process; no port, no key management). The user service is
for the streamable-HTTP mode on :3010 - multi-client, metrics scraping, or
remote-session scenarios.

---

## 7. MCP client configuration (stdio)

All snippets spawn `ultranix-mcp --transport stdio`. Stdio mode is
single-client and requires **no**API key (auth applies to the HTTP
transport). Use `--category=` to shrink the tool payload sent to the model.

### 7.1 Claude Desktop (Linux)

`~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ultranix-mcp": {
      "command": "/usr/bin/ultranix-mcp",
      "args": ["--transport", "stdio"],
      "env": { "ULTRANIX_MCP_LOG_LEVEL": "info" }
    }
  }
}
```

### 7.2 Cursor

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ultranix-mcp": {
      "command": "/usr/bin/ultranix-mcp",
      "args": ["--transport", "stdio", "--category=mouse,keyboard,vision"]
    }
  }
}
```

### 7.3 Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "ultranix-mcp": {
      "command": "/usr/bin/ultranix-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

If installed via `cargo install` instead of a package, replace the command
with `"$HOME/.cargo/bin/ultranix-mcp"` (absolute path - MCP clients do not
reliably expand `~` or shell `PATH`).

---

## 8. Post-install verification checklist

Run in order on a live Hyprland session:

- [ ] `ultranix-mcp --version` prints the release and build feature set.
- [ ] `echo $WAYLAND_DISPLAY $XDG_CURRENT_DESKTOP` - non-empty; on Hyprland,
      `hyprctl version` responds and `HYPRLAND_INSTANCE_SIGNATURE` is set.
- [ ] `ultranix-mcp --transport stdio` starts; an MCP `initialize` handshake
      succeeds and `tools/list` returns all 40 tools (unfiltered run).
- [ ] Startup probe logs (`RUST_LOG=info`) show provider resolution -
      `CaptureProvider=WlrCapture`, `InputProvider=WlrInput`,
      `WindowProvider=HyprctlWindow` on Hyprland (`sway-ipc` on sway);
      degraded sessions log the portal/uinput/`None` substitutions per the
      fallback chain.
- [ ] HTTP mode `/readyz` reports which of the eight providers (including
      `OverlayProvider` since v1.1.0 and `ClipboardProvider` since v1.2.0)
      resolved to `Some` - the authoritative capability statement for the
      session.
- [ ] A `screenshot` tool call returns a frame with no portal prompt
      (wlroots path) - or a prompt appears once and is remembered (portal path).
- [ ] `mouse_move` + `type_text` round-trip into a test window; `get_windows`
      returns live clients via the hyprctl socket.
- [ ] If using uinput: `test -w /dev/uinput` succeeds after rule + re-login.
- [ ] AT-SPI: `busctl --user introspect org.a11y.Bus /org/a11y/bus` responds.
- [ ] `~/.ultranix-mcp/` exists with `0700`; `logs/` JSONL appends one audit
      line per tool call; `history.json` is not plaintext.
- [ ] HTTP mode: `systemctl --user start ultranix-mcp`,
      `curl -H "Authorization: Bearer uxcp_..." 127.0.0.1:3010/mcp` negotiates,
      `curl 127.0.0.1:3010/metrics` returns Prometheus exposition.
- [ ] Auth negative test: request without `ULTRANIX_MCP_API_KEY` -> `401`;
      with `ULTRANIX_MCP_DISABLE_AUTH=true` (dev only) -> `200`.
- [ ] `--category=mouse` run exposes only the 7 mouse tools via `tools/list`.
- [ ] With `wl-clipboard` installed: `clipboard_set` -> `-32015` consent
      challenge -> retry with `consent_token` -> `clipboard_get` returns the
      payload. Without the helpers, the clipboard tools answer
      `ProviderUnavailable`.
- [ ] `plugin_list` returns `[]` (or the manifests dropped into
      `~/.ultranix-mcp/plugins/`); `plugin_reload` reports
      loaded-vs-skipped.

---

## 9. Shipped artifacts

Files in the repo that implement this spec:

| Path | Purpose |
| --- | --- |
| `packaging/ultranix-mcp/PKGBUILD` | AUR source build (§3.1). `sha256sums` ships as `SKIP` - run `updpkgsums` after tagging, before pushing to the AUR. |
| `packaging/ultranix-mcp/ultranix-mcp.install` | Post-install permission notes (§5) - prints guidance only, never `udevadm trigger`s silently. |
| `packaging/ultranix-mcp-git/PKGBUILD` | VCS build of `main` HEAD (§3.3); `pkgver()` derives from `git describe --tags --long`. |
| `packaging/ultranix-mcp.service` | systemd `--user` unit (§6 shape): stdio transport by default, `WantedBy=default.target`, comments carry the HTTP-mode and non-`/usr/bin` `ExecStart` variants. |
| `packaging/99-ultranix-mcp-uinput.rules` | Opt-in udev rule (§5.1) - inert until the dedicated `ultranix-input` group exists. |
| `packaging/README-uinput.md` | Copy-paste uinput setup, verification, and removal. |
| `flake.nix` | Nix package + devShell + app (§4) - **unverified**, contributions welcome. |
| `.github/workflows/release.yml` | On `v*` tags: `cargo build --release --locked` for `x86_64-unknown-linux-gnu`, strip, `tar.gz` + `.sha256` sidecar, attached to the GitHub release via `softprops/action-gh-release`. | ### `cargo install`

Unchanged and canonical (§2): `cargo install ultranix-mcp --locked` lands
the binary at `~/.cargo/bin/ultranix-mcp`. `cargo install` ships no unit or
udev rule - for supervised operation copy `packaging/ultranix-mcp.service`
to `~/.config/systemd/user/` and point `ExecStart` at
`%h/.cargo/bin/ultranix-mcp`. **Build-time caveat:**`ort` fetches the
prebuilt ONNX Runtime shared library mid-build, so the install requires
network access (or `ORT_STRATEGY=system` against a distro `onnxruntime`) -
see §2.

### Non-Arch distro notes (Fedora, Debian/Ubuntu, ...)

No `.rpm`/`.deb` artifacts ship yet - use `cargo install` or the GitHub
release tarball, then:

- **Build deps**(needed by `cargo install` too - crates.io builds from
  source): Debian/Ubuntu `pkg-config libwayland-dev libxkbcommon-dev
  libpipewire-0.3-dev`; Fedora `pkgconf-pkg-config wayland-devel
  libxkbcommon-devel pipewire-devel`.
- **udev**: copy `packaging/99-ultranix-mcp-uinput.rules` to
  `/etc/udev/rules.d/`, then follow the groupadd/usermod/udevadm steps in
  `packaging/README-uinput.md`. Dedicated `ultranix-input` group - never
  `input`.
- **systemd `--user`**: copy the unit to `~/.config/systemd/user/` and
  adjust `ExecStart` to the real install path (`%h/.cargo/bin` or
  `%h/.local/bin`), then `systemctl --user daemon-reload`.
- **Portal backend**: `xdg-desktop-portal` plus the backend matching the
  session (`-hyprland`/`-wlr`/`-gnome`/`-kde`) and `pipewire` for the
  `RemoteDesktop` stream - package names vary by distro.

---

*Companion docs: `docs/ENTERPRISE_PLAN.md` (governance/compliance),
`docs/MARKET_ANALYSIS.md` (landscape). Packaging files live under
`packaging/` in the repo root.*
