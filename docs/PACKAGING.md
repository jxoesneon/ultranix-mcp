# ultranix-mcp — Packaging & Distribution Specification

**Status:** Approved design · Spec phase
**Applies to:** ultranix-mcp ≥ 0.1.0 (Rust 2024, `rmcp` SDK)
**Primary target:** CachyOS / Arch Linux + Hyprland (wlroots), with XDG-portal
fallbacks covering GNOME / KDE / other desktops. X11 support lands in Phase 5.

This document defines every supported install path, the runtime permission
model, the systemd integration, and the post-install verification procedure.
It is the single source of truth for packagers (crates.io, AUR, Nix) and for
MCP client wiring.

---

## 1. Distribution matrix

| Channel | Artifact | Audience | Phase required |
| --- | --- | --- | --- |
| crates.io | `cargo install ultranix-mcp` | Rust toolchain users, all distros | Phase 1 |
| AUR `ultranix-mcp` | source build (PKGBUILD) | Arch/CachyOS users | Phase 1 |
| AUR `ultranix-mcp-bin` | prebuilt release binary | fast install, no toolchain | Phase 1 |
| AUR `ultranix-mcp-git` | builds `main` HEAD | bleeding-edge testers | Phase 1 |
| Nix flake | `github:jxoesneon/ultranix-mcp` | NixOS / nixpkgs users | Phase 5 |
| GitHub Releases | `x86_64-unknown-linux-gnu` tarball + `.deb`-less raw binary | generic distros, CI | Phase 1 |

There is deliberately **no Docker image in the distribution matrix**:
desktop automation is inherently single-seat — the server must share the
user's live Wayland session, seat, and session D-Bus. A **degraded container
mode is documented** (`docs/ARCHITECTURE.md`, Deployment Architecture) for
headless tooling and CI smoke tests only — it requires bind-mounting
`$XDG_RUNTIME_DIR`, the session bus, and `/dev/uinput`, and yields
portal/`None` providers with reduced tool coverage. That is a documented
limitation, not a supported production topology. The Prometheus scrape
config and HTTP transport exist for the *supervision* of a host-native
process. (Contrast with ultramac's Dockerfile, which serves its HTTP tooling
mode.)

---

## 2. crates.io — `cargo install ultranix-mcp`

The canonical install for users who already have a Rust toolchain.

```bash
# Stable Rust 2024 (verified toolchain: 1.98.1)
rustup default stable

cargo install ultranix-mcp --locked
# Binary lands at ~/.cargo/bin/ultranix-mcp
```

Publish requirements (enforced in `Cargo.toml` before `cargo publish`):

- `license = "ISC"`, `edition = "2024"`, `rust-version` pinned to the MSRV.
- `readme`, `repository`, `homepage`, `keywords = ["mcp","wayland","automation",
  "hyprland","desktop"]`, `categories = ["command-line-utilities"]`.
- `--locked` is documented because `Cargo.lock` is committed to the repo and
  reproducibility is part of the security story.
- Native dependencies must remain pure-Rust or `pkg-config`-detectable at
  install time: `wayland-client`/`wayland-protocols` (system `libwayland`),
  `zbus` (pure Rust D-Bus), `ort` (downloads the ONNX Runtime prebuilt shared
  library at build time — document that `cargo install` performs a network
  fetch of `libonnxruntime`; packagers may set
  `ORT_STRATEGY=system` to link a distro `onnxruntime` package instead).

Build-time feature flags:

| Flag | Default | Effect |
| --- | --- | --- |
| `backend-wlroots` | on | wlr-screencopy + wlr-virtual-pointer + virtual-keyboard |
| `backend-uinput` | on | `/dev/uinput` evdev input fallback |
| `backend-portal` | on | XDG portal capture via `zbus` |
| `backend-x11` | off (Phase 5) | xdotool/scrot/wmctrl subprocess fallback |
| `a11y` | on | AT-SPI2 semantic UI tree (Phase 2) |
| `vision` | on | `ort` ONNX inference, model dir `~/.ultranix-mcp/models/` |
| `cdp` | on | Chrome DevTools Protocol browser bridge (Phase 3) |

Minimal install for headless/non-vision use:

```bash
cargo install ultranix-mcp --locked --no-default-features \
  --features backend-wlroots,backend-portal
```

---

## 3. AUR packaging plan

Three AUR entries, following Arch Rust-packaging conventions.

### 3.1 `ultranix-mcp` (source build) — PKGBUILD outline

```bash
# Maintainer: <name> <email>
pkgname=ultranix-mcp
pkgver=0.1.0
pkgrel=1
pkgdesc="Wayland-native, security-first MCP server for Linux desktop automation (Hyprland-first)"
arch=('x86_64' 'aarch64')
url="https://github.com/jxoesneon/ultranix-mcp"
license=('ISC')
depends=(
  'libxkbcommon'      # virtual-keyboard keymap handling
  'dbus'              # zbus / portals / AT-SPI2 session bus
)
makedepends=('cargo' 'pkgconf' 'wayland' 'wayland-protocols')
optdepends=(
  'xdg-desktop-portal-hyprland: screen-capture consent path on Hyprland'
  'xdg-desktop-portal-wlr: portal backend for other wlroots compositors'
  'xdg-desktop-portal-gnome: portal backend under GNOME'
  'pipewire: stream transport for the portal RemoteDesktop path'
  'wl-clipboard: post-v1 clipboard tools (wl-copy/wl-paste) — NOT a v1 runtime dep'
  'at-spi2-core: semantic UI tree (Phase 2 a11y backend)'
  'onnxruntime: system ONNX Runtime for ORT_STRATEGY=system builds'
  'grim: whitelisted system_command capture helper (wlroots)'
  'slurp: whitelisted system_command region-picker (wlroots)'
  'xdotool: X11 input fallback (Phase 5)'
  'scrot: X11 capture fallback (Phase 5)'
  'wmctrl: X11 window management fallback (Phase 5)'
)
install=ultranix-mcp.install
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/v${pkgver}.tar.gz")
sha256sums=('…')

prepare() {
  cd "${pkgname}-${pkgver}"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
  cd "${pkgname}-${pkgver}"
  export RUSTUP_TOOLCHAIN=stable CARGO_TARGET_DIR=target
  cargo build --frozen --release --all-features
}

check() {
  cd "${pkgname}-${pkgver}"
  cargo test --frozen --release
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
(uinput udev rule activation, AT-SPI bus check) on first install — packagers
must not silently `udevadm trigger` inside `.install`; prompt the user.

### 3.2 `ultranix-mcp-bin` — prebuilt binary

- `source=("ultranix-mcp-${pkgver}-x86_64.tar.gz::…/releases/download/v${pkgver}/…"
  "…sha256sums.txt")` plus detached `.sig` when signing lands.
- `provides=('ultranix-mcp')`, `conflicts=('ultranix-mcp')`.
- Same `depends`/`optdepends`; ships the same service unit and udev rule
  extracted from the release tarball.
- `options=('!strip')` is NOT set — release artifacts are shipped unstripped
  and the package may strip normally.

### 3.3 `ultranix-mcp-git` — VCS build

- `pkgname=ultranix-mcp-git`, `source=('git+https://github.com/jxoesneon/ultranix-mcp.git')`.
- `pkgver()` derives from `git describe --tags --long` →
  `0.1.0.rNN.g<sha>`; `provides=('ultranix-mcp')`,
  `conflicts=('ultranix-mcp' 'ultranix-mcp-bin')`.
- Builds with `cargo build --release` (no `--frozen`; lockfile still honored).
- Standard `-git` disclaimer applies: for testers; `main` may be between
  phases.

---

## 4. Optional Nix flake (Phase 5)

`flake.nix` exposes `packages.<system>.default` via
`rustPlatform.buildRustPackage`, a `devShells.default` with the full native
deps, and a `nixosModules.default` user-service module.

```nix
{
  description = "ultranix-mcp — Wayland-native MCP desktop-automation server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "ultranix-mcp";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.wayland pkgs.libxkbcommon ];
          meta.mainProgram = "ultranix-mcp";
        };
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo rustc pkg-config wayland wayland-protocols
            libxkbcommon wl-clipboard # wl-clipboard: post-v1 clipboard category only, not a v1 dep
          ];
        };
      });
}
```

NixOS consumers enable the user service via `systemd.user.services.ultranix-mcp`
in the module; the flake is optional and must never become the only install
path — crates.io and AUR remain canonical.

---

## 5. Runtime permission model (REQUIRED reading)

ultranix-mcp is designed for **least privilege**: on its primary target it
needs *no* elevated permissions at all. Backends are attempted in priority
order; the permission requirements below are per-backend.

| Backend | Capability used | Privilege required | Setup |
| --- | --- | --- | --- |
| **wlroots-native** (wlr-screencopy-unstable-v1) | screen capture | **None.** Compositor-granted to any client on the socket. | Hyprland/wlroots session; `WAYLAND_DISPLAY` set. |
| **wlroots-native** (wlr-virtual-pointer-unstable-v1, virtual-keyboard-unstable-v1) | mouse + keyboard injection | **None.** No root, no group, no portal prompt on Hyprland. | Same as above. |
| **uinput/evdev** (input fallback) | `/dev/uinput` event injection | Write access to `/dev/uinput` — per the documented rule (`docs/ARCHITECTURE.md` §5): `MODE="0660", GROUP="ultranix-input"` with the service user in the **dedicated** `ultranix-input` group. A seat-scoped `uaccess` variant is also supported. **Never** reuse `GROUP="input"` — that group can read *real* input devices, i.e. it is a keylogger permission (see `docs/THREAT_MODEL.md` §4.1). | Install rule `99-ultranix-mcp-uinput.rules` (§5.1), `udevadm control --reload`, `groupadd ultranix-input`, `usermod -aG ultranix-input $USER`, re-login. Add **only** the service user to the group. No root daemon, no `ydotoold`. |
| **XDG portal** (`org.freedesktop.portal.Screenshot` + `RemoteDesktop` via `zbus`) | capture + input fallback | **None**, but the user must accept the compositor/portal **consent dialog** on first use. Portal session tokens are persisted to avoid repeated prompts; failures degrade to `None`, never escalate. | `xdg-desktop-portal` + a backend (`-hyprland`, `-wlr`, `-gnome`, `-kde`) installed; PipeWire for the `RemoteDesktop` stream. |
| **AT-SPI2** (Phase 2) | semantic UI tree, accessible-name targeting | Accessibility bus must be enabled; no extra privileges. | `at-spi2-core` installed; `org.a11y.Bus` reachable on the session bus (usually via `at-spi-bus-launcher` autostart or D-Bus activation). Under GNOME also: `gsettings set org.gnome.desktop.interface toolkit-accessibility true`. Under Hyprland ensure `exec-once = dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP` so the a11y bus inherits the session. |
| **hyprctl IPC** | window list/focus/move/resize | **None** — `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock` is user-owned. | Hyprland session. |
| **CDP bridge** (Phase 3) | browser automation (`web_query`) | **None** beyond a browser launched with `--remote-debugging-port=9222`; the bridge connects to `127.0.0.1:9222`. | Chromium-family browser. |
| **X11 fallback** (Phase 5) | capture + input on Xorg sessions | Runs as the session user; `DISPLAY` + `XAUTHORITY`. | `xdotool`, `scrot`, `wmctrl` installed. |

### 5.1 Shipped udev rule — `packaging/99-ultranix-mcp-uinput.rules`

Documented rule (per `docs/ARCHITECTURE.md` §5, group-based):

```
# ultranix-mcp — uinput access for the evdev input fallback.
# Dedicated group: create `ultranix-input` and add ONLY the service user.
# Never GROUP="input" — `input` membership grants read of real devices
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
| `wl-clipboard` (`wl-copy`/`wl-paste`) | clipboard get/set tools — a **post-v1** category, not in the v1 tool catalog | No — post-v1 optional only; not a current runtime dependency |
| `xdg-desktop-portal-*` + `pipewire` | portal `Screenshot`/`RemoteDesktop` fallback + consent UX | Recommended |
| `grim` / `slurp` | whitelisted `system_command` helpers on wlroots | Recommended |
| `at-spi2-core` | AT-SPI2 backend | Recommended (Phase 2) |
| `onnxruntime` | system ONNX lib instead of bundled download | No |
| `xdotool` / `scrot` / `wmctrl` | X11 fallback | No (Phase 5) |

### 5.3 Environment & data directory

| Variable | Purpose | Default |
| --- | --- | --- |
| `ULTRANIX_MCP_API_KEY` | `uxcp_*` API key(s) for HTTP transport auth (comma-separated for rotation overlap) | unset — HTTP **fails closed**: the server refuses to bind `:3010` without a configured key; stdio is unaffected |
| `ULTRANIX_MCP_API_KEY_FILE` | Path to a file holding one `uxcp_*` key per line (must be mode `0600` or the server refuses to start) — preferred over the env var under systemd/credential layouts | unset |
| `ULTRANIX_MCP_API_KEY_EXPIRES` | Optional key-expiry metadata — comma-separated RFC 3339 timestamps aligned positionally with `ULTRANIX_MCP_API_KEY`; key files take a per-line `expires=` suffix (see `docs/API_KEY_MANAGEMENT.md` §6) | unset — keys do not expire |
| `ULTRANIX_MCP_DISABLE_AUTH` | Dev-only auth bypass (`true`) — startup warning + `auth.disabled` audit event | `false` |
| `ULTRANIX_MCP_HISTORY_SECRET` | AES-256-GCM key for `history.json` | per-install generated at first run (stored `0600` under `~/.ultranix-mcp/`); a dev fallback warns loudly |
| `ULTRANIX_MCP_LOG_LEVEL` / `RUST_LOG` | tracing verbosity | `info` |
| `ULTRANIX_MCP_SENTRY_DSN` | Optional Sentry error reporting | unset (disabled) |
| `PORT` | HTTP listen port (or `--port` flag) | `3010` |

Key-source precedence: `ULTRANIX_MCP_API_KEY` → `ULTRANIX_MCP_API_KEY_FILE`
→ `~/.ultranix-mcp/api-keys` (convention fallback, one key per line, mode
`0600` required — see `docs/API_KEY_MANAGEMENT.md` §3).

Startup flags (the other half of configuration): `--transport stdio|http`
(the canonical selector; `--stdio` is an accepted alias), `--port <n>`,
`--category=<csv>` to cap the served tool surface, and
`--allow-destructive` to bypass the destructive-tool consent gate (§5.4).

ONNX models are *not* packaged: the vision provider lazily downloads
SHA-256-pinned weights into `~/.ultranix-mcp/models/` on the first vision
call (see `docs/ARCHITECTURE.md` §6), so packages must not ship model blobs.

All state lives under `~/.ultranix-mcp/`: `logs/` (incl. `audit.jsonl`),
`history.json` (AES-256-GCM-encrypted action history), `models/` (ONNX).
Permissions are created `0700`/file `0600` at first run.

### 5.4 Whitelisted helpers & the consent gate

`system_command` may only invoke the arg-constrained command whitelist
(canonical definition: `docs/ARCHITECTURE.md` §2): `grim`, `slurp`,
`hyprctl`, `scrot`, `xdotool`, `wmctrl`. Constraints that packagers and
operators must not weaken:

- **Absolute binary pinning.** Each whitelist entry resolves to a pinned
  absolute path at startup (e.g. `/usr/bin/grim`); `PATH` tricks and
  same-name shims elsewhere cannot satisfy the whitelist. If the pinned
  binary is absent, that entry is simply unavailable.
- **Per-command argument constraints.** `hyprctl` may not be invoked with
  `dispatch exec` / `dispatch exec-once` (arbitrary code execution — the
  sharpest edge flagged in `docs/THREAT_MODEL.md` §4.4). `xdotool` and
  `wmctrl` are accepted **only** when the session probe resolved an X11
  backend. `busctl`/`gdbus` are **not** whitelisted (free-form D-Bus calls
  are out of scope for v1).
- **No shell.** Arguments pass as an `exec` argv vector, never through
  `sh -c`; sanitization strips metacharacters before dispatch.
- **Path whitelist.** File arguments must canonicalize beneath
  `$XDG_RUNTIME_DIR`, `/tmp`, or `~/.ultranix-mcp/**`; anything else returns
  `-32004 PathNotWhitelisted`.

**Consent gate (Phase 1).** Destructive tools — `system_command`,
`clear_action_history`, `replay_action`, and `window_control` with
`action: "close"` — return `-32015 ConsentRequired` with a single-use
challenge token on first invocation; the client retries the identical call
with `consent_token` attached. Passing `--allow-destructive` at startup
bypasses the gate (operator opt-out, logged as a startup warning and an
audit event).

---

## 6. systemd `--user` service (HTTP transport)

For daemonized operation — e.g. a long-running HTTP endpoint on :3010 scraped
by Prometheus and shared by several MCP clients — install the unit to
`~/.config/systemd/user/ultranix-mcp.service` (or use the packaged
`/usr/lib/systemd/user/` unit). The canonical unit lives in
`docs/ARCHITECTURE.md` (Deployment Architecture); the copy below is identical
to it and must not diverge:

```ini
# ~/.config/systemd/user/ultranix-mcp.service (packaged at /usr/lib/systemd/user/)
[Unit]
Description=ultranix-mcp — MCP server for Linux desktop automation (HTTP :3010)
After=graphical-session.target
PartOf=graphical-session.target
ConditionEnvironment=WAYLAND_DISPLAY

[Service]
Type=simple
# API key: prefer systemd-creds / EnvironmentFile over inline secrets.
EnvironmentFile=-%h/.config/ultranix-mcp/env
Environment=ULTRANIX_MCP_LOG_LEVEL=info
ExecStart=/usr/bin/ultranix-mcp --transport http --port 3010
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
#   PrivateDevices=yes        — would hide /dev/uinput from the evdev fallback.
#   MemoryDenyWriteExecute=yes — ONNX Runtime JIT may need W+X.
#   RestrictNamespaces=yes    — portals spawn helper sockets via userns.

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

**Transport note:** for single-client desktop use, prefer **stdio** (the MCP
client spawns the process; no port, no key management). The user service is
for the streamable-HTTP mode on :3010 — multi-client, metrics scraping, or
remote-session scenarios.

---

## 7. MCP client configuration (stdio)

All snippets spawn `ultranix-mcp --transport stdio`. Stdio mode is
single-client and requires **no** API key (auth applies to the HTTP
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
with `"$HOME/.cargo/bin/ultranix-mcp"` (absolute path — MCP clients do not
reliably expand `~` or shell `PATH`).

---

## 8. Post-install verification checklist

Run in order on a live Hyprland session:

- [ ] `ultranix-mcp --version` prints the release and build feature set.
- [ ] `echo $WAYLAND_DISPLAY $XDG_CURRENT_DESKTOP` — non-empty; on Hyprland,
      `hyprctl version` responds and `HYPRLAND_INSTANCE_SIGNATURE` is set.
- [ ] `ultranix-mcp --transport stdio` starts; an MCP `initialize` handshake
      succeeds and `tools/list` returns all 32 tools (unfiltered run).
- [ ] Startup probe logs (`RUST_LOG=info`) show provider resolution —
      `CaptureProvider=WlrScreencopy`, `InputProvider=WlrVirtualInput`,
      `WindowProvider=HyprctlWindow` on Hyprland; degraded sessions log the
      portal/uinput/`None` substitutions per the fallback chain.
- [ ] HTTP mode `/readyz` reports which of the six providers resolved to
      `Some` — the authoritative capability statement for the session.
- [ ] A `screenshot` tool call returns a frame with no portal prompt
      (wlroots path) — or a prompt appears once and is remembered (portal path).
- [ ] `mouse_move` + `type_text` round-trip into a test window; `get_windows`
      returns live clients via the hyprctl socket.
- [ ] If using uinput: `test -w /dev/uinput` succeeds after rule + re-login.
- [ ] AT-SPI: `busctl --user introspect org.a11y.Bus /org/a11y/bus` responds.
- [ ] `~/.ultranix-mcp/` exists with `0700`; `logs/` JSONL appends one audit
      line per tool call; `history.json` is not plaintext.
- [ ] HTTP mode: `systemctl --user start ultranix-mcp`,
      `curl -H "Authorization: Bearer uxcp_…" 127.0.0.1:3010/mcp` negotiates,
      `curl 127.0.0.1:3010/metrics` returns Prometheus exposition.
- [ ] Auth negative test: request without `ULTRANIX_MCP_API_KEY` → `401`;
      with `ULTRANIX_MCP_DISABLE_AUTH=true` (dev only) → `200`.
- [ ] `--category=mouse` run exposes only the 7 mouse tools via `tools/list`.

---

*Companion docs: `docs/ENTERPRISE_PLAN.md` (governance/compliance),
`docs/MARKET_ANALYSIS.md` (landscape). Packaging files live under
`packaging/` in the repo root.*
