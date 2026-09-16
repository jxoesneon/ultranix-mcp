# Headless Operation — ultranix-mcp

**Status**: describes shipped v1.4.0 behaviour, verified against
`src/backend/detect.rs` (`SessionInfo::from_env`, `plan_backends`).
**Companion doc**: [HEADLESS_AUTH.md](HEADLESS_AUTH.md) covers transport
authentication (stdio/HTTP/`uxcp_*` keys, SSH tunnelling). This doc covers
*what runs* when there is no physical display — and the useful middle
ground of a **headless compositor**.

Two different situations are both casually called "headless" — the code
treats them very differently:

| Deployment | `SessionType` | Provider ladders |
| ---------- | ------------- | ---------------- |
| Headless **compositor** (wlroots `WLR_BACKENDS=headless`, weston headless) — a Wayland socket exists | `Wayland` | Full — the compositor is real, it just has no physical outputs |
| **No display at all** — bare SSH shell, container, `systemd --user` without a graphical session | `Headless` | **All empty** — every provider-backed tool returns `-32010 ProviderUnavailable` |

---

## 1. What `SessionType::Headless` actually means in code

`SessionInfo::from_env` (src/backend/detect.rs) resolves the session in
this order:

1. `XDG_SESSION_TYPE=wayland` → `Wayland`; `=x11` → `X11`.
2. Otherwise, inference: non-empty `WAYLAND_DISPLAY` → `Wayland`;
   non-empty `DISPLAY` → `X11`.
3. Otherwise → **`Headless`**.

So "headless" to ultranix-mcp is *exactly*: no display variable set.
`XDG_SESSION_TYPE=tty`/`unspecified`/unset doesn't decide it — the display
vars do. A session entered via `dbus-run-session` with `WAYLAND_DISPLAY`
exported is still a Wayland session.

`plan_backends` then maps `SessionType::Headless` onto **empty candidate
lists for all eight provider slots** — capture, input, window,
ui_automation, vision, browser, overlay, clipboard. `detect_providers`
walks nothing; nothing is registered. This is deliberate: there is no
display to automate, and each slot fails closed.

### Consequences people get wrong

- **`/dev/uinput` is not probed headless.** The uinput rung only exists on
  the Wayland/X11 input ladders. On a true headless boot the evdev
  fallback is never attempted — input tools return `-32010` even if the
  udev rule and device node are perfect. (Kernel input with no session to
  receive it would be meaningless anyway.)
- **`web_query` is not available headless.** The CDP browser ladder is
  empty too — `CdpBrowser::new()`'s loopback probe of `127.0.0.1:9222` is
  never run, so the tool returns `-32010 ProviderUnavailable` even with a
  headless Chrome listening on `:9222`. If you need `web_query` on a
  headless host, run the server under a headless compositor (§2) or set
  `DISPLAY`/`WAYLAND_DISPLAY` to a live session — anything that makes the
  session non-`Headless` re-enables the browser ladder.
- **AT-SPI2 is not probed headless** either — `a11y` tools are `-32010`
  even under `dbus-run-session`, because the slot is gated on session
  type, not on bus availability.

### Tool surface on a truly headless host

Works (provider-independent — "core" backend in metrics):

- `sleep` — tokio timer
- `metrics` — Prometheus-style counters/gauges of this process
- `get_action_history`, `clear_action_history` — the encrypted
  `~/.ultranix-mcp/history.json` log
- `replay_action` — replays a recorded call; replaying a provider-backed
  call re-dispatches it and *then* hits `-32010` at the provider boundary
- `plugin_list`, `plugin_reload`, `plugin_run` — plugin host is
  compositor-independent (what a plugin *does* is up to the plugin)
- `system_command` — still dispatches through the pinned-binary whitelist;
  the whitelisted helpers that need a display (`grim`, `scrot`,
  `xdotool`, `wmctrl`, `hyprctl`) fail inside the helper, not at dispatch

Everything else — all `mouse_*`, `type_text`, `key_control`,
`mouse_move_path`, `screenshot`, `screen_info`, `screen_highlight`,
`color_at`, `set_spatial_focus`, `get_ui_tree`, `get_focused_element`,
`find_element`, `find_text_on_screen`, `find_icon`, `wait_for_ui_element`,
`invoke_element`, `screen_record`, `screen_stream`, `window_control`,
`get_windows`,
`get_active_window`, `web_query`, `clipboard_*` — returns
**`-32010 ProviderUnavailable`** with `data.provider` naming the empty
slot. Failure is loud and honest; nothing silently degrades.

> Note: `--mock` (`Providers::all_mocks()`) bypasses detection entirely —
> every slot is populated with a mock. Useful to exercise the *tool
> surface* headless in CI; the results are synthetic, not real automation.

---

## 2. The useful middle ground: a headless compositor

A wlroots compositor built on the **headless backend** creates a real
`wayland-*` socket and advertises real protocols (including
`wlr-screencopy` and virtual input) while rendering to no physical
output. Export `WAYLAND_DISPLAY` at it and ultranix-mcp sees a normal
`SessionType::Wayland` — full provider ladders, real screenshots of a
virtual output, real virtual-input injection into real (virtual) clients.

This is how the repo's own CI rig works: `scripts/nested-test.sh`
(docs/TESTING_STRATEGY.md §2.2, the `nested-live` job in
`.github/workflows/rust_ci.yml`). Condensed recipes:

### sway (what CI uses — packaged everywhere)

```bash
# Private runtime dir is required — never reuse the ambient session's.
export RUNTIME="$(mktemp -d /tmp/uxn.XXXXXX)/rt" && mkdir -p "$RUNTIME" && chmod 700 "$RUNTIME"

env -u WAYLAND_DISPLAY -u DISPLAY -u HYPRLAND_INSTANCE_SIGNATURE \
    XDG_RUNTIME_DIR="$RUNTIME" XDG_SESSION_TYPE=wayland \
    WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1 \
    sway -c minimal.conf &
COMP_PID=$!

# wlroots headless starts with ZERO outputs — screencopy needs one:
SWAYSOCK="$(find "$RUNTIME" -name 'sway-ipc.*.sock' | head -n1)" \
    swaymsg create_output

# Then point the server at it:
env XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY=wayland-1 \
    SWAYSOCK="$SWAYSOCK" \
    ultranix-mcp --transport http --bind 127.0.0.1:3010
```

Detected as `SessionKind::Sway` (via `SWAYSOCK`): capture = wlr-screencopy,
input = wlr-virtual-input, window = sway IPC, overlay = layer-shell. All
functional.

### Hyprland

```bash
# No parent Wayland session → headless backend + pixman renderer:
env -u HYPRLAND_INSTANCE_SIGNATURE -u DISPLAY \
    XDG_RUNTIME_DIR="$RUNTIME" XDG_SESSION_TYPE=wayland \
    WLR_BACKENDS=headless WLR_RENDERER=pixman \
    Hyprland -c minimal.conf &

# Create the output wlroots headless doesn't create by itself:
XDG_RUNTIME_DIR="$RUNTIME" HYPRLAND_INSTANCE_SIGNATURE="$HIS" \
    hyprctl output create headless
```

(With a parent Wayland session, omit `WLR_BACKENDS` and pass the parent
socket as `WAYLAND_DISPLAY` instead — Hyprland nests windowed. Keep
`XDG_RUNTIME_DIR` private either way; Hyprland's IPC path length is
sensitive, so keep the dir short — see `nested-test.sh`.)

### weston (last resort)

```bash
env -u WAYLAND_DISPLAY -u DISPLAY XDG_RUNTIME_DIR="$RUNTIME" \
    weston --backend=headless-backend.so --socket=ultranix-nested \
    --idle-time=0 --width=1280 --height=720
```

weston lacks `wlr-screencopy`: `screenshot`/`screen_info` honestly return
`-32010` rather than fabricating. Input via wlr-virtual-input works.

### What works under a headless wlroots compositor

Capture (wlr-screencopy → real PNGs of the HEADLESS-1 output), input
(wlr virtual pointer/keyboard → real events to clients on the nested
session), window (sway IPC / hyprctl), overlay (layer-shell), clipboard
(wl-clipboard serves the nested session's selection), AT-SPI (tree is
real but only contains apps you launch into the session), vision
(ONNX on captured frames), `web_query` (CDP is session-independent once
the browser ladder is enabled by the session being non-headless). Portals
(`xdg-desktop-portal`) generally do not run in these scratch sessions —
the portal rungs simply fail their probes and drop out, which is fine.

---

## 3. systemd unit — headless-host variant

The packaged unit (`packaging/ultranix-mcp.service`, reproduced in
HEADLESS_AUTH.md §4) is bound to `graphical-session.target` and gated on
`WAYLAND_DISPLAY` — correct for co-session deployment, dead on a seatless
host. For a headless host where you still want the core tools (history,
metrics, plugins):

```ini
# ~/.config/systemd/user/ultranix-mcp.service — HEADLESS HOST variant
[Unit]
Description=ultranix-mcp — MCP server (headless: core tools only)
After=default.target

[Service]
Type=simple
EnvironmentFile=-%h/.config/ultranix-mcp/env   # ULTRANIX_MCP_API_KEY=uxcp_...
ExecStart=/usr/bin/ultranix-mcp --transport http --bind 127.0.0.1:3010
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.ultranix-mcp
PrivateTmp=true

[Install]
WantedBy=default.target
```

Expect every provider-backed call to return `-32010` — that's the design,
not a bug. To get real automation on a headless box, run the compositor
as a service instead:

```ini
# ~/.config/systemd/user/ultranix-nested.service — headless sway + server
[Unit]
Description=ultranix-mcp with headless sway session
After=default.target

[Service]
Type=simple
EnvironmentFile=-%h/.config/ultranix-mcp/env
ExecStartPre=/usr/bin/env -u WAYLAND_DISPLAY -u DISPLAY \
    XDG_RUNTIME_DIR=%t WLR_BACKENDS=headless WLR_RENDERER=pixman \
    WLR_LIBINPUT_NO_DEVICES=1 /usr/bin/sway -c %h/.config/ultranix-mcp/sway-minimal.conf
# (in practice wrap compositor+server in one ExecStart script — see
#  scripts/nested-test.sh for the launch/wait-for-socket/output-creation
#  sequence; a oneshot+socket dance is fiddlier than a wrapper)
ExecStart=/usr/bin/ultranix-mcp --transport http --bind 127.0.0.1:3010
Environment=WAYLAND_DISPLAY=wayland-1
Restart=on-failure

[Install]
WantedBy=default.target
```

In practice: put the compositor launch, socket wait, and
`swaymsg create_output` into a small wrapper script (clone the launch
half of `scripts/nested-test.sh`) and `ExecStart=` that.

---

## 4. CI example (the shipped rig)

`.github/workflows/rust_ci.yml` job `nested-live` — runs on
`workflow_dispatch` or a PR labelled `live`:

```yaml
- name: Install headless compositor and native build dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends sway \
      pkg-config libpipewire-0.3-dev

- name: Run nested-compositor rig
  run: bash scripts/nested-test.sh --compositor sway
  env:
    ULTRANIX_MCP_BIN: ${{ github.workspace }}/target/debug/ultranix-mcp
```

sway needs no seat/GPU under `WLR_BACKENDS=headless`; wlroots advertises
wlr-screencopy anyway, so the rig's PNG-magic-bytes assertion is fully
exercised on a github-hosted runner.

---

## 5. Container note

The OCI image (`Dockerfile`, `ghcr.io/jxoesneon/ultranix-mcp`) follows the
same rule: with no `WAYLAND_DISPLAY`/`DISPLAY` in the container it is
`SessionType::Headless` → core tools only. For real automation either
mount a live session's sockets (see the RUNNING block at the bottom of
the Dockerfile) or run a headless compositor *inside* the container and
export `WAYLAND_DISPLAY` for the server.

---

*See also: [HEADLESS_AUTH.md](HEADLESS_AUTH.md) (transport auth and SSH
tunnelling), [TESTING_STRATEGY.md](TESTING_STRATEGY.md) §2.2 (Tier-2
session integration), `scripts/nested-test.sh` (the reference launcher).*
