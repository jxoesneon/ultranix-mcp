# Headless & Remote Authentication — ultranix-mcp

**Status**: Implemented (v1.4.0) — everything here describes shipped behaviour
except the Unix-socket listener, which remains a planned hardening option.
**Audience**: operators running ultranix-mcp over SSH, on a headless box, or
under `systemd --user` without an active graphical seat.

ultranix-mcp is a **desktop** automation server — "headless" here means *the
operator isn't physically at the machine*, not *there is no desktop*. The
interesting cases are: driving a Wayland/Hyprland session remotely, and
running on a host where no compositor/seat exists at all (degraded).

---

## 1. The stdio No-Auth Model — and Why It Is Acceptable

**stdio never requires an API key. This is deliberate, not an omission.**

The trust reasoning:

- In stdio mode, the MCP client *spawns* `ultranix-mcp` and owns its
  stdin/stdout pipes. The server runs **as the spawning user** with no
  elevated privilege.
- Therefore, anyone who can establish a stdio channel to the server already
  possesses the stronger capability of **executing arbitrary code as that
  user** — they could just run `grim` or `hyprctl` themselves. An API key
  would authenticate a caller who already holds superset access: pure
  ceremony, no security.
- The local trust boundary is the Unix account itself (`fork`/`exec` + DAC),
  which the OS already enforces.

**What this means in practice:**

| Scenario | Risk added by no-auth stdio |
| -------- | --------------------------- |
| Local AI client launches ultranix-mcp | None — same-user by construction |
| SSH session: client config launches it on login shell | None — attacker inside your SSH session already has a shell |
| A *different* local UID | Cannot open your stdio pipes — DAC blocks it |

**The boundary this does NOT create:** an authenticated-but-malicious *agent*
talking over stdio is fully trusted — same as any other transport. stdio
removes transport auth, not tool risk. The pipeline (whitelist, paths, audit)
still applies to every call.

---

## 2. Reaching a Remote ultranix-mcp: SSH Tunneling (recommended)

The HTTP transport binds `:3010`. The supported remote pattern is:

```bash
# On the operator's workstation — forward remote :3010 to local :3010
ssh -L 3010:127.0.0.1:3010 user@desktop-host

# MCP client then points at http://127.0.0.1:3010/mcp with its uxcp_ key
```

**Why a tunnel, not an open port:**

- ultranix-mcp ships **no TLS**. A LAN-exposed `:3010` sends keystrokes and
  screenshots in cleartext and invites brute-force/`auth.failure` noise.
- SSH gives you mutual authentication, encryption, and — with
  `ProxyJump`/agent forwarding — auditability at the OS level.
- Keep the server bound to `127.0.0.1` even when tunneling; the tunnel maps to
  loopback, so a bind mistake can't expose you.

### `ssh -X` / `ssh -Y` cautions

- `ssh -X` forwards **X11**, not Wayland — ultranix-mcp's primary paths
  (wlr-screencopy, virtual input, hyprctl) are Wayland-native and don't use
  the X connection at all. X forwarding buys you nothing here.
- Worse, `-X`/`-Y` lets the *remote* host snoop/inject into your *local* X
  session if you run X apps through it — a real exposure in the wrong
  direction. Don't forward X just to reach `:3010`; use `-L`.
- Never `ssh -R` the port the other way (exposing your local session's
  ultranix to the remote host) unless you fully trust that host.

### Remote port-forward cautions for `:3010` itself

```bash
# DANGEROUS — do NOT do this:
ssh -R 3010:127.0.0.1:3010 ...     # exposes your desktop control to the remote
# or binding :3010 to 0.0.0.0 and punching a firewall hole
```

If `:3010` ever faces a network: `uxcp_*` auth is mandatory
(`ULTRANIX_MCP_DISABLE_AUTH` **must** be unset — it is a hard safety
requirement, not a preference), rate limiting is the only flood control, and
there is still no TLS. Prefer the tunnel. Always.

---

## 3. Recommended Listener Configurations

| Deployment | Listener | Auth |
| ---------- | -------- | ---- |
| Local client, same machine | stdio | none (by design) |
| Same machine, HTTP convenience | `127.0.0.1:3010` | `uxcp_*` required |
| Remote operator | `127.0.0.1:3010` + `ssh -L` | `uxcp_*` required |
| Hardened local | **Unix socket** (`$XDG_RUNTIME_DIR/ultranix-mcp.sock`, mode `0600`) — planned alternative to TCP | `uxcp_*` still recommended |
| LAN-exposed `0.0.0.0:3010` | — | **Unsupported.** No TLS + bearer keys + full desktop control = do not. |

A Unix-socket listener removes the entire "who else can reach the port" class
of questions; it is the preferred hardening option for single-machine HTTP use
and is on the roadmap.

---

## 4. systemd `--user` Without a Seat — Degraded Operation

Running under `systemd --user` is the recommended service model, but a
user manager **without an active graphical seat** changes what the backends
can reach. `loginctl` shows whether the user has a seat/session; `XDG_RUNTIME_DIR`
exists either way (`/run/user/<uid>`), but Wayland and the portals do not.

```ini
# ~/.config/systemd/user/ultranix-mcp.service (packaged at /usr/lib/systemd/user/)
# Canonical unit — identical to docs/ARCHITECTURE.md §Deployment Architecture
# (the canonical systemd unit definition); this copy must not diverge.
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
#   PrivateDevices=yes        — would hide /dev/uinput from the evdev fallback.
#   MemoryDenyWriteExecute=yes — ONNX Runtime JIT may need W+X.
#   RestrictNamespaces=yes    — portals spawn helper sockets via userns.

[Install]
WantedBy=graphical-session.target
```

**Headless alternative (noted exception):** a seatless host has no
`graphical-session.target` and `WAYLAND_DISPLAY` is never set, so the
canonical unit's `After=`/`PartOf=`/`ConditionEnvironment=` and
`WantedBy=graphical-session.target` never fire. On such hosts substitute
`After=default.target` + `WantedBy=default.target` and drop
`ConditionEnvironment=WAYLAND_DISPLAY` — then accept the degraded tool table
below. cargo-install users substitute
`ExecStart=%h/.local/bin/ultranix-mcp --transport http --bind 127.0.0.1:3010`.

The env file (`%h/.config/ultranix-mcp/env`, mode `0600`) carries
`ULTRANIX_MCP_API_KEY` (or `ULTRANIX_MCP_API_KEY_FILE` pointing at a key
file; `~/.ultranix-mcp/api-keys/*.json` — key-record files, mode `0600` each —
is the convention fallback source when neither is set; see
`docs/API_KEY_MANAGEMENT.md` §3), the
optional `ULTRANIX_MCP_API_KEY_EXPIRES` key-expiry metadata,
`ULTRANIX_MCP_HISTORY_SECRET`, and any `ULTRANIX_MCP_BIND`/`--bind` override; the
listener defaults to `127.0.0.1:3010`.

### Degraded-tools table — what works without a seat

| Capability | Backend | Seat present | No seat |
| ---------- | ------- | ------------ | ------- |
| Screenshot / capture | wlr-screencopy | ✅ | ❌ no compositor |
| Screenshot | portal Screenshot | ✅ (consent dialog) | ❌ **portals unavailable** — no `org.freedesktop.portal.*` without a session |
| Input injection | zwlr_virtual_pointer_v1 + virtual-keyboard | ✅ | ❌ |
| Input injection | uinput/evdev | ✅ | ❌ never probed — the input ladder is empty on `SessionType::Headless`, so `/dev/uinput` is not even opened (see docs/HEADLESS.md §1) |
| Input injection | portal RemoteDesktop | ✅ (consent) | ❌ unavailable |
| Window/app control | hyprctl IPC | ✅ | ❌ no Hyprland |
| a11y tree | AT-SPI2 | ✅ | ❌ `-32010` — the ui_automation ladder is empty headless, even under `dbus-run-session` |
| Browser automation | CDP `127.0.0.1:9222` | ✅ | ❌ `-32010` — the browser ladder is empty headless; `CdpBrowser` is never probed even with Chrome listening on :9222. Run a headless compositor (docs/HEADLESS.md §2) to enable it |
| Action history, audit, metrics | internal | ✅ | ✅ |

**Bottom line for true headless hosts:** with no `WAYLAND_DISPLAY`/`DISPLAY`
the session resolves to `SessionType::Headless` and **every** provider
ladder is empty — all provider-backed tools fail closed with an explicit
`-32010 ProviderUnavailable`. What remains is the compositor-independent
core: encrypted history/audit/metrics, plugins, `sleep`, and
`system_command` dispatch (its whitelisted helpers still fail at exec
time without a display). Portals do not exist without a session, so
nothing escalates into a consent dialog that can't render. If you need
real automation on a seatless box, run the server under a headless
wlroots compositor — see [HEADLESS.md](HEADLESS.md).

### The dangerous middle case: seat exists but nobody is watching

The riskiest headless deployment is a machine with a **logged-in but
unattended graphical session** — everything works, and there is no human to
notice an agent clicking. If you enable this:

- Keep `ULTRANIX_MCP_DISABLE_AUTH` unset — no exceptions.
- Prefer the Wayland virtual-input backend over uinput, so injected input
  stays compositor-scoped.
- Watch `audit.jsonl`; an unattended session makes the audit log your only
  witness.
- Consider a screen-lock policy on idle — but note uinput-level input is
  physical-equivalent and **can interact with the lock screen itself**
  (THREAT_MODEL §4.1, R-7).

---

## 5. Quick-Start Recipes

### A. Drive a remote Hyprland desktop

```bash
# desktop-host (once)
systemctl --user enable --now ultranix-mcp   # bound to 127.0.0.1:3010

# workstation
ssh -L 3010:127.0.0.1:3010 desktop-host
# MCP client config → http://127.0.0.1:3010/mcp, Authorization: Bearer uxcp_…
```

### B. Local client only (simplest + strongest)

```json
{
  "mcpServers": {
    "ultranix": {
      "command": "/usr/bin/ultranix-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

No key, no port, no tunnel — the process-spawn boundary is the security model.

### C. Headless host — core tools only (no CDP either)

```bash
systemctl --user start ultranix-mcp    # no graphical-session dependency
# All provider-backed tools — including web_query/CDP — return
# -32010 ProviderUnavailable: SessionType::Headless empties every ladder.
# For browser automation on a headless box, run the server under a
# headless wlroots compositor so WAYLAND_DISPLAY is set (docs/HEADLESS.md).
```

---

## 6. Checklist

- [ ] Prefer **stdio** for same-machine clients — zero network surface
- [ ] Bind HTTP to `127.0.0.1` (or Unix socket); reach it remotely via `ssh -L`
- [ ] Never expose `:3010` on a LAN interface; never `ssh -R` it outward
- [ ] `ULTRANIX_MCP_DISABLE_AUTH` unset everywhere except a loopback dev box
- [ ] `ssh -X` not used for this purpose (it forwards X11, not Wayland)
- [ ] systemd unit: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`
- [ ] Headless: know which tools degrade (§4 table); portals unavailable is
      expected, not a bug
- [ ] Unattended-but-logged-in sessions treated as high-risk (§4, final note)

---

*See also: [HEADLESS.md](HEADLESS.md) (headless-compositor recipes and the
`SessionType::Headless` tool matrix), [API_KEY_MANAGEMENT.md](API_KEY_MANAGEMENT.md)
(key sourcing under systemd credentials), [THREAT_MODEL.md](THREAT_MODEL.md)
(TB-1, R-9 — unencrypted transport), [SECURITY.md](../SECURITY.md).*
