# Security Policy

**Project**: ultranix-mcp — Rust MCP server for Linux desktop automation (Wayland/Hyprland, CachyOS)
**Status**: Implemented (v1.0.0) — this document describes the shipped security design. Where the implementation still lags this document (called out inline — e.g. optional Sentry reporting, planned post-v1), the gap is tracked as a defect or roadmap item.

ultranix-mcp grants AI agents the ability to see the screen and inject input on a
live desktop session. That is an inherently high-privilege capability. This
document covers (1) the vulnerability reporting policy, (2) the security
architecture, and (3) a hardening checklist for deployers. The detailed attack
surface analysis lives in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x | ✅ — security fixes ship as patch releases on `main` |
| 0.1.x–0.5.x (pre-stable) | ❌ — upgrade to 1.x |
| forks | ❌ |

The project does not maintain backport branches. Security fixes are
released as new patch versions; operators are expected to upgrade.

---

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues,
public Discord channels, or PR descriptions.**

### Private reporting channel

1. **GitHub Security Advisories** (preferred):
   `https://github.com/jxoesneon/ultranix-mcp/security/advisories/new`
2. **Email fallback**: security contact listed in `Cargo.toml` `authors` field
   (pending assignment). If no contact is listed yet, use GitHub
   Security Advisories only.

### What to include

- Affected version / commit
- Description of the vulnerability and its security impact
- Steps to reproduce (a minimal MCP client script is ideal)
- Whether exploitation requires stdio access, the HTTP port, an API key, or
  local user access
- Suggested mitigation, if any

### Response SLA

| Stage | Commitment |
| ----- | ---------- |
| Acknowledgment | Within **48 hours** |
| Triage & severity assessment | Within **7 days** (CVSS 3.1 scored) |
| Fix — Critical (RCE-equivalent: auth bypass, whitelist escape) | Within **14 days** |
| Fix — High/Medium | Within **30 days** |
| Fix — Low | Next regular release |

### Disclosure process

1. Reporter is kept informed at each stage above.
2. Fix is developed privately, released as a patch version with a generic
   changelog entry.
3. A GitHub Security Advisory (GHSA) is published **7 days after** the patch
   release, crediting the reporter unless anonymity is requested.
4. If a fix slips past SLA, the reporter may disclose independently; we will not
   contest good-faith disclosure after SLA expiry.

There is currently **no bug bounty program**. Reporters are credited in the
GHSA and release notes.

---

## Security Architecture

ultranix-mcp is built in Rust 2024 on the `rmcp` SDK. Every tool invocation —
regardless of transport — passes through a fixed defense-in-depth pipeline.
No layer is trusted to be sufficient on its own.

### Transports

| Transport | Auth model | Rationale |
| --------- | ---------- | --------- |
| **stdio** | None — never requires auth | The client spawns the process and owns its stdin/stdout. Any party able to attach to stdio already executes code as the user; authentication would add no boundary. |
| **Streamable HTTP** (`:3010`) | `uxcp_*` API key required | A listening socket is reachable by any local process (and the LAN if mis-bound). Auth is mandatory here. |
| **HTTP, dev mode** | Auth disabled iff `ULTRANIX_MCP_DISABLE_AUTH=true` | Explicit opt-in escape hatch for local development. Logs a loud startup warning and emits an audit event. Never acceptable outside loopback development. |

### Request pipeline (every tool call)

```
API-key auth (HTTP only)
    → 10 req/s token bucket per client identity
    → shell-metacharacter sanitization
    → arg-constrained command whitelist {grim, slurp, hyprctl, scrot, xdotool, wmctrl}
    → path whitelist {$XDG_RUNTIME_DIR, /tmp, ~/.ultranix-mcp/**}
    → consent gate (destructive-class tools)
    → audit log (JSONL, append-only, hash-chained)
```

| Layer | Control | Failure mode |
| ----- | ------- | ------------ |
| Authentication | `uxcp_*` key from `ULTRANIX_MCP_API_KEY`, compared as SHA-256 hash in constant time | Reject + `auth.failure` audit event |
| Rate limiting | Token bucket, 10 req/s per client identity (API-key ID; remote addr as fallback) | Reject + `ratelimit.exceeded` audit event |
| Sanitization | Strip/reject shell metacharacters in any argument that reaches a spawned process | Reject + `sanitize.rejected` audit event |
| Command whitelist | Arg-constrained closed set of desktop tools (below); binaries resolved to absolute paths and pinned at startup | Reject + `whitelist.violation` audit event |
| Path whitelist | Canonicalized paths must resolve under `$XDG_RUNTIME_DIR`, `/tmp`, or `~/.ultranix-mcp/**` — `$HOME` at large is **not** writable; symlinks resolved before the check | Reject + `path.violation` audit event |
| Consent gate | Destructive-class tools require a short-lived `consent_token` obtained via a `-32015 ConsentRequired` challenge | Challenge + `consent.required` audit event |
| Audit | Every invocation — accepted or rejected — appended to `~/.ultranix-mcp/logs/audit.jsonl`, each record `prev_hash`-chained to its predecessor | Always-on |

#### Arg-constrained command whitelist

Whitelist membership is necessary but not sufficient — each member's
arguments are constrained at the validator layer:

- **`hyprctl`** — read subcommands only (`clients`, `activewindow`,
  `monitors`, `workspaces`) plus `dispatch` restricted to `focuswindow`,
  `movewindow`, `resizewindow`, `workspace`, `movetoworkspace`.
  **`dispatch exec` / `exec-once` are denied** — they are arbitrary command
  execution wearing a whitelisted binary's name.
- **`scrot`** — output path must canonicalize inside the path whitelist.
- **`xdotool`, `wmctrl`** — permitted only under the X11-session fallback
  backend; refused on Wayland sessions.
- **`busctl`, `gdbus`** — **removed from the whitelist.** D-Bus access
  (portals, AT-SPI2) happens in-process via `zbus`; the CLI helpers can
  reach methods like `StartTransientUnit` that amount to arbitrary exec.
- Every whitelisted binary is resolved to its **absolute path at startup
  and pinned** — a hijacked `PATH` cannot redirect execution.

#### Consent gate for destructive-class tools

Authentication proves *which key* called; it cannot prove *a human approved
the action*. Destructive-class tools — `system_command`,
`clear_action_history`, `replay_action`, and
`window_control{action:"close"}` — therefore return JSON-RPC error
`-32015 ConsentRequired` with a short-lived (60 s), single-use challenge
token on first call; the client surfaces the challenge to the operator and
re-issues the call with `consent_token`. Tokens are CSPRNG-generated
(≥128-bit) and bound to `{key_id or stdio session id, tool, args_hash}`,
so they cannot be transplanted across callers, tools, or arguments —
and `replay_action` never inherits the original call's consent: replaying
a recorded destructive-class action re-challenges through the full gate.
`--allow-destructive` bypasses the gate for
trusted local use; the bypass is logged at startup and stamped on the
affected audit records.

### Backend privilege posture

Input injection and capture use the least-privileged backend available, in this
preference order:

1. **Wayland-native virtual input** (`zwlr_virtual_pointer_v1` + virtual
   keyboard protocol) — compositor-sandboxed, runs as the session user,
   **no root, no extra group membership**.
2. **uinput/evdev fallback** — requires the service user to hold write access to
   `/dev/uinput`, typically granted via a udev rule. This widens the blast
   radius: any process running as the service user can inject *kernel-level*
   input events indistinguishable from physical devices. See
   [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#4-linux-specific-attack-surfaces-detailed).
3. **XDG portals** (`org.freedesktop.portal.RemoteDesktop` / `Screenshot`) —
   last resort; surfaces a native consent dialog. Highest user friction,
   strongest per-action consent.

Screen capture uses **wlr-screencopy** where the compositor supports it, falling
back to the Screenshot portal (with its consent UX). Compositor control goes
through the **hyprctl IPC socket** and **AT-SPI2** for the accessibility tree.

### Storage

| Artifact | Location | Protection |
| -------- | -------- | ---------- |
| Action history | `~/.ultranix-mcp/history.json` | AES-256-GCM at rest (`ULTRANIX_MCP_HISTORY_SECRET` or per-install derived key) |
| Audit log | `~/.ultranix-mcp/logs/audit.jsonl` | JSONL, file mode `0600`, dir mode `0700`; `prev_hash` hash-chaining makes silent edits detectable |
| API keys | Env `ULTRANIX_MCP_API_KEY` | Only SHA-256 hashes held in memory |
| Screenshots | In-memory; tmp files only when required | `mktemp` + mode `0600` + explicit cleanup |
| ONNX models | `~/.ultranix-mcp/models/` | SHA-256 checksum verified at download |

### Supply chain

- `Cargo.lock` committed; releases built with `--locked`.
- `cargo audit` and `cargo deny` in CI; advisories gate release.
- Dependencies pinned to exact versions; new dependencies require review.
- Vendored/downloaded ONNX models verified against published SHA-256 checksums
  before first use.

---

## Hardening Checklist for Deployers

**Authentication**

- [ ] `ULTRANIX_MCP_API_KEY` set to a freshly generated `uxcp_` key (see
  [docs/API_KEY_MANAGEMENT.md](docs/API_KEY_MANAGEMENT.md))
- [ ] Key rotated at least every **90 days**, and immediately upon any
  suspicion of exposure
- [ ] `ULTRANIX_MCP_HISTORY_SECRET` set to a strong secret — or rely on the
  per-install secret generated on first run (stored mode `0600` under
  `~/.ultranix-mcp/`). The built-in dev fallback encrypts `history.json`
  with a *known* key and emits a loud startup warning: that is obfuscation,
  not protection. Rotate deliberately: existing history must be
  re-encrypted or it becomes unreadable.
- [ ] Optionally stamp an `expires=` timestamp on each key record so keys
  self-revoke — expired keys are rejected with a distinct
  `auth.expired_key` audit event (see
  [docs/API_KEY_MANAGEMENT.md](docs/API_KEY_MANAGEMENT.md))
- [ ] `ULTRANIX_MCP_DISABLE_AUTH` is **unset** in any environment where `:3010`
  is reachable by anything other than the calling process. Setting it on a
  shared machine or a non-loopback bind is equivalent to giving every process
  that can reach the port full keyboard/mouse control of the session.
- [ ] HTTP listener bound to `127.0.0.1` (or a Unix socket) — never `0.0.0.0`.
  For remote use, tunnel over SSH; see
  [docs/HEADLESS_AUTH.md](docs/HEADLESS_AUTH.md).

**Process isolation**

- [ ] Runs under a dedicated, unprivileged service user — **not** root, and
  ideally not the interactive login user (so a compromised MCP client cannot
  silently read unrelated user files through tool path arguments)
- [ ] `~/.ultranix-mcp/` mode `0700`; `logs/` mode `0700`; key files mode `0600`
- [ ] systemd hardening recommended: `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=read-only` (with `ReadWritePaths=` for
  the data dir), `PrivateTmp=yes`
- [ ] If uinput fallback is in use: udev rule grants access to a **dedicated
  `ultranix-input` group** containing only the service user — never
  `MODE="0666"` on `/dev/uinput`, never `GROUP="input"` (which also grants
  read of *real* devices — a keylogger permission). Understand that uinput
  input is trusted by the kernel as
  physical input; it can type into `sudo` prompts and unlock dialogs. Prefer
  the Wayland virtual-input backend where the compositor supports it.

**Exposure surface**

- [ ] CDP debug port `127.0.0.1:9222` (browser automation) is loopback-only and
  firewalled; treat anything listening there as having full control of that
  browser profile
- [ ] Prometheus `/metrics` endpoint bound to loopback or scraped via Unix
  socket; metrics expose tool-call counts and can reveal usage patterns
- [ ] hyprctl IPC socket (`$XDG_RUNTIME_DIR/hypr/`) not forwarded, not shared
  into containers, not chmod'd beyond session-user access

**Operations**

- [ ] Audit log (`audit.jsonl`) reviewed or shipped to a local SIEM;
  `auth.failure`, `whitelist.violation`, and `path.violation` events warrant
  alerting
- [ ] `cargo audit` run on every upgrade
- [ ] Full-disk encryption (e.g., LUKS) enabled — history is encrypted at rest,
  but swap and tmp files are outside the server's control

---

## Known Limitations (honest assessment)

- **A fully authorized client can drive the whole desktop.** The consent
  gate forces a human-visible challenge for the destructive tool class, but
  authentication still proves *which* key called, not *whether the human
  approved every action*. A prompt-injected but properly authenticated
  agent is inside the trust boundary; the arg-constrained whitelist,
  consent gate, and hash-chained audit log bound but do not eliminate that
  risk.
- **stdio is deliberately unauthenticated.** This is correct for the local
  threat model but means any process running as the user that can launch or
  ptrace the server can use it.
- **uinput mode weakens input provenance.** Kernel-level input cannot be
  distinguished from physical input by other applications.
- **AT-SPI2 exposes the a11y tree to the session bus.** Any local application
  on the same bus can read window contents; ultranix-mcp does not add a
  boundary there, it inherits the existing one.
- **No built-in TLS on `:3010`.** If transport encryption is needed, terminate
  it in a reverse proxy or use an SSH tunnel.

---

**Last updated**: 2026 — Policy version 1.0.0
