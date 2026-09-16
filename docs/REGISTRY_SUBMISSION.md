# Registry Submission Packet

Ready-to-paste listings for the major MCP registries and package channels.
Copy each section to the corresponding registry's "Add server / Submit" form.
All six phases shipped at **v1.0.0**, the post-v1 backlog wave (Sentry,
X11-native providers, PipeWire capture, OCR cache, extra metrics) landed at
**v1.1.0**, and the breadth wave (clipboard tools, plugin tool-macros,
bounded `screen_record`, sway/Wayfire/river/KDE/GNOME detection + the
`sway-ipc` window provider, per-backend cargo features, history v2) landed
at **v1.2.0**, and the policy-and-governance wave (runtime `policy.toml`
access control with per-key role scoping, `--readonly`/`--allow-tools`/
`--deny-tools`, `-32018`/`-32019` denials, backend + build-info metrics,
audit-log HMAC signing) landed at **v1.3.0** — the package/channel rows
below mark which submissions are still pending.

**Date:** 2026-09-14
**Maintainer:** jxoesneon (`https://github.com/jxoesneon`)
**Repo:** `https://github.com/jxoesneon/ultranix-mcp`
**License:** ISC

---

## Universal one-liner

```
ultranix-mcp — Enterprise-grade, secure Linux desktop automation for AI
agents (mouse, keyboard, screen/OCR/vision + bounded recording, AT-SPI2 UI
tree, Hyprland/sway window control, clipboard tools, plugin tool-macros,
browser DOM) via the Model Context Protocol. Rust + tokio + rmcp.
SOC2-ready posture: audit logging, rate limiting, input sanitization, and
AES-256-GCM-encrypted action history.
```

---

## Package naming

| Channel | Name | Status |
| --- | --- | --- |
| crates.io | `ultranix-mcp` | publish pending (`cargo install ultranix-mcp`) |
| AUR | `ultranix-mcp` (source build), `ultranix-mcp-bin` (prebuilt binary), `ultranix-mcp-git` (`main` HEAD) | PKGBUILDs shipped under `packaging/`; submission pending — see [PACKAGING.md](PACKAGING.md) |
| GitHub Releases | `ultranix-mcp` (per-arch tarballs) | every tag (`release.yml`) |
| OCI image | `ghcr.io/jxoesneon/ultranix-mcp` | planned — the committed `server.json` already points its single `packages[]` entry at `ghcr.io/jxoesneon/ultranix-mcp:1.3.0`; the image itself is a planned artifact for the **documented degraded mode** (headless/CI use only; the native install is primary — see [PACKAGING.md](PACKAGING.md) §1) |
| Nix flake | `github:jxoesneon/ultranix-mcp` | `flake.nix` shipped at v1.2.0 — **unverified** (never evaluated; see [PACKAGING.md](PACKAGING.md) §4) |

## Install commands (documented in README)

```bash
# crates.io
cargo install ultranix-mcp

# AUR (Arch / Manjaro) — prebuilt binary, source build, or git HEAD
paru -S ultranix-mcp-bin        # or: ultranix-mcp / ultranix-mcp-git

# From source
git clone https://github.com/jxoesneon/ultranix-mcp
cd ultranix-mcp && cargo build --release

# Run — stdio (default, for MCP client embedding)
ultranix-mcp --transport stdio

# Run — streamable HTTP on :3010
ULTRANIX_MCP_API_KEY="uxcp_<64-hex>" ultranix-mcp --transport http --bind 127.0.0.1:3010
```

## Environment variables (referenced by every listing)

| Variable | Purpose | Default |
| --- | --- | --- |
| `ULTRANIX_MCP_API_KEY` | API key(s) for HTTP auth (`uxcp_<64-hex>`, comma-separated for rotation) | none — **fail-closed**: the server refuses to bind `:3010` without a configured key; the stdio transport is unaffected |
| `ULTRANIX_MCP_API_KEY_FILE` | Path to a key file (one `uxcp_*` key per line, mode `0600` enforced) — preferred over the env var under systemd | none |
| `ULTRANIX_MCP_API_KEY_EXPIRES` | Optional key expiry — comma-separated RFC 3339 timestamps aligned with `ULTRANIX_MCP_API_KEY` (`expires=` suffix per line in key files) | none |
| `ULTRANIX_MCP_DISABLE_AUTH` | Disable auth entirely (development only) | `false` |
| `ULTRANIX_MCP_HISTORY_SECRET` | AES-256-GCM secret for `~/.ultranix-mcp/history.json` | per-install generated at first run; a dev fallback warns loudly |
| `ULTRANIX_MCP_SENTRY_DSN` | Optional Sentry error reporting — opt-in; unset, empty, or malformed DSN disables it (malformed logs a startup warning) | unset |
| `ULTRANIX_MCP_AUDIT_SECRET` | Optional HMAC-SHA256 signing of every `audit.jsonl` line (v1.3.0) — enable on a fresh/rotated log; pre-secret unsigned lines fail verification | unset |
| `ULTRANIX_MCP_BIND` | HTTP bind address (or `--bind` flag) | `127.0.0.1:3010` |

Key-source precedence: `ULTRANIX_MCP_API_KEY` → `ULTRANIX_MCP_API_KEY_FILE`
→ `~/.ultranix-mcp/api-keys/*.json` (convention fallback: a directory of
key-record files, JSON or line format, mode `0600` enforced per file).

## Runtime requirements (must appear in listings)

- Linux, Wayland session; **Hyprland** for full functionality (uinput +
  portal fallbacks cover other Wayland sessions — sway gets the `sway-ipc`
  window provider, KDE/GNOME route capture/input through portals; X11
  sessions get the shipped `scrot`/`xdotool`/`wmctrl` rungs)
- Optional: browser on `127.0.0.1:9222` (`--remote-debugging-port`) for
  `web_query`; AT-SPI2 enabled for `get_ui_tree`/`find_element`;
  `wl-clipboard` (`wl-copy`/`wl-paste`) or `xclip`/`xsel` for the
  clipboard tools
- No Node/Python dependency — single static Rust binary

---

## 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

**Required metadata** (per the registry's `server.json` schema):

- `name`: `io.github.jxoesneon/ultranix-mcp` (reverse-DNS, GitHub-namespaced)
- `description`: one line, ≤ 100 chars
- `version`: must equal the release tag being published
- `packages[]`: at least one installable package reference

**`server.json`** (committed at `server.json` in repo root — schema
2025-09-29, camelCase fields — passes `mcp-publisher validate`; the
validator warns the schema is deprecated in favour of 2025-12-11, which
we can migrate to when the registry requires it; published
via `mcp-publisher` on each tag):

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json",
  "name": "io.github.jxoesneon/ultranix-mcp",
  "description": "Secure Linux desktop automation — input, screen/OCR/vision, AT-SPI2 UI tree, window, clipboard",
  "version": "1.3.0",
  "title": "ultranix-mcp",
  "repository": {
    "url": "https://github.com/jxoesneon/ultranix-mcp",
    "source": "github"
  },
  "websiteUrl": "https://github.com/jxoesneon/ultranix-mcp",
  "packages": [
    {
      "registryType": "oci",
      "identifier": "ghcr.io/jxoesneon/ultranix-mcp:1.3.0",
      "version": "1.3.0",
      "transport": { "type": "stdio" },
      "runtimeHint": "docker",
      "environmentVariables": [
        { "name": "ULTRANIX_MCP_API_KEY", "description": "API key(s) (uxcp_*) for HTTP transport auth — required for --transport http (fail-closed), unused on stdio", "isRequired": false, "isSecret": true },
        { "name": "ULTRANIX_MCP_API_KEY_FILE", "description": "Path to a 0600 file holding uxcp_* keys, one per line", "isRequired": false, "isSecret": false },
        { "name": "ULTRANIX_MCP_API_KEY_EXPIRES", "description": "Optional RFC 3339 expiry for the env-sourced key (self-revoking)", "isRequired": false, "isSecret": false },
        { "name": "ULTRANIX_MCP_HISTORY_SECRET", "description": "AES-256-GCM secret for encrypted action history (per-install generated if unset)", "isRequired": false, "isSecret": true },
        { "name": "ULTRANIX_MCP_SENTRY_DSN", "description": "Optional Sentry DSN for error reporting (unset = disabled)", "isRequired": false, "isSecret": true },
        { "name": "ULTRANIX_MCP_AUDIT_SECRET", "description": "Optional HMAC-SHA256 signing secret for audit.jsonl lines (tamper evidence for SIEM ingestion)", "isRequired": false, "isSecret": true }
      ]
    }
  ],
  "remotes": [],
  "keywords": ["mcp", "linux", "wayland", "hyprland", "automation", "accessibility", "ocr", "computer-use", "rust"]
}
```

Notes for the submission PR:

- crates.io is not a `registryType` the official registry accepts today; the
  OCI package is the canonical installable, with `cargo install` documented
  in the README and description.
- The OCI/`docker` `runtimeHint` is the **documented degraded container
  mode** (`docs/ARCHITECTURE.md` Deployment Architecture, PACKAGING.md §1):
  it requires bind-mounting `$XDG_RUNTIME_DIR`, the session bus, and
  `/dev/uinput`, and yields portal/`None` providers. The **native install is
  primary** (crates.io/AUR + `systemd --user`); the image exists for
  headless tooling and CI smoke tests only — do not present it as a
  production topology in any listing.
- `transport.type` is `stdio`; the streamable-HTTP listener on `:3010` is
  operator-invoked (`--transport http`) and documented, not advertised as a
  remote.
- Version in `server.json` MUST equal the git tag. `server.json` is
  validated with `mcp-publisher validate` before registry submission (there
  is no automated CI gate — re-check `version`, `identifier`, and
  `packages[].version` against the tag by hand).

---

## 2. mcp.so

- **Name:** ultranix-mcp
- **Description:** Secure Linux desktop automation MCP server: mouse,
  keyboard, screenshots + bounded screen recording, OCR + vision finding,
  AT-SPI2 UI tree, Hyprland/sway window control, clipboard tools, plugin
  tool-macros, browser DOM queries. Enterprise controls (audit, rate
  limit, sanitization, encrypted action history, consent gate) built in.
- **Repo:** `https://github.com/jxoesneon/ultranix-mcp`
- **Tags:** `linux`, `wayland`, `hyprland`, `automation`, `vision`, `ocr`

---

## 3. awesome-mcp-servers (PR entry)

Append under **🖥️ Desktop Automation**:

```markdown
- [jxoesneon/ultranix-mcp](https://github.com/jxoesneon/ultranix-mcp) 🦀 🐧 🏠 - Secure Linux desktop automation for AI agents: mouse/keyboard injection, screenshots + bounded recording, OCR + OWL-ViT visual search, AT-SPI2 UI tree, Hyprland/sway window control, clipboard tools, plugin macros, and browser DOM queries. Rust + rmcp; stdio and streamable-HTTP transports.
```

Emoji legend compliance: 🦀 Rust, 🐧 Linux, 🏠 local/self-hosted. Entry is
alphabetised and one line, per the list's contributing rules.

---

## 4. Glama.ai

- **Name:** ultranix-mcp
- **Description:** Enterprise-grade, secure Linux desktop automation for AI
  agents (mouse, keyboard, screen/OCR/vision, window & UI control).
- **GitHub:** `https://github.com/jxoesneon/ultranix-mcp`
- **Language:** Rust
- **Runtime:** native binary (cargo / AUR)
- **Transports:** stdio, HTTP (streamable)
- **License:** ISC
- **Topics:** `mcp-server`, `linux`, `wayland`, `hyprland`, `automation`,
  `accessibility`, `computer-use`

---

## 5. PulseMCP

- **Name:** ultranix-mcp
- **Category:** Desktop Automation / Linux
- **URL:** `https://github.com/jxoesneon/ultranix-mcp`
- **Description:** Desktop automation + visual intelligence for Linux via
  MCP. Native mouse/keyboard/screen control on Wayland/Hyprland, OCR and
  open-vocabulary icon finding (ONNX), AT-SPI2 UI-tree access, browser DOM
  queries over CDP. Security-first: audit logging, rate limiting, input
  sanitization, AES-256-GCM-encrypted action history, API-key auth. Single
  Rust binary; stdio and HTTP transports; crates.io and AUR packages.
- **Tags:** `linux`, `wayland`, `automation`, `ocr`, `vision`, `computer-use`

---

## 6. Smithery.ai

- **Name:** ultranix-mcp
- **Category:** Desktop / OS Automation
- **Description:** Enterprise-grade Linux desktop automation for AI agents.
- **Install:** `cargo install ultranix-mcp && ultranix-mcp --transport stdio`
  (`--stdio` is an accepted alias)
- **Env vars:** `ULTRANIX_MCP_API_KEY`, `ULTRANIX_MCP_API_KEY_FILE`,
  `ULTRANIX_MCP_API_KEY_EXPIRES`, `ULTRANIX_MCP_DISABLE_AUTH`,
  `ULTRANIX_MCP_HISTORY_SECRET`, `ULTRANIX_MCP_AUDIT_SECRET` (opt-in),
  `ULTRANIX_MCP_SENTRY_DSN` (opt-in),
  `ULTRANIX_MCP_BIND` (default `127.0.0.1:3010`)
- **Repo:** `https://github.com/jxoesneon/ultranix-mcp`

---

## Submission checklist

- [ ] `README.md` leads with security posture + tool summary table; links to
  `docs/TOOLS.md`, `docs/API_VERSIONING.md`, `SECURITY.md`
- [ ] `docs/TOOLS.md` complete for every shipped tool (this repo)
- [ ] `SECURITY.md` and `LICENSE` (ISC) present
- [ ] `server.json` committed at repo root; `mcp-publisher validate` passes;
  version matches the release tag
- [ ] `Cargo.toml` metadata complete: `description`, `license = "ISC"`,
  `repository`, `keywords = ["mcp", "linux", "automation", "wayland", "hyprland"]`,
  `categories = ["command-line-utilities"]`
- [ ] Release tag + notes published (`v1.3.0`)
- [ ] `cargo publish` run for `ultranix-mcp`; AUR `ultranix-mcp-bin` PKGBUILD
  submitted
- [ ] GitHub topics set: `mcp`, `mcp-server`, `linux`, `wayland`, `hyprland`,
  `automation`, `ocr`, `computer-use`, `rust`
- [ ] `assets/icon.png` (512×512) present for registry icons
- [ ] Health endpoint (`GET /health`) and `GET /metrics` verified on `:3010`
- [ ] Each registry entry above submitted; links recorded in this file's git
  history
