# API Versioning Strategy

## Overview

ultranix-mcp follows semantic versioning (SemVer) for API stability and
backwards compatibility, modelled on the ultramac-mcp / ultrawin-mcp family
policy. Because the project has three distinct contracts — the **server
release**, the **tool surface**, and the **MCP protocol** spoken on the wire —
each is versioned and evolved under its own rules below.

## The Three Version Tracks

| Track | Identifies | Bumped when | Exposed via |
| --- | --- | --- | --- |
| **Server version** | The `ultranix-mcp` crate/release | every release | `initialize` → `serverInfo.version`; `--version`; crates.io/AUR package version |
| **Tool-surface version** | The set of tool names + inputSchemas + response shapes documented in [TOOLS.md](TOOLS.md) | per the change matrix below | `initialize` → `capabilities.ultranix.toolSurfaceVersion` |
| **MCP protocol version** | The wire protocol negotiated with the client | only when the MCP spec revs | `initialize` → `protocolVersion` (negotiated) |

Server version and tool-surface version move together (the tool surface is
frozen per server release); the protocol version moves independently and is
always the *highest mutually supported* version from the `initialize`
handshake.

**Current versions:** server `1.1.0` · tool surface `1.0`
(32 tools) · protocol negotiated per MCP spec.

## Versioning Scheme

**Format**: `MAJOR.MINOR.PATCH` (tool-surface version drops `PATCH` — schema
fixes ship as server PATCH releases without changing the surface identifier).

- **MAJOR**: breaking changes to the tool surface (see matrix)
- **MINOR**: new tools or backwards-compatible additions
- **PATCH**: bug fixes, performance, provider internals, doc/schema-clarifying
  fixes that change no behaviour

## Change Classification Matrix

✅ **Breaking** (requires MAJOR bump):

- Removing a tool
- Renaming a tool or parameter (see [Renames](#renames) — never silent)
- Removing or renaming a required parameter
- Changing a parameter's type or a response's field types
- Changing response *structure* (e.g. `matches[]` → `match`)
- Tightening an enum used as input, or widening an enum clients must switch on
- Changing error **codes** or `data.kind` discriminators
- Changing coordinate-space or unit semantics of an existing field

❌ **Non-breaking** (MINOR or PATCH):

- Adding new tools (MINOR)
- Adding **optional** parameters with defaults (MINOR) — including the
  `consent_token` parameter on destructive tools
- Adding fields to JSON text-content responses (MINOR)
- Widening an input enum, tightening an output range (MINOR)
- New error codes in the server-defined `-32000…-32099` range and new
  `data.kind` variants for existing codes (MINOR — clients must treat
  unknown codes/kinds as opaque). The destructive-action **consent gate**
  (`-32015 ConsentRequired` challenge + `consent_token` retry) is such an
  additive guard: it adds a new code and optional parameter without
  changing any existing tool's schema, success shape, or code/kind set.
- Bug fixes, performance, provider fallback-chain changes (PATCH)
- Exact error message text (PATCH — only codes/kinds are stable)

## Renames

**A tool or parameter is never silently renamed.** A rename is a removal plus
an addition and follows this process:

1. **Release N**: the new name is added; the old name remains registered as a
   working alias marked `[DEPRECATED] use <new> instead; removal in v<next MAJOR>`
   in its `tools/list` description.
2. **Releases N → N+2** (minimum two MINOR releases **or** 90 days, whichever
   is longer): both names work. Calls to the old name succeed and are
   recorded in `audit.jsonl` with `"deprecated_alias": true`.
3. **Next MAJOR**: the old name is removed; calls return `-32601
   MethodNotFound` with `data.kind = "RemovedTool"` and `data.removed_in`.

The same rule applies to parameters: an old parameter name is accepted as an
alias (mapped to the new name) for the deprecation window, then rejected with
`InvalidParams`.

## Deprecation Process

1. **Announce** — mark in the tool description and `CHANGELOG.md`:

   ```json
   {
     "name": "old_tool",
     "description": "[DEPRECATED] Use new_tool instead. Will be removed in v2.0.0"
   }
   ```

2. **Support** — maintain for ≥ 2 minor versions (or ≥ 90 days); log a
   deprecation line to `audit.jsonl` on every use; keep docs updated with a
   migration note.
3. **Remove** — at the next MAJOR only, with a migration guide in the
   changelog. `tools/list` output and `docs/TOOLS.md` are updated atomically
   with the removal — a tool never exists in code while absent from docs.

**Changelog requirement**: every release that adds, deprecates, renames, or
removes a tool MUST carry a `CHANGELOG.md` entry naming the tool and the
migration path. A release PR without a changelog entry for a surface change
fails CI (`cargo xtask verify-changelog`).

## Adding Tools

- New tools are always MINOR; they ship behind their maturity phase and are
  listed in `tools/list` as soon as merged.
- Tool names are permanent once published — `snake_case`, prefixed by
  category convention (`mouse_`, `key_`, `screen_`, `get_`, `find_`,
  `wait_for_`, `web_`, `window_`). Name review happens pre-merge, not
  post-release.
- Tools gated to a future phase may ship disabled-by-default under
  `[EXPERIMENTAL]` marking (below).

## Category Filters

The `--category` launch flag (e.g. `--category mouse,vision`) restricts which
tool groups are registered:

- Filtering is a **deployment/configuration** concern, not a versioned API
  change: it never requires a version bump and never alters the guarantees of
  the remaining surface.
- Filtered-out tools are **omitted from `tools/list`** entirely; calls to
  them return `-32601 MethodNotFound` with `data.kind = "CategoryDisabled"`
  and `data.category`, so clients can distinguish "does not exist" from
  "disabled by operator".
- The **default** category set (all categories enabled) is part of the stable
  contract: removing a tool from the default set is a removal (MAJOR); adding
  one is MINOR.
- `--category` accepts the five groups used in TOOLS.md: `mouse`,
  `keyboard`, `vision`, `automation`, `admin`.

## Capability Negotiation

On `initialize`, the server performs standard MCP negotiation and additionally
publishes an extension block:

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "result": {
    "protocolVersion": "2025-06-18",
    "serverInfo": { "name": "ultranix-mcp", "version": "1.1.0" },
    "capabilities": {
      "tools": { "listChanged": true },
      "ultranix": {
        "toolSurfaceVersion": "1.0",
        "categories": ["mouse", "keyboard", "vision", "automation", "admin"],
        "providers": ["wlr-screencopy", "wlr-virtual-input", "atspi2", "hyprctl", "ort", "cdp"],
        "features": {
          "spatialFocus": true,
          "actionHistory": true,
          "imageContent": true
        }
      }
    }
  }
}
```

Rules:

- `protocolVersion` in the response is the negotiated version — the server's
  highest version ≤ the client's request, or the server's minimum when the
  client asks for something older; clients MUST honour the returned value.
- `capabilities.ultranix` is additive-only within a MAJOR line: new keys may
  appear in MINOR releases; existing keys never change type or disappear.
- `providers` reports which backends actually initialised — clients can
  pre-flight `find_element` by checking for `atspi2` rather than catching
  `ProviderUnavailable`.
- `features.spatialFocus` is `true` at v1.0.0 — `set_spatial_focus` installs a
  process-global rect that scopes `screenshot`/`find_text_on_screen`/
  `find_icon` (never persisted; see docs/TOOLS.md §Spatial Focus).
- When the enabled tool set changes at runtime (future dynamic loading), the
  server emits `notifications/tools/list_changed` (`listChanged: true`
  advertises support).

## Version Detection

```rust
// initialize handshake — serverInfo.version
let info = client.initialize(...).await?;
assert_eq!(info.server_info.name, "ultranix-mcp");
```

```bash
# Binary
ultranix-mcp --version        # ultranix-mcp 1.1.0

# HTTP transport
curl -s http://127.0.0.1:3010/health | jq .version   # "1.1.0"

# Package metadata
cargo info ultranix-mcp | head -1
```

## Backwards Compatibility Guarantees

**Guaranteed stable within a MAJOR line:**

- Tool names and categories
- Required parameters, parameter types, enums used as input
- Response content shape (text vs image; JSON field names/types)
- Error codes and `data.kind` values
- `uxcp_*` key format, `ULTRANIX_MCP_*` env var names, `:3010` default port,
  canonical health endpoints (`/health`, `/readyz`)
- Destructive-tool consent-gate semantics (`-32015 ConsentRequired`
  challenge flow, `consent_token` parameter, `--allow-destructive` bypass)
- Command arg-constraint semantics (allowed binaries and their sanctioned
  argument sets may be added, never removed, in a MINOR; removing a binary
  or tightening an existing binary's argument set is MAJOR)

**May change in MINOR/PATCH:**

- Optional parameters and response fields (additions only)
- Provider fallback order and internal mechanisms
- Error message text, audit log line format (schema-tagged)
- Performance characteristics

## Experimental Features

Tools or parameters marked `[EXPERIMENTAL]` in their description may change
without a MAJOR bump and are excluded from the stability guarantee until the
marker is removed (removal of the marker is itself a MINOR changelog entry).
Experimental tools are never enabled by default in the stable category set;
they require `--category +experimental` or per-tool opt-in.

## Support Policy

| Version | Support status | Notes |
| --- | --- | --- |
| `main` | Development | no guarantees; post-v1 work lands here |
| `0.x` | EOL (pre-stable) | superseded by 1.x — upgrade; no further 0.x releases |
| `1.x` | Active | full guarantees above; security + critical fixes ship as patch releases |

## Version Metadata

All `tools/call` results carry server identity in `result._meta`:

```json
{
  "_meta": {
    "server": "ultranix-mcp",
    "serverVersion": "1.1.0",
    "toolSurfaceVersion": "1.0",
    "protocolVersion": "2025-06-18"
  }
}
```

## References

- [Semantic Versioning](https://semver.org/)
- [Model Context Protocol spec](https://modelcontextprotocol.io)
- [TOOLS.md](TOOLS.md) — the versioned surface this policy protects
