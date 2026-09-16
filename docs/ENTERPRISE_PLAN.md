# ultranix-mcp - Enterprise & Governance Plan

Strategic framing to position ultranix-mcp in the enterprise/security lane and
define the governance surface organisations need before letting AI agents
drive a Linux desktop. Adapted from `ultramac/docs/ENTERPRISE_PLAN.md`; the
primitives (audit JSONL, encrypted history, Prometheus, key auth) are shared
across the Ultra\* family so operators see one control model on every OS.

**Status: v1.4.0 shipped.**The core governance surface (key auth, consent
gate, audit JSONL + HMAC signing, AES-256-GCM history, rate limiting,
Prometheus metrics, opt-in Sentry) is implemented; the v1.3.0 wave added the
runtime access-control policy (`policy.toml` + `--readonly`/`--allow-tools`/
`--deny-tools`), per-key role scoping, and the per-backend/build-info metrics.
The v1.4.0 reach wave added reach (new window rungs, `screen_stream`, dynamic
plugin tools, OCI/`-bin` distribution) without changing this governance
surface - plugin-exposed tools are policy-checked under their own names and
still require `plugin_run` to be allowed.
Items still tagged *post-v1* below are the
planned policy roadmap, not shipped features.

---

## 1. Positioning statement

> **ultranix-mcp is the enterprise-grade, Wayland-native
> desktop-automation layer for AI agents on Linux.**Where existing Linux
> automation is a scatter of `xdotool` scripts and X11-era hacks, ultranix-mcp
> delivers compositor-native control (Hyprland/wlroots first, portals
> everywhere else) wrapped in the same governance surface as its macOS and
> Windows siblings - so organisations can let agents drive a Linux desktop
> without giving up auditability, least privilege, or observability.

Target buyer: **platform/infrastructure teams**running Linux developer
workstations or VDI fleets, **AI-automation leads**who need SOC2-adjacent
controls over agent desktop access, and **power users**(Arch/CachyOS,
Hyprland) who value security and deterministic behaviour.

---

## 2. Governance story

Governance is the product. Every agent action is attributable, rate-limited,
sanitized, encrypted at rest, and observable - on a single user daemon with
no external dependencies.

### 2.1 Access control

- **`uxcp_*` API keys**- HTTP transport requires `X-API-Key: uxcp_...`
  (canonical header; `Authorization: Bearer uxcp_...` is accepted as an
  equivalent) validated against `ULTRANIX_MCP_API_KEY` or
  `ULTRANIX_MCP_API_KEY_FILE`. Auth is **fail-closed**: with no key source
  configured, the server refuses to bind `:3010` - there is no dev-key
  generation. Stdio transport is single-owner (spawned by the client) and
  needs no key. `ULTRANIX_MCP_DISABLE_AUTH=true` is a development-only
  escape hatch and is logged as a warning at startup.
- **Least privilege by construction**- the primary Hyprland path
  (wlr-screencopy, wlr-virtual-pointer, virtual-keyboard) requires **no
  root, no groups, no udev changes**. Elevation is only ever needed for the
  *fallback* uinput path, and even then via a group-scoped udev rule
  (dedicated `ultranix-input` group holding only the service user;
  seat-scoped `uaccess` variant supported - it **complements**, never
  replaces, the dedicated-group rule) rather than a daemon running as
  root. Reusing the `input` group is explicitly rejected - it grants read
  of real input devices, i.e. a keylogger permission.
- **Consent gate**- destructive tools (`system_command`,
  `clear_action_history`, `replay_action`, `window_control` `close`,
  `clipboard_set`, `clipboard_clear`)
  return `-32015 ConsentRequired` plus a single-use challenge token; the
  client retries with `consent_token` attached. `--allow-destructive`
  bypasses the gate as an operator opt-out, announced at startup and in
  the audit log.
- **Tool-category gating**- `--category=mouse,keyboard,vision,automation,admin,clipboard`
  at process start defines the maximum capability surface across the 40
  snake_case tools; a client cannot enumerate tools outside the served set.

### 2.2 Audit trail - `~/.ultranix-mcp/logs/audit.jsonl`

One JSON object per line, append-only, fsync-batched. The v1 schema below
extends the canonical record (`timestamp`, `tool`, `args_hash`, `outcome`,
`duration_ms`, `key_id`, `prev_hash`) mandated by `docs/ARCHITECTURE.md` §2/§7 -
**extension fields may be added, but canonical fields are never renamed**:

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | string (RFC 3339, UTC, µs) | Event timestamp. |
| `event_id` | string (UUIDv7) | Unique, time-ordered event ID. |
| `session_id` | string | MCP session; ties N calls to one client connection. |
| `tool` | string | Tool name, e.g. `mouse_click`. |
| `category` | string | `mouse` \| `keyboard` \| `vision` \| `automation` \| `admin` \| `clipboard`. |
| `args_hash` | string (SHA-256) | Hash of canonicalized arguments - enables correlation without storing secrets/typed text. |
| `args_summary` | object | Redacted argument summary (coordinates, window id, selector kind - never raw typed strings). |
| `outcome` | string | `ok` \| `tool_error` \| `consent_required` \| `denied` \| `error`; `http_gate` records use `auth_rejected` \| `rate_limited`. |
| `denial_reason` | string \| null | Emitted only on `tools/call` policy denials: `readonly_mode` \| `not_in_tool_list`. HTTP gate rejections (auth/rate-limit) record their reason in `outcome`, not here. |
| `duration_ms` | number (ms) | Server-side execution time. |
| `backend` | string | Executing backend: `wlroots` \| `uinput` \| `portal` \| `atspi` \| `hyprland-ipc` \| `cdp` \| `x11`. |
| `client_id` | string | MCP client identity from `initialize` (e.g. `claude-desktop/1.x`). |
| `key_id` | string (SHA-256, truncated to 8 hex chars) | Which `uxcp_*` key authorized the call - the same key-ID used by rate limiting and `auth.*` events (`docs/API_KEY_MANAGEMENT.md` §5); `null` for stdio. |
| `prev_hash` | string (SHA-256) | Hash of the preceding audit record's serialized line (including its `hmac`, when present) - chains the log for tamper-evidence before SIEM ingestion. |
| `hmac` | string (hex) | Optional per-line HMAC-SHA256 over the record's canonical JSON *without* this field; present only when `ULTRANIX_MCP_AUDIT_SECRET` is set (v1.3.0). Enable on a fresh/rotated log - verification of a file containing pre-secret unsigned lines fails on those lines. |
| `transport` | string | `stdio` \| `http` (+ remote IP for http). |
| `version` | string | ultranix-mcp semver + build feature set. | Design rules: **typed text and screenshots are never written to the audit
log**- only hashes and metadata. Denied calls are audited identically to
allowed calls (rejection is itself a security event). Log rotation is
spec'd at a **30-day retention default**(`audit.jsonl` rolls to
`audit.<date>.jsonl`; fleet shippers should ingest before rotation).

### 2.3 Encrypted action history

`~/.ultranix-mcp/history.json` is the replayable action history (what the
agent did, for `get_action_history` and session resume). It is encrypted
with **AES-256-GCM**, keyed by `ULTRANIX_MCP_HISTORY_SECRET` (generated
per-install if unset). The audit log stays plaintext JSONL by design -
tamper-evidence is provided by shipping it to SIEM, not by hiding it.

### 2.4 Input sanitization & rate limiting

- All tool arguments pass rmcp-generated schema validation plus the security
  layer's semantic checks: shell-metacharacter and control-character
  stripping, length caps, an **arg-constrained six-binary command whitelist**
  for `system_command` (`grim`, `slurp`, `hyprctl`, `scrot`, `xdotool`,
  `wmctrl` - resolved to absolute binary paths at startup so `PATH` shims
  cannot satisfy it), and a canonicalized path whitelist
  (`$XDG_RUNTIME_DIR`, `/tmp`, `~/.ultranix-mcp/**` only).
  Argument constraints are part of the whitelist contract: `hyprctl` denies
  `dispatch exec`/`exec-once`; `xdotool`/`wmctrl` are X11-session-only;
  `busctl`/`gdbus` are deliberately absent.
- Token-bucket rate limiting: **10 requests/second per client identity**;
  `/metrics` and `/health`/`/readyz` are exempt so monitoring is never
  starved. Rejections return 429, emit `outcome=denied` audit events, and
  increment `ultranix_mcp_rate_limit_rejections_total`.

### 2.5 Prometheus observability

`GET /metrics` on `127.0.0.1:3010` (HTTP mode) exposes the ten shipped
metrics. The table below **mirrors `docs/ARCHITECTURE.md` §7
verbatim**- that document owns the metric names, types, and labels; this
copy exists for reader convenience and must not diverge:

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `ultranix_mcp_tool_calls_total` | Counter | `tool`, `outcome` | Tool call count by outcome |
| `ultranix_mcp_tool_duration_seconds` | Histogram | `tool` | Per-tool execution latency |
| `ultranix_mcp_backend_calls_total` | Counter | `backend`, `outcome` | Tool call count by resolved backend and outcome (v1.3.0) |
| `ultranix_mcp_build_info` | Gauge | `version` | Build info - constant `1` labelled with the package version (v1.3.0) |
| `ultranix_mcp_rate_limit_rejections_total` | Counter | `reason` | 429 rejections |
| `ultranix_mcp_auth_failures_total` | Counter | `reason` | HTTP auth failures (401s) |
| `ultranix_mcp_active_sessions` | Gauge | `transport` | Live stdio/HTTP sessions |
| `ultranix_mcp_backend_active` | Gauge | `backend` | Backends initialised at startup (1 = active) |
| `ultranix_mcp_action_history_size` | Gauge | - | Records retained in encrypted history |
| `ultranix_mcp_ocr_cache_entries` | Gauge | - | Live entries in the OCR/icon result cache (shipped at v1.1.0) | `/readyz` doubles as a governance surface: it reports which of the eight
providers resolved to `Some`, so monitoring can detect unexpected backend
degradation (e.g. `CaptureProvider` falling from `WlrCapture` to portal
or `None`).

The v1.3.0 wave shipped the two former candidates - the per-backend
invocation counter (`ultranix_mcp_backend_calls_total`) and the
build-info gauge (`ultranix_mcp_build_info`) - bringing the shipped set
to ten series.

Scrape config mirrors ultramac's `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "ultranix-mcp"
    static_configs:
      - targets: ["localhost:3010"]
    metrics_path: "/metrics"
    scrape_interval: 10s
```

Alert candidates: `ultranix_mcp_rate_limit_rejections_total` growth,
`ultranix_mcp_auth_failures_total` growth, `outcome="error"` ratio on
`ultranix_mcp_tool_calls_total` > 5%, `ultranix_mcp_backend_active`
transitioning to a weaker backend, and `/readyz` reporting a degraded
provider set versus the wlroots baseline.

---

## 3. Compliance mapping (SOC2-friendly controls)

ultranix-mcp is not itself certifiable, but it provides the *evidence
primitives* auditors ask for:

| SOC2-ish criterion | ultranix-mcp control |
| --- | --- |
| **CC6.1 - Logical access**| `uxcp_*` bearer auth on HTTP; stdio is spawn-scoped to the owning user; `ULTRANIX_MCP_DISABLE_AUTH` flagged at startup and in the audit log (`auth.disabled` event). |
| **CC6.6 - Boundary protection**| Server binds localhost by default; no inbound remote-desktop surface; desktop control never crosses a network hop. |
| **CC6.7 - Data in transit**| stdio = no transport exposure; HTTP = localhost TLS optional via reverse proxy; nothing leaves the host except what the MCP client already sends. |
| **CC6.8 - Least privilege**| wlroots protocols need zero elevation; uinput uses a documented udev rule (dedicated `ultranix-input` group or seat `uaccess`), never root; `--category` caps capability; arg-constrained `system_command` whitelist with absolute binary pinning; consent gate on destructive tools; no `sudo` anywhere in the design. |
| **CC7.2 - Monitoring/detection**| append-only `audit.jsonl`; denied-call auditing; Prometheus metrics incl. the rate-limit rejection and auth-failure counters. |
| **CC7.3 - Security event evaluation**| `denial_reason` taxonomy distinguishes abuse (rate limit) from misconfig (whitelist) from attack (sanitization rejection). |
| **CC8.1 - Change management**| semver releases on crates.io/AUR; committed `Cargo.lock`; `--locked` installs; SBOM via `cargo audit`/`cargo sbom` in CI. |
| **A1.2 / C1.1 - Confidentiality**| AES-256-GCM history at rest; audit log carries hashes, not payloads; `~/.ultranix-mcp/` created `0700`. | **Data residency:**ultranix-mcp performs zero telemetry egress - no
phone-home, no analytics. Sentry error reporting is **strictly opt-in**via
`ULTRANIX_MCP_SENTRY_DSN` (wired at v1.1.0; unset or malformed DSN leaves
it disabled). The single built-in network fetch is the **first-call ONNX
model download**into `~/.ultranix-mcp/models/` (SHA-256-pinned; see
`docs/ARCHITECTURE.md` §6), which can be pre-seeded by fleet tooling to make
deployment fully offline. All other egress is operator-added (Prometheus
scrape, SIEM shipper).

---

## 4. Deployment patterns

### 4.1 Per-developer workstation (primary pattern)

- Install via AUR/`cargo install`; MCP client spawns
  `ultranix-mcp --transport stdio`.
- The server inherits the developer's Wayland session - same user, same
  seat, same D-Bus. No service management needed; the client is the process
  supervisor.
- Governance still applies: audit JSONL + encrypted history are per-user
  under `~/.ultranix-mcp/`; org shippers (Vector/Filebeat, §5) forward to
  central SIEM.
- For multi-agent fleets on one workstation, run the **user service**
  (`WantedBy=graphical-session.target`, see `docs/PACKAGING.md` §6) and
  point clients at `http://localhost:3010` with per-client `uxcp_*` keys.

### 4.2 VDI / remote-desktop caveat (important)

Desktop automation requires a **real composited session**. ultranix-mcp
controls the session it is launched inside - it cannot reach into a remote
framebuffer from outside.

-  Works: VDI where each user lands in a genuine Wayland session (e.g.
  wayvnc-attached wlroots seat, GNOME/KDE remote sessions backed by a real
  compositor), with ultranix-mcp installed inside the session.
-  Partial: portal fallback works on GNOME/KDE remote sessions but shows
  a consent prompt per capture unless restore tokens persist - VDI images
  must persist `~/.local/share/flatpak`-adjacent portal token state or
  pre-seed it.
-  Does not work: driving the console of a headless VM, RDP virtual
  channels where no wlroots/XDG session exists for the target user, or
  cross-seat injection. Do not market ultranix-mcp as an RPA-over-RDP tool.

### 4.3 CI / headless limits (be honest about it)

- Unit and integration tests run headless via **nested wlroots compositors**
  (`cage`/`weston` headless instances give disposable sessions, per the
  testing strategy): capture + virtual input function, so E2E tool tests
  are possible in CI.
- Portals and AT-SPI are degraded in headless CI (no real consent UX, sparse
  a11y trees) - those paths are covered by mocked `zbus` peers, not live
  desktops.
- ultranix-mcp is **not**a CI scraping tool: the only container topology is
  the documented degraded mode (`docs/PACKAGING.md` §1,
  `docs/ARCHITECTURE.md` Deployment Architecture) for CI smoke tests, and
  there is no "headless production" mode. CI is for testing ultranix-mcp,
  not for running agents against disposable desktops at scale - that
  workload should use browser automation (CDP/Playwright).

---

## 5. SIEM ingestion

`audit.jsonl` is deliberately line-delimited JSON on disk - the most
shippable format that exists. Reference integrations:

**Vector**(`vector.toml`):

```toml
[sources.ultranix_audit]
type = "file"
include = ["/home/*/.ultranix-mcp/logs/audit.jsonl"]

[transforms.ultranix_parse]
type = "remap"
inputs = ["ultranix_audit"]
source = '. = merge(., parse_json!(.message))'

[sinks.siem]
type = "elasticsearch"   # or splunk_hec / loki / kafka
inputs = ["ultranix_parse"]
endpoint = "https://siem.internal:9200"
```

**Filebeat:**

```yaml
filebeat.inputs:
  - type: filestream
    paths: [/home/*/.ultranix-mcp/logs/audit.jsonl]
    parsers: [{ ndjson: { target: ultranix, add_error_key: true } }]
    fields: { source: ultranix-mcp, event_type: agent-desktop-action }
```

**Grep/forensics without a SIEM:**`jq 'select(.outcome=="denied")'` over the
log; `args_hash` lets an investigator prove *which* calls an agent made
without the log ever containing the payload.

Correlation keys for the SIEM schema: `session_id` (client session),
`key_id` (which credential), `client_id` (which MCP client),
`event_id` (dedup on reship), `prev_hash` (chain verification on ingest).

---

## 6. Policy knobs roadmap

Shipped controls vs. planned policy surface:

| Knob | Status | Notes |
| --- | --- | --- |
| `--category=` tool filtering | **Shipped (v1.0.0)**| Startup capability cap; the primary policy lever today. |
| Input sanitization + arg-constrained whitelists | **Shipped (v1.0.0)**| Security scaffolding: keysym whitelist, bounds checks, selector-injection rejection, the six-binary `system_command` whitelist with absolute binary pinning (`hyprctl` denies `dispatch exec`/`exec-once`; `xdotool`/`wmctrl` X11-only), and the path whitelist (`$XDG_RUNTIME_DIR`, `/tmp`, `~/.ultranix-mcp/**`). |
| Consent gate | **Shipped (v1.0.0)**| Destructive tools (`system_command`, `clear_action_history`, `replay_action`, `window_control` `close`, `clipboard_set`/`clipboard_clear` since v1.2.0) return `-32015 ConsentRequired` + challenge token; retry with `consent_token`; `plugin_run` steps re-challenge per step; `--allow-destructive` bypass. |
| Audit skeleton (JSONL append + schema) | **Shipped (v1.0.0)**| `audit.jsonl` with `key_id`/`args_hash`/`prev_hash` chaining. |
| API-key auth + disable flag | **Shipped (v1.0.0)**| The HTTP-transport auth surface (`uxcp_*` key check, `X-API-Key`/`Bearer` headers, key files, rotation overlap, auth audit events). Fail-closed bind semantics are intrinsic - the server refuses to bind `:3010` without a key unless `ULTRANIX_MCP_DISABLE_AUTH=true`. |
| Rate limiting (10 req/s token bucket per client identity) | **Shipped (v1.0.0)**| HTTP-transport feature; `/metrics` and health endpoints exempt; env-tunable budget. |
| Encrypted history + Prometheus | **Shipped (v1.0.0)**| AES-256-GCM `history.json`, the shipped metrics (8 series as of v1.1.0; 10 since v1.3.0), `/health`+`/readyz`. |
| Sentry crash reporting | **Shipped (v1.1.0)**| Opt-in via `ULTRANIX_MCP_SENTRY_DSN`; malformed DSN warns and disables. |
| **Tool whitelists**(`--allow-tools=`, deny-by-default profiles) | **Shipped (v1.3.0)**| `--allow-tools=t1,t2` and `--deny-tools=t3` on the CLI, plus `allow_tools`/`deny_tools` per role in `policy.toml`. Deny wins; unlisted tools get `-32019`. |
| **Read-only mode**(`--readonly`) | **Shipped (v1.3.0)**| Advertises and allows only the non-mutating catalog (15 tools); every input/mutation call is denied (`-32018 ReadOnlyMode`, `denial_reason=readonly_mode`). |
| **Approval gates (beyond the shipped consent gate)**| **Post-v1**| Out-of-band confirmation for sensitive calls - e.g. text typed into password-focused fields - pluggable: local libnotify/dunst prompt on the desktop, or a webhook to an approver service. Builds on, does not replace, the `-32015 ConsentRequired` challenge. |
| **Per-key scoping**| **Shipped (v1.3.0)**| `policy.toml` maps API-key fingerprints to named roles; HTTP sessions see and call only their role's tools. Unknown keys fall back to `default_role`. |
| **Config file policy**(`~/.config/ultranix-mcp/policy.toml` or `--policy`) | **Shipped (v1.3.0)**| TOML file defining `default_role`, named `roles`, and `keys` mappings; CLI flags layer on top. |
| **Audit HMAC**(`ULTRANIX_MCP_AUDIT_SECRET`) | **Shipped (v1.3.0)**| Every `audit.jsonl` line is HMAC-SHA256-signed over its canonical JSON; `verify_hmac_at` validates the full chain + signatures. | ---

## 7. Competitive wedge (vs the Linux status quo)

| Alternative | Strength | ultranix-mcp's counter-position |
| --- | --- | --- |
| `xdotool`/`scrot`/`wmctrl` scripts + bespoke MCP wrappers | Ubiquitous, trivially installed | X11-only, zero security surface; ultranix-mcp is **Wayland-native**with audit/rate-limit/encryption. |
| Anthropic "computer use" on X11 VMs | Official pattern, model-driven | Requires a full X11 VM + pure-vision loop; ultranix-mcp adds **AT-SPI2 semantic UI**(deterministic targeting) and real-session control. |
| ydotool/uinput DIY | Wayland-compatible input | Input-only, needs root or broad `input` group; ultranix-mcp's wlroots path needs **no privilege at all**and adds capture+a11y+governance. |
| ultramac / UltraWin (siblings) | Proven enterprise surface on their OSes | ultranix-mcp completes the tri-OS governance story with **one control model**: same key format, audit schema, metric naming. | ---

## 8. Metrics to track adoption

- **Distribution funnel:**AUR votes/popularity -> crates.io downloads ->
  weekly active servers (opt-in metric proxy: release-asset hits).
- **Enterprise signals:**SIEM-config shares in docs traffic, policy.toml
  usage, read-only-mode deployments reported.
- **Security credibility:**advisories handled, `cargo audit` posture,
  third-party reviews of the audit/encryption design.
- **Community:**Hyprland/AUR community adoption, awesome-mcp listing,
  dotfiles-repo mentions.

---

## 9. Open decisions

- [ ] OSS license: ISC (family convention) vs Apache-2.0 - revisit only if a
      commercial tier is introduced.
- [ ] Approval-gate UX: local desktop prompt vs webhook - post-v1 design.
- [x] ~~Whether audit JSONL needs optional signing~~ - **resolved at
      v1.3.0**: `ULTRANIX_MCP_AUDIT_SECRET` signs each line with
      HMAC-SHA256 over its canonical JSON (optional, env-gated; the
      `prev_hash` chain covers the signed line). Enable on a
      fresh/rotated log - pre-secret unsigned lines fail verification.
- [ ] Enterprise tier scope (if any): policy.toml fleet management,
      per-key scoping, and SSO-brokered key issuance are the natural paid
      surface - mirroring ultramac's $19-49/mo band.

---

*Companion to `docs/PACKAGING.md` and `docs/MARKET_ANALYSIS.md`.*
