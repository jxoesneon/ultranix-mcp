# Privacy Policy

**Last updated**: 2026 — **Policy version**: 1.0.0
**Status**: Implemented — describes the data handling of shipped ultranix-mcp
v1.1.0; features marked *post-v1* are not yet wired.

## Overview

ultranix-mcp is a **local-first** desktop automation server. It runs on your
machine, under your user session, and — by default — makes **zero outbound
network calls**. It exists to let an AI client see and drive your desktop;
everything it learns stays on the host unless you explicitly configure an
integration.

**The short version:** no analytics, no crash telemetry, no cloud sync, no
third-party SDKs phoning home — unless you turn one on.

---

## Local-First Guarantees

1. **No default egress.** The server opens no outbound connections during
   normal operation. The only listening socket it creates is the HTTP
   transport (`127.0.0.1:3010`, only when `--transport http` is used), which
   also serves the Prometheus `/metrics` endpoint — you control both.
2. **No hidden persistence.** Every artifact the server writes lives under
   `~/.ultranix-mcp/`. There is no state anywhere else except temporary
   screenshot files under `/tmp` (created via `mktemp`, mode `0600`, deleted
   after use).
3. **No covert channels.** Screenshot pixel data is returned to the MCP client
   that requested it and is otherwise never transmitted, logged, or persisted.

---

## Data Inventory

### What exists, where it lives, and how long it stays

| Data | Contents | Location | At-rest protection | Retention |
| ---- | -------- | -------- | ------------------ | --------- |
| **Action history** | Tool name, timestamp, arguments, result status | `~/.ultranix-mcp/history.json` | **AES-256-GCM** encrypted (key from `ULTRANIX_MCP_HISTORY_SECRET` or per-install derived material) | Until manually deleted (configurable cap) |
| **Audit log** | Every tool invocation (`key_id`, `args_hash` — never raw args — `prev_hash`-chained) + auth events (accepted *and* rejected) | `~/.ultranix-mcp/logs/audit.jsonl` | Plaintext JSONL, dir `0700`, file `0600` | 30 days (rotated) |
| **Runtime/debug log** | Operational messages, errors | `~/.ultranix-mcp/logs/` | Plaintext, `0600` | 30 days (rotated) |
| **Screenshots** | Raw frame data requested by capture tools | In-memory; `/tmp` only if a tool needs a file | `mktemp` + `0600` + explicit cleanup | Lifetime of the request |
| **API keys** | `uxcp_*` keys | Env `ULTRANIX_MCP_API_KEY` | SHA-256 hash in memory; plaintext only in your env/config | Until rotation |
| **ONNX models** | Local vision/inference models | `~/.ultranix-mcp/models/` | SHA-256-verified at download | Until deleted |
| **Metrics** | Tool-call counts, latencies, error rates | In-memory, exposed at `/metrics` | None (counters only, no content) | Process lifetime |

### Notes on the sensitive items

- **Screenshots are the crown jewels.** Frame data is processed in memory and
  returned directly to the requesting client. A file under `/tmp` is only
  created when an external whitelisted tool (e.g. `grim`, `scrot`) requires a
  path argument — it is then created via `mktemp` with mode `0600` inside the
  path whitelist and removed after the call completes.
- **Action history is encrypted**, not just permissioned. AES-256-GCM protects
  `history.json` against casual reading by other processes or backups. The key
  comes from `ULTRANIX_MCP_HISTORY_SECRET` when set, otherwise per-install
  derived material under `~/.ultranix-mcp/` — note that a key stored next to
  the ciphertext only protects against off-host copies (backups, stolen
  disks), not same-host readers. It is *not* a substitute for full-disk
  encryption — see the honest caveats below.
- **Typed text is the sharpest edge.** `type_text` arguments necessarily
  contain whatever the agent was asked to type — which may include secrets the
  *user* pasted into a prompt. These land in `history.json` (encrypted, needed
  for `replay_action`); the audit log records only a keyed `args_hash` of the
  arguments, never the raw text. Still, **do not type passwords through
  automation** — history retains them until cleared or rotated out.

---

## What Is NEVER Collected or Transmitted

- ❌ Screen contents, window titles, or a11y-tree text — sent anywhere other
  than the requesting MCP client
- ❌ Keystroke content beyond what an explicit `type_text` call was given
- ❌ Microphone, camera, or any sensor data
- ❌ Contact lists, browser history, or file contents outside an explicit tool
  call's arguments
- ❌ Device fingerprinting, install IDs, or usage analytics
- ❌ Any telemetry to us — there is no "ultranix cloud" to send it to

---

## Optional Telemetry — Strictly Opt-In

### Sentry error reporting — *opt-in, shipped at v1.1.0*

`ULTRANIX_MCP_SENTRY_DSN` enables Sentry error reporting. It is **strictly
opt-in**: unset, empty, or malformed values leave it disabled (a malformed
DSN logs a startup warning and the server continues without Sentry). When
enabled, the contract is:

- Only panic/error reports and stack frames are sent — never screenshots,
  tool arguments, history, or a11y-tree content.
- Redaction rules applied before send: environment variables are stripped,
  file paths are hashed to their basename + a hash of the parent dir, and any
  argument matching the `uxcp_*` key format is replaced with `[REDACTED]`.
- We recommend reviewing one captured event in your Sentry project before
  leaving it enabled.

### Prometheus `/metrics`

Exposes counters and histograms only (invocations per tool, latency,
rate-limit rejections). It contains **no payload data**, but it does reveal
*usage patterns* (when you automate, how often). Bind it to loopback or
protect it like the HTTP port.

---

## Third-Party / Network Interactions

| Interaction | When | Destination | Opt-out |
| ----------- | ---- | ----------- | ------- |
| ONNX model download | **Once**, on first use of a vision tool | Model host (checksum-pinned) | Place models manually in `~/.ultranix-mcp/models/` — no download occurs |
| CDP (Chrome DevTools Protocol) | Browser automation tools | `127.0.0.1:9222` — **localhost only, never remote** | Don't launch a browser with `--remote-debugging-port` |
| Sentry (opt-in, shipped at v1.1.0) | Only fires if `ULTRANIX_MCP_SENTRY_DSN` is set to a valid DSN | Your configured DSN | Off by default — unset/malformed DSN disables it |
| Everything else | — | **None** | — |

There is no update checker, no license phone-home, no feature-flag service.

---

## Your Rights & Controls

### Access

```bash
# Action history (encrypted — use the built-in export or your configured key)
cat ~/.ultranix-mcp/history.json          # ciphertext
ls ~/.ultranix-mcp/logs/                  # audit.jsonl, runtime logs
```

### Erasure

```bash
rm ~/.ultranix-mcp/history.json     # encrypted action history
rm -rf ~/.ultranix-mcp/logs/        # audit + runtime logs
rm -rf ~/.ultranix-mcp/models/      # downloaded ONNX models
```

Deleting the entire `~/.ultranix-mcp/` directory returns the host to a
pre-install data state.

### Restriction of processing

- Disable history persistence via configuration (keeps the audit log, which is
  a security control).
- The audit log can be redirected but should not be disabled on a shared
  machine — it is your only record of what an agent did.

### Portability

Audit logs are JSONL — one JSON object per line, importable anywhere. Action
history decrypts to JSON.

---

## Honest Caveats

- **AES-256-GCM protects history at rest, not in use.** While the server runs,
  history plaintext exists in memory; anything able to read the process's
  memory (the same user, root, a debugger) can read it.
- **The audit log is plaintext.** It records `key_id`, `args_hash`, outcome,
  and timing metadata — never raw arguments — and is permissioned `0600`; it
  can still reveal usage patterns on a shared machine.
- **Wayland gives screenshot data to any app the compositor authorizes.** Once
  wlr-screencopy or a portal grants capture, the pixels are as exposed as your
  compositor allows — which is a session-policy decision, not ours.
- **The MCP client sees what you let it see.** Privacy ends at the trust
  boundary of whichever AI client you connect; this policy governs the server,
  not your client's upstream behavior.
- **Full-disk encryption is on you.** We recommend LUKS on CachyOS; without it,
  `/tmp` artifacts and swap can leak what `0600` permissions cannot.

---

## Compliance Posture

Designed against GDPR principles (data minimization, local storage, consent
for optional telemetry) and Privacy-by-Design. Because all processing is local
and no data controller relationship with us exists, most regulatory transfer
concerns do not apply to default operation.

**Open source transparency**: every collection claim in this document is
verifiable in the source tree.

---

*Questions about this policy: open a GitHub issue (non-sensitive) — for
sensitive matters use the security channel in SECURITY.md.*
