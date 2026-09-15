# API Key Management — ultranix-mcp

**Status**: Specification phase — describes the approved authentication design.
Applies to the **streamable-HTTP transport only** (`:3010`). The stdio
transport never requires a key — see §7 for why.

---

## 1. Key Format

```
uxcp_<64 lowercase hex chars>
 └─┬─┘ └──────────┬──────────┘
prefix      32 bytes from CSPRNG
```

- `uxcp_` — fixed prefix ("ultranix control plane"), makes keys greppable in
  logs/configs and identifiable in secret scanners.
- **Entropy**: 32 bytes (256 bits) generated from the OS CSPRNG
  (`getrandom`/`OsRng` in Rust; `openssl rand` for manual generation),
  rendered as 64 hex characters.
- Validation regex: `^uxcp_[0-9a-f]{64}$`

**Storage model**: the server **never stores plaintext keys**. On startup,
each configured key is hashed with SHA-256; request credentials are hashed and
compared in constant time. Only the hash lives in memory; nothing key-related
is written to `~/.ultranix-mcp/` by the server.

---

## 2. Generating a Key

Canonical generation (any machine, no ultranix install needed):

```bash
echo "uxcp_$(openssl rand -hex 32)"
# uxcp_9f3c...e1a4   (64 hex chars after the prefix)
```

Alternative with `dd`/`/dev/urandom`:

```bash
echo "uxcp_$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

A `ultranix-mcp keygen` convenience subcommand producing the identical format
is planned; the shell command above is the portable reference and works today.

**Do not** derive keys from passwords, timestamps, or `uuidgen` (128 bits,
weak RNG on some systems). Do not reuse keys across environments.

---

## 3. Key Sourcing & Precedence

At startup the server resolves the active key set in this order — **first
match wins**, and a warning is logged if a lower-precedence source is also
configured (to surface stale keys):

| Priority | Source | Notes |
| -------- | ------ | ----- |
| 1 | `ULTRANIX_MCP_API_KEY` environment variable | Single key, or comma-separated list `key1,key2` for rotation overlap |
| 2 | `ULTRANIX_MCP_API_KEY_FILE` → path to a file containing one key per line | File must be mode `0600`; the server **refuses to start** if it is group/world-readable |
| 3 | `~/.ultranix-mcp/api-keys` | Convention fallback; same `0600` requirement |

Rules:

- If **no** source yields a key and `ULTRANIX_MCP_DISABLE_AUTH` is not set,
  the HTTP transport **fails closed**: it refuses to bind `:3010` and logs the
  reason. Stdio still works.
- If both env and file sources exist, env wins and a `config.key.shadowed`
  warning is logged so a forgotten file key cannot silently linger.
- systemd deployments should prefer `LoadCredential=` / `EnvironmentFile=`
  (mode `0400`, root-owned) over a visible environment, since env vars are
  readable by same-UID processes via `/proc/<pid>/environ`.

---

## 4. Using the Key (client side)

```bash
# X-API-Key header (canonical — keeps keys out of URLs/logs)
curl -H "X-API-Key: uxcp_…" http://127.0.0.1:3010/mcp

# Authorization: Bearer (accepted equivalent)
curl -H "Authorization: Bearer uxcp_…" http://127.0.0.1:3010/mcp
```

**Query-parameter keys are not supported** — URLs leak into proxy logs, shell
history, and process lists.

---

## 5. Rate-Limit Identity

- The token bucket (**10 req/s**) is keyed by **key-ID**, computed as the
  first 8 hex chars of `SHA-256(key)` — the same ID printed in logs and audit
  records. One key = one budget.
- If a request somehow arrives authenticated but keyless in identity terms
  (shouldn't happen; defense-in-depth), the fallback identity is the remote
  socket address.
- Practical consequence: **give each client its own key**. Two clients sharing
  a key share one 10 req/s budget and are indistinguishable in the audit log.

---

## 6. Rotation Procedure

Keys support overlap via comma-separated configuration, so rotation is
zero-downtime:

```bash
# 1. Generate the replacement
NEW_KEY="uxcp_$(openssl rand -hex 32)"

# 2. Configure BOTH keys — old stays valid during cutover
export ULTRANIX_MCP_API_KEY="$OLD_KEY,$NEW_KEY"
systemctl --user restart ultranix-mcp

# 3. Update every client to NEW_KEY; verify in audit.jsonl that
#    the OLD key-ID no longer appears:
#    key-ID = sha256(key) first 8 chars — check with:
echo -n "$OLD_KEY" | sha256sum | cut -c1-8

# 4. Remove the old key
export ULTRANIX_MCP_API_KEY="$NEW_KEY"
systemctl --user restart ultranix-mcp
```

- **Cadence**: rotate at least every **90 days**, and **immediately** on any
  suspected exposure (key in a committed file, paste, screenshot, ticket).
- On restart, an `auth.keys.loaded` audit event records how many keys loaded
  and their key-IDs — verify the old ID is gone.

### Optional expiry metadata

A key record may carry an expiry timestamp, which makes rotation
self-enforcing rather than purely procedural:

- In a key file (`ULTRANIX_MCP_API_KEY_FILE` or
  `~/.ultranix-mcp/api-keys`), append `expires=<RFC 3339 timestamp>` after
  the key on the same line, whitespace-separated:
  `uxcp_… expires=2025-09-01T00:00:00Z`.
- For the env source, `ULTRANIX_MCP_API_KEY_EXPIRES` takes a
  comma-separated list aligned positionally with `ULTRANIX_MCP_API_KEY`.

Expired keys stay loaded but marked inactive: a request presenting one
fails authentication with a distinct `auth.expired_key` audit event
(`key_id`, expiry timestamp, remote addr) rather than a generic
`auth.failure{reason:"unknown"}` — so a client left behind after rotation
is distinguishable from an attacker guessing. `auth.keys.loaded` reports
the active and expired-but-loaded counts separately. Combined with the
90-day cadence, expiry turns "remember to revoke" into "the key revokes
itself".

---

## 7. Revocation

There is no revocation list — a key is valid iff it is configured. To revoke:

1. Remove it from `ULTRANIX_MCP_API_KEY` / the key file.
2. Restart (or send `SIGHUP` for config reload, where supported).
3. Confirm via `auth.keys.loaded` that its key-ID is absent.
4. Grep `audit.jsonl` for the revoked key-ID to scope what it did while live:

```bash
grep '"key_id":"<8-hex-id>"' ~/.ultranix-mcp/logs/audit.jsonl
```

Emergency revocation = stop the server, strip the key, restart. Because keys
are bearer tokens, a leaked key is live until this happens — keep revocation
fast, not clever.

---

## 8. Development Mode & the No-Dev-Key Rule

One escape hatch and one hard rule:

- **`ULTRANIX_MCP_DISABLE_AUTH=true`** — disables HTTP auth entirely. At
  startup the server emits a **loud stderr warning** *and* an
  `auth.disabled` audit event on every boot, plus a periodic reminder in
  `audit.jsonl`. Use only on loopback-only development machines. **Anyone who
  can reach `:3010` then controls your mouse and keyboard.**
- **No bootstrap or dev key — ever.** If no key is configured and auth is
  not disabled, the HTTP transport fails closed: it refuses to bind
  `:3010` and logs the reason. The server never generates, prints, or
  derives a key on your behalf — a key emitted to a terminal ends up in
  scrollback, shell logs, and tmux capture-panes. Generating a real key
  (§2) is the only path, and it takes one shell command.

---

## 9. Audit Events

Every authentication outcome is recorded in
`~/.ultranix-mcp/logs/audit.jsonl`:

| Event | When | Fields of note |
| ----- | ---- | -------------- |
| `auth.success` | Valid key presented | `key_id`, remote addr, transport |
| `auth.failure` | Missing / malformed / unknown key | remote addr, reason (`missing`, `malformed`, `unknown`), key prefix if parseable — **never the full key** |
| `auth.disabled` | Server started with `ULTRANIX_MCP_DISABLE_AUTH=true` | timestamp, listener |
| `auth.expired_key` | Valid-format key presented past its `expires=` timestamp | `key_id`, expiry timestamp, remote addr |
| `auth.keys.loaded` | Startup / reload | active + expired-but-loaded counts, key-IDs of the active set |
| `ratelimit.exceeded` | Bucket empty | `key_id`, remote addr |

Audit records never contain plaintext keys — only the 8-char key-ID and, on
malformed attempts, the literal prefix substring (e.g. `uxcp_`) for
diagnostics. Alert-worthy signals: `auth.failure` bursts from one address,
`auth.failure` with `reason:"unknown"` after a rotation (a client left
behind), or `key_id` values you don't recognize.

---

## 10. Best-Practice Summary

1. One `uxcp_` key **per client**, never shared — preserves rate-limit
   fairness and audit attribution.
2. Generate with `openssl rand -hex 32` + prefix; never handcraft.
3. Prefer `ULTRANIX_MCP_API_KEY_FILE` or systemd credentials over a plain env
   var where `/proc` exposure matters.
4. Rotate ≥ every 90 days with the overlap procedure — zero downtime;
   stamp `expires=` so a forgotten key revokes itself.
5. Never commit keys; add `uxcp_[0-9a-f]{64}` to your secret-scanner rules.
6. Treat `ULTRANIX_MCP_DISABLE_AUTH=true` as a loaded gun: loopback dev only.
7. Review `audit.jsonl` weekly; `auth.failure` is your tripwire.

---

*See also: [SECURITY.md](../SECURITY.md) (hardening checklist),
[THREAT_MODEL.md](THREAT_MODEL.md) (R-1, R-3 — bearer-token residual risks),
[HEADLESS_AUTH.md](HEADLESS_AUTH.md) (SSH-tunneled deployments).*
