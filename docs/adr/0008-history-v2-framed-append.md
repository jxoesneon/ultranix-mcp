# ADR 0008: Action History v2 - Framed Append Format

- **Status:**Accepted
- **Date:**v1.2.0 wave
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0004 (degradation), THREAT_MODEL (history confidentiality)

## Context

v1 history stored the entire action log as a single AES-256-GCM blob: every
`record()` decrypted the whole file, appended in memory, re-encrypted, and
rewrote - **O(n) I/O per action**with a full-file plaintext window on every
call. At the 10k-record FIFO cap each append paid for decrypting and
re-sealing 10k records.

Requirements:

- O(1) append for the common case.
- Per-record tamper evidence: a torn or flipped frame must fail loudly, not
  silently truncate history.
- No plaintext-at-rest regression, no format flag day: existing v1 files
  must migrate transparently.

## Decision

- **Framed format:**file starts with magic `UNXHIST2`, then one encrypted
  frame per record - `[u32 frame-len][nonce | ciphertext+tag]`, where
  `frame-len` counts only `nonce | ciphertext+tag`. Each
  frame carries its own AEAD tag, so truncation and bit-flips surface as
  per-frame decrypt errors on open.
- **Append path**writes one frame with `OpenOptions::append` - O(1).
- **Full rewrite**happens only for (a) FIFO-cap eviction and (b) one-shot
  **v1->v2 migration**on first open of a legacy file. Eviction is batched:
  on overflow the store drains down to `max_records - evict_batch`
  (`evict_batch = max(max_records/10, 1)`) once, then appends O(1)
  until the next batch boundary - full rewrites amortize over ~10% of
  the cap rather than running on every action.
- **AAD chain continuity:**each frame's GCM AAD is the SHA-256 of the
  previous frame's raw bytes (the first frame's is SHA-256 of the
  magic), so reordering, deleting, duplicating, or splicing frames -
  including across files under the same key - fails a tag check on
  open. `record.index` is additionally verified strictly increasing on
  load. Honest caveat: a truncated *tail* still yields a valid shorter
  prefix (inherent to append-only logs); the store tracks the chain
  tail in memory as the file's only writer.

## Consequences

- Steady-state append cost drops from O(history) to O(1).
- Eviction still rewrites - bounded, rare, and correct by construction.
- Readers accept v1 (migrate) or v2 (stream frames); anything else is
  rejected with a typed error rather than a parse guess.
- Tests cover migration, torn tails, invalid frame lengths, tampered
  ciphertext, and append-failure rollback.
