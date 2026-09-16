# ADR 0009: Declarative Plugin Tools via Secured Re-Entry

- **Status:**Accepted
- **Date:**v1.2.0 wave
- **Deciders:**ultranix-mcp maintainers
- **Related:**ADR 0006 (categories), THREAT_MODEL (consent boundary)

## Context

Users asked for composable workflows ("focus window -> screenshot -> OCR")
without shipping a bespoke tool per workflow. Options:

1. **Server-side scripting**(Lua/WASM sandbox) - real expressiveness, but a
   new interpreter, a new supply-chain surface, and a second security
   boundary to audit.
2. **Declarative manifests**- a JSON file lists named tool calls with
   templated parameters; execution re-enters the *same* secured dispatch
   every other tool uses.

## Decision

- **Manifests**live in `<state-root>/plugins/*.json`: name (lowercase
  alnum/`-`, ≤64), semver version, `params` (typed: string/number/boolean),
  `steps` (1-32 `tool`+`args` entries). `${param}` substitutes inside
  strings (stringified) or whole-value (typed); `$$` escapes a literal `$`.
- **Validation**at scan time: unknown tools, undeclared params, and
  **plugin tools as steps are rejected**(no recursion); malformed
  manifests are skipped with warnings - `plugin_list` stays honest.
- **Execution**(`plugin_run`) resolves args, then calls
  `call_tool_secured` per step - consent challenges, audit, history, and
  metrics apply to every step exactly as if the client had called the tool
  itself. First failing step aborts the run with step context.
- `plugin_list`/`plugin_reload` rescan the directory live - no restart.

## Consequences

- Plugins inherit the entire security model for free; there is no second
  execution path to audit.
- A plugin cannot exceed the caller's authority - a consent-gated step
  still challenges.
- Cost: no conditionals/loops - multi-step linear workflows only, which is
  the stated use case.

## Addendum: fail-closed manifest versioning

- Manifests may declare an optional `manifest_version` (unsigned
  integer). Absent means `1` - the only schema revision this server
  parses. Any other value skips the file with a warning at scan time: a
  future-format manifest is never interpreted under a schema it did not
  declare. The key is reserved in the manifest schema, and
  `deny_unknown_fields` keeps every other unknown key rejected outright,
  so a future revision can rely on `manifest_version` never having meant
  anything else.
