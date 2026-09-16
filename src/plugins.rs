//! Declarative plugin tool-macros - `<state-root>/plugins/*.json`.
//!
//! A plugin is a *macro*, not code: an ordered list of calls to real
//! catalog tools with `${param}` placeholders in string arguments. The
//! plugin tools (`tools/plugin.rs`) surface them as `plugin_list` /
//! `plugin_run` / `plugin_reload`; this module owns loading, validation,
//! and `${...}` substitution.
//!
//! Manifest shape:
//! ```json
//! {
//!   "name": "focus-firefox",
//!   "version": "1.0.0",
//!   "description": "Focus the Firefox window",
//!   "params": { "title": {"type": "string", "required": true, "description": "title substring"} },
//!   "steps": [
//!     {"tool": "window_control", "args": {"action": "focus", "window": "${title}"}}
//!   ]
//! }
//! ```
//!
//! Format versioning is **fail-closed**: an optional `manifest_version`
//! (unsigned integer) declares the schema revision. Absent means
//! version 1 - the only revision this server parses. A manifest that
//! declares any other value is skipped with a warning rather than
//! interpreted under a schema it did not declare; the field itself is
//! reserved so a future format can rely on it never having meant
//! anything else (`deny_unknown_fields` keeps every other unknown key
//! rejected outright).
//!
//! Validation (all failures are manifest errors - the file is skipped
//! with a `tracing::warn`, never fatal):
//! - `manifest_version`, when present, must be `1` (see above).
//! - `name` matches `^[a-z][a-z0-9-]{0,63}$` and must not collide with a
//!   catalog tool name (a plugin named `sleep` would shadow the real
//!   tool in operator UX).
//! - `version` is semver-ish: `MAJOR.MINOR.PATCH` with optional
//!   `-prerelease` / `+build` suffixes.
//! - `params` keys match `^[a-z][a-z0-9_]{0,63}$`; each declares
//!   `type` (`string` | `number` | `boolean`), `required`, and an
//!   optional `description`. Cap: [`MAX_PARAMS`].
//! - `steps` is non-empty and capped at [`MAX_STEPS`].
//! - `step.tool` must be a real catalog tool name
//!   ([`crate::tools::category_of`]); `plugin_*` names are rejected so
//!   plugins cannot compose into unbounded macro recursion.
//! - Every `${ref}` inside a step's string args must reference a
//!   declared param.
//! - An optional `tool` (alias `expose_as_tool`) section registers the
//!   plugin as a *first-class tool* in `tools/list`:
//!   ```json
//!   "tool": {
//!     "name": "deploy_notes",
//!     "description": "Deploy the notes bundle",
//!     "params": { "env": {"type": "string", "required": true} }
//!   }
//!   ```
//!   `tool.name` uses the tool grammar `^[a-z][a-z0-9_]{0,63}$` and is
//!   advertised **verbatim**- no `plugin_` prefix. Verbatim names are
//!   unambiguous by construction: the grammar reaches every catalog
//!   name, so the catalog-collision check keeps them disjoint from the
//!   static catalog, and scan-time dedup keeps them unique among
//!   plugins (a second manifest claiming a registered tool name is
//!   skipped with a diagnostic). `tool.description` is capped at
//!   [`MAX_TOOL_DESCRIPTION`] chars. `tool.params` declares
//!   *additional* params in the same shape as `params` - they merge
//!   into the manifest's param set (so `${ref}` resolution and
//!   `plugin_run` binding treat them identically); a name declared in
//!   both places is an authoring error. `plugin_run` itself remains
//!   the dispatch target: calling `deploy_notes{env: "prod"}` is
//!   exactly `plugin_run{name: "deploy-notes", params: {env: "prod"}}`
//!   through the secured pipeline.
//!
//! [`ToolRegistry`] is the server's live view over these exposed tools:
//! it rescans the manifest dir on every access (the always-fresh model
//! `plugin_list`/`plugin_run` already use), so `plugin_reload` needs no
//! cache flush - and no `tools/list_changed` notification is emitted
//! (the server does not advertise that capability; clients see the new
//! surface on their next `tools/list`).
//!
//! Template rules (`${...}` in `args` string values, at any depth):
//! - A string that is *exactly* `${name}` substitutes the typed JSON
//!   value - a `number`/`boolean` param lands as a JSON number/bool, so
//!   `"ms": "${ms}"` feeds `sleep` a real number. Inside a larger
//!   string the value is stringified.
//! - `$$` escapes a literal `$`, so `$${x}` renders as `${x}`; a lone
//!   `$` not followed by `$`/`{` is literal text.
//! - Referencing a declared-but-unsupplied (optional) param is a
//!   run-time error - manifests cannot declare defaults.
//! - Supplied params not declared by the manifest are *rejected*
//!   (strict; mirrors `deny_unknown_fields` across the tool surface).
//!
//! Scanning is strictly read-only: no directory is created and no file
//! is written. Duplicate `name`s across files resolve to the first file
//! in lexical filename order; later duplicates are skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value};

/// Subdirectory of the state root holding plugin manifests.
pub const PLUGINS_DIR_NAME: &str = "plugins";

/// Hard cap on `steps` per manifest - keeps a single `plugin_run`
/// bounded (each step is a full secured dispatch + audit record).
pub const MAX_STEPS: usize = 32;

/// Hard cap on declared `params` per manifest.
pub const MAX_PARAMS: usize = 64;

/// Hard cap on `tool.description` - tool metadata is bounded like the
/// other manifest fields (a manifest is trusted content, but a
/// runaway string still bloats every `tools/list` response).
pub const MAX_TOOL_DESCRIPTION: usize = 256;

/// Hard cap on a single manifest file - the largest legal manifest
/// (64 params × short strings + 32 steps) fits in tens of KiB; 256 KiB
/// is generous headroom while keeping a same-UID writer from making
/// every `tools/list` parse megabytes of JSON.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Hard cap on manifest files scanned per call - the scan reruns on
/// every `tools/list`/`plugin_*`/dynamic-tool dispatch, so an
/// unbounded dir would make each request do unbounded file I/O.
/// Extras are skipped with a `tracing::warn` (they surface nowhere -
/// the cap is a resource bound, not a correctness rule).
pub const MAX_MANIFEST_FILES: usize = 256;

// ---------------------------------------------------------------------------
// Manifest schema
// ---------------------------------------------------------------------------

/// Declared type of a plugin parameter (`params.<name>.type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    /// JSON string.
    String,
    /// JSON number.
    Number,
    /// JSON boolean.
    Boolean,
}

impl ParamType {
    /// The manifest vocabulary spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
        }
    }

    /// Whether `v` is a JSON value of this type.
    fn accepts(self, v: &Value) -> bool {
        match self {
            Self::String => v.is_string(),
            Self::Number => v.is_number(),
            Self::Boolean => v.is_boolean(),
        }
    }
}

/// One declared parameter (`params.<name>`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    /// Value type enforced at `plugin_run` bind time.
    #[serde(rename = "type")]
    pub ty: ParamType,
    /// Whether `plugin_run.params` must carry a value.
    #[serde(default)]
    pub required: bool,
    /// Human-readable description surfaced by `plugin_list`.
    #[serde(default)]
    pub description: Option<String>,
}

/// One step - a catalog tool call with templated args.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Catalog tool name (validated at load).
    pub tool: String,
    /// Arguments object; `${param}` placeholders in string values.
    #[serde(default)]
    pub args: Map<String, Value>,
}

/// A validated `tool`/`expose_as_tool` section - the plugin's own
/// `tools/list` entry. The params advertised in its `inputSchema` are
/// the manifest's merged [`PluginManifest::params`], so this carries
/// only the name/description.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// `^[a-z][a-z0-9_]{0,63}$` - advertised verbatim (no `plugin_`
    /// prefix; see the module docs for why that is unambiguous).
    pub name: String,
    /// Human-readable description (`""` when omitted).
    pub description: String,
}

/// Serde target for the `tool` section - validated into [`ToolSpec`]
/// by [`validate`]. `params` entries use the same [`ParamSpec`] shape
/// as top-level `params` and merge into that set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolSpec {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    params: BTreeMap<String, ParamSpec>,
}

/// A validated manifest - the unit `plugin_run` executes.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    /// `^[a-z][a-z0-9-]{0,63}$` identifier.
    pub name: String,
    /// Semver-ish version string.
    pub version: String,
    /// Human-readable description (`""` when omitted).
    pub description: String,
    /// Declared parameters, name -> spec - the union of `params` and
    /// `tool.params` (merged at validation; the two sites must be
    /// disjoint).
    pub params: BTreeMap<String, ParamSpec>,
    /// Ordered steps (1..=[`MAX_STEPS`]).
    pub steps: Vec<Step>,
    /// `Some` when the manifest registers itself as a first-class
    /// tool in `tools/list`.
    pub tool: Option<ToolSpec>,
}

impl PluginManifest {
    /// The `tools/list` entry for the `tool` section: an rmcp [`Tool`]
    /// whose `inputSchema` is generated from the merged `params` -
    /// `type: "object"`, per-param `type`/`description`, a `required`
    /// array (omitted when empty, matching schemars' habit), and
    /// `additionalProperties: false` - the same shape
    /// `crate::tools::tool_schema` produces for the static catalog.
    /// `None` when the manifest declares no `tool` section.
    pub fn exposed_tool(&self) -> Option<rmcp::model::Tool> {
        let spec = self.tool.as_ref()?;
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, p) in &self.params {
            let mut prop = Map::from_iter([("type".into(), Value::from(p.ty.as_str()))]);
            if let Some(d) = &p.description {
                prop.insert("description".into(), Value::from(d.clone()));
            }
            properties.insert(name.clone(), Value::Object(prop));
            if p.required {
                required.push(Value::from(name.clone()));
            }
        }
        let mut schema = Map::from_iter([
            ("type".into(), Value::from("object")),
            ("properties".into(), Value::Object(properties)),
            ("additionalProperties".into(), Value::Bool(false)),
        ]);
        if !required.is_empty() {
            schema.insert("required".into(), Value::Array(required));
        }
        Some(rmcp::model::Tool::new(
            spec.name.clone(),
            spec.description.clone(),
            schema,
        ))
    }
}

/// The only manifest schema revision this server parses.
const MANIFEST_VERSION: u32 = 1;

/// Serde target - every field validated into [`PluginManifest`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    /// Schema revision - absent means [`MANIFEST_VERSION`]; any other
    /// value fails closed in [`validate`].
    #[serde(default)]
    manifest_version: Option<u32>,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    params: BTreeMap<String, ParamSpec>,
    /// Optional self-registration as a `tools/list` tool.
    /// `expose_as_tool` is accepted as an alias spelling.
    #[serde(default, alias = "expose_as_tool")]
    tool: Option<RawToolSpec>,
    steps: Vec<Step>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a manifest file was skipped (load-time validation).
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// File unreadable.
    #[error("read failed: {0}")]
    Io(String),
    /// Not a manifest-shaped JSON document.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// `manifest_version` present and not [`MANIFEST_VERSION`] - the
    /// file may be a future format; fail closed rather than guess.
    #[error(
        "unsupported manifest_version {0}: this server reads version {MANIFEST_VERSION} manifests only"
    )]
    UnsupportedVersion(u32),
    /// `name` fails the grammar.
    #[error("invalid name {0:?}: must match ^[a-z][a-z0-9-]{{0,63}}$")]
    Name(String),
    /// `name` shadows a real tool.
    #[error("name {0:?} collides with a catalog tool name")]
    NameCollidesWithTool(String),
    /// `version` is not semver-ish.
    #[error("invalid version {0:?}: expected MAJOR.MINOR.PATCH (semver-ish)")]
    Version(String),
    /// A `params` key fails the grammar.
    #[error("invalid param name {0:?}: must match ^[a-z][a-z0-9_]{{0,63}}$")]
    ParamName(String),
    /// `params` exceeds [`MAX_PARAMS`].
    #[error("too many params: {0} > {MAX_PARAMS}")]
    TooManyParams(usize),
    /// `steps` is `[]` - a no-op macro is an authoring error.
    #[error("manifest declares no steps")]
    EmptySteps,
    /// `steps` exceeds [`MAX_STEPS`].
    #[error("too many steps: {0} > {MAX_STEPS}")]
    TooManySteps(usize),
    /// `tool.name` fails the tool-name grammar.
    #[error("invalid tool name {0:?}: must match ^[a-z][a-z0-9_]{{0,63}}$")]
    ToolName(String),
    /// `tool.name` shadows a real catalog tool.
    #[error("tool name {0:?} collides with a catalog tool name")]
    ToolNameCollidesWithTool(String),
    /// `tool.description` exceeds [`MAX_TOOL_DESCRIPTION`].
    #[error("tool description too long: {0} chars > {MAX_TOOL_DESCRIPTION}")]
    ToolDescription(usize),
    /// A param is declared in both `params` and `tool.params` - the two
    /// sites must be disjoint so the bindable set cannot diverge from
    /// the advertised schema.
    #[error("param {0:?} declared in both `params` and `tool.params`")]
    ToolParamDuplicate(String),
    /// `step.tool` is not a catalog tool.
    #[error("step {index}: unknown tool {tool:?}")]
    UnknownTool {
        /// 0-based step index.
        index: usize,
        /// The rejected tool name.
        tool: String,
    },
    /// `step.tool` is a `plugin_*` tool - composition would allow
    /// unbounded macro recursion.
    #[error("step {index}: {tool:?} is a plugin tool - plugins cannot compose")]
    SelfReference {
        /// 0-based step index.
        index: usize,
        /// The rejected tool name.
        tool: String,
    },
    /// `step.tool` re-enters the dispatch layer (`replay_action`) - under
    /// `--allow-destructive` it could replay a recorded `plugin_run`,
    /// recursing through the plugin executor.
    #[error("step {index}: {tool:?} re-enters dispatch - plugins may not invoke it")]
    DispatchReentry {
        /// 0-based step index.
        index: usize,
        /// The rejected tool name.
        tool: String,
    },
    /// Malformed `${...}` placeholder in a step arg string.
    #[error("step {index}: {source}")]
    Template {
        /// 0-based step index.
        index: usize,
        /// The template parse failure.
        source: TemplateError,
    },
    /// `${name}` references a param the manifest does not declare.
    #[error("step {index}: ${{{name}}} is not a declared param")]
    UndeclaredParam {
        /// 0-based step index.
        index: usize,
        /// The referenced name.
        name: String,
    },
}

/// `${...}` template parse failure (shared by load-time validation and
/// run-time substitution - post-validation it is unreachable in
/// practice).
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// `${` with no closing `}`.
    #[error("unclosed `${{` placeholder")]
    Unclosed,
    /// `${...}` whose contents are not a legal param name.
    #[error("invalid placeholder `${{{0}}}`: param names match ^[a-z][a-z0-9_]{{0,63}}$")]
    BadName(String),
}

/// `plugin_run`-time binding/substitution failure - all map to
/// `-32602 InvalidParams` at the tool layer (the caller can fix them).
#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    /// A `required` param was not supplied.
    #[error("missing required param {0:?}")]
    Missing(String),
    /// A supplied param is not declared by the manifest (strict).
    #[error("unknown param {0:?} (not declared by the manifest)")]
    Unknown(String),
    /// A supplied param fails its declared type.
    #[error("param {name:?} must be {expected}")]
    WrongType {
        /// Param name.
        name: String,
        /// `"string"` | `"number"` | `"boolean"`.
        expected: &'static str,
    },
    /// A step references a declared-but-optional param the call did not
    /// supply.
    #[error("param {name:?} is referenced by a step but was not supplied")]
    Unsupplied {
        /// Param name.
        name: String,
    },
    /// Malformed template - unreachable for validated manifests.
    #[error("template error: {0}")]
    Template(#[from] TemplateError),
}

// ---------------------------------------------------------------------------
// Name / version grammars (no regex dep - plain byte checks)
// ---------------------------------------------------------------------------

/// `^[a-z][a-z0-9-]{0,63}$` - plugin names.
fn valid_plugin_name(name: &str) -> bool {
    let mut it = name.bytes();
    match it.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.len() <= 64 && it.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// `^[a-z][a-z0-9_]{0,63}$` - param names (underscore so `${x}` reads
/// like an identifier; `-` is reserved for plugin names).
fn valid_param_name(name: &str) -> bool {
    let mut it = name.bytes();
    match it.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.len() <= 64 && it.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Semver-ish: `MAJOR.MINOR.PATCH` numeric core, optional `-prerelease`
/// and `+build` suffixes of dot-separated alphanumeric/hyphen labels.
fn valid_version(v: &str) -> bool {
    let (head, build) = match v.split_once('+') {
        Some((h, b)) => (h, Some(b)),
        None => (v, None),
    };
    let (core, pre) = match head.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (head, None),
    };
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let labels = |s: &str| {
        !s.is_empty()
            && s.split('.')
                .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    };
    let mut it = core.split('.');
    let core_ok = it.next().is_some_and(numeric)
        && it.next().is_some_and(numeric)
        && it.next().is_some_and(numeric)
        && it.next().is_none();
    core_ok && pre.is_none_or(labels) && build.is_none_or(labels)
}

// ---------------------------------------------------------------------------
// `${...}` templates
// ---------------------------------------------------------------------------

/// One parsed template segment.
enum Segment {
    /// Literal text (`$$` already folded to `$`).
    Lit(String),
    /// `${name}` reference.
    Ref(String),
}

/// Parse a manifest string into literal/reference segments.
/// `$$` -> literal `$`; lone `$` -> literal; `${name}` -> [`Segment::Ref`].
fn parse_template(s: &str) -> Result<Vec<Segment>, TemplateError> {
    let mut segs = Vec::new();
    let mut lit = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '$' {
            lit.push(c);
            continue;
        }
        match it.next() {
            // `$$` - escaped literal `$` (`$${x}` renders as `${x}`).
            Some('$') => lit.push('$'),
            Some('{') => {
                let mut name = String::new();
                let mut closed = false;
                for c in it.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    name.push(c);
                }
                if !closed {
                    return Err(TemplateError::Unclosed);
                }
                if !valid_param_name(&name) {
                    return Err(TemplateError::BadName(name));
                }
                if !lit.is_empty() {
                    segs.push(Segment::Lit(std::mem::take(&mut lit)));
                }
                segs.push(Segment::Ref(name));
            }
            // `$x` / trailing `$` - plain text, not a placeholder.
            Some(other) => {
                lit.push('$');
                lit.push(other);
            }
            None => lit.push('$'),
        }
    }
    if !lit.is_empty() {
        segs.push(Segment::Lit(lit));
    }
    Ok(segs)
}

/// Append every `${ref}` in `v`'s string leaves (recursing through
/// objects and arrays) to `refs`.
fn collect_refs(v: &Value, refs: &mut Vec<String>) -> Result<(), TemplateError> {
    match v {
        Value::String(s) => {
            for seg in parse_template(s)? {
                if let Segment::Ref(name) = seg {
                    refs.push(name);
                }
            }
            Ok(())
        }
        Value::Array(a) => a.iter().try_for_each(|v| collect_refs(v, refs)),
        Value::Object(o) => o.values().try_for_each(|v| collect_refs(v, refs)),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

/// Parse and validate one manifest document.
pub fn parse_manifest(bytes: &[u8]) -> Result<PluginManifest, ManifestError> {
    let raw: RawManifest =
        serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
    validate(raw)
}

fn validate(raw: RawManifest) -> Result<PluginManifest, ManifestError> {
    // The format gate runs first: a manifest written for a different
    // schema revision is rejected before its fields are interpreted.
    match raw.manifest_version {
        None | Some(MANIFEST_VERSION) => {}
        Some(v) => return Err(ManifestError::UnsupportedVersion(v)),
    }
    if !valid_plugin_name(&raw.name) {
        return Err(ManifestError::Name(raw.name));
    }
    if crate::tools::category_of(&raw.name).is_some() {
        return Err(ManifestError::NameCollidesWithTool(raw.name));
    }
    if !valid_version(&raw.version) {
        return Err(ManifestError::Version(raw.version));
    }
    if raw.params.len() > MAX_PARAMS {
        return Err(ManifestError::TooManyParams(raw.params.len()));
    }
    for name in raw.params.keys() {
        if !valid_param_name(name) {
            return Err(ManifestError::ParamName(name.clone()));
        }
    }
    // The `tool` section validates into the param set it extends -
    // `tool.params` entries are *additional* declarations merged into
    // `params`, so `${ref}` resolution and `plugin_run` binding see a
    // single declared set.
    let mut params = raw.params;
    let tool = raw
        .tool
        .map(|t| validate_tool(t, &mut params))
        .transpose()?;
    if params.len() > MAX_PARAMS {
        return Err(ManifestError::TooManyParams(params.len()));
    }
    if raw.steps.is_empty() {
        return Err(ManifestError::EmptySteps);
    }
    if raw.steps.len() > MAX_STEPS {
        return Err(ManifestError::TooManySteps(raw.steps.len()));
    }
    for (index, step) in raw.steps.iter().enumerate() {
        // The `plugin_` guard runs before the catalog check so it holds
        // whether or not the plugin tools are catalogued yet - a
        // self-referential manifest is rejected either way.
        if step.tool.starts_with("plugin_") {
            return Err(ManifestError::SelfReference {
                index,
                tool: step.tool.clone(),
            });
        }
        // `replay_action` also re-enters the secured dispatch layer and
        // could chain back into plugin execution - block it for defense in
        // depth even though it is a normal catalog tool.
        if step.tool == "replay_action" {
            return Err(ManifestError::DispatchReentry {
                index,
                tool: step.tool.clone(),
            });
        }
        if crate::tools::category_of(&step.tool).is_none() {
            return Err(ManifestError::UnknownTool {
                index,
                tool: step.tool.clone(),
            });
        }
        let mut refs = Vec::new();
        for v in step.args.values() {
            collect_refs(v, &mut refs)
                .map_err(|source| ManifestError::Template { index, source })?;
        }
        for name in refs {
            if !params.contains_key(&name) {
                return Err(ManifestError::UndeclaredParam { index, name });
            }
        }
    }
    Ok(PluginManifest {
        name: raw.name,
        version: raw.version,
        description: raw.description,
        params,
        steps: raw.steps,
        tool,
    })
}

/// Validate the `tool`/`expose_as_tool` section. `tool.params` entries
/// are additional declared params - merged into `params` here so the
/// advertised `inputSchema`, `${ref}` resolution, and `plugin_run`
/// binding can never disagree. A name already present in `params` is
/// rejected rather than silently overridden.
fn validate_tool(
    raw: RawToolSpec,
    params: &mut BTreeMap<String, ParamSpec>,
) -> Result<ToolSpec, ManifestError> {
    // Tool names use the *param* grammar (`^[a-z][a-z0-9_]{0,63}$` -
    // underscores like `window_control`, never hyphens). The name is
    // advertised verbatim: every catalog name is reachable by this
    // grammar, so the collision check below is what keeps plugin tools
    // disjoint from the static catalog; scan-time dedup keeps them
    // unique among plugins.
    if !valid_param_name(&raw.name) {
        return Err(ManifestError::ToolName(raw.name));
    }
    if crate::tools::category_of(&raw.name).is_some() {
        return Err(ManifestError::ToolNameCollidesWithTool(raw.name));
    }
    let desc_len = raw.description.chars().count();
    if desc_len > MAX_TOOL_DESCRIPTION {
        return Err(ManifestError::ToolDescription(desc_len));
    }
    if raw.params.len() > MAX_PARAMS {
        return Err(ManifestError::TooManyParams(raw.params.len()));
    }
    for (name, spec) in raw.params {
        if !valid_param_name(&name) {
            return Err(ManifestError::ParamName(name));
        }
        if params.insert(name.clone(), spec).is_some() {
            return Err(ManifestError::ToolParamDuplicate(name));
        }
    }
    Ok(ToolSpec {
        name: raw.name,
        description: raw.description,
    })
}

// ---------------------------------------------------------------------------
// Run-time binding + substitution
// ---------------------------------------------------------------------------

/// Validate caller-supplied `params` against the manifest: every
/// `required` param present, every supplied param declared and
/// type-correct, no extras (strict - undocumented keys are rejected).
/// Returns the bound `name -> Value` map consumed by
/// [`substitute_args`]; declared-but-unsupplied optional params are
/// simply absent.
pub fn bind_params(
    manifest: &PluginManifest,
    supplied: Map<String, Value>,
) -> Result<BTreeMap<String, Value>, ParamError> {
    let mut bound = BTreeMap::new();
    for (name, value) in &supplied {
        let spec = manifest
            .params
            .get(name)
            .ok_or_else(|| ParamError::Unknown(name.clone()))?;
        if !spec.ty.accepts(value) {
            return Err(ParamError::WrongType {
                name: name.clone(),
                expected: spec.ty.as_str(),
            });
        }
        bound.insert(name.clone(), value.clone());
    }
    for (name, spec) in &manifest.params {
        if spec.required && !bound.contains_key(name) {
            return Err(ParamError::Missing(name.clone()));
        }
    }
    Ok(bound)
}

/// Resolve every `${ref}` in a step's `args` against `bound` -
/// recursively through objects and arrays; non-string leaves pass
/// through untouched. A string that is exactly `${name}` substitutes
/// the *typed* value (so `"ms": "${ms}"` yields a JSON number); inside
/// a larger string the value is stringified. A declared-but-unsupplied
/// reference is [`ParamError::Unsupplied`].
pub fn substitute_args(
    args: &Map<String, Value>,
    bound: &BTreeMap<String, Value>,
) -> Result<Map<String, Value>, ParamError> {
    args.iter()
        .map(|(k, v)| Ok((k.clone(), substitute_value(v, bound)?)))
        .collect()
}

fn substitute_value(v: &Value, bound: &BTreeMap<String, Value>) -> Result<Value, ParamError> {
    match v {
        Value::String(s) => {
            let segs = parse_template(s)?;
            // Exactly `${name}` - keep the JSON type.
            if let [Segment::Ref(name)] = segs.as_slice() {
                return bound
                    .get(name)
                    .cloned()
                    .ok_or_else(|| ParamError::Unsupplied { name: name.clone() });
            }
            let mut out = String::new();
            for seg in segs {
                match seg {
                    Segment::Lit(l) => out.push_str(&l),
                    Segment::Ref(name) => {
                        let v = bound
                            .get(&name)
                            .ok_or_else(|| ParamError::Unsupplied { name: name.clone() })?;
                        match v {
                            Value::String(s) => out.push_str(s),
                            other => out.push_str(&other.to_string()),
                        }
                    }
                }
            }
            Ok(Value::String(out))
        }
        Value::Array(a) => a
            .iter()
            .map(|v| substitute_value(v, bound))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(o) => substitute_args(o, bound).map(Value::Object),
        other => Ok(other.clone()),
    }
}

// ---------------------------------------------------------------------------
// Manifest-dir scanning
// ---------------------------------------------------------------------------

/// A loaded, validated plugin plus its provenance.
#[derive(Debug, Clone)]
pub struct Plugin {
    /// The validated manifest.
    pub manifest: PluginManifest,
    /// File it was loaded from.
    pub source: PathBuf,
}

/// A manifest file that failed to load - reported by `plugin_reload`.
#[derive(Debug, Clone)]
pub struct Skipped {
    /// The skipped file.
    pub file: PathBuf,
    /// Human-readable validation/parse failure.
    pub error: String,
}

/// Result of one [`PluginStore::scan`] pass.
#[derive(Debug, Default)]
pub struct Scan {
    /// Valid plugins, sorted by name.
    pub plugins: Vec<Plugin>,
    /// Files skipped as malformed (each also logged via
    /// `tracing::warn`).
    pub skipped: Vec<Skipped>,
}

/// Read-only view over a plugin manifest directory.
///
/// `plugin_list`/`plugin_run`/`plugin_reload` rescan on every call -
/// manifests are small, the scan is a directory listing + JSON parse,
/// and an always-fresh view eliminates cache invalidation entirely
/// (`plugin_reload` exists to surface *what* loaded and what was
/// skipped, not to flush a cache).
#[derive(Clone)]
pub struct PluginStore {
    dir: PathBuf,
}

impl PluginStore {
    /// Store over an explicit directory - the test seam (tempdirs, no
    /// env mutation).
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// `<state-root>/plugins` for an explicit root.
    pub fn for_state_root(root: impl Into<PathBuf>) -> Self {
        Self::at(root.into().join(PLUGINS_DIR_NAME))
    }

    /// `<state-root>/plugins` resolved from the process environment -
    /// the same precedence [`crate::state::StateDir::resolve_root`]
    /// fixes (`ULTRANIX_MCP_STATE_DIR` -> `$HOME/.ultranix-mcp` ->
    /// `./.ultranix-mcp`). In production this equals the
    /// `SecurityContext`'s data dir (main.rs builds the context on the
    /// same resolved root).
    pub fn ambient() -> Self {
        Self::for_state_root(crate::state::StateDir::resolve_root(|k| {
            std::env::var_os(k)
        }))
    }

    /// The manifest directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// List and parse every `*.json` in the dir. Missing/unreadable
    /// dirs yield an empty scan (a warn for anything but `NotFound`);
    /// malformed files are skipped with a `tracing::warn` - never
    /// fatal. Duplicate names: first file in lexical order wins, later
    /// files are skipped.
    pub fn scan(&self) -> Scan {
        let mut scan = Scan::default();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(dir = %self.dir.display(), %e, "plugin dir unreadable");
                }
                return scan;
            }
        };
        let mut paths: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        if paths.len() > MAX_MANIFEST_FILES {
            tracing::warn!(
                dir = %self.dir.display(),
                files = paths.len(),
                cap = MAX_MANIFEST_FILES,
                "plugin dir exceeds the file cap - extra manifests skipped"
            );
            paths.truncate(MAX_MANIFEST_FILES);
        }

        let mut seen = BTreeSet::new();
        // Registered `tool.name`s - a plugin-exposed tool is a
        // `tools/list` entry, so two manifests claiming the same tool
        // name collide exactly like duplicate plugin names: first file
        // in lexical order wins, the later one is skipped.
        let mut seen_tools = BTreeSet::new();
        for path in paths {
            match load_one(&path) {
                Ok(manifest) => {
                    if !seen.insert(manifest.name.clone()) {
                        let error = format!("duplicate plugin name {:?}", manifest.name);
                        tracing::warn!(file = %path.display(), %error, "skipping plugin manifest");
                        scan.skipped.push(Skipped { file: path, error });
                        continue;
                    }
                    if let Some(tool) = manifest.tool.as_ref()
                        && !seen_tools.insert(tool.name.clone())
                    {
                        let error = format!("duplicate plugin tool name {:?}", tool.name);
                        tracing::warn!(file = %path.display(), %error, "skipping plugin manifest");
                        scan.skipped.push(Skipped { file: path, error });
                        continue;
                    }
                    scan.plugins.push(Plugin {
                        manifest,
                        source: path,
                    });
                }
                Err(e) => {
                    tracing::warn!(file = %path.display(), %e, "skipping plugin manifest");
                    scan.skipped.push(Skipped {
                        file: path,
                        error: e.to_string(),
                    });
                }
            }
        }
        scan.plugins
            .sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        scan
    }

    /// `scan` + lookup by name.
    pub fn get(&self, name: &str) -> Option<Plugin> {
        self.scan()
            .plugins
            .into_iter()
            .find(|p| p.manifest.name == name)
    }

    /// `scan` + lookup by *exposed tool* name (`manifest.tool.name`) -
    /// the resolution `tools/call` uses for non-catalog names.
    pub fn by_tool_name(&self, tool_name: &str) -> Option<Plugin> {
        self.scan().plugins.into_iter().find(|p| {
            p.manifest
                .tool
                .as_ref()
                .is_some_and(|t| t.name == tool_name)
        })
    }
}

// ---------------------------------------------------------------------------
// Dynamic tool registry
// ---------------------------------------------------------------------------

/// Live registry of plugin-exposed tools - the `tools/list` /
/// `tools/call` view over manifests' `tool` sections.
///
/// Like [`PluginStore`] (which it wraps), every accessor rescans the
/// manifest dir: `tools/list` always reflects the on-disk state,
/// `plugin_reload` needs no cache flush, and dropping a manifest file
/// in registers its tool on the next request - no restart. Callers on
/// the async runtime should run these through
/// `tokio::task::spawn_blocking` like the `plugin_*` tools do (a scan
/// is a directory listing plus a JSON parse per manifest).
#[derive(Clone)]
pub struct ToolRegistry {
    store: PluginStore,
}

impl ToolRegistry {
    /// `<state-root>/plugins` resolved from the process environment -
    /// the same root [`PluginStore::ambient`] uses.
    pub fn ambient() -> Self {
        Self {
            store: PluginStore::ambient(),
        }
    }

    /// `<state-root>/plugins` for an explicit root.
    pub fn for_state_root(root: impl Into<PathBuf>) -> Self {
        Self {
            store: PluginStore::for_state_root(root),
        }
    }

    /// Registry over an explicit manifest dir - the test seam.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self {
            store: PluginStore::at(dir),
        }
    }

    /// The manifest dir backing this registry.
    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    /// Every currently-registered plugin tool as an rmcp `Tool`,
    /// sorted by tool name (blocking scan).
    pub fn tools(&self) -> Vec<rmcp::model::Tool> {
        let mut tools: Vec<rmcp::model::Tool> = self
            .store
            .scan()
            .plugins
            .iter()
            .filter_map(|p| p.manifest.exposed_tool())
            .collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    /// The plugin exposing `tool_name`, or `None` (blocking scan).
    pub fn resolve(&self, tool_name: &str) -> Option<Plugin> {
        self.store.by_tool_name(tool_name)
    }
}

fn load_one(path: &Path) -> Result<PluginManifest, ManifestError> {
    // Bounded read - `scan` reruns per request, so an unbounded
    // same-UID write must not make every scan slurp megabytes. `take`
    // enforces the cap during the read itself (no stat-then-read
    // TOCTOU window); the trailing byte signals "oversized".
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| ManifestError::Io(e.to_string()))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ManifestError::Io(e.to_string()))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Io(format!(
            "manifest too large: > {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    parse_manifest(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn manifest(v: Value) -> Result<PluginManifest, ManifestError> {
        parse_manifest(&serde_json::to_vec(&v).unwrap())
    }

    /// The spec's example manifest.
    fn valid() -> Value {
        json!({
            "name": "focus-firefox",
            "version": "1.0.0",
            "description": "Focus the Firefox window",
            "params": {
                "title": {"type": "string", "required": true, "description": "title substring"}
            },
            "steps": [
                {"tool": "window_control", "args": {"action": "focus", "window": "${title}"}}
            ]
        })
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write(dir: &Path, file: &str, contents: &str) {
        fs::write(dir.join(file), contents).unwrap();
    }

    // --- manifest roundtrip -------------------------------------------------

    #[test]
    fn valid_manifest_roundtrips() {
        let m = manifest(valid()).unwrap();
        assert_eq!(m.name, "focus-firefox");
        assert_eq!(m.version, "1.0.0");
        assert_eq!(m.description, "Focus the Firefox window");
        assert_eq!(m.steps.len(), 1);
        assert_eq!(m.steps[0].tool, "window_control");
        let p = &m.params["title"];
        assert_eq!(p.ty, ParamType::String);
        assert!(p.required);
    }

    #[test]
    fn minimal_manifest_defaults() {
        let m = manifest(json!({
            "name": "a",
            "version": "0.0.1",
            "steps": [{"tool": "metrics"}]
        }))
        .unwrap();
        assert_eq!(m.description, "");
        assert!(m.params.is_empty());
        assert!(m.steps[0].args.is_empty());
    }

    // --- name / version / structure validation ------------------------------

    #[test]
    fn name_grammar() {
        for good in ["a", "focus-firefox", "x1-2-3", &"a".repeat(64)] {
            assert!(valid_plugin_name(good), "{good}");
        }
        for bad in [
            "",
            "A",
            "-a",
            "a_b", // underscore: params only
            "a.b",
            "a/b",
            &"a".repeat(65),
        ] {
            assert!(!valid_plugin_name(bad), "{bad}");
            assert!(matches!(
                manifest(json!({"name": bad, "version": "1.0.0",
                                "steps": [{"tool": "metrics"}]})),
                Err(ManifestError::Name(_))
            ));
        }
    }

    #[test]
    fn name_colliding_with_catalog_tool_rejected() {
        // Only underscore-free catalog names can ever collide -
        // `window_control` etc. fail the plugin-name grammar first.
        // Assert the collision branch on the names that can reach it.
        for tool in ["sleep", "metrics", "screenshot"] {
            assert!(crate::tools::category_of(tool).is_some(), "{tool} fixture");
            let err = manifest(json!({"name": tool, "version": "1.0.0",
                                      "steps": [{"tool": "metrics"}]}));
            assert!(
                matches!(err, Err(ManifestError::NameCollidesWithTool(_))),
                "{tool} must be rejected, got {err:?}"
            );
        }
        // An underscored catalog name hits the grammar error instead.
        let err = manifest(json!({"name": "window_control", "version": "1.0.0",
                                  "steps": [{"tool": "metrics"}]}));
        assert!(matches!(err, Err(ManifestError::Name(_))));
        // A legal-but-not-a-tool name passes through fine.
        assert!(
            manifest(json!({"name": "window-control", "version": "1.0.0",
                                "steps": [{"tool": "metrics"}]}))
            .is_ok()
        );
    }

    #[test]
    fn version_semverish() {
        for good in [
            "1.0.0",
            "0.0.0",
            "1.2.3-rc.1",
            "1.2.3+build.7",
            "10.20.30-alpha-x",
        ] {
            let mut v = valid();
            v["version"] = json!(good);
            assert!(manifest(v).is_ok(), "{good}");
        }
        for bad in ["", "1.0", "v1.0.0", "1.0.0.0", "1.0.x", "1.0.0-", "1.0.0+"] {
            let mut v = valid();
            v["version"] = json!(bad);
            assert!(
                matches!(manifest(v), Err(ManifestError::Version(_))),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn steps_bounds() {
        // 0 steps -> EmptySteps.
        let err = manifest(json!({"name": "x", "version": "1.0.0", "steps": []})).unwrap_err();
        assert!(matches!(err, ManifestError::EmptySteps));
        // 33 steps -> TooManySteps.
        let steps: Vec<Value> = (0..=MAX_STEPS)
            .map(|_| json!({"tool": "metrics"}))
            .collect();
        let err = manifest(json!({"name": "x", "version": "1.0.0", "steps": steps})).unwrap_err();
        assert!(matches!(err, ManifestError::TooManySteps(n) if n == MAX_STEPS + 1));
        // Exactly MAX_STEPS is fine.
        let steps: Vec<Value> = (0..MAX_STEPS).map(|_| json!({"tool": "metrics"})).collect();
        assert!(manifest(json!({"name": "x", "version": "1.0.0", "steps": steps})).is_ok());
    }

    #[test]
    fn step_tool_must_be_catalogued() {
        let err = manifest(json!({"name": "x", "version": "1.0.0",
                                  "steps": [{"tool": "does_not_exist"}]}))
        .unwrap_err();
        assert!(matches!(err, ManifestError::UnknownTool { index: 0, .. }));
        // A bad tool in a *later* step is still caught, with its index.
        let err = manifest(json!({"name": "x", "version": "1.0.0",
                                  "steps": [{"tool": "metrics"}, {"tool": "nope"}]}))
        .unwrap_err();
        assert!(matches!(err, ManifestError::UnknownTool { index: 1, .. }));
    }

    #[test]
    fn plugin_tools_cannot_be_step_tools() {
        for tool in [
            "plugin_run",
            "plugin_list",
            "plugin_reload",
            "plugin_anything",
        ] {
            let err = manifest(json!({"name": "x", "version": "1.0.0",
                                      "steps": [{"tool": tool}]}))
            .unwrap_err();
            assert!(
                matches!(err, ManifestError::SelfReference { .. }),
                "{tool} must be rejected, got {err:?}"
            );
        }
    }

    // --- params schema validation -------------------------------------------

    #[test]
    fn param_name_grammar() {
        for bad in ["X", "a-b", "_x", "9x"] {
            let err = manifest(json!({"name": "x", "version": "1.0.0",
                                      "params": {bad: {"type": "string"}},
                                      "steps": [{"tool": "metrics"}]}))
            .unwrap_err();
            assert!(matches!(err, ManifestError::ParamName(_)), "{bad}");
        }
        assert!(
            manifest(json!({"name": "x", "version": "1.0.0",
                                "params": {"ok_name1": {"type": "boolean"}},
                                "steps": [{"tool": "metrics"}]}))
            .is_ok()
        );
    }

    #[test]
    fn param_type_must_be_known() {
        let err = manifest(json!({"name": "x", "version": "1.0.0",
                                  "params": {"p": {"type": "integer"}},
                                  "steps": [{"tool": "metrics"}]}))
        .unwrap_err();
        assert!(matches!(err, ManifestError::Json(_)));
    }

    #[test]
    fn unknown_top_level_fields_rejected() {
        let mut v = valid();
        v.as_object_mut()
            .unwrap()
            .insert("exec".into(), json!("rm -rf /"));
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
    }

    // --- manifest_version (fail-closed format seam) ---------------------------

    #[test]
    fn manifest_version_absent_or_one_accepted() {
        // Absent means version 1 - the baseline case.
        assert!(manifest(valid()).is_ok());
        // An explicit `1` declares the same revision.
        let mut v = valid();
        v["manifest_version"] = json!(1);
        assert!(manifest(v).is_ok());
    }

    #[test]
    fn manifest_version_future_fails_closed() {
        for bad in [0, 2, 99] {
            let mut v = valid();
            v["manifest_version"] = json!(bad);
            assert!(
                matches!(
                    manifest(v),
                    Err(ManifestError::UnsupportedVersion(n)) if n == bad
                ),
                "manifest_version {bad} must fail closed"
            );
        }
        // A non-integer declaration never reaches the version gate -
        // it is malformed for this schema (`u32` expected).
        let mut v = valid();
        v["manifest_version"] = json!("2");
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
    }

    #[test]
    fn scan_skips_future_manifest_version_with_reason() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        write(&dir, "good.json", &serde_json::to_string(&valid()).unwrap());
        let mut future = valid();
        future["name"] = json!("future-plugin");
        future["manifest_version"] = json!(2);
        write(
            &dir,
            "future.json",
            &serde_json::to_string(&future).unwrap(),
        );

        let scan = PluginStore::at(&dir).scan();
        assert_eq!(scan.plugins.len(), 1);
        assert_eq!(scan.skipped.len(), 1);
        assert_eq!(scan.skipped[0].file.file_name().unwrap(), "future.json");
        assert!(
            scan.skipped[0].error.contains("manifest_version"),
            "the skip reason must name the field: {}",
            scan.skipped[0].error
        );
    }

    #[test]
    fn manifest_version_does_not_loosen_unknown_fields() {
        // The reserved key is the *only* addition to the schema -
        // `deny_unknown_fields` still rejects everything else.
        let mut v = valid();
        v["manifest_version"] = json!(1);
        v.as_object_mut()
            .unwrap()
            .insert("exec".into(), json!("rm -rf /"));
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
    }

    // --- `${...}` validation ---------------------------------------------------

    #[test]
    fn undeclared_param_ref_rejected() {
        let err = manifest(json!({"name": "x", "version": "1.0.0",
                                  "params": {"a": {"type": "string"}},
                                  "steps": [{"tool": "sleep", "args": {"ms": "${b}"}}]}))
        .unwrap_err();
        assert!(matches!(
            err,
            ManifestError::UndeclaredParam { index: 0, ref name } if name == "b"
        ));
    }

    #[test]
    fn malformed_placeholders_rejected() {
        for bad_arg in ["${", "${x", "${}", "${Bad}", "${a-b}"] {
            let err = manifest(json!({"name": "x", "version": "1.0.0",
                                      "params": {"x": {"type": "string"}},
                                      "steps": [{"tool": "sleep",
                                                 "args": {"note": bad_arg}}]}))
            .unwrap_err();
            assert!(
                matches!(err, ManifestError::Template { .. }),
                "{bad_arg} must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn dollar_escapes_and_literals_are_not_refs() {
        // `$$` escape, lone `$`, `$x` - none reference params.
        let m = manifest(json!({"name": "x", "version": "1.0.0",
                                "steps": [{"tool": "type_text",
                                           "args": {"text": "cost $5 $${x} tail$"}}]}))
        .unwrap();
        let bound = BTreeMap::new();
        let args = substitute_args(&m.steps[0].args, &bound).unwrap();
        assert_eq!(args["text"], "cost $5 ${x} tail$");
    }

    // --- scan ---------------------------------------------------------------

    #[test]
    fn scan_loads_valid_skips_malformed() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        write(&dir, "good.json", &serde_json::to_string(&valid()).unwrap());
        write(&dir, "bad.json", "{\"name\": \"NOPE\"}");
        write(&dir, "not-json.txt", "{\"name\": \"x\"}");
        write(&dir, "also-bad.json", "not json at all");
        fs::create_dir(dir.join("sub.json")).unwrap(); // a dir named *.json - ignored

        let store = PluginStore::at(&dir);
        let scan = store.scan();
        assert_eq!(scan.plugins.len(), 1);
        assert_eq!(scan.plugins[0].manifest.name, "focus-firefox");
        assert_eq!(scan.skipped.len(), 2);
        assert!(
            scan.skipped
                .iter()
                .all(|s| s.file.extension() == Some(std::ffi::OsStr::new("json")))
        );
        // Scanning is read-only - nothing new was created in the dir.
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn scan_missing_dir_is_empty_not_error() {
        let tmp = tmp();
        let store = PluginStore::at(tmp.path().join("does-not-exist"));
        let scan = store.scan();
        assert!(scan.plugins.is_empty());
        assert!(scan.skipped.is_empty());
        // ...and the scan must not have created it (read-only).
        assert!(!store.dir().exists());
    }

    #[test]
    fn scan_duplicate_names_first_wins() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        let mut v2 = valid();
        v2["description"] = json!("second file - must lose");
        write(
            &dir,
            "a-first.json",
            &serde_json::to_string(&valid()).unwrap(),
        );
        write(&dir, "z-second.json", &serde_json::to_string(&v2).unwrap());

        let scan = PluginStore::at(&dir).scan();
        assert_eq!(scan.plugins.len(), 1);
        assert_eq!(
            scan.plugins[0].manifest.description,
            "Focus the Firefox window"
        );
        assert_eq!(scan.skipped.len(), 1);
        assert!(scan.skipped[0].error.contains("duplicate"));
    }

    #[test]
    fn get_resolves_by_name() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        write(&dir, "p.json", &serde_json::to_string(&valid()).unwrap());
        let store = PluginStore::at(&dir);
        assert!(store.get("focus-firefox").is_some());
        assert!(store.get("nope").is_none());
    }

    // --- exposed tools (`tool` / `expose_as_tool` section) --------------------

    /// The spec's example: a plugin that registers `deploy_notes`.
    fn exposed() -> Value {
        json!({
            "manifest_version": 1,
            "name": "deploy-notes",
            "version": "1.0.0",
            "tool": {
                "name": "deploy_notes",
                "description": "Deploy the notes bundle",
                "params": { "env": {"type": "string", "description": "target env", "required": true} }
            },
            "steps": [ {"tool": "type_text", "args": {"text": "${env}"}} ]
        })
    }

    #[test]
    fn tool_section_registers_and_merges_params() {
        let m = manifest(exposed()).unwrap();
        let t = m.tool.as_ref().unwrap();
        assert_eq!(t.name, "deploy_notes");
        assert_eq!(t.description, "Deploy the notes bundle");
        // `tool.params` merged into the bindable set - `${env}` resolved,
        // and `plugin_run{name, params}` binds it identically.
        assert!(m.params["env"].required);
        let bound = bind_params(&m, obj(json!({"env": "prod"}))).unwrap();
        assert_eq!(bound["env"], json!("prod"));
    }

    #[test]
    fn expose_as_tool_alias_accepted() {
        let mut v = exposed();
        let tool = v.as_object_mut().unwrap().remove("tool").unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("expose_as_tool".into(), tool);
        assert_eq!(manifest(v).unwrap().tool.unwrap().name, "deploy_notes");
    }

    #[test]
    fn tool_absent_means_no_exposed_tool() {
        let m = manifest(valid()).unwrap();
        assert!(m.tool.is_none());
        assert!(m.exposed_tool().is_none());
    }

    #[test]
    fn tool_name_grammar() {
        for bad in ["", "Deploy", "-x", "9x", "a-b", "a.b", &"a".repeat(65)] {
            let mut v = exposed();
            v["tool"]["name"] = json!(bad);
            assert!(
                matches!(manifest(v), Err(ManifestError::ToolName(_))),
                "{bad} must be rejected"
            );
        }
        for good in ["a", "deploy_notes", "x1_2_3", &"a".repeat(64)] {
            let mut v = exposed();
            v["tool"]["name"] = json!(good);
            assert!(manifest(v).is_ok(), "{good}");
        }
    }

    #[test]
    fn tool_name_colliding_with_catalog_rejected() {
        // Unlike plugin names, the tool grammar reaches *every*
        // catalog name (underscores included).
        for tool in ["sleep", "metrics", "window_control", "plugin_run"] {
            let mut v = exposed();
            v["tool"]["name"] = json!(tool);
            assert!(
                matches!(manifest(v), Err(ManifestError::ToolNameCollidesWithTool(_))),
                "{tool} must be rejected"
            );
        }
    }

    #[test]
    fn tool_description_capped() {
        let mut v = exposed();
        v["tool"]["description"] = json!("x".repeat(MAX_TOOL_DESCRIPTION));
        assert!(manifest(v).is_ok());
        let mut v = exposed();
        v["tool"]["description"] = json!("x".repeat(MAX_TOOL_DESCRIPTION + 1));
        assert!(matches!(
            manifest(v),
            Err(ManifestError::ToolDescription(n)) if n == MAX_TOOL_DESCRIPTION + 1
        ));
    }

    #[test]
    fn tool_params_validated_like_params() {
        // Bad param name inside tool.params.
        let mut v = exposed();
        v["tool"]["params"] = json!({"Bad-Name": {"type": "string"}});
        assert!(matches!(manifest(v), Err(ManifestError::ParamName(_))));
        // >MAX_PARAMS tool params.
        let many: Map<String, Value> = (0..=MAX_PARAMS)
            .map(|i| (format!("p{i}"), json!({"type": "string"})))
            .collect();
        let mut v = exposed();
        v["tool"]["params"] = Value::Object(many);
        assert!(matches!(
            manifest(v),
            Err(ManifestError::TooManyParams(n)) if n == MAX_PARAMS + 1
        ));
    }

    #[test]
    fn tool_param_declared_twice_rejected() {
        // `env` in both `params` and `tool.params` - declare once.
        let mut v = exposed();
        v["params"] = json!({"env": {"type": "string"}});
        assert!(matches!(
            manifest(v),
            Err(ManifestError::ToolParamDuplicate(ref n)) if n == "env"
        ));
    }

    #[test]
    fn merged_param_count_capped() {
        // params + disjoint tool.params can each be under the cap yet
        // exceed it in union.
        let many: Map<String, Value> = (0..MAX_PARAMS)
            .map(|i| (format!("p{i}"), json!({"type": "string"})))
            .collect();
        let mut v = exposed();
        v["params"] = Value::Object(many);
        v["tool"]["params"] = json!({"extra": {"type": "string"}});
        assert!(matches!(
            manifest(v),
            Err(ManifestError::TooManyParams(n)) if n == MAX_PARAMS + 1
        ));
    }

    #[test]
    fn malformed_tool_section_fails_closed() {
        // tool not an object -> JSON error (skipped at scan).
        let mut v = exposed();
        v["tool"] = json!("deploy_notes");
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
        // tool missing `name`.
        let mut v = exposed();
        v["tool"].as_object_mut().unwrap().remove("name");
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
        // Unknown key inside tool.
        let mut v = exposed();
        v["tool"]["exec"] = json!("rm -rf /");
        assert!(matches!(manifest(v), Err(ManifestError::Json(_))));
    }

    #[test]
    fn tool_schema_generation() {
        let m = manifest(exposed()).unwrap();
        let t = m.exposed_tool().unwrap();
        assert_eq!(t.name.as_ref(), "deploy_notes");
        assert_eq!(t.description.as_deref(), Some("Deploy the notes bundle"));
        let s = &t.input_schema;
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], false);
        assert_eq!(s["properties"]["env"]["type"], "string");
        assert_eq!(s["properties"]["env"]["description"], "target env");
        assert_eq!(s["required"], json!(["env"]));
    }

    #[test]
    fn tool_schema_falls_back_to_manifest_params() {
        // `tool` without `params` advertises the manifest's own params.
        let mut v = valid();
        v["tool"] = json!({"name": "focus_firefox", "description": "Focus Firefox"});
        let m = manifest(v).unwrap();
        let t = m.exposed_tool().unwrap();
        assert_eq!(t.input_schema["properties"]["title"]["type"], "string");
        assert_eq!(t.input_schema["required"], json!(["title"]));
    }

    #[test]
    fn tool_schema_without_params_omits_required() {
        let mut v = exposed();
        v["tool"].as_object_mut().unwrap().remove("params");
        // The step still references ${env} -> now undeclared -> invalid.
        assert!(matches!(
            manifest(v),
            Err(ManifestError::UndeclaredParam { .. })
        ));
        // With a param-free step the schema has an empty properties and
        // no `required` key (schemars' convention for the catalog).
        let v = json!({
            "name": "ping",
            "version": "1.0.0",
            "tool": {"name": "ping_tool", "description": ""},
            "steps": [{"tool": "metrics"}]
        });
        let m = manifest(v).unwrap();
        let t = m.exposed_tool().unwrap();
        assert_eq!(t.input_schema["properties"], json!({}));
        assert!(t.input_schema.get("required").is_none());
    }

    #[test]
    fn scan_skips_duplicate_tool_names() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        write(
            &dir,
            "a-first.json",
            &serde_json::to_string(&exposed()).unwrap(),
        );
        // Different plugin name, same tool name - must lose to the
        // lexically-earlier file.
        let mut second = exposed();
        second["name"] = json!("deploy-other");
        second["tool"]["description"] = json!("second file - must lose");
        write(
            &dir,
            "z-second.json",
            &serde_json::to_string(&second).unwrap(),
        );

        let scan = PluginStore::at(&dir).scan();
        assert_eq!(scan.plugins.len(), 1);
        assert_eq!(scan.plugins[0].manifest.name, "deploy-notes");
        assert_eq!(scan.skipped.len(), 1);
        assert!(
            scan.skipped[0].error.contains("duplicate plugin tool name"),
            "{}",
            scan.skipped[0].error
        );
    }

    #[test]
    fn tool_registry_resolves_and_lists() {
        let tmp = tmp();
        let dir = tmp.path().join("plugins");
        fs::create_dir(&dir).unwrap();
        write(&dir, "d.json", &serde_json::to_string(&exposed()).unwrap());
        write(&dir, "p.json", &serde_json::to_string(&valid()).unwrap());

        let registry = ToolRegistry::at(&dir);
        // resolve by tool name yields the owning plugin.
        let p = registry.resolve("deploy_notes").unwrap();
        assert_eq!(p.manifest.name, "deploy-notes");
        assert!(registry.resolve("focus_firefox").is_none()); // valid() exposes none
        assert!(registry.resolve("nope").is_none());
        // tools() yields the exposed entries only.
        let tools = registry.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name.as_ref(), "deploy_notes");
        // Live view: drop a manifest, next call sees it - the
        // `plugin_reload` "refresh" is a scan, not a cache flush.
        let mut extra = exposed();
        extra["name"] = json!("other-plugin");
        extra["tool"]["name"] = json!("other_tool");
        write(&dir, "o.json", &serde_json::to_string(&extra).unwrap());
        assert_eq!(registry.tools().len(), 2);
    }

    // --- bind_params ---------------------------------------------------------

    fn manifest_with_params() -> PluginManifest {
        manifest(json!({
            "name": "x",
            "version": "1.0.0",
            "params": {
                "req_s": {"type": "string", "required": true},
                "opt_n": {"type": "number"},
                "opt_b": {"type": "boolean"}
            },
            "steps": [{"tool": "metrics"}]
        }))
        .unwrap()
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn bind_accepts_and_type_checks() {
        let m = manifest_with_params();
        let bound =
            bind_params(&m, obj(json!({"req_s": "hi", "opt_n": 5, "opt_b": true}))).unwrap();
        assert_eq!(bound.len(), 3);
        // Missing required -> Missing.
        assert!(matches!(
            bind_params(&m, obj(json!({}))),
            Err(ParamError::Missing(ref n)) if n == "req_s"
        ));
        // Extra supplied -> Unknown (strict - documented).
        assert!(matches!(
            bind_params(&m, obj(json!({"req_s": "x", "zzz": 1}))),
            Err(ParamError::Unknown(ref n)) if n == "zzz"
        ));
        // Wrong type.
        assert!(matches!(
            bind_params(&m, obj(json!({"req_s": "x", "opt_n": "5"}))),
            Err(ParamError::WrongType {
                expected: "number",
                ..
            })
        ));
        assert!(matches!(
            bind_params(&m, obj(json!({"req_s": 5}))),
            Err(ParamError::WrongType {
                expected: "string",
                ..
            })
        ));
    }

    // --- substitute_args -----------------------------------------------------

    #[test]
    fn substitute_whole_string_keeps_json_type() {
        let mut bound = BTreeMap::new();
        bound.insert("ms".to_string(), json!(0));
        bound.insert("flag".to_string(), json!(true));
        bound.insert("s".to_string(), json!("txt"));
        let args = obj(json!({"a": "${ms}", "b": "${flag}", "c": "${s}"}));
        let out = substitute_args(&args, &bound).unwrap();
        assert_eq!(out["a"], json!(0)); // number stays a number
        assert_eq!(out["b"], json!(true)); // bool stays a bool
        assert_eq!(out["c"], json!("txt"));
    }

    #[test]
    fn substitute_embedded_stringifies() {
        let mut bound = BTreeMap::new();
        bound.insert("ms".to_string(), json!(42));
        bound.insert("flag".to_string(), json!(false));
        let args = obj(json!({"note": "wait ${ms}ms flag=${flag}"}));
        let out = substitute_args(&args, &bound).unwrap();
        assert_eq!(out["note"], "wait 42ms flag=false");
    }

    #[test]
    fn substitute_recurses_objects_and_arrays() {
        let mut bound = BTreeMap::new();
        bound.insert("x".to_string(), json!("V"));
        let args = obj(json!({
            "outer": {"inner": ["${x}", {"deep": "pre-${x}-post"}], "n": 7}
        }));
        let out = substitute_args(&args, &bound).unwrap();
        assert_eq!(out["outer"]["inner"][0], "V");
        assert_eq!(out["outer"]["inner"][1]["deep"], "pre-V-post");
        assert_eq!(out["outer"]["n"], 7); // non-strings untouched
    }

    #[test]
    fn substitute_unsupplied_optional_is_runtime_error() {
        let args = obj(json!({"note": "${maybe}"}));
        let err = substitute_args(&args, &BTreeMap::new()).unwrap_err();
        assert!(matches!(err, ParamError::Unsupplied { ref name } if name == "maybe"));
    }

    #[test]
    fn ambient_resolves_under_state_root() {
        // Pure resolution - no env mutation: for_state_root pins the
        // subdirectory name ambient() joins onto the resolved root.
        let s = PluginStore::for_state_root("/some/root");
        assert_eq!(s.dir(), Path::new("/some/root/plugins"));
    }
}
