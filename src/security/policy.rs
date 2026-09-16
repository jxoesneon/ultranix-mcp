//! Runtime access-control policy - per-key scoping, `--readonly`, and
//! per-tool allow/deny lists (docs/adr/0010-policy-controls.md).
//!
//! The policy is loaded once at startup from a TOML file and/or CLI flags.
//! For every `tools/list` and `tools/call` the resolved [`Role`] decides
//! whether the tool is advertised and executable.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level policy file plus CLI overrides.
///
/// `default_role` applies to stdio sessions and HTTP keys that are not
/// explicitly mapped. `keys` maps a key *fingerprint* (not the secret) to a
/// `roles` entry. Unknown key IDs fall back to `default_role`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub default_role: Role,
    #[serde(default)]
    pub roles: HashMap<String, Role>,
    /// key_id fingerprint -> role name.
    #[serde(default)]
    pub keys: HashMap<String, String>,
}

/// One named role: a set of allowed/denied tools plus a readonly shortcut.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    /// Shortcut that implicitly allows only the non-mutating tools.
    #[serde(default)]
    pub readonly: bool,
    /// If `Some`, only these tools are visible/callable (unioned with
    /// the readonly preset when `readonly` is true). `None` means no
    /// tool-specific allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_tools: Option<HashSet<String>>,
    /// Tools explicitly denied even if they would otherwise be allowed.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub deny_tools: HashSet<String>,
}

impl Policy {
    /// Load policy from an optional TOML file, then layer CLI overrides on
    /// top. CLI `--readonly`, `--allow-tools`, and `--deny-tools` mutate
    /// the `default_role`; `--policy` provides a file that may define
    /// named roles and per-key mappings.
    ///
    /// `file` semantics are fail-closed: `Some(path)` means the caller
    /// *named* a file, so a missing or unparsable file is a startup error -
    /// never a silent fallback to the permissive default. `None` means "no
    /// file was requested" and yields the default policy.
    pub fn from_file_and_cli(
        file: Option<&Path>,
        readonly: bool,
        allow: &[String],
        deny: &[String],
    ) -> anyhow::Result<Self> {
        let mut policy = match file {
            Some(path) => {
                let contents = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("policy file {}: {e}", path.display()))?;
                toml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("policy file {}: {e}", path.display()))?
            }
            None => Self::default(),
        };

        if readonly {
            policy.default_role.readonly = true;
        }
        if !allow.is_empty() {
            if readonly {
                // A CLI allowlist augments the readonly preset. This deliberately
                // permits operators to opt individual mutating tools back in.
                policy
                    .default_role
                    .allow_tools
                    .get_or_insert_with(HashSet::new)
                    .extend(allow.iter().cloned());
            } else {
                policy.default_role.allow_tools = Some(allow.iter().cloned().collect());
            }
        }
        policy.default_role.deny_tools.extend(deny.iter().cloned());
        policy.validate()?;
        Ok(policy)
    }

    /// Fail-closed structural validation, run at load time:
    /// - every `keys` mapping must reference a defined role (a typo'd role
    ///   name would otherwise silently grant `default_role`);
    /// - unknown tool names in allow/deny lists and malformed key
    ///   fingerprints are warned (they may be forward-references to newer
    ///   tool names, so they warn rather than abort).
    fn validate(&self) -> anyhow::Result<()> {
        let mut dangling: Vec<(&str, &str)> = self
            .keys
            .iter()
            .filter(|(_, role)| !self.roles.contains_key(*role))
            .map(|(key, role)| (key.as_str(), role.as_str()))
            .collect();
        dangling.sort_unstable();
        anyhow::ensure!(
            dangling.is_empty(),
            "policy keys map to undefined roles: {}",
            dangling
                .iter()
                .map(|(k, r)| format!("{k} -> {r}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for key in self.keys.keys() {
            // key_id fingerprints are lowercase hex (auth.rs); uppercase
            // passes is_ascii_hexdigit but never matches the lookup.
            let malformed = key.len() != 8
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b.is_ascii_hexdigit());
            if malformed {
                tracing::warn!(
                    key_id = %key,
                    "policy keys entry is not an 8-char lowercase-hex key_id fingerprint; it will never match"
                );
            }
        }
        for (role_name, role) in self
            .roles
            .iter()
            .map(|(n, r)| (n.as_str(), r))
            .chain(std::iter::once(("default_role", &self.default_role)))
        {
            for tool in role
                .deny_tools
                .iter()
                .chain(role.allow_tools.iter().flatten())
            {
                if crate::tools::category_of(tool).is_none() {
                    // Plugin-exposed tool names are valid targets but live
                    // outside the static catalog - name grammar
                    // distinguishes a plausible plugin tool from a typo.
                    let plausible_plugin_name =
                        tool.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                            && tool
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                    if plausible_plugin_name {
                        tracing::debug!(
                            role = %role_name,
                            tool = %tool,
                            "policy references a non-catalog name - expected for plugin-exposed tools"
                        );
                    } else {
                        tracing::warn!(
                            role = %role_name,
                            tool = %tool,
                            "policy references a tool name not in the catalog (typo?)"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve the effective role for a caller: `key_id` fingerprint lookup
    /// wins, then the default role.
    pub fn resolve(&self, key_id: Option<&str>) -> &Role {
        key_id
            .and_then(|id| self.keys.get(id))
            .and_then(|role| self.roles.get(role))
            .unwrap_or(&self.default_role)
    }

    /// Returns true if `tool` is allowed under `role`.
    pub fn is_tool_allowed(&self, role: &Role, tool: &str) -> bool {
        role.allows(tool)
    }
}

impl Role {
    /// Convenience predicate combining `readonly`, allowlist, and denylist.
    pub fn allows(&self, tool: &str) -> bool {
        if self.deny_tools.contains(tool) {
            return false;
        }
        if self.readonly {
            return readonly_allowlist().contains(&tool)
                || self
                    .allow_tools
                    .as_ref()
                    .is_some_and(|allowed| allowed.contains(tool));
        }
        self.allow_tools
            .as_ref()
            .is_none_or(|allowed| allowed.contains(tool))
    }
}

/// The catalog tools that are safe to expose in `--readonly` mode.
///
/// Strictly observation-only: no input injection, no AT-SPI actions
/// (`invoke_element`), no visible overlay (`screen_highlight`), no
/// process-global state writes (`set_spatial_focus`), no file output
/// (`screen_record`), no cross-caller disclosure (`get_action_history`,
/// `clipboard_get`), and no server-state mutation (`plugin_reload`).
/// Operators can opt individual tools back in via `--allow-tools` /
/// `allow_tools`, which is unioned with this preset for readonly roles.
pub fn readonly_allowlist() -> &'static [&'static str] {
    &[
        "screenshot",
        "screen_info",
        "color_at",
        "get_ui_tree",
        "get_focused_element",
        "find_element",
        "find_text_on_screen",
        "find_icon",
        "wait_for_ui_element",
        "sleep",
        "mouse_get_position",
        "get_windows",
        "get_active_window",
        "metrics",
        "plugin_list",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn loads_policy_file_and_resolves_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            r#"
[default_role]
allow_tools = ["screenshot", "get_windows"]
deny_tools = ["get_windows"]

[roles.automation]
allow_tools = ["type_text", "screenshot"]

[keys]
"b8695f39" = "automation"
"#,
        )
        .unwrap();

        let policy = Policy::from_file_and_cli(Some(&path), false, &[], &[]).unwrap();
        assert!(policy.resolve(Some("b8695f39")).allows("type_text"));
        assert!(!policy.default_role.allows("get_windows"));
    }

    #[test]
    fn missing_explicit_file_is_a_startup_error() {
        // Fail-closed: an explicitly named policy file must exist - a typo'd
        // path must not silently grant the permissive default.
        assert!(
            Policy::from_file_and_cli(Some(Path::new("/definitely/missing")), false, &[], &[])
                .is_err()
        );
        // No file requested -> default policy.
        let policy = Policy::from_file_and_cli(None, false, &[], &[]).unwrap();
        assert!(std::ptr::eq(policy.resolve(None), &policy.default_role));
        assert!(std::ptr::eq(
            policy.resolve(Some("unknown")),
            &policy.default_role
        ));
    }

    #[test]
    fn dangling_role_reference_and_unknown_fields_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        // A keys entry pointing at an undefined role fails closed at load.
        std::fs::write(&path, "[keys]\n\"b8695f39\" = \"ghost\"\n").unwrap();
        assert!(Policy::from_file_and_cli(Some(&path), false, &[], &[]).is_err());
        // Misspelled TOML keys are rejected, not silently ignored.
        std::fs::write(&path, "[default_role]\nreadnly = true\n").unwrap();
        assert!(Policy::from_file_and_cli(Some(&path), false, &[], &[]).is_err());
    }

    #[test]
    fn cli_allow_replaces_file_allow_and_deny_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            "[default_role]\nallow_tools = [\"old\"]\ndeny_tools = [\"prior\"]\n",
        )
        .unwrap();
        let policy = Policy::from_file_and_cli(
            Some(&path),
            false,
            &strings(&["new"]),
            &strings(&["blocked"]),
        )
        .unwrap();
        assert!(policy.default_role.allows("new"));
        assert!(!policy.default_role.allows("old"));
        assert!(!policy.default_role.allows("prior"));
        assert!(!policy.default_role.allows("blocked"));
        assert!(!policy.default_role.allows("unknown"));
    }

    #[test]
    fn readonly_preset_and_explicit_cli_allow_are_unioned() {
        let policy = Policy::from_file_and_cli(
            None,
            true,
            &strings(&["type_text"]),
            &strings(&["screenshot"]),
        )
        .unwrap();
        assert!(policy.default_role.allows("get_windows"));
        assert!(policy.default_role.allows("type_text"));
        assert!(!policy.default_role.allows("screenshot"));
        assert!(!policy.default_role.allows("system_command"));
    }

    #[test]
    fn deny_wins_over_allow() {
        let role = Role {
            allow_tools: Some(strings(&["screenshot"]).into_iter().collect()),
            deny_tools: strings(&["screenshot"]).into_iter().collect(),
            ..Role::default()
        };
        assert!(!role.allows("screenshot"));
        assert!(!role.allows("unknown"));
        assert!(!Policy::default().is_tool_allowed(&role, "screenshot"));
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "not valid = [toml").unwrap();
        assert!(Policy::from_file_and_cli(Some(&path), false, &[], &[]).is_err());
    }
}
