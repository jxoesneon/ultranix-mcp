//! Arg-constrained command whitelist - SECURITY.md "Arg-constrained command
//! whitelist" and docs/TOOLS.md `system_command`.
//!
//! Membership in the closed set `{grim, slurp, hyprctl, scrot, xdotool,
//! wmctrl}` is necessary but not sufficient: each member's argv is
//! constrained here, and every binary is resolved to an absolute path at
//! startup and pinned so a later `PATH` hijack cannot substitute a trojan.
//! The pin set is wider than the invocable set - provider-internal
//! helpers (`xrandr`, `xprop`, `wl-copy`, `wl-paste`, `xclip`, `xsel`,
//! `kdotool`) are resolved-and-spawned by providers but have no
//! `validate_command` arm, so `system_command` can never reach them.
//!
//! `busctl`/`gdbus` are deliberately absent - generic D-Bus clients are
//! arbitrary-exec primitives (THREAT_MODEL.md §4.10); D-Bus work happens
//! in-process via `zbus`/`atspi`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::security::paths;
use crate::security::sanitize::{SanitizeError, sanitize_arg};

/// Binaries that may ever be spawned by `system_command`.
/// Pin set - includes provider-internal helpers (`xrandr`, `xprop`,
/// `wl-copy`, `wl-paste`, `xclip`, `xsel`, `kdotool`, `riverctl`) that
/// are resolved-and-spawned by X11/clipboard/compositor providers but
/// have no `validate_command` arm, so `system_command` cannot invoke
/// them.
pub const WHITELIST: &[&str] = &[
    "grim", "slurp", "hyprctl", "scrot", "xdotool", "wmctrl", "xrandr", "xprop", "wl-copy",
    "wl-paste", "xclip", "xsel", "kdotool", "riverctl",
];

/// Schema-level cap on argv length (docs/TOOLS.md `system_command.args.maxItems`).
pub const MAX_ARGS: usize = 16;

/// `hyprctl` read-only subcommands.
const HYPRCTL_READS: &[&str] = &["clients", "activewindow", "monitors", "workspaces"];

/// `hyprctl dispatch` subcommands that are permitted - window management,
/// never process execution. `exec`/`exec-once` are arbitrary code execution
/// wearing a whitelisted binary's name (SECURITY.md).
const HYPRCTL_DISPATCHERS: &[&str] = &[
    "focuswindow",
    "movewindow",
    "resizewindow",
    "workspace",
    "movetoworkspace",
];

/// Rejection reasons - `NotWhitelisted` and `ArgConstraint` both map to
/// `-32003`; `Sanitize` maps to `-32006`; `Path` to `-32004`
/// (docs/TOOLS.md error table).
#[derive(Debug, thiserror::Error)]
pub enum WhitelistError {
    /// Binary outside the closed set, or absent from `PATH` at pin time.
    #[error("command not whitelisted or unavailable: {0}")]
    NotWhitelisted(String),
    /// Whitelisted binary invoked with a denied subcommand/flag/argument.
    #[error("argument constraint violation for {cmd}: {detail}")]
    ArgConstraint { cmd: String, detail: String },
    /// Defense-in-depth resanitization caught a metacharacter/control byte.
    #[error("sanitization rejected: {0}")]
    Sanitize(#[from] SanitizeError),
    /// Server-supplied capture path failed the path whitelist.
    #[error("capture path rejected: {0}")]
    Path(#[from] paths::PathWhitelistError),
}

fn arg_constraint(cmd: &str, detail: impl Into<String>) -> WhitelistError {
    WhitelistError::ArgConstraint {
        cmd: cmd.to_string(),
        detail: detail.into(),
    }
}

/// A validated invocation: the pinned absolute binary path plus the final
/// argv (argv[0] is the command name, conventions of `Command::new`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsoluteInvocation {
    /// Pinned absolute path to the binary - spawn this, never a bare name.
    pub abs_path: PathBuf,
    /// Complete argument vector, output path included where applicable.
    pub argv: Vec<String>,
}

/// The command set resolved to absolute paths, pinned at startup.
///
/// Resolution happens once: every member is looked up along `PATH`, and the
/// first executable hit is canonicalized and stored. A member absent from
/// `PATH` is simply unpinned - [`PinnedBins::validate_command`] then rejects
/// it as `NotWhitelisted` (spec: "binary absent at startup pin time is
/// treated as unavailable").
#[derive(Debug, Clone, Default)]
pub struct PinnedBins {
    bins: HashMap<String, PathBuf>,
}

impl PinnedBins {
    /// Resolve every whitelist member along `PATH` exactly once.
    pub fn resolve() -> Self {
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        let dirs: Vec<PathBuf> = std::env::split_paths(&path_var).collect();
        Self::resolve_in(&dirs)
    }

    /// Resolution against an explicit directory list - factored out for
    /// hermetic tests (mutating `PATH` inside a test process is unsound).
    pub(crate) fn resolve_in(dirs: &[PathBuf]) -> Self {
        let mut bins = HashMap::with_capacity(WHITELIST.len());
        'members: for name in WHITELIST {
            for dir in dirs {
                let candidate = dir.join(name);
                if is_executable(&candidate)
                    && let Ok(abs) = candidate.canonicalize()
                {
                    bins.insert((*name).to_string(), abs);
                    continue 'members;
                }
            }
        }
        Self { bins }
    }

    /// The pinned path for `name`, if resolved at startup.
    pub fn get(&self, name: &str) -> Option<&Path> {
        self.bins.get(name).map(PathBuf::as_path)
    }

    /// Whether `name` was resolved at pin time.
    pub fn is_available(&self, name: &str) -> bool {
        self.bins.contains_key(name)
    }

    /// Validate `cmd` + `args` against the per-binary constraints and return
    /// a spawn-ready [`AbsoluteInvocation`].
    ///
    /// `x11_active` gates `xdotool`/`wmctrl` - they are refused on native
    /// Wayland sessions (they are the X11/XWayland fallback backend).
    ///
    /// `capture_out` is the **server-supplied**output path for `grim`/
    /// `scrot` (inside a fresh `0700` dir from [`crate::security::captures`]);
    /// required for those two, forbidden for every other command. Callers
    /// never supply an output file argument - the whitelist enforces that
    /// structurally.
    pub fn validate_command(
        &self,
        cmd: &str,
        args: &[String],
        x11_active: bool,
        capture_out: Option<&Path>,
    ) -> Result<AbsoluteInvocation, WhitelistError> {
        if args.len() > MAX_ARGS {
            return Err(arg_constraint(cmd, "too many arguments"));
        }
        // Defense in depth: the pipeline sanitizes before this layer, but a
        // future callsite must not be able to skip it - e.g. `slurp -f`
        // legitimately takes a free-form format string that could carry `;`.
        // The command name itself is user-supplied too, so it is resanitized
        // alongside the args (metachars in `cmd` -> `-32006`, not `-32003`).
        sanitize_arg(cmd)?;
        for a in args {
            sanitize_arg(a)?;
        }

        let abs_path = self
            .get(cmd)
            .ok_or_else(|| WhitelistError::NotWhitelisted(cmd.to_string()))?
            .to_path_buf();

        let mut argv: Vec<String> = Vec::with_capacity(args.len() + 1);
        argv.push(cmd.to_string());
        match cmd {
            "grim" => {
                validate_grim(cmd, args, &mut argv)?;
                argv.push(capture_arg(cmd, capture_out)?);
            }
            "scrot" => {
                validate_scrot(cmd, args, &mut argv)?;
                argv.push(capture_arg(cmd, capture_out)?);
            }
            "slurp" => {
                reject_capture_out(cmd, capture_out)?;
                validate_slurp(cmd, args, &mut argv)?;
            }
            "hyprctl" => {
                reject_capture_out(cmd, capture_out)?;
                validate_hyprctl(cmd, args, &mut argv)?;
            }
            "xdotool" => {
                reject_capture_out(cmd, capture_out)?;
                if !x11_active {
                    return Err(arg_constraint(
                        cmd,
                        "permitted only under the X11/XWayland fallback backend",
                    ));
                }
                validate_xdotool(cmd, args, &mut argv)?;
            }
            "wmctrl" => {
                reject_capture_out(cmd, capture_out)?;
                if !x11_active {
                    return Err(arg_constraint(
                        cmd,
                        "permitted only under the X11/XWayland fallback backend",
                    ));
                }
                // wmctrl exposes no exec-capable subcommand - the X11
                // gate + sanitization are the constraint.
                argv.extend(args.iter().cloned());
            }
            _ => return Err(WhitelistError::NotWhitelisted(cmd.to_string())),
        }
        Ok(AbsoluteInvocation { abs_path, argv })
    }
}

/// Search `PATH` once and pin the whitelist set - process-wide. Every
/// caller (`SecurityContext::pins`, each provider's pin field) shares
/// the single snapshot taken on first use, so resolution can never
/// observe a `PATH` mutated between two construction sites (S-1).
pub fn resolve_binaries() -> PinnedBins {
    static SHARED: std::sync::OnceLock<PinnedBins> = std::sync::OnceLock::new();
    SHARED.get_or_init(PinnedBins::resolve).clone()
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && path
            .metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// `grim`/`scrot` output path: server-supplied only. Validated against the
/// path whitelist's *parent* rule (the leaf does not exist yet - the spawned
/// binary creates it).
fn capture_arg(cmd: &str, capture_out: Option<&Path>) -> Result<String, WhitelistError> {
    let out = capture_out
        .ok_or_else(|| arg_constraint(cmd, "requires a server-supplied capture path"))?;
    if !paths::parent_under_roots(out, &paths::roots()) {
        // A path-whitelist failure maps to `-32004 PathNotWhitelisted`
        // (docs/TOOLS.md error table), not the arg-constraint code.
        return Err(WhitelistError::Path(
            paths::PathWhitelistError::OutsideRoots(out.to_path_buf()),
        ));
    }
    Ok(out.to_string_lossy().into_owned())
}

fn reject_capture_out(cmd: &str, capture_out: Option<&Path>) -> Result<(), WhitelistError> {
    if capture_out.is_some() {
        return Err(arg_constraint(cmd, "does not take a capture output path"));
    }
    Ok(())
}

/// `grim [-o <output>] [-g <geometry>]` - no caller `[file]` argument, no
/// other flags (`-t`, `-c`, `-l`, `-s`, `-w`, `-h` all denied).
fn validate_grim(cmd: &str, args: &[String], argv: &mut Vec<String>) -> Result<(), WhitelistError> {
    let mut seen_o = false;
    let mut seen_g = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (seen, flag) = match a.as_str() {
            "-o" => (&mut seen_o, "-o"),
            "-g" => (&mut seen_g, "-g"),
            _ => {
                return Err(arg_constraint(
                    cmd,
                    format!(
                        "unsupported argument {a:?} - only -o <output> and -g <geometry> are allowed"
                    ),
                ));
            }
        };
        if *seen {
            return Err(arg_constraint(cmd, format!("duplicate {flag}")));
        }
        *seen = true;
        let val = it
            .next()
            .ok_or_else(|| arg_constraint(cmd, format!("{flag} requires a value")))?;
        argv.push(flag.to_string());
        argv.push(val.clone());
    }
    Ok(())
}

/// `scrot [-s] [-d <sec>]` - no caller `[file]` argument.
fn validate_scrot(
    cmd: &str,
    args: &[String],
    argv: &mut Vec<String>,
) -> Result<(), WhitelistError> {
    let mut seen_s = false;
    let mut seen_d = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-s" => {
                if seen_s {
                    return Err(arg_constraint(cmd, "duplicate -s"));
                }
                seen_s = true;
                argv.push("-s".into());
            }
            "-d" => {
                if seen_d {
                    return Err(arg_constraint(cmd, "duplicate -d"));
                }
                seen_d = true;
                let val = it
                    .next()
                    .ok_or_else(|| arg_constraint(cmd, "-d requires a seconds value"))?;
                if val.parse::<f64>().map(|v| v >= 0.0).unwrap_or(false) {
                    argv.push("-d".into());
                    argv.push(val.clone());
                } else {
                    return Err(arg_constraint(
                        cmd,
                        format!("-d expects a non-negative number of seconds, got {val:?}"),
                    ));
                }
            }
            _ => {
                return Err(arg_constraint(
                    cmd,
                    format!("unsupported argument {a:?} - only -s and -d <sec> are allowed"),
                ));
            }
        }
    }
    Ok(())
}

/// `xdotool` subcommands that `system_command` may invoke. Pointing,
/// typing, and window queries only - the exec-capable primitives
/// (`exec`, `execsync`, `behave`, `behave_screen_edge`) are denied the
/// same way `hyprctl dispatch exec` is (THREAT_MODEL §7).
const XDOTOOL_SUBCOMMANDS: &[&str] = &[
    // pointer
    "mousemove",
    "mousemove_relative",
    "click",
    "mousedown",
    "mouseup",
    "getmouselocation",
    // keyboard
    "type",
    "key",
    "keydown",
    "keyup",
    // window ops / queries (no exec primitives)
    "windowactivate",
    "windowfocus",
    "windowraise",
    "windowminimize",
    "windowmap",
    "windowunmap",
    "windowsize",
    "windowmove",
    "windowclose",
    "getactivewindow",
    "getwindowname",
    "getwindowpid",
    "getwindowgeometry",
    "getwindowfocus",
    "getdisplaygeometry",
    "get_desktop",
    "get_num_desktops",
    "search",
];

fn validate_xdotool(
    cmd: &str,
    args: &[String],
    argv: &mut Vec<String>,
) -> Result<(), WhitelistError> {
    // The first non-flag argument is the subcommand. xdotool takes
    // global flags before it; the value-taking ones must be skipped so
    // their operand isn't mistaken for the subcommand.
    const VALUE_FLAGS: &[&str] = &[
        "--delay",
        "--repeat-delay",
        "--repeat",
        "--window",
        "--screen",
    ];
    let mut it = args.iter();
    let mut sub = None;
    while let Some(a) = it.next() {
        if a.starts_with('-') {
            if VALUE_FLAGS.contains(&a.as_str()) {
                it.next(); // consume the flag's operand
            }
            continue;
        }
        sub = Some(a.as_str());
        break;
    }
    let sub = sub.ok_or_else(|| arg_constraint(cmd, "missing subcommand"))?;
    if !XDOTOOL_SUBCOMMANDS.contains(&sub) {
        return Err(arg_constraint(
            cmd,
            format!("unsupported subcommand {sub:?} - exec-capable and unlisted verbs are denied"),
        ));
    }
    argv.extend(args.iter().cloned());
    Ok(())
}

/// `slurp [-f <format>] [-d] [-b <color>] [-c <color>]` - fixed flag set,
/// no path arguments. All other slurp flags (`-o`, `-p`, `-w`, `-s`, `-h`,
/// `-r`, ...) are denied per the spec table ("everything else").
fn validate_slurp(
    cmd: &str,
    args: &[String],
    argv: &mut Vec<String>,
) -> Result<(), WhitelistError> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-d" => argv.push("-d".into()),
            "-f" | "-b" | "-c" => {
                let val = it
                    .next()
                    .ok_or_else(|| arg_constraint(cmd, format!("{a} requires a value")))?;
                argv.push(a.clone());
                argv.push(val.clone());
            }
            _ => {
                return Err(arg_constraint(
                    cmd,
                    format!(
                        "unsupported argument {a:?} - allowed: -f <fmt>, -d, -b <color>, -c <color>"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// `hyprctl [-j] <read-sub>` or `hyprctl [-j] dispatch <allowed-dispatcher>
/// <args...>`. Everything else - `keyword`, `setprop`, `reload`, `dispatch
/// exec`/`exec-once`, other dispatchers, other flags - is denied.
fn validate_hyprctl(
    cmd: &str,
    args: &[String],
    argv: &mut Vec<String>,
) -> Result<(), WhitelistError> {
    let mut rest: &[String] = args;
    // `-j` is the one sanctioned global flag; allow it once, leading.
    if let Some((first, tail)) = rest.split_first()
        && first == "-j"
    {
        argv.push("-j".into());
        rest = tail;
    }
    let (sub, sub_args) = rest
        .split_first()
        .ok_or_else(|| arg_constraint(cmd, "missing subcommand"))?;
    if HYPRCTL_READS.contains(&sub.as_str()) {
        if !sub_args.is_empty() {
            return Err(arg_constraint(
                cmd,
                format!("{sub} takes no further arguments"),
            ));
        }
        argv.push(sub.clone());
        return Ok(());
    }
    if sub == "dispatch" {
        let (dispatcher, dargs) = sub_args
            .split_first()
            .ok_or_else(|| arg_constraint(cmd, "dispatch requires a dispatcher"))?;
        if !HYPRCTL_DISPATCHERS.contains(&dispatcher.as_str()) {
            return Err(arg_constraint(
                cmd,
                format!("dispatcher {dispatcher:?} denied - allowed: {HYPRCTL_DISPATCHERS:?}"),
            ));
        }
        if dargs.is_empty() || dargs.len() > 4 {
            return Err(arg_constraint(
                cmd,
                format!("dispatch {dispatcher} expects 1..=4 arguments"),
            ));
        }
        argv.push("dispatch".into());
        argv.push(dispatcher.clone());
        argv.extend(dargs.iter().cloned());
        return Ok(());
    }
    Err(arg_constraint(
        cmd,
        format!(
            "subcommand {sub:?} denied - allowed: {HYPRCTL_READS:?} plus dispatch {HYPRCTL_DISPATCHERS:?}"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// A pin set with every member mapped into `dir` - arg-validation tests
    /// don't need real binaries, just non-empty pins.
    fn pins_all(dir: &Path) -> PinnedBins {
        let mut bins = HashMap::new();
        for name in WHITELIST {
            bins.insert((*name).to_string(), dir.join(name));
        }
        PinnedBins { bins }
    }

    /// A pin set containing only `names`.
    fn pins_some(dir: &Path, names: &[&str]) -> PinnedBins {
        let mut bins = HashMap::new();
        for name in names {
            bins.insert((*name).to_string(), dir.join(name));
        }
        PinnedBins { bins }
    }

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    /// A capture dir inside an allowed root for capture_out tests.
    fn capture_dir() -> tempfile::TempDir {
        tempfile::tempdir_in("/tmp").expect("capture dir under /tmp")
    }

    // ---- grim ------------------------------------------------------------

    #[test]
    fn grim_accepts_sanctioned_forms() {
        let pins = pins_all(Path::new("/pinned"));
        let cap = capture_dir();
        let out = cap.path().join("shot.png");

        for args in [
            vec![],
            s(&["-o", "DP-1"]),
            s(&["-g", "0,0 1920x1080"]),
            s(&["-o", "DP-1", "-g", "0,0 100x100"]),
            s(&["-g", "0,0 100x100", "-o", "HDMI-A-1"]),
        ] {
            let inv = pins
                .validate_command("grim", &args, false, Some(&out))
                .unwrap_or_else(|e| panic!("grim {args:?} should pass: {e}"));
            assert_eq!(inv.abs_path, Path::new("/pinned/grim"));
            assert_eq!(inv.argv.last().unwrap(), &out.to_string_lossy());
        }
    }

    #[test]
    fn grim_denies_caller_paths_and_other_flags() {
        let pins = pins_all(Path::new("/pinned"));
        let cap = capture_dir();
        let out = cap.path().join("shot.png");
        for args in [
            s(&["/tmp/evil.png"]),       // caller-chosen output path
            s(&["-o", "DP-1", "x.png"]), // positional file arg
            s(&["-t", "png"]),
            s(&["-c"]),
            s(&["-s", "1.5"]),
            s(&["-o"]),                 // dangling flag
            s(&["-o", "a", "-o", "b"]), // duplicate
        ] {
            assert!(
                pins.validate_command("grim", &args, false, Some(&out))
                    .is_err(),
                "grim {args:?} must be denied"
            );
        }
        // And without a server-supplied path grim is refused outright.
        assert!(pins.validate_command("grim", &[], false, None).is_err());
    }

    // ---- scrot -----------------------------------------------------------

    #[test]
    fn scrot_accepts_sanctioned_forms() {
        let pins = pins_all(Path::new("/pinned"));
        let cap = capture_dir();
        let out = cap.path().join("shot.png");
        for args in [vec![], s(&["-s"]), s(&["-d", "2"]), s(&["-s", "-d", "1"])] {
            assert!(
                pins.validate_command("scrot", &args, false, Some(&out))
                    .is_ok(),
                "scrot {args:?} should pass"
            );
        }
    }

    #[test]
    fn scrot_denies_paths_and_bad_flags() {
        let pins = pins_all(Path::new("/pinned"));
        let cap = capture_dir();
        let out = cap.path().join("shot.png");
        for args in [
            s(&["out.png"]),
            s(&["-o", "x"]),
            s(&["-d", "abc"]),
            s(&["-d", "-1"]),
            s(&["-u"]),
            s(&["-d", "1", "-d", "2"]),
        ] {
            assert!(
                pins.validate_command("scrot", &args, false, Some(&out))
                    .is_err(),
                "scrot {args:?} must be denied"
            );
        }
    }

    // ---- slurp -----------------------------------------------------------

    #[test]
    fn slurp_accepts_fixed_flag_set() {
        let pins = pins_all(Path::new("/pinned"));
        for args in [
            vec![],
            s(&["-f", "%x %y %w %h"]),
            s(&["-d"]),
            s(&["-b", "#ff0000"]),
            s(&["-c", "#00ff00", "-f", "%x"]),
            s(&["-d", "-f", "%w"]),
        ] {
            let inv = pins
                .validate_command("slurp", &args, false, None)
                .unwrap_or_else(|e| panic!("slurp {args:?} should pass: {e}"));
            assert_eq!(inv.argv[0], "slurp");
        }
    }

    #[test]
    fn slurp_denies_everything_else() {
        let pins = pins_all(Path::new("/pinned"));
        for args in [
            s(&["-o"]), // outputs flag - not in the sanctioned set
            s(&["-w", "0"]),
            s(&["-p"]),
            s(&["-s", "0"]),
            s(&["-f"]),            // dangling
            s(&["/tmp/x"]),        // positional
            s(&["-f", "a", "-z"]), // unknown trailing flag
        ] {
            assert!(
                pins.validate_command("slurp", &args, false, None).is_err(),
                "slurp {args:?} must be denied"
            );
        }
    }

    #[test]
    fn slurp_rejects_metachars_via_defense_in_depth() {
        let pins = pins_all(Path::new("/pinned"));
        let err = pins
            .validate_command("slurp", &s(&["-f", "%x;rm -rf /"]), false, None)
            .unwrap_err();
        assert!(matches!(err, WhitelistError::Sanitize(_)));
    }

    // ---- hyprctl ---------------------------------------------------------

    #[test]
    fn hyprctl_accepts_read_subcommands_and_j() {
        let pins = pins_all(Path::new("/pinned"));
        for args in [
            s(&["clients"]),
            s(&["activewindow"]),
            s(&["monitors"]),
            s(&["workspaces"]),
            s(&["-j", "clients"]),
            s(&["-j", "monitors"]),
        ] {
            assert!(
                pins.validate_command("hyprctl", &args, false, None).is_ok(),
                "hyprctl {args:?} should pass"
            );
        }
    }

    #[test]
    fn hyprctl_accepts_sanctioned_dispatchers() {
        let pins = pins_all(Path::new("/pinned"));
        for args in [
            s(&["dispatch", "focuswindow", "address:0x55f0"]),
            s(&["dispatch", "movewindow", "address:0x55f0,2"]),
            s(&["dispatch", "resizewindow", "address:0x55f0,100,100"]),
            s(&["dispatch", "workspace", "3"]),
            s(&["dispatch", "movetoworkspace", "2,address:0x55f0"]),
            s(&["-j", "dispatch", "workspace", "1"]),
        ] {
            assert!(
                pins.validate_command("hyprctl", &args, false, None).is_ok(),
                "hyprctl {args:?} should pass"
            );
        }
    }

    #[test]
    fn hyprctl_denies_exec_and_friends() {
        let pins = pins_all(Path::new("/pinned"));
        for args in [
            s(&["dispatch", "exec", "firefox"]),
            s(&["dispatch", "exec-once", "kitty"]),
            s(&["keyword", "general:gaps_in", "0"]),
            s(&["setprop", "active", "noinitialfocus", "1"]),
            s(&["reload"]),
            s(&["kill"]),
            s(&["dispatch", "exit"]),
            s(&["dispatch", "togglegroup"]),
            s(&["--instance", "0", "clients"]), // foreign flags
            s(&["clients", "extra"]),           // read sub with args
            s(&["dispatch"]),                   // missing dispatcher
            s(&["dispatch", "workspace"]),      // dispatcher w/o args
            s(&["--batch", "dispatch workspace 1"]), // batch is multi-exec
            s(&["-j", "-j", "clients"]),        // -j only once, leading
        ] {
            assert!(
                pins.validate_command("hyprctl", &args, false, None)
                    .is_err(),
                "hyprctl {args:?} must be denied"
            );
        }
    }

    // ---- xdotool / wmctrl ------------------------------------------------

    #[test]
    fn x11_tools_gated_on_session() {
        let pins = pins_all(Path::new("/pinned"));
        // X11 fallback active -> permitted
        assert!(
            pins.validate_command("xdotool", &s(&["key", "Return"]), true, None)
                .is_ok()
        );
        assert!(
            pins.validate_command("wmctrl", &s(&["-l"]), true, None)
                .is_ok()
        );
        // Wayland session -> ArgConstraintViolation
        for cmd in ["xdotool", "wmctrl"] {
            let err = pins
                .validate_command(cmd, &s(&["-l"]), false, None)
                .unwrap_err();
            assert!(
                matches!(err, WhitelistError::ArgConstraint { .. }),
                "{cmd} on Wayland must be ArgConstraint, got {err:?}"
            );
        }
    }

    #[test]
    fn xdotool_exec_primitives_denied() {
        let pins = pins_all(Path::new("/pinned"));
        for bad in [
            s(&["exec", "firefox"]),
            s(&["execsync", "sh"]),
            s(&["behave", "1", "exec", "xterm"]),
            s(&["behave_screen_edge", "top-left", "exec", "xterm"]),
            s(&["desktops_follow_windows"]), // unknown verb
            s(&[]),                          // missing subcommand
        ] {
            let err = pins
                .validate_command("xdotool", &bad, true, None)
                .unwrap_err();
            assert!(
                matches!(err, WhitelistError::ArgConstraint { .. }),
                "xdotool {bad:?} must be ArgConstraint, got {err:?}"
            );
        }
    }

    #[test]
    fn xdotool_allowed_subcommands_pass() {
        let pins = pins_all(Path::new("/pinned"));
        for ok in [
            s(&["key", "Return"]),
            s(&["mousemove", "100", "200"]),
            s(&["type", "--delay", "0", "--", "hello"]),
            s(&["getmouselocation", "--shell"]),
            s(&["--delay", "10", "click", "1"]), // global flag before verb
        ] {
            assert!(
                pins.validate_command("xdotool", &ok, true, None).is_ok(),
                "xdotool {ok:?} must be permitted"
            );
        }
    }

    // ---- generic rules ---------------------------------------------------

    #[test]
    fn unlisted_commands_rejected() {
        let pins = pins_all(Path::new("/pinned"));
        for cmd in ["curl", "sh", "busctl", "gdbus", "bash", "grim2"] {
            let err = pins.validate_command(cmd, &[], false, None).unwrap_err();
            assert!(
                matches!(err, WhitelistError::NotWhitelisted(_)),
                "{cmd} must be NotWhitelisted, got {err:?}"
            );
        }
    }

    #[test]
    fn unpinned_binary_is_unavailable() {
        // grim resolved but hyprctl absent from PATH at pin time.
        let pins = pins_some(Path::new("/pinned"), &["grim"]);
        let err = pins
            .validate_command("hyprctl", &s(&["clients"]), false, None)
            .unwrap_err();
        assert!(matches!(err, WhitelistError::NotWhitelisted(_)));
    }

    #[test]
    fn kdotool_is_pin_only_never_invocable() {
        // `kdotool` is a WHITELIST member (providers may pin+spawn it
        // internally) but has no `validate_command` arm - same contract
        // as `xrandr`/`xprop` - so `system_command` must reject it as
        // NotWhitelisted even though the pin resolves.
        assert!(WHITELIST.contains(&"kdotool"));
        let pins = pins_all(Path::new("/pinned"));
        assert!(pins.is_available("kdotool"));
        for args in [
            s(&[]),
            s(&["search", "--class", "firefox"]),
            s(&["windowactivate", "1"]),
        ] {
            let err = pins
                .validate_command("kdotool", &args, true, None)
                .unwrap_err();
            assert!(
                matches!(err, WhitelistError::NotWhitelisted(_)),
                "kdotool {args:?} must be NotWhitelisted, got {err:?}"
            );
        }
    }

    #[test]
    fn clipboard_helpers_are_pin_only_never_invocable() {
        // `wl-copy`/`wl-paste`/`xclip`/`xsel`/`riverctl` are WHITELIST
        // members - the clipboard/river providers pin+spawn them
        // internally - but none has a `validate_command` arm (same
        // contract as `xrandr`/`xprop`/`kdotool`), so `system_command`
        // must reject every one as NotWhitelisted even though the pins
        // resolve.
        let pins = pins_all(Path::new("/pinned"));
        for cmd in ["wl-copy", "wl-paste", "xclip", "xsel", "riverctl"] {
            assert!(WHITELIST.contains(&cmd), "{cmd} must be a member");
            assert!(pins.is_available(cmd), "{cmd} must resolve a pin");
            let err = pins.validate_command(cmd, &s(&[]), true, None).unwrap_err();
            assert!(
                matches!(err, WhitelistError::NotWhitelisted(_)),
                "{cmd} must be NotWhitelisted, got {err:?}"
            );
        }
    }

    #[test]
    fn non_capture_commands_reject_capture_out() {
        let pins = pins_all(Path::new("/pinned"));
        let cap = capture_dir();
        let out = cap.path().join("x.png");
        for cmd in ["slurp", "hyprctl", "xdotool", "wmctrl"] {
            assert!(
                pins.validate_command(cmd, &[], true, Some(&out)).is_err(),
                "{cmd} must not accept a capture path"
            );
        }
    }

    #[test]
    fn capture_out_must_be_under_allowed_roots() {
        let pins = pins_all(Path::new("/pinned"));
        // /etc exists and canonicalizes, but is not an allowed root -
        // a path-whitelist failure (-32004), not an arg constraint.
        let err = pins
            .validate_command("grim", &[], false, Some(Path::new("/etc/evil.png")))
            .unwrap_err();
        assert!(matches!(err, WhitelistError::Path(_)));
    }

    #[test]
    fn command_name_is_resanitized() {
        let pins = pins_all(Path::new("/pinned"));
        // A metachar in the command name is a sanitization failure
        // (-32006), not merely "not whitelisted" (-32003) - callers map
        // the variants to distinct error codes.
        let err = pins
            .validate_command("grim;rm", &[], false, None)
            .unwrap_err();
        assert!(matches!(err, WhitelistError::Sanitize(_)));
    }

    #[test]
    fn argv_too_long_rejected() {
        let pins = pins_all(Path::new("/pinned"));
        let args: Vec<String> = (0..MAX_ARGS + 1).map(|i| i.to_string()).collect();
        assert!(pins.validate_command("slurp", &args, false, None).is_err());
    }

    // ---- pinning ---------------------------------------------------------

    #[test]
    fn resolve_in_pins_first_executable() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        // grim only in d2; non-executable grim in d1 must be skipped.
        let decoy = d1.path().join("grim");
        fs::write(&decoy, b"not executable").unwrap();
        fs::set_permissions(&decoy, fs::Permissions::from_mode(0o644)).unwrap();
        let real = d2.path().join("grim");
        fs::write(&real, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();

        let pins = PinnedBins::resolve_in(&[d1.path().to_path_buf(), d2.path().to_path_buf()]);
        assert_eq!(
            pins.get("grim").unwrap(),
            real.canonicalize().unwrap().as_path()
        );
        assert!(!pins.is_available("slurp"));
    }
}
