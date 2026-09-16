//! Path whitelist - canonicalize-then-check against a deliberately narrow
//! root set (SECURITY.md "Request pipeline", THREAT_MODEL.md §4.6):
//!
//! - `$XDG_RUNTIME_DIR` (per-user tmpfs, already `0700`)
//! - `/tmp`
//! - `~/.ultranix-mcp/**`
//!
//! `$HOME` at large is **not**an allowed root - a `scrot -o ~/.bashrc`-style
//! call would turn a capture tool into a dotfile-overwrite vector. Symlinks
//! are resolved *before* the prefix check, so a symlink inside `/tmp` that
//! points at `$HOME` is rejected.

use std::path::{Component, Path, PathBuf};

/// Rejection reasons - callers map these to `-32004 PathNotWhitelisted`.
#[derive(Debug, thiserror::Error)]
pub enum PathWhitelistError {
    /// The path (or its nearest existing ancestor) cannot be canonicalized.
    #[error("cannot resolve path {0}: {1}")]
    Unresolvable(PathBuf, String),
    /// Resolved cleanly but lands outside every allowed root.
    #[error("path {0} resolves outside the allowed roots")]
    OutsideRoots(PathBuf),
    /// The path contains no usable final component (e.g. `/`, `..`).
    #[error("path {0} has no usable final component")]
    NoLeaf(PathBuf),
}

/// The canonicalized allowed roots for this process, in check order.
///
/// Roots that cannot be canonicalized are skipped - except the
/// `~/.ultranix-mcp` root, which may legitimately not exist yet (first run):
/// for it we fall back to `canonicalize($HOME)/.ultranix-mcp` so that a
/// not-yet-created state dir is still a valid root. A lexical `$HOME` is
/// never trusted directly - `$HOME` itself may be a symlink.
fn allowed_roots() -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(3);

    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        let xdg = PathBuf::from(xdg);
        if let Ok(canon) = xdg.canonicalize() {
            roots.push(canon);
        }
    }

    if let Ok(tmp) = Path::new("/tmp").canonicalize() {
        roots.push(tmp);
    }

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let state = home.join(".ultranix-mcp");
        match state.canonicalize() {
            Ok(canon) => roots.push(canon),
            Err(_) => {
                if let Ok(home_canon) = home.canonicalize() {
                    roots.push(home_canon.join(".ultranix-mcp"));
                }
            }
        }
    }

    roots
}

/// Canonicalize `path`, tolerating a not-yet-existing final component.
///
/// `fs::canonicalize` requires the whole path to exist; output paths inside
/// a fresh captures dir do not. When the leaf does not exist we canonicalize
/// the nearest existing ancestor and re-append the remaining lexical tail -
/// which is safe because the tail is verified to contain only `Normal`
/// components (no `..`, no root re-anchor).
fn canonicalize_lenient(path: &Path) -> Result<PathBuf, PathWhitelistError> {
    if let Ok(canon) = path.canonicalize() {
        return Ok(canon);
    }
    // Walk up until something canonicalizes; collect the missing tail.
    let mut tail: Vec<PathBuf> = Vec::new();
    let mut cursor: &Path = path;
    loop {
        match cursor.canonicalize() {
            Ok(mut canon) => {
                for part in tail.iter().rev() {
                    canon.push(part);
                }
                return Ok(canon);
            }
            Err(e) => {
                let name = cursor
                    .file_name()
                    .ok_or_else(|| PathWhitelistError::NoLeaf(path.to_path_buf()))?;
                // Reject anything that is not a plain path component - a
                // `..` or separator smuggled into the tail would let the
                // re-attached path escape the canonicalized ancestor.
                let mut comps = Path::new(name).components();
                if !(comps.clone().count() == 1
                    && matches!(comps.next(), Some(Component::Normal(_))))
                {
                    return Err(PathWhitelistError::NoLeaf(path.to_path_buf()));
                }
                tail.push(PathBuf::from(name));
                match cursor.parent() {
                    Some(parent) => cursor = parent,
                    None => {
                        return Err(PathWhitelistError::Unresolvable(
                            path.to_path_buf(),
                            e.to_string(),
                        ));
                    }
                }
            }
        }
    }
}

/// Canonicalize `path` (resolving every symlink first) and require the
/// result to live under `$XDG_RUNTIME_DIR`, `/tmp`, or `~/.ultranix-mcp/**`.
///
/// Returns the canonicalized path on success - callers should use the
/// returned value, not the input, to avoid a check/use mismatch.
pub fn check_path(path: &Path) -> Result<PathBuf, PathWhitelistError> {
    check_path_with_roots(path, &allowed_roots())
}

/// [`check_path`] against an explicit root set - factored out so tests can
/// run hermetically without mutating process env.
pub(crate) fn check_path_with_roots(
    path: &Path,
    roots: &[PathBuf],
) -> Result<PathBuf, PathWhitelistError> {
    let resolved = canonicalize_lenient(path)?;
    if roots.iter().any(|root| resolved.starts_with(root)) {
        Ok(resolved)
    } else {
        Err(PathWhitelistError::OutsideRoots(resolved))
    }
}

/// Whether `path`'s parent directory resolves under an allowed root.
/// Used by the command whitelist to validate server-supplied capture paths
/// whose leaf does not exist yet.
pub(crate) fn parent_under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    path.parent()
        .and_then(|p| p.canonicalize().ok())
        .is_some_and(|parent| roots.iter().any(|r| parent.starts_with(r)))
}

/// Allowed roots, exposed within the crate for the whitelist layer.
pub(crate) fn roots() -> Vec<PathBuf> {
    allowed_roots()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// Scratch root standing in for `/tmp`-class allowed roots.
    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn accepts_file_under_allowed_root() {
        let tmp = scratch();
        let f = tmp.path().join("shot.png");
        fs::write(&f, b"x").unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        let got = check_path_with_roots(&f, &roots).unwrap();
        assert_eq!(got, f.canonicalize().unwrap());
    }

    #[test]
    fn accepts_nonexistent_leaf_under_allowed_parent() {
        let tmp = scratch();
        let pending = tmp.path().join("not-yet.png");
        let roots = vec![tmp.path().to_path_buf()];
        let got = check_path_with_roots(&pending, &roots).unwrap();
        assert!(got.ends_with("not-yet.png"));
    }

    #[test]
    fn rejects_path_outside_roots() {
        let tmp = scratch();
        let etc = Path::new("/etc/passwd");
        assert!(etc.exists());
        let roots = vec![tmp.path().to_path_buf()];
        assert!(matches!(
            check_path_with_roots(etc, &roots),
            Err(PathWhitelistError::OutsideRoots(_))
        ));
    }

    #[test]
    fn rejects_broad_home_style_escape() {
        // $HOME at large must not pass even when a file exists there.
        let tmp = scratch();
        let home_like = scratch();
        let dotfile = home_like.path().join(".bashrc");
        fs::write(&dotfile, b"x").unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        assert!(check_path_with_roots(&dotfile, &roots).is_err());
    }

    #[test]
    fn rejects_dotdot_escape() {
        let tmp = scratch();
        let sub = tmp.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let outside = tmp.path().join("..").join("escape-target");
        let roots = vec![sub.clone()];
        // `..` canonicalizes out of `sub` -> outside the root.
        assert!(matches!(
            check_path_with_roots(&outside, &roots),
            Err(PathWhitelistError::OutsideRoots(_))
        ));
    }

    #[test]
    fn rejects_symlink_escaping_root() {
        let tmp = scratch();
        let outside = scratch();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"hunter2").unwrap();
        let link = tmp.path().join("innocent.txt");
        symlink(&secret, &link).unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        // Canonicalizes to the real file outside the root -> denied.
        let err = check_path_with_roots(&link, &roots).unwrap_err();
        assert!(matches!(err, PathWhitelistError::OutsideRoots(_)));
    }

    #[test]
    fn accepts_symlink_staying_inside_root() {
        let tmp = scratch();
        let real = tmp.path().join("real.txt");
        fs::write(&real, b"ok").unwrap();
        let link = tmp.path().join("link.txt");
        symlink(&real, &link).unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        let got = check_path_with_roots(&link, &roots).unwrap();
        assert_eq!(got, real.canonicalize().unwrap());
    }

    #[test]
    fn rejects_symlinked_dir_escape() {
        // A directory *inside* the root that is itself a symlink out.
        let tmp = scratch();
        let outside = scratch();
        fs::write(outside.path().join("f"), b"x").unwrap();
        let linkdir = tmp.path().join("linkdir");
        symlink(outside.path(), &linkdir).unwrap();
        let probe = linkdir.join("f");
        let roots = vec![tmp.path().to_path_buf()];
        assert!(check_path_with_roots(&probe, &roots).is_err());
    }

    #[test]
    fn rejects_root_prefix_lookalike() {
        // `/tmp/allowed-evil` must NOT match root `/tmp/allowed`.
        let tmp = scratch();
        let allowed = tmp.path().join("allowed");
        let evil = tmp.path().join("allowed-evil");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&evil).unwrap();
        let f = evil.join("x");
        fs::write(&f, b"x").unwrap();
        let roots = vec![allowed.canonicalize().unwrap()];
        assert!(matches!(
            check_path_with_roots(&f, &roots),
            Err(PathWhitelistError::OutsideRoots(_))
        ));
    }

    #[test]
    fn rejects_unresolvable_garbage() {
        let tmp = scratch();
        let roots = vec![tmp.path().to_path_buf()];
        // `..` as the final component has no usable Normal leaf.
        let p = tmp.path().join("sub").join("..");
        fs::create_dir(tmp.path().join("sub")).unwrap();
        // This canonicalizes to tmp itself - which IS under the root; fine.
        assert!(check_path_with_roots(&p, &roots).is_ok());
        // A missing chain ending in `..` is rejected instead of resolved.
        let bad = tmp.path().join("missing").join("..");
        assert!(check_path_with_roots(&bad, &roots).is_err());
    }

    #[test]
    fn env_roots_cover_tmp() {
        // Real-env smoke check: a real file under /tmp passes check_path.
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let f = dir.path().join("ok.bin");
        fs::write(&f, b"x").unwrap();
        assert!(check_path(&f).is_ok(), "/tmp must be an allowed root");
    }

    #[test]
    fn env_roots_reject_etc() {
        assert!(check_path(Path::new("/etc/passwd")).is_err());
        assert!(check_path(Path::new("/proc/self/environ")).is_err());
    }
}
