//! Capture scratch directories and no-follow opens — docs/TOOLS.md
//! "Capture Output Writes" and THREAT_MODEL.md §4.6.
//!
//! Capture tools and capture-adjacent whitelist binaries (`grim`, `scrot`)
//! never write to a caller-chosen path. The server creates a **fresh
//! `mktemp`-style directory** (mode `0700`) per capture under
//! `~/.ultranix-mcp/captures/` (preferred) — falling back to `/tmp` when
//! the state directory is unavailable — and passes the spawned binary a
//! path inside it. Because the directory is freshly created, unpredictable,
//! and owner-only, a same-UID attacker cannot pre-place a symlink inside
//! it: this closes the canonicalize-then-write TOCTOU window that spawned
//! binaries cannot close themselves.
//!
//! When the *server* opens the capture file (e.g. to return image content
//! to the client) it uses [`open_nofollow`]: `O_NOFOLLOW` at mode `0600`.
//! `O_NOFOLLOW` guards only the leaf component — parent-dir traversal
//! resistance comes from the fresh unpredictable `0700` dir, which is why
//! capture paths must always live inside one. Files are unlinked after
//! the tool returns, including on error paths (callers' duty).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context;

/// Random bytes carried in a capture-dir suffix — 16 bytes = 128 bits of
/// CSPRNG entropy (the same budget as consent tokens). Unpredictability
/// is the security property: a same-UID attacker cannot pre-place a
/// symlink inside a directory it cannot name.
const SUFFIX_BYTES: usize = 16;

/// `EEXIST` retry budget — effectively unreachable at 128 bits of
/// entropy, but bounded so a pathological RNG fails instead of spinning.
const MAX_ATTEMPTS: usize = 32;

/// Directory-name prefix — makes capture scratch dirs greppable under
/// the captures dir and `/tmp`.
const DIR_PREFIX: &str = "capture-";

/// Directory-name prefix for bounded screen recordings (`screen_record`)
/// — `rec-<ulid>` sorts chronologically and greps separately from
/// single-shot `capture-` scratch dirs.
const REC_PREFIX: &str = "rec-";

/// Create a fresh, unpredictable, owner-only (`0700`) directory for one
/// capture's output files.
///
/// Preferred base: `<state-dir>/captures` where `<state-dir>` resolves
/// per [`crate::state::StateDir::resolve_root`] (`ULTRANIX_MCP_STATE_DIR`
/// → `~/.ultranix-mcp` → `./.ultranix-mcp`; `XDG_STATE_HOME` is
/// deliberately *not* consulted — see state.rs module docs).
/// The state root and the `captures/` leaf are created/tightened to
/// `0700` as needed.
///
/// Fallback: if the preferred tree cannot be created or a leaf cannot be
/// made inside it, a `0700` mktemp dir directly under `/tmp` is used
/// instead (`/tmp` itself is of course never chmod'd). An error is
/// returned only when both locations fail.
pub fn fresh_capture_dir() -> anyhow::Result<PathBuf> {
    let preferred = preferred_captures_base();
    match fresh_capture_dir_at(&preferred, Path::new("/tmp")) {
        Ok(dir) => Ok(dir),
        Err(err) => Err(err.context("no usable capture scratch dir")),
    }
}

/// The full create-preferred-then-fall-back flow, factored out so tests
/// can run hermetically against tempdirs instead of the real state dir.
fn fresh_capture_dir_at(preferred: &Path, fallback: &Path) -> anyhow::Result<PathBuf> {
    match ensure_private_tree(preferred).and_then(|()| mktemp_leaf(preferred)) {
        Ok(dir) => return Ok(dir),
        Err(err) => {
            tracing::warn!(
                error = %err,
                dir = %preferred.display(),
                "preferred captures dir unusable — falling back to /tmp"
            );
        }
    }
    mktemp_leaf(fallback)
        .with_context(|| format!("create capture dir under {}", fallback.display()))
}

/// Create a fresh, unpredictable, owner-only (`0700`) directory for one
/// bounded screen recording's frame files (`screen_record`). Same
/// preferred-`<state-dir>/captures`-then-`/tmp` flow as
/// [`fresh_capture_dir`]; the leaf is `rec-<ULID>` — time-sortable, and
/// the ULID's 80 random bits serve the same anti-symlink-preplacement
/// role as the capture-dir suffix. Unlike `capture-` dirs, recording
/// dirs are **kept** after the tool returns (the frames are the result).
pub fn fresh_recording_dir() -> anyhow::Result<PathBuf> {
    let preferred = preferred_captures_base();
    match fresh_recording_dir_at(&preferred, Path::new("/tmp")) {
        Ok(dir) => Ok(dir),
        Err(err) => Err(err.context("no usable recording dir")),
    }
}

/// The recording-dir create-preferred-then-fall-back flow, factored out
/// for hermetic tests against tempdirs.
fn fresh_recording_dir_at(preferred: &Path, fallback: &Path) -> anyhow::Result<PathBuf> {
    match ensure_private_tree(preferred).and_then(|()| recording_leaf(preferred)) {
        Ok(dir) => return Ok(dir),
        Err(err) => {
            tracing::warn!(
                error = %err,
                dir = %preferred.display(),
                "preferred captures dir unusable — falling back to /tmp"
            );
        }
    }
    recording_leaf(fallback)
        .with_context(|| format!("create recording dir under {}", fallback.display()))
}

/// One `rec-<ulid>` leaf inside an existing `base`, mode `0700`.
/// `pub(crate)` so the record tool's test seam can mint a leaf under an
/// injected base without touching the real state dir.
pub(crate) fn recording_leaf(base: &Path) -> anyhow::Result<PathBuf> {
    mktemp_leaf_named(base, || format!("{REC_PREFIX}{}", ulid::Ulid::new()))
}

/// `<state-dir>/captures` for the real process environment.
fn preferred_captures_base() -> PathBuf {
    crate::state::StateDir::resolve_root(|key| std::env::var_os(key)).join("captures")
}

/// Ensure `captures_base` and its parent (the state root) exist and are
/// owner-only. Only used for the *preferred* location — the `/tmp`
/// fallback base is pre-existing system ground and must not be touched.
///
/// `create_dir_all`/`set_permissions` follow symlinks, so a pre-planted
/// symlink at the base would have its *target* tightened to `0700` and
/// then receive capture frames. `lstat` *before* creating/chmod'ing and
/// refuse to operate through a link — the caller falls back to `/tmp`
/// instead.
fn ensure_private_tree(captures_base: &Path) -> anyhow::Result<()> {
    if let Some(root) = captures_base.parent()
        && root != captures_base
    {
        create_private_dir(root)?;
    }
    if let Ok(meta) = fs::symlink_metadata(captures_base) {
        anyhow::ensure!(
            !meta.file_type().is_symlink(),
            "captures dir {} is a symlink — refusing to follow",
            captures_base.display()
        );
    }
    create_private_dir(captures_base)?;
    Ok(())
}

/// Create a fresh `capture-<128-bit-hex>` directory inside an existing
/// `base`, mode `0700`.
fn mktemp_leaf(base: &Path) -> anyhow::Result<PathBuf> {
    mktemp_leaf_named(base, || format!("{DIR_PREFIX}{}", random_suffix()))
}

/// Create a fresh `name()`-named directory inside an existing `base`,
/// mode `0700`. `create_dir` (non-recursive) fails on `EEXIST`, giving
/// the atomic create-or-collide semantics `mktemp` relies on; `name` is
/// re-invoked per attempt so retries get a fresh candidate.
fn mktemp_leaf_named(base: &Path, mut name: impl FnMut() -> String) -> anyhow::Result<PathBuf> {
    for _ in 0..MAX_ATTEMPTS {
        let candidate = base.join(name());
        match create_dir_0700(&candidate) {
            Ok(()) => {
                // Tighten unconditionally: a permissive umask cannot widen
                // the creation mode, but a restrictive one could have
                // stripped owner bits we actually want.
                set_mode(&candidate, 0o700)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("create capture dir in {}", base.display()));
            }
        }
    }
    anyhow::bail!(
        "exhausted {MAX_ATTEMPTS} capture-dir name attempts under {}",
        base.display()
    )
}

/// 16 CSPRNG bytes, hex-encoded → a 32-char unpredictable suffix.
fn random_suffix() -> String {
    let mut bytes = [0u8; SUFFIX_BYTES];
    rand::fill(&mut bytes);
    let mut s = String::with_capacity(SUFFIX_BYTES * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Open `path` server-side with symlink-following disabled — `O_NOFOLLOW`
/// makes a final-component symlink fail with `ELOOP` instead of silently
/// redirecting the open. The file is created (if missing) and forced to
/// mode `0600`, including pre-existing files left looser by a spawned
/// binary's umask.
///
/// Scope note: `O_NOFOLLOW` protects the leaf only. Parent-component
/// symlinks still resolve — the defense for those is that capture paths
/// always live inside a [`fresh_capture_dir`] directory, freshly created
/// and owner-only.
pub fn open_nofollow(path: &Path) -> anyhow::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    apply_nofollow(&mut opts);
    let file = opts
        .open(path)
        .with_context(|| format!("open {} (O_NOFOLLOW)", path.display()))?;
    // fchmod via the fd — avoids a second path lookup racing a swap.
    file.set_permissions(private_file_permissions())
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(file)
}

#[cfg(unix)]
fn apply_nofollow(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn apply_nofollow(_opts: &mut OpenOptions) {
    // No O_NOFOLLOW — Linux-only crate, kept for check builds.
}

#[cfg(unix)]
fn private_file_permissions() -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(0o600)
}

#[cfg(not(unix))]
fn private_file_permissions() -> fs::Permissions {
    fs::Permissions::new()
}

/// `create_dir` failing on `EEXIST` with creation mode `0700`.
#[cfg(unix)]
fn create_dir_0700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_dir_0700(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

/// `create_dir_all` + tighten to `0700` (unconditional chmod so a
/// pre-existing looser directory is corrected). Same contract as
/// `state::create_private_dir`.
fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create private dir {}", path.display()))?;
    set_mode(path, 0o700)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // ---- fresh capture dirs -------------------------------------------

    #[test]
    fn leaf_is_fresh_0700_and_unpredictable() {
        let base = tempfile::tempdir().unwrap();
        let d1 = mktemp_leaf(base.path()).unwrap();
        let d2 = mktemp_leaf(base.path()).unwrap();
        assert_ne!(d1, d2, "fresh dir per capture — never reused");
        for d in [&d1, &d2] {
            assert!(d.is_dir());
            assert_eq!(mode_of(d), 0o700);
            let name = d.file_name().unwrap().to_str().unwrap();
            let suffix = name.strip_prefix(DIR_PREFIX).expect("capture- prefix");
            assert_eq!(suffix.len(), SUFFIX_BYTES * 2);
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn preferred_tree_created_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("state").join("captures");
        let fallback = tempfile::tempdir().unwrap();

        let dir = fresh_capture_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(&preferred), "must land under preferred");
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&preferred), 0o700);
        // The state root we just created is tightened too.
        assert_eq!(mode_of(preferred.parent().unwrap()), 0o700);
    }

    #[test]
    fn preexisting_loose_tree_is_tightened() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("state").join("captures");
        fs::create_dir_all(&preferred).unwrap();
        fs::set_permissions(&preferred, fs::Permissions::from_mode(0o755)).unwrap();
        let fallback = tempfile::tempdir().unwrap();

        let dir = fresh_capture_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(&preferred));
        assert_eq!(mode_of(&preferred), 0o700);
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn symlinked_base_is_rejected_not_followed() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        // A planted link at the captures base pointing at an attacker-
        // controlled dir: ensure must refuse, not chmod+use the target.
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let preferred = tmp.path().join("captures");
        symlink(&real, &preferred).unwrap();

        assert!(ensure_private_tree(&preferred).is_err());
        // …and the full flow falls back rather than writing into `real`.
        let fallback = tempfile::tempdir().unwrap();
        let dir = fresh_capture_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(fallback.path()), "must land under fallback");
        assert!(fs::read_dir(&real).unwrap().next().is_none());
    }

    #[test]
    fn falls_back_when_preferred_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular file where the preferred base should be — mkdir fails.
        let preferred = tmp.path().join("not-a-dir");
        fs::write(&preferred, b"x").unwrap();
        let fallback = tempfile::tempdir().unwrap();

        let dir = fresh_capture_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(fallback.path()), "must land under fallback");
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn errors_when_both_locations_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("not-a-dir");
        fs::write(&preferred, b"x").unwrap();
        let fallback = tmp.path().join("also-not-a-dir");
        fs::write(&fallback, b"x").unwrap();

        assert!(fresh_capture_dir_at(&preferred, &fallback).is_err());
    }

    #[test]
    fn leaf_fails_inside_a_file_base() {
        let tmp = tempfile::tempdir().unwrap();
        let file_base = tmp.path().join("file");
        fs::write(&file_base, b"x").unwrap();
        assert!(mktemp_leaf(&file_base).is_err());
    }

    // ---- recording dirs ------------------------------------------------

    #[test]
    fn recording_leaf_is_fresh_0700_rec_ulid() {
        let base = tempfile::tempdir().unwrap();
        let d1 = recording_leaf(base.path()).unwrap();
        let d2 = recording_leaf(base.path()).unwrap();
        assert_ne!(d1, d2, "fresh dir per recording — never reused");
        for d in [&d1, &d2] {
            assert!(d.is_dir());
            assert_eq!(mode_of(d), 0o700);
            let name = d.file_name().unwrap().to_str().unwrap();
            let ulid = name.strip_prefix(REC_PREFIX).expect("rec- prefix");
            assert_eq!(ulid.len(), 26, "ULID is 26 Crockford-Base32 chars");
            ulid.parse::<ulid::Ulid>().expect("suffix parses as a ULID");
        }
    }

    #[test]
    fn recording_dir_prefers_state_captures_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("state").join("captures");
        let fallback = tempfile::tempdir().unwrap();

        let dir = fresh_recording_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(&preferred), "must land under preferred");
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&preferred), 0o700);
    }

    #[test]
    fn recording_dir_falls_back_when_preferred_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("not-a-dir");
        fs::write(&preferred, b"x").unwrap();
        let fallback = tempfile::tempdir().unwrap();

        let dir = fresh_recording_dir_at(&preferred, fallback.path()).unwrap();
        assert!(dir.starts_with(fallback.path()), "must land under fallback");
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn recording_dir_errors_when_both_locations_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let preferred = tmp.path().join("not-a-dir");
        fs::write(&preferred, b"x").unwrap();
        let fallback = tmp.path().join("also-not-a-dir");
        fs::write(&fallback, b"x").unwrap();

        assert!(fresh_recording_dir_at(&preferred, &fallback).is_err());
    }

    // ---- open_nofollow --------------------------------------------------

    #[test]
    fn opens_real_file_and_forces_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("shot.png");
        fs::write(&f, b"png-bytes").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        let mut file = open_nofollow(&f).unwrap();
        use std::io::Read;
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "png-bytes");
        assert_eq!(mode_of(&f), 0o600, "loose mode must be tightened");
    }

    #[test]
    fn creates_missing_file_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("new.png");
        let _file = open_nofollow(&f).unwrap();
        assert_eq!(mode_of(&f), 0o600);
    }

    #[test]
    fn rejects_symlink_leaf() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret.txt");
        fs::write(&secret, b"hunter2").unwrap();
        let link = tmp.path().join("innocent.png");
        symlink(&secret, &link).unwrap();

        let err = open_nofollow(&link).unwrap_err();
        // ELOOP → the open fails rather than following the link.
        assert!(
            err.to_string().contains("O_NOFOLLOW"),
            "error should identify the no-follow open: {err:#}"
        );
    }

    #[test]
    fn rejects_dangling_symlink_leaf() {
        // ELOOP fires even when the link target does not exist — without
        // O_NOFOLLOW this would happily create the target.
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("dangling.png");
        symlink(tmp.path().join("nonexistent-target"), &link).unwrap();
        assert!(open_nofollow(&link).is_err());
        assert!(!tmp.path().join("nonexistent-target").exists());
    }
}
