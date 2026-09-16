//! Clipboard backends - `wl-clipboard` (`wl-copy`/`wl-paste`) on Wayland,
//! `xclip` (plus `xsel` for clearing) on X11/XWayland.
//!
//! [`WlClipboard`] is the Wayland rung of the clipboard fallback ladder;
//! it constructs only when `WAYLAND_DISPLAY` is set and both helpers were
//! pinned on `PATH` at startup. [`XclipClipboard`] is the X11 rung - the
//! primary backend under `XDG_SESSION_TYPE=x11` and the XWayland fallback
//! behind `WlClipboard` on Wayland sessions; it constructs only when
//! `DISPLAY` is set (mirroring [`super::x11_capture::X11Capture`]).
//!
//! All spawns go through [`crate::security::spawn`]: the canonicalized
//! absolute paths pinned by [`crate::security::whitelist`] at
//! construction, a scrubbed environment, and [`spawn::SUBPROCESS_TIMEOUT`]
//! per spawn - a `PATH` hijack after construction cannot substitute a
//! trojan, and a wedged child cannot hang a call.
//!
//! Reads are text-first: `get_text` never surfaces binary payloads. A
//! non-zero read exit is the helpers' "empty/no-text selection" signal
//! (`wl-paste` exits 1 with "Nothing is copied"; `xclip -o` fails with
//! "target STRING not available") and maps to `Ok(None)` - a dead session
//! still surfaces as an error on the write paths, which check exit status.
//!
//! Writes feed the payload over stdin - never argv - so copied secrets
//! cannot leak through the process list, and so `sanitize_arg` never has
//! to bless arbitrary text. `wl-copy`/`xclip -i` daemonize to serve the
//! selection; their stdout/stderr are set to null because an inherited or
//! piped fd would be held open by the serving child and stall the wait
//! until the timeout.

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt as _;

use crate::security::{spawn, whitelist};
use crate::traits::ClipboardProvider;

/// Clipboard via `wl-copy`/`wl-paste` (the `wl-clipboard` package),
/// Wayland-only.
pub struct WlClipboard {
    /// Pinned `wl-copy` - `set_text` (stdin payload) and `clear`.
    wl_copy: PathBuf,
    /// Pinned `wl-paste` - `get_text` and `list_mimes`.
    wl_paste: PathBuf,
}

/// Clipboard via `xclip` (`xsel` for `clear` when pinned), X11-only.
pub struct XclipClipboard {
    /// Pinned `xclip` - `-selection clipboard -o`/`-i` and the TARGETS
    /// target query for `list_mimes`.
    xclip: PathBuf,
    /// Pinned `xsel` - `clear` path (`xclip` cannot disown a selection,
    /// only overwrite it); `None` when `xsel` was absent at pin time.
    xsel: Option<PathBuf>,
}

/// Compile-time contract: `ClipboardProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WlClipboard>();
    assert_send_sync::<XclipClipboard>();
};

/// Session gate for the Wayland backend: a non-empty `WAYLAND_DISPLAY`.
fn wayland_display() -> Option<()> {
    let d = std::env::var_os("WAYLAND_DISPLAY")?;
    (!d.is_empty()).then_some(())
}

/// Session gate shared by the X11 backends: a non-empty `DISPLAY`.
/// (Sibling copies live in `x11_capture.rs` / `x11_input.rs`.)
fn x11_display() -> Option<()> {
    let d = std::env::var_os("DISPLAY")?;
    (!d.is_empty()).then_some(())
}

/// Pinned `<bin> <args>` -> the full `Output`; the caller decides what a
/// non-zero exit means (read paths map it to an empty clipboard, write
/// paths map it to an error).
async fn run_status(bin: &Path, args: &[&str]) -> Result<Output> {
    let mut cmd = spawn::command(bin, args);
    spawn::output_within(&mut cmd, spawn::SUBPROCESS_TIMEOUT)
        .await
        .with_context(|| format!("spawn {}", bin.display()))
}

/// [`run_status`] + the usual "non-zero exit is an error" contract -
/// the write paths (`wl-copy --clear`, `xsel --clear`).
async fn run(bin: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = run_status(bin, args).await?;
    if !out.status.success() {
        bail!("{} {:?} exited {}", bin.display(), args, out.status);
    }
    Ok(out.stdout)
}

/// Pinned `<bin> <args>` with `input` fed to stdin; non-zero exit is an
/// error. Stdout/stderr are null - the copy helpers daemonize to serve
/// the selection, and a captured fd held by the daemon child would keep
/// the wait open until the timeout.
async fn run_stdin(bin: &Path, args: &[&str], input: &[u8]) -> Result<()> {
    let mut cmd = spawn::command(bin, args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    let mut stdin = child.stdin.take().expect("stdin was piped");
    // Feed the payload on its own task so a child that exits early (or
    // stops reading) cannot deadlock the wait on a full pipe buffer.
    // Dropping `stdin` at the end of the task sends the child its EOF.
    let input = input.to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
    });
    let status = match tokio::time::timeout(spawn::SUBPROCESS_TIMEOUT, child.wait()).await {
        Ok(r) => r.with_context(|| format!("wait on {}", bin.display()))?,
        Err(_) => {
            let _ = child.kill().await; // reap the wedged child
            let _ = writer.await;
            bail!(
                "{} timed out after {:?}",
                bin.display(),
                spawn::SUBPROCESS_TIMEOUT
            );
        }
    };
    let _ = writer.await;
    if !status.success() {
        bail!("{} {:?} exited {}", bin.display(), args, status);
    }
    Ok(())
}

/// `--list-types`/TARGETS output -> MIME list: one entry per line,
/// blanks dropped.
fn parse_mimes(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

impl WlClipboard {
    /// Available iff `WAYLAND_DISPLAY` is set (non-empty) and both
    /// `wl-copy` and `wl-paste` were pinned on `PATH` at construction -
    /// reads need `wl-paste`, writes need `wl-copy`, and a half-installed
    /// package is a broken backend either way.
    pub fn new() -> Option<Self> {
        wayland_display()?;
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the
    /// `WAYLAND_DISPLAY` session gate - the testable seam: hermetic
    /// tests resolve a fresh `PinnedBins` over a tempdir `PATH` and
    /// exercise the real spawn paths without mutating process env.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            wl_copy: pins.get("wl-copy")?.to_path_buf(),
            wl_paste: pins.get("wl-paste")?.to_path_buf(),
        })
    }
}

#[async_trait]
impl ClipboardProvider for WlClipboard {
    /// `wl-paste --no-newline --type text` -> text; a non-zero exit or
    /// empty stdout reads as `Ok(None)` (empty/no-text selection).
    async fn get_text(&self) -> Result<Option<String>> {
        let out = run_status(&self.wl_paste, &["--no-newline", "--type", "text"]).await?;
        if !out.status.success() || out.stdout.is_empty() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    }

    /// `wl-copy` with the text on stdin - the helper daemonizes to serve
    /// the selection; the foreground spawn exits once the copy is taken.
    async fn set_text(&self, text: &str) -> Result<()> {
        run_stdin(&self.wl_copy, &[], text.as_bytes()).await
    }

    /// `wl-copy --clear`.
    async fn clear(&self) -> Result<()> {
        run(&self.wl_copy, &["--clear"]).await.map(|_| ())
    }

    /// `wl-paste --list-types` -> offered MIME types; an empty selection
    /// yields an empty list, not an error.
    async fn list_mimes(&self) -> Result<Vec<String>> {
        let out = run_status(&self.wl_paste, &["--list-types"]).await?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        Ok(parse_mimes(&String::from_utf8_lossy(&out.stdout)))
    }
}

impl XclipClipboard {
    /// Available iff `DISPLAY` is set (non-empty) and `xclip` was pinned
    /// on `PATH` at construction. `xsel` is an optional extra pinned the
    /// same way - it supplies the real `clear` primitive.
    pub fn new() -> Option<Self> {
        x11_display()?;
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the
    /// `DISPLAY` session gate - the testable seam (see
    /// [`WlClipboard::with_pins`]).
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            xclip: pins.get("xclip")?.to_path_buf(),
            xsel: pins.get("xsel").map(Path::to_path_buf),
        })
    }
}

#[async_trait]
impl ClipboardProvider for XclipClipboard {
    /// `xclip -selection clipboard -o` -> text; a non-zero exit
    /// ("target STRING not available" on an empty/non-text selection)
    /// reads as `Ok(None)`.
    async fn get_text(&self) -> Result<Option<String>> {
        let out = run_status(&self.xclip, &["-selection", "clipboard", "-o"]).await?;
        if !out.status.success() || out.stdout.is_empty() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    }

    /// `xclip -selection clipboard -i` with the text on stdin - xclip
    /// daemonizes to serve the selection.
    async fn set_text(&self, text: &str) -> Result<()> {
        run_stdin(
            &self.xclip,
            &["-selection", "clipboard", "-i"],
            text.as_bytes(),
        )
        .await
    }

    /// `xsel --clipboard --clear` when `xsel` was pinned (the real
    /// clear); otherwise the xclip approximation - installing empty
    /// content. `xclip` cannot disown a selection, so the fallback leaves
    /// an empty-string owner: reads still report an empty clipboard.
    async fn clear(&self) -> Result<()> {
        match &self.xsel {
            Some(xsel) => run(xsel, &["--clipboard", "--clear"]).await.map(|_| ()),
            None => run_stdin(&self.xclip, &["-selection", "clipboard", "-i"], b"").await,
        }
    }

    /// `xclip -selection clipboard -o -t TARGETS` -> offered target atoms;
    /// an empty selection yields an empty list, not an error.
    async fn list_mimes(&self) -> Result<Vec<String>> {
        let out = run_status(
            &self.xclip,
            &["-selection", "clipboard", "-o", "-t", "TARGETS"],
        )
        .await?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        Ok(parse_mimes(&String::from_utf8_lossy(&out.stdout)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write `body` as an executable named `name` inside `dir`.
    fn write_exe(dir: &Path, name: &str, body: &str) {
        use std::io::Write;
        let path = dir.join(name);
        // Write a sibling temp file then rename: `File::create` on a path
        // that a still-running child exec'd earlier fails ETXTBSY, while a
        // rename over a busy executable is atomic and allowed.
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
    }

    /// Fake `wl-copy`: keeps the "clipboard" in `<dir>/clip` - `wl-copy`
    /// stores stdin, `wl-copy --clear` removes the file.
    fn wl_copy_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             f='{d}/clip'\n\
             if [ \"$1\" = \"--clear\" ]; then rm -f \"$f\"; exit 0; fi\n\
             cat > \"$f\"\n",
            d = dir.display()
        )
    }

    /// Fake `wl-paste`: `--list-types` prints a fixed type list when the
    /// clip file is non-empty; otherwise prints the clip file or exits 1
    /// with the real helper's "Nothing is copied" message.
    fn wl_paste_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             f='{d}/clip'\n\
             if [ \"$1\" = \"--list-types\" ]; then\n\
             \tif [ -s \"$f\" ]; then printf 'text/plain\\nUTF8_STRING\\ntext/plain;charset=utf-8\\n'; exit 0; fi\n\
             \texit 1\n\
             fi\n\
             if [ -s \"$f\" ]; then cat \"$f\"; exit 0; fi\n\
             echo 'Nothing is copied' >&2\n\
             exit 1\n",
            d = dir.display()
        )
    }

    /// Fake `xclip`: `<dir>/clip` is the selection. `-i` stores stdin;
    /// `-o -t TARGETS` prints the target list; `-o` prints the selection
    /// or exits 1 with xclip's "target not available" error.
    fn xclip_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             f='{d}/clip'\n\
             mode=out; targets=0\n\
             for a in \"$@\"; do\n\
             \tcase \"$a\" in\n\
             \t\t-i) mode=in;;\n\
             \t\t-o) mode=out;;\n\
             \t\tTARGETS) targets=1;;\n\
             \tesac\n\
             done\n\
             if [ \"$mode\" = in ]; then cat > \"$f\"; exit 0; fi\n\
             if [ \"$targets\" = 1 ]; then\n\
             \tif [ -f \"$f\" ]; then printf 'TARGETS\\ntext/plain\\nUTF8_STRING\\n'; exit 0; fi\n\
             \techo 'Error: target TARGETS not available' >&2; exit 1\n\
             fi\n\
             if [ -f \"$f\" ]; then cat \"$f\"; exit 0; fi\n\
             echo 'Error: target STRING not available' >&2\n\
             exit 1\n",
            d = dir.display()
        )
    }

    /// Fake `xsel`: `--clear` removes the clip file.
    fn xsel_script(dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             f='{d}/clip'\n\
             for a in \"$@\"; do\n\
             \tcase \"$a\" in\n\
             \t\t--clear|-c) rm -f \"$f\"; exit 0;;\n\
             \tesac\n\
             done\n\
             exit 0\n",
            d = dir.display()
        )
    }

    // ---- pure parsing -------------------------------------------------

    #[test]
    fn parse_mimes_drops_blank_lines() {
        assert_eq!(
            parse_mimes("text/plain\n\n UTF8_STRING \n\ntext/html\n"),
            vec!["text/plain", "UTF8_STRING", "text/html"]
        );
        assert_eq!(parse_mimes(""), Vec::<String>::new());
        assert_eq!(parse_mimes("  \n \n"), Vec::<String>::new());
    }

    // ---- construction probes -------------------------------------------

    #[test]
    fn wl_with_pins_requires_both_helpers() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(WlClipboard::with_pins(&pins).is_none());

        // Half the package is not a backend - writes would be dead.
        write_exe(dir.path(), "wl-copy", &wl_copy_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(WlClipboard::with_pins(&pins).is_none());

        write_exe(dir.path(), "wl-paste", &wl_paste_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = WlClipboard::with_pins(&pins).expect("both pins resolve");
        assert!(cb.wl_copy.is_absolute() && cb.wl_paste.is_absolute());
    }

    #[test]
    fn xclip_with_pins_requires_xclip_only() {
        let dir = tempfile::tempdir().unwrap();
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(XclipClipboard::with_pins(&pins).is_none());

        write_exe(dir.path(), "xclip", &xclip_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = XclipClipboard::with_pins(&pins).expect("xclip pin resolves");
        assert!(cb.xclip.is_absolute());
        assert!(cb.xsel.is_none()); // optional - absent here
    }

    #[test]
    fn new_is_none_without_session_vars() {
        // SAFETY: test-only env mutation, restored before returning -
        // the same pattern the sibling gate tests in x11_capture.rs /
        // wlr_capture.rs use.
        let saved_w = std::env::var_os("WAYLAND_DISPLAY");
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        assert!(WlClipboard::new().is_none());
        if let Some(v) = saved_w {
            unsafe { std::env::set_var("WAYLAND_DISPLAY", v) };
        }

        let saved_d = std::env::var_os("DISPLAY");
        unsafe { std::env::remove_var("DISPLAY") };
        assert!(XclipClipboard::new().is_none());
        if let Some(v) = saved_d {
            unsafe { std::env::set_var("DISPLAY", v) };
        }
    }

    // ---- hermetic spawn paths (fake helpers via resolve_in) -----------

    #[tokio::test]
    async fn wl_clipboard_roundtrip_via_fakes() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "wl-copy", &wl_copy_script(dir.path()));
        write_exe(dir.path(), "wl-paste", &wl_paste_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = WlClipboard::with_pins(&pins).unwrap();

        // Empty selection: reads report None / empty, not errors.
        assert_eq!(cb.get_text().await.unwrap(), None);
        assert!(cb.list_mimes().await.unwrap().is_empty());

        cb.set_text("hello clipboard").await.unwrap();
        assert_eq!(
            cb.get_text().await.unwrap().as_deref(),
            Some("hello clipboard")
        );
        let mimes = cb.list_mimes().await.unwrap();
        assert!(mimes.contains(&"text/plain".to_string()), "{mimes:?}");

        cb.clear().await.unwrap();
        assert_eq!(cb.get_text().await.unwrap(), None);
        assert!(cb.list_mimes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn wl_clipboard_binary_payload_and_failures() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "wl-copy", &wl_copy_script(dir.path()));
        write_exe(dir.path(), "wl-paste", &wl_paste_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = WlClipboard::with_pins(&pins).unwrap();

        // Payloads with newlines/metacharacters cross stdin untouched -
        // they never pass through argv or a shell.
        let payload = "line1\nline2; rm -rf / $(evil) `x` 'quoted' é";
        cb.set_text(payload).await.unwrap();
        assert_eq!(cb.get_text().await.unwrap().as_deref(), Some(payload));

        // A failing wl-copy surfaces as an error on the write path.
        write_exe(dir.path(), "wl-copy", "#!/bin/sh\nexit 1\n");
        assert!(cb.set_text("x").await.is_err());
        assert!(cb.clear().await.is_err());
    }

    #[tokio::test]
    async fn xclip_clipboard_roundtrip_via_fakes() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xclip", &xclip_script(dir.path()));
        write_exe(dir.path(), "xsel", &xsel_script(dir.path()));
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = XclipClipboard::with_pins(&pins).unwrap();

        assert_eq!(cb.get_text().await.unwrap(), None);
        assert!(cb.list_mimes().await.unwrap().is_empty());

        cb.set_text("x11 text").await.unwrap();
        assert_eq!(cb.get_text().await.unwrap().as_deref(), Some("x11 text"));
        let mimes = cb.list_mimes().await.unwrap();
        assert!(mimes.contains(&"UTF8_STRING".to_string()), "{mimes:?}");

        // xsel is pinned -> the real clear primitive runs.
        cb.clear().await.unwrap();
        assert_eq!(cb.get_text().await.unwrap(), None);
    }

    #[tokio::test]
    async fn xclip_clear_falls_back_to_empty_write_without_xsel() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xclip", &xclip_script(dir.path()));
        // No xsel in the pin set -> clear installs empty content.
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = XclipClipboard::with_pins(&pins).unwrap();

        cb.set_text("data").await.unwrap();
        cb.clear().await.unwrap();
        assert_eq!(cb.get_text().await.unwrap(), None);
    }

    #[tokio::test]
    async fn xclip_failures_surface_on_write_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "xclip", "#!/bin/sh\nexit 1\n");
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cb = XclipClipboard::with_pins(&pins).unwrap();

        // Reads of a dead selection still map to "empty", not an error.
        assert_eq!(cb.get_text().await.unwrap(), None);
        assert!(cb.list_mimes().await.unwrap().is_empty());
        // Writes check the exit status.
        assert!(cb.set_text("x").await.is_err());
    }
}
