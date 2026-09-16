//! X11-native capture backend - `scrot` for frames, `xdotool`/`xrandr`
//! for the read channels (pointer position, monitor inventory).
//!
//! This is the X11 rung of the capture fallback ladder (`CaptureBackend::
//! Scrot`). [`X11Capture::new`] requires a non-empty `DISPLAY` plus a
//! `scrot` binary pinned from `PATH`; `xdotool` and `xrandr` are optional
//! extras pinned the same way.
//!
//! `scrot` writes the PNG into a fresh private capture dir
//! ([`crate::security::captures`]: `0700`, unpredictable name) which is
//! deleted after the read - on error paths too. Unlike
//! [`super::grim_capture`], the leaf is deliberately **not**pre-created:
//! `scrot` refuses to overwrite an existing file (older versions prompt
//! on stdin, which is `/dev/null` under [`crate::security::spawn`] - a
//! guaranteed failure). The fresh unpredictable `0700` dir is itself the
//! anti-symlink defense - a same-UID attacker cannot pre-place a symlink
//! inside a directory it cannot name - and the read-back still goes
//! through [`captures::open_nofollow`], so even a malicious `scrot`
//! dropping a symlink leaf is caught.
//!
//! Binary paths are the canonicalized absolute paths pinned by
//! [`crate::security::whitelist`] at construction, spawned under the
//! scrubbed environment and per-spawn timeouts of
//! [`crate::security::spawn`] - a `PATH` hijack after construction
//! cannot substitute a trojan, and a wedged child cannot hang a call.
//!
//! NOTE: `xrandr` is pinned for provider use (in
//! [`whitelist::WHITELIST`]) but has no `validate_command` arm - it is
//! never invocable through `system_command`. When pinned, `screen_info`
//! uses `xrandr --query` for real per-monitor geometry; otherwise it
//! falls back to `xdotool getdisplaygeometry` (single virtual-screen
//! rect).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::security::{captures, spawn, whitelist};
use crate::traits::{CaptureProvider, Frame, Rect};

/// Capture via the `scrot` CLI (`scrot [-a x,y,w,h] <file>`), X11-only.
pub struct X11Capture {
    scrot: PathBuf,
    /// Pinned `xdotool` - `cursor_position`, `screen_info` fallback.
    xdotool: Option<PathBuf>,
    /// Pinned `xrandr` - `screen_info` preferred path (see module docs);
    /// `None` when `xrandr` was absent at pin time.
    xrandr: Option<PathBuf>,
}

/// Compile-time contract: `CaptureProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<X11Capture>();
};

/// Session gate shared by the X11 backends: a non-empty `DISPLAY`.
fn x11_display() -> Option<()> {
    let d = std::env::var_os("DISPLAY")?;
    (!d.is_empty()).then_some(())
}

/// Pinned `<bin> <args>` -> stdout bytes; non-zero exit is an error.
/// (Sibling copies live in `x11_input.rs` / `x11_window.rs`.)
async fn run(bin: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = spawn::command(bin, args);
    let out = spawn::output_within(&mut cmd, spawn::SUBPROCESS_TIMEOUT)
        .await
        .with_context(|| format!("spawn {}", bin.display()))?;
    if !out.status.success() {
        bail!("{} {:?} exited {}", bin.display(), args, out.status);
    }
    Ok(out.stdout)
}

impl X11Capture {
    /// Available iff `DISPLAY` is set (non-empty) and `scrot` was pinned
    /// on `PATH` at construction. `xdotool`/`xrandr` are optional extras
    /// pinned the same way.
    pub fn new() -> Option<Self> {
        x11_display()?;
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set, minus the
    /// `DISPLAY` session gate - the testable seam: hermetic tests resolve
    /// a fresh `PinnedBins` over a tempdir `PATH` and exercise the real
    /// spawn paths without mutating process env.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            scrot: pins.get("scrot")?.to_path_buf(),
            xdotool: pins.get("xdotool").map(Path::to_path_buf),
            xrandr: pins.get("xrandr").map(Path::to_path_buf),
        })
    }

    /// `scrot [-a x,y,w,h] <dir>/capture.png` + no-follow read-back. The
    /// dir is removed by the caller on every path.
    async fn capture_into(&self, dir: &Path, region: Option<Rect>) -> Result<Frame> {
        let path = dir.join("capture.png");
        // Do NOT pre-create the leaf (see module docs): `scrot` aborts
        // on an existing output file under a null stdin.
        let mut cmd = spawn::command(&self.scrot, &[]);
        if let Some(r) = region {
            if r.w < 1 || r.h < 1 {
                bail!("scrot: region requires w,h >= 1");
            }
            // `scrot -a x,y,w,h` - non-interactive area capture (scrot
            // ≥ 1.7); older scrots exit non-zero and surface as an error.
            cmd.arg("-a")
                .arg(format!("{},{},{},{}", r.x, r.y, r.w, r.h));
        }
        cmd.arg(&path);

        let out = spawn::output_within(&mut cmd, spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("spawn scrot")?;
        if !out.status.success() {
            bail!("scrot exited {}", out.status);
        }

        let mut png = Vec::new();
        std::io::Read::read_to_end(
            &mut captures::open_nofollow(&path).context("read scrot output")?,
            &mut png,
        )
        .context("read scrot output")?;
        let img = image::load_from_memory(&png).context("scrot output is not a PNG")?;
        Ok(Frame {
            png,
            width: img.width(),
            height: img.height(),
        })
    }
}

#[async_trait]
impl CaptureProvider for X11Capture {
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame> {
        // A fresh unpredictable 0700 dir per capture - the file inside
        // it cannot be preplanted, and the dir is removed no matter how
        // the capture resolves (success, scrot failure, decode failure).
        let dir = captures::fresh_capture_dir().context("create capture dir")?;
        let result = self.capture_into(&dir, region).await;
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    /// `xdotool getmouselocation --shell` -> `X=`/`Y=` pair.
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        let xdotool = self
            .xdotool
            .as_ref()
            .ok_or_else(|| anyhow!("xdotool not on PATH at pin time"))?;
        let stdout = run(xdotool, &["getmouselocation", "--shell"]).await?;
        parse_getmouselocation(&String::from_utf8_lossy(&stdout))
            .ok_or_else(|| anyhow!("unparseable xdotool getmouselocation output"))
    }

    /// Monitor inventory: `xrandr --query` when pinned (per-monitor
    /// `WxH+X+Y` geometry), else the single virtual-screen rect from
    /// `xdotool getdisplaygeometry --shell`.
    async fn screen_info(&self) -> Result<Value> {
        if let Some(xrandr) = &self.xrandr
            && let Ok(stdout) = run(xrandr, &["--query"]).await
        {
            let monitors = parse_xrandr_monitors(&String::from_utf8_lossy(&stdout));
            if !monitors.is_empty() {
                return Ok(json!({ "monitors": monitors }));
            }
        }
        if let Some(xdotool) = &self.xdotool {
            let stdout = run(xdotool, &["getdisplaygeometry", "--shell"]).await?;
            let text = String::from_utf8_lossy(&stdout);
            if let (Some(w), Some(h)) = (
                shell_var_i64(&text, "WIDTH"),
                shell_var_i64(&text, "HEIGHT"),
            ) {
                return Ok(json!({
                    "monitors": [{
                        "name": "default",
                        "x": 0,
                        "y": 0,
                        "width": w,
                        "height": h,
                        "focused": true,
                    }]
                }));
            }
            bail!("unparseable xdotool getdisplaygeometry output");
        }
        Err(anyhow!(
            "no screen-info backend pinned at construction (xrandr/xdotool)"
        ))
    }
}

/// `NAME=value` line in `--shell` output -> integer value. Kept in sync
/// with the sibling copy in `x11_input.rs`.
fn shell_var_i64(s: &str, key: &str) -> Option<i64> {
    for line in s.lines() {
        if let Some(v) = line
            .trim()
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return v.trim().parse().ok();
        }
    }
    None
}

/// `xdotool getmouselocation --shell` output -> `(x, y)`.
fn parse_getmouselocation(s: &str) -> Option<(i32, i32)> {
    Some((shell_var_i64(s, "X")? as i32, shell_var_i64(s, "Y")? as i32))
}

/// `WxH+X+Y` -> `(w, h, x, y)`; the offsets may carry a sign.
fn parse_xrandr_geometry(tok: &str) -> Option<(i64, i64, i64, i64)> {
    let (ws, rest) = tok.split_once('x')?;
    let w: i64 = ws.parse().ok()?;
    let mut parts = rest.split('+');
    let h: i64 = parts.next()?.parse().ok()?;
    let x: i64 = parts.next()?.parse().ok()?;
    let y: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    (w > 0 && h > 0).then_some((w, h, x, y))
}

/// `xrandr --query` `NAME connected [primary] WxH+X+Y ...` header lines ->
/// monitor records. `disconnected` outputs and the `Screen N:` line are
/// skipped; `primary` maps onto `focused` (X11 has no per-output focus).
fn parse_xrandr_monitors(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(name), Some(state)) = (it.next(), it.next()) else {
            continue;
        };
        if state != "connected" {
            continue;
        }
        let mut primary = false;
        let mut geom = None;
        for tok in it {
            if tok == "primary" {
                primary = true;
            } else if let Some(g) = parse_xrandr_geometry(tok) {
                geom = Some(g);
                break;
            }
        }
        let Some((w, h, x, y)) = geom else {
            continue;
        };
        out.push(json!({
            "name": name,
            "x": x,
            "y": y,
            "width": w,
            "height": h,
            "focused": primary,
        }));
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Canonical 1×1 PNG, base64-embedded (same fixture the hermetic
    /// integration tests use).
    const PNG_1X1_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    fn b64decode(s: &str) -> Vec<u8> {
        let mut acc = 0u32;
        let mut nbits = 0u32;
        let mut out = Vec::new();
        for b in s.bytes() {
            if b == b'=' {
                break;
            }
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                other => panic!("bad base64 byte {other:#x}"),
            };
            acc = (acc << 6) | u32::from(v);
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((acc >> nbits) as u8);
            }
        }
        out
    }

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

    /// Fake `scrot`: writes the PNG fixture to its last argv - the same
    /// `while/shift/printf` shape the grim hermetic fake uses.
    fn scrot_script() -> String {
        use std::fmt::Write as _;
        let mut fmt = String::new();
        for b in b64decode(PNG_1X1_B64) {
            match b {
                b'%' => fmt.push_str("%%"),
                b'\\' => fmt.push_str("\\\\"),
                b'\'' => fmt.push_str("'\\''"),
                0x20..=0x7e => fmt.push(b as char),
                _ => write!(fmt, "\\{b:03o}").unwrap(),
            }
        }
        format!(
            "#!/bin/sh\n\
             while [ $# -gt 1 ]; do shift; done\n\
             printf '{fmt}' > \"$1\"\n"
        )
    }

    // ---- pure parsing -------------------------------------------------

    #[test]
    fn parse_getmouselocation_shell() {
        let out = "X=1017\nY=664\nSCREEN=0\nWINDOW=83886083\n";
        assert_eq!(parse_getmouselocation(out), Some((1017, 664)));
        assert_eq!(parse_getmouselocation("X=1"), None); // missing Y
        assert_eq!(parse_getmouselocation("garbage"), None);
        // XSCREENSAVER-style keys must not satisfy the `X` lookup.
        assert_eq!(parse_getmouselocation("XFOO=9\nY=3"), None);
    }

    #[test]
    fn parse_xrandr_geometry_forms() {
        assert_eq!(
            parse_xrandr_geometry("1920x1080+0+0"),
            Some((1920, 1080, 0, 0))
        );
        assert_eq!(
            parse_xrandr_geometry("2560x1440+1920+-20"),
            Some((2560, 1440, 1920, -20))
        );
        assert_eq!(parse_xrandr_geometry("1920x1080"), None);
        assert_eq!(parse_xrandr_geometry("(normal"), None);
        assert_eq!(parse_xrandr_geometry("1x2+3+4+5"), None);
    }

    #[test]
    fn parse_xrandr_monitors_connected_only() {
        let text = "Screen 0: minimum 320 x 200, current 4480 x 1440, maximum 16384 x 16384\n\
                    eDP-1 connected primary 1920x1080+0+0 (normal left inverted right x axis y axis) 344mm x 193mm\n\
                    DP-1 connected 2560x1440+1920+0 (normal left inverted right x axis y axis) 598mm x 336mm\n\
                    HDMI-1 disconnected (normal left inverted right x axis y axis)\n\
                    VGA-1 connected (normal left inverted right x axis y axis)\n";
        let m = parse_xrandr_monitors(text);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0]["name"], json!("eDP-1"));
        assert_eq!(m[0]["width"], json!(1920));
        assert_eq!(m[0]["focused"], json!(true));
        assert_eq!(m[1]["name"], json!("DP-1"));
        assert_eq!(m[1]["x"], json!(1920));
        assert_eq!(m[1]["focused"], json!(false));
    }

    // ---- construction probe -------------------------------------------

    #[test]
    fn with_pins_requires_scrot() {
        let dir = tempfile::tempdir().unwrap();
        // resolve_in over an explicit dir list - no PATH mutation needed.
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        assert!(X11Capture::with_pins(&pins).is_none());

        write_exe(dir.path(), "scrot", &scrot_script());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cap = X11Capture::with_pins(&pins).expect("scrot pin resolves");
        assert!(cap.scrot.is_absolute());
    }

    #[test]
    fn new_is_none_without_display() {
        // SAFETY: test-only env mutation, restored before returning. The
        // sibling x11_* gate tests make the same mutation and every
        // ordering leaves DISPLAY either absent or at its original value.
        let saved = std::env::var_os("DISPLAY");
        unsafe { std::env::remove_var("DISPLAY") };
        assert!(X11Capture::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("DISPLAY", v) };
        }
    }

    // ---- hermetic spawn paths (fake scrot/xdotool via resolve_in) -----

    #[tokio::test]
    async fn capture_full_and_region_via_fake_scrot() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "scrot", &scrot_script());
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cap = X11Capture::with_pins(&pins).unwrap();

        let frame = cap.capture_frame(None).await.unwrap();
        assert_eq!(&frame.png[..4], b"\x89PNG");
        assert_eq!((frame.width, frame.height), (1, 1));

        let frame = cap
            .capture_frame(Some(Rect {
                x: 5,
                y: 6,
                w: 7,
                h: 8,
            }))
            .await
            .unwrap();
        assert_eq!((frame.width, frame.height), (1, 1));
    }

    #[tokio::test]
    async fn capture_failure_and_garbage_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "scrot", "#!/bin/sh\nexit 1\n");
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cap = X11Capture::with_pins(&pins).unwrap();
        let err = cap.capture_frame(None).await.unwrap_err();
        assert!(err.to_string().contains("scrot exited"), "{err}");

        // Exit 0 but non-PNG output - the decode guard must reject it.
        write_exe(
            dir.path(),
            "scrot",
            "#!/bin/sh\nwhile [ $# -gt 1 ]; do shift; done\necho nope > \"$1\"\n",
        );
        let err = cap.capture_frame(None).await.unwrap_err();
        assert!(err.to_string().contains("not a PNG"), "{err}");
    }

    #[tokio::test]
    async fn cursor_and_screen_info_via_fake_xdotool() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "scrot", &scrot_script());
        write_exe(
            dir.path(),
            "xdotool",
            "#!/bin/sh\n\
             case \"$1\" in\n\
             getmouselocation) printf 'X=11\\nY=22\\nSCREEN=0\\n';;\n\
             getdisplaygeometry) printf 'WIDTH=1920\\nHEIGHT=1080\\n';;\n\
             esac\nexit 0\n",
        );
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cap = X11Capture::with_pins(&pins).unwrap();

        assert_eq!(cap.cursor_position().await.unwrap(), (11, 22));
        // xrandr is absent from the tempdir PATH -> the xdotool
        // fallback path is what runs here.
        let info = cap.screen_info().await.unwrap();
        assert_eq!(info["monitors"][0]["width"], json!(1920));

        // Helper failure surfaces as an error.
        write_exe(dir.path(), "xdotool", "#!/bin/sh\nexit 1\n");
        assert!(cap.cursor_position().await.is_err());
        assert!(cap.screen_info().await.is_err());
    }

    #[tokio::test]
    async fn read_channels_error_without_helpers() {
        let dir = tempfile::tempdir().unwrap();
        write_exe(dir.path(), "scrot", &scrot_script());
        // Only scrot resolves - xdotool/xrandr unpinned.
        let pins = whitelist::PinnedBins::resolve_in(&[dir.path().to_path_buf()]);
        let cap = X11Capture::with_pins(&pins).unwrap();
        let err = cap.cursor_position().await.unwrap_err();
        assert!(err.to_string().contains("xdotool not on PATH"), "{err}");
        let err = cap.screen_info().await.unwrap_err();
        assert!(err.to_string().contains("no screen-info backend"), "{err}");
    }
}
