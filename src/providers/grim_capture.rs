//! Fallback capture backend — shells out to `grim` (and `slurp` for
//! interactive region selection). Works on any wlroots compositor that
//! exposes wlr-screencopy, at the cost of a process spawn per frame.
//!
//! `grim` writes the PNG to a server-created temp file which is read back
//! and deleted on drop. Binary paths are resolved to absolute paths once at
//! construction (`PATH` lookup) so the running provider never depends on
//! `PATH` mutations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::traits::{CaptureProvider, Frame, Rect};

/// Capture via the `grim` CLI (`grim [-g "x,y wxh"] <file>`).
pub struct GrimCapture {
    grim: PathBuf,
    slurp: Option<PathBuf>,
    hyprctl: Option<PathBuf>,
}

impl GrimCapture {
    /// Available iff `grim` resolves on `PATH`. `slurp`/`hyprctl` are
    /// optional extras probed the same way.
    pub fn new() -> Option<Self> {
        Some(Self {
            grim: which("grim")?,
            slurp: which("slurp"),
            hyprctl: which("hyprctl"),
        })
    }
}

/// `PATH` lookup for an executable regular file.
fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.is_file()
        && p.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// `grim -g` geometry for a Rect (output-local `x,y wxh`).
fn rect_geometry(r: Rect) -> String {
    format!("{},{} {}x{}", r.x, r.y, r.w, r.h)
}

/// Parse `hyprctl cursorpos` output — modern JSON `{"x":N,"y":M}` or the
/// legacy `x, y` pair.
fn parse_cursorpos(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        let x = v.get("x")?.as_i64()?;
        let y = v.get("y")?.as_i64()?;
        return Some((x as i32, y as i32));
    }
    let (xs, ys) = t.split_once(',')?;
    Some((xs.trim().parse().ok()?, ys.trim().parse().ok()?))
}

impl GrimCapture {
    /// Geometry for a region capture: interactive `slurp` when installed
    /// (blocks for a user drag — intended UX for a region request), else the
    /// requested rect verbatim.
    async fn region_geometry(&self, r: Rect) -> Result<String> {
        if let Some(slurp) = &self.slurp {
            let out = tokio::process::Command::new(slurp)
                .output()
                .await
                .context("spawn slurp")?;
            if !out.status.success() {
                bail!("slurp cancelled or failed ({})", out.status);
            }
            let geom = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if geom.is_empty() {
                bail!("slurp returned empty geometry");
            }
            Ok(geom)
        } else {
            Ok(rect_geometry(r))
        }
    }
}

#[async_trait]
impl CaptureProvider for GrimCapture {
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame> {
        // NamedTempFile auto-deletes on drop, error paths included.
        let tmp = tempfile::Builder::new()
            .prefix("ultranix-grim-")
            .suffix(".png")
            .tempfile()
            .context("create capture tempfile")?;
        let path = tmp.path().to_path_buf();

        let mut cmd = tokio::process::Command::new(&self.grim);
        if let Some(r) = region {
            let geom = self.region_geometry(r).await?;
            cmd.arg("-g").arg(geom);
        }
        cmd.arg(&path);

        let status = cmd.status().await.context("spawn grim")?;
        if !status.success() {
            bail!("grim exited {status}");
        }

        let png = std::fs::read(&path).context("read grim output")?;
        let img = image::load_from_memory(&png).context("grim output is not a PNG")?;
        Ok(Frame {
            png,
            width: img.width(),
            height: img.height(),
        })
    }

    async fn cursor_position(&self) -> Result<(i32, i32)> {
        let hyprctl = self
            .hyprctl
            .as_ref()
            .ok_or_else(|| anyhow!("hyprctl not on PATH"))?;
        let out = tokio::process::Command::new(hyprctl)
            .args(["-j", "cursorpos"])
            .output()
            .await
            .context("run hyprctl cursorpos")?;
        if !out.status.success() {
            bail!("hyprctl cursorpos exited {}", out.status);
        }
        parse_cursorpos(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| anyhow!("unparseable hyprctl cursorpos output"))
    }

    async fn screen_info(&self) -> Result<Value> {
        let hyprctl = self
            .hyprctl
            .as_ref()
            .ok_or_else(|| anyhow!("hyprctl not on PATH"))?;
        let out = tokio::process::Command::new(hyprctl)
            .args(["-j", "monitors"])
            .output()
            .await
            .context("run hyprctl monitors")?;
        if !out.status.success() {
            bail!("hyprctl monitors exited {}", out.status);
        }
        serde_json::from_slice(&out.stdout).context("parse hyprctl monitors JSON")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_real_binary_and_misses_fake() {
        // `sh` exists on any unix; this name must never resolve.
        assert!(which("sh").is_some());
        assert!(which("ultranix-definitely-missing-binary").is_none());
    }

    #[test]
    fn which_returns_absolute_path() {
        let sh = which("sh").unwrap();
        assert!(sh.is_absolute());
        assert!(is_executable(&sh));
    }

    #[test]
    fn rect_geometry_formats_grim_style() {
        assert_eq!(
            rect_geometry(Rect {
                x: 10,
                y: 20,
                w: 300,
                h: 200
            }),
            "10,20 300x200"
        );
    }

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn new_probes_grim_presence() {
        // On hosts with grim installed this is Some; without, None.
        // Either way it must agree with `which`.
        assert_eq!(GrimCapture::new().is_some(), which("grim").is_some());
    }

    #[tokio::test]
    #[ignore = "requires a live wlr-screencopy compositor"]
    async fn live_grim_capture_produces_real_png() {
        let Some(cap) = GrimCapture::new() else {
            eprintln!("grim not installed; skipping");
            return;
        };
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            eprintln!("no wayland session; skipping");
            return;
        }
        let frame = cap.capture_frame(None).await.unwrap();
        assert_eq!(&frame.png[..4], b"\x89PNG");
        assert!(frame.width > 0 && frame.height > 0);
    }

    #[test]
    fn tempfile_lifecycle_for_grim_output() {
        // grim truncates/writes a path we hand it; emulate with bytes and
        // confirm the path is readable and the file is deleted on drop.
        let tmp = tempfile::Builder::new()
            .prefix("ultranix-grim-")
            .suffix(".png")
            .tempfile()
            .unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::write(&path, b"png-bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"png-bytes");
        drop(tmp);
        assert!(!path.exists());
    }
}
