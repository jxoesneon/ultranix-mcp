//! Fallback capture backend — shells out to `grim` (and `slurp` for
//! interactive region selection). Works on any wlroots compositor that
//! exposes wlr-screencopy, at the cost of a process spawn per frame.
//!
//! `grim` writes the PNG into a fresh private capture dir
//! ([`crate::security::captures`]: `0700`, `O_NOFOLLOW` on create+read,
//! leaf `0600`) which is deleted after the read — on error paths too —
//! so a capture can never be redirected through a planted symlink.
//!
//! Binary paths are the canonicalized absolute paths pinned by
//! [`crate::security::whitelist`] at construction, spawned under the
//! scrubbed environment and per-spawn timeouts of
//! [`crate::security::spawn`] — a `PATH` hijack after construction
//! cannot substitute a trojan, and a wedged child cannot hang a call.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::security::{captures, spawn, whitelist};
use crate::traits::{CaptureProvider, Frame, Rect};

/// Capture via the `grim` CLI (`grim [-g "x,y wxh"] <file>`).
pub struct GrimCapture {
    grim: PathBuf,
    slurp: Option<PathBuf>,
    hyprctl: Option<PathBuf>,
}

impl GrimCapture {
    /// Available iff `grim` was pinned on `PATH` at construction.
    /// `slurp`/`hyprctl` are optional extras pinned the same way.
    pub fn new() -> Option<Self> {
        Self::with_pins(&whitelist::resolve_binaries())
    }

    /// [`Self::new`] against a caller-supplied pin set — the testable
    /// seam: hermetic tests resolve a fresh `PinnedBins` over a tempdir
    /// `PATH` instead of the process-wide snapshot.
    pub fn with_pins(pins: &whitelist::PinnedBins) -> Option<Self> {
        Some(Self {
            grim: pins.get("grim")?.to_path_buf(),
            slurp: pins.get("slurp").map(Path::to_path_buf),
            hyprctl: pins.get("hyprctl").map(Path::to_path_buf),
        })
    }
}

/// `grim -g` geometry for a Rect (output-local `x,y wxh`).
fn rect_geometry(r: Rect) -> String {
    format!("{},{} {}x{}", r.x, r.y, r.w, r.h)
}

impl GrimCapture {
    /// Geometry for a region capture: interactive `slurp` when installed
    /// (blocks for a user drag — intended UX for a region request; bounded
    /// by [`spawn::INTERACTIVE_TIMEOUT`]), else the requested rect
    /// verbatim.
    async fn region_geometry(&self, r: Rect) -> Result<String> {
        if let Some(slurp) = &self.slurp {
            let mut cmd = spawn::command(slurp, &[]);
            let out = spawn::output_within(&mut cmd, spawn::INTERACTIVE_TIMEOUT)
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

    /// `grim [-g geom] <dir>/capture.png` + no-follow read-back. The dir
    /// is removed by the caller on every path.
    async fn capture_into(&self, dir: &Path, region: Option<Rect>) -> Result<Frame> {
        let path = dir.join("capture.png");
        // Pre-create the leaf with O_NOFOLLOW at 0600 so `grim` can only
        // write into a regular file we own — never a planted symlink.
        drop(captures::open_nofollow(&path).context("create capture output")?);

        let mut cmd = spawn::command(&self.grim, &[]);
        if let Some(r) = region {
            let geom = self.region_geometry(r).await?;
            cmd.arg("-g").arg(geom);
        }
        cmd.arg(&path);

        let out = spawn::output_within(&mut cmd, spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("spawn grim")?;
        if !out.status.success() {
            bail!("grim exited {}", out.status);
        }

        let mut png = Vec::new();
        std::io::Read::read_to_end(
            &mut captures::open_nofollow(&path).context("read grim output")?,
            &mut png,
        )
        .context("read grim output")?;
        let img = image::load_from_memory(&png).context("grim output is not a PNG")?;
        Ok(Frame {
            png,
            width: img.width(),
            height: img.height(),
        })
    }

    /// The pinned `hyprctl` binary, or an error when it was absent at
    /// pin time.
    fn hyprctl_bin(&self) -> Result<&Path> {
        self.hyprctl
            .as_deref()
            .ok_or_else(|| anyhow!("hyprctl not on PATH at pin time"))
    }
}

#[async_trait]
impl CaptureProvider for GrimCapture {
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame> {
        // A fresh unpredictable 0700 dir per capture — the file inside
        // it cannot be preplanted, and the dir is removed no matter how
        // the capture resolves (success, grim failure, decode failure).
        let dir = captures::fresh_capture_dir().context("create capture dir")?;
        let result = self.capture_into(&dir, region).await;
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    async fn cursor_position(&self) -> Result<(i32, i32)> {
        super::common::hyprctl_cursorpos(self.hyprctl_bin()?).await
    }

    async fn screen_info(&self) -> Result<Value> {
        super::common::hyprctl_monitors(self.hyprctl_bin()?).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::providers::common::parse_cursorpos;
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn new_probes_grim_presence() {
        // On hosts with grim installed this is Some; without, None.
        // Either way it must agree with the shared pin resolver.
        assert_eq!(
            GrimCapture::new().is_some(),
            whitelist::resolve_binaries().is_available("grim")
        );
    }

    #[test]
    fn pinned_paths_are_absolute() {
        // Whatever pins resolve, they are canonicalized absolute paths —
        // a later `PATH` edit cannot redirect a spawn.
        if let Some(cap) = GrimCapture::new() {
            assert!(cap.grim.is_absolute());
            if let Some(s) = &cap.slurp {
                assert!(s.is_absolute());
            }
            if let Some(h) = &cap.hyprctl {
                assert!(h.is_absolute());
            }
        }
    }

    #[test]
    fn capture_dir_lifecycle_and_nofollow_leaf() {
        // The dir `capture_frame` writes into is a fresh private 0700
        // dir; the leaf is only ever touched through O_NOFOLLOW opens.
        let dir = captures::fresh_capture_dir().unwrap();
        let leaf = dir.join("capture.png");
        drop(captures::open_nofollow(&leaf).unwrap());
        std::fs::write(&leaf, b"png-bytes").unwrap();
        let mut back = Vec::new();
        std::io::Read::read_to_end(&mut captures::open_nofollow(&leaf).unwrap(), &mut back)
            .unwrap();
        assert_eq!(back, b"png-bytes");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
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
}
