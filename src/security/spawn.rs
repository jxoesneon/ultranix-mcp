//! Spawn hygiene for whitelisted external binaries (S-10 / EFF-3).
//!
//! Every subprocess this crate launches goes through [`command`] /
//! [`std_command`], which apply two rules:
//!
//! - **Scrubbed environment**- `env_clear()` plus a minimal allowlist
//!   of session variables the binaries genuinely need ([`PASS_ENV`]).
//!   Process-local secrets (`ULTRANIX_MCP_API_KEY`,
//!   `ULTRANIX_MCP_HISTORY_SECRET`, HTTP/SOCKS proxies, `LD_*`) never
//!   reach a child's environment.
//! - **Bounded wait**- [`output_within`] / [`std_output_within`] wrap
//!   the wait in a timeout and kill the child on expiry, so a wedged
//!   `grim`/`hyprctl` cannot hang a tool call.

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Default subprocess budget - a healthy `grim`/`hyprctl` answers in
/// milliseconds; five seconds bounds a wedged child without false
/// positives.
pub const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for interactive helpers - `slurp` blocks on a user
/// region-drag, so it gets a longer (still bounded) window.
pub const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variables forwarded to spawned binaries; everything else
/// is scrubbed by `env_clear()`.
const PASS_ENV: &[&str] = &[
    // Resolution of relative helper names + per-user runtime paths.
    "PATH",
    "HOME",
    // Wayland/compositor session for grim/slurp/hyprctl.
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "HYPRLAND_INSTANCE_SIGNATURE",
    // X11 fallback paths (scrot/xdotool/wmctrl on non-Hyprland sessions).
    "DISPLAY",
    // Portal helpers may need to reach the session bus.
    "DBUS_SESSION_BUS_ADDRESS",
];

/// `bin args...` as a [`tokio::process::Command`] under the scrubbed
/// environment, `kill_on_drop` set so a timed-out wait still reaps the
/// child.
pub fn command(bin: &Path, args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .env_clear();
    for key in PASS_ENV {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd
}

/// `cmd` spawned with both streams piped, drained *while* the child
/// runs, and bounded by `dur`. Same contract as [`std_output_within`]:
/// stdout and stderr are capped at [`MAX_STDOUT`] each (a giant
/// `wl-paste` selection cannot OOM the server) but drained to EOF so
/// the child never blocks on a full pipe and deadlocks the wait. On
/// expiry the child is killed (`kill_on_drop`) and an error is
/// returned.
pub async fn output_within(cmd: &mut tokio::process::Command, dur: Duration) -> Result<Output> {
    use tokio::io::AsyncRead;

    /// Read `stream` to EOF keeping at most [`MAX_STDOUT`] bytes - the
    /// drain must outlast the cap or a chatty child wedges on write.
    async fn drain_capped(mut stream: impl AsyncRead + Unpin) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) if buf.len() < MAX_STDOUT => {
                    let keep = (MAX_STDOUT - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..keep]);
                }
                Ok(_) => {} // discard beyond the cap, keep draining
            }
        }
        buf
    }

    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn subprocess")?;
    let out = tokio::spawn(drain_capped(child.stdout.take().expect("stdout is piped")));
    let err = tokio::spawn(drain_capped(child.stderr.take().expect("stderr is piped")));
    let status = match tokio::time::timeout(dur, child.wait()).await {
        Err(_) => {
            let _ = child.kill().await;
            bail!("subprocess timed out after {dur:?}");
        }
        Ok(result) => result.context("wait subprocess")?,
    };
    // The child has exited, so both pipes are at EOF - the join awaits
    // return promptly. Bound the join anyway: a pipe-holding grandchild
    // could otherwise leave this "bounded" wait hanging indefinitely.
    const DRAIN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
    Ok(Output {
        status,
        stdout: tokio::time::timeout(DRAIN_JOIN_TIMEOUT, out)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default(),
        stderr: tokio::time::timeout(DRAIN_JOIN_TIMEOUT, err)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default(),
    })
}

/// `bin args...` as a blocking [`std::process::Command`] under the scrubbed
/// environment - for the synchronous probes that run at provider
/// construction time.
pub fn std_command(bin: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).stdin(Stdio::null()).env_clear();
    for key in PASS_ENV {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd
}

/// Cap on captured stdout - bounds memory when a whitelisted helper
/// misbehaves.
const MAX_STDOUT: usize = 4 * 1024 * 1024;

/// Blocking `output()` with a deadline - `std::process` has no timeout
/// primitive, so this polls `try_wait` and kills the child on expiry.
/// Stdout is drained *during* the wait: a child that emits more than a
/// pipe buffer's worth would otherwise block on write and deadlock
/// until the deadline. Output beyond [`MAX_STDOUT`] is discarded.
/// Returns `None` on spawn failure or timeout (callers treat both as
/// "helper unavailable").
pub fn std_output_within(cmd: &mut std::process::Command, dur: Duration) -> Option<Output> {
    use std::io::Read;

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Drain stdout on a dedicated thread: a child emitting more than a
    // pipe buffer would otherwise block on write and never exit - and a
    // blocking read in this loop would wedge on a silent-but-alive
    // child. The drainer unblocks when the child exits or is killed.
    let mut out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match out.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) if buf.len() < MAX_STDOUT => {
                    let keep = (MAX_STDOUT - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..keep]);
                }
                Ok(_) => {} // discard beyond the cap, keep draining
            }
        }
        let _ = tx.send(buf);
    });
    let deadline = std::time::Instant::now() + dur;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Bound the EOF join: a leaked pipe-holding grandchild
                // must not leave this "bounded" wait open.
                let stdout = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
                return Some(Output {
                    status,
                    stdout,
                    stderr: Vec::new(),
                });
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_is_scrubbed_to_allowlist() {
        // A secret-looking var set in the parent must not propagate.
        // SAFETY: single-threaded test module + the var is restored.
        unsafe { std::env::set_var("ULTRANIX_SPAWN_TEST_SECRET", "x") };
        let mut cmd = std_command(Path::new("/bin/sh"), &["-c", "env"]);
        let out = std_output_within(&mut cmd, SUBPROCESS_TIMEOUT).expect("sh runs");
        unsafe { std::env::remove_var("ULTRANIX_SPAWN_TEST_SECRET") };
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("ULTRANIX_SPAWN_TEST_SECRET"));
        // PATH survives the scrub - children can still resolve helpers.
        assert!(text.contains("PATH="));
    }

    #[tokio::test]
    async fn tokio_timeout_kills_wedged_child() {
        let mut cmd = command(Path::new("/bin/sh"), &["-c", "sleep 30"]);
        let err = output_within(&mut cmd, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn tokio_output_is_capped_without_deadlock() {
        // 8 MiB of stdout is far beyond both the pipe buffer and the
        // 4 MiB cap: an undrained child would block on write and hit the
        // timeout; an uncapped buffer would retain all 8 MiB.
        let mut cmd = command(Path::new("/bin/sh"), &["-c", "head -c 8388608 /dev/zero"]);
        let out = output_within(&mut cmd, SUBPROCESS_TIMEOUT)
            .await
            .expect("chatty child completes");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), MAX_STDOUT);
    }

    #[tokio::test]
    async fn tokio_stderr_is_captured() {
        let mut cmd = command(
            Path::new("/bin/sh"),
            &["-c", "echo out; echo err >&2; exit 3"],
        );
        let out = output_within(&mut cmd, SUBPROCESS_TIMEOUT)
            .await
            .expect("sh runs");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
    }

    #[test]
    fn std_timeout_kills_wedged_child() {
        let mut cmd = std_command(Path::new("/bin/sh"), &["-c", "sleep 30"]);
        let started = std::time::Instant::now();
        assert!(std_output_within(&mut cmd, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
