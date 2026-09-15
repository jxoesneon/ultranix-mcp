//! Spawn hygiene for whitelisted external binaries (S-10 / EFF-3).
//!
//! Every subprocess this crate launches goes through [`command`] /
//! [`std_command`], which apply two rules:
//!
//! - **Scrubbed environment** — `env_clear()` plus a minimal allowlist
//!   of session variables the binaries genuinely need ([`PASS_ENV`]).
//!   Process-local secrets (`ULTRANIX_MCP_API_KEY`,
//!   `ULTRANIX_MCP_HISTORY_SECRET`, HTTP/SOCKS proxies, `LD_*`) never
//!   reach a child's environment.
//! - **Bounded wait** — [`output_within`] / [`std_output_within`] wrap
//!   the wait in a timeout and kill the child on expiry, so a wedged
//!   `grim`/`hyprctl` cannot hang a tool call.

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Default subprocess budget — a healthy `grim`/`hyprctl` answers in
/// milliseconds; five seconds bounds a wedged child without false
/// positives.
pub const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for interactive helpers — `slurp` blocks on a user
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

/// `bin args…` as a [`tokio::process::Command`] under the scrubbed
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

/// `cmd.output()` bounded by `dur`; on expiry the child is killed
/// (`kill_on_drop`) and an error is returned.
pub async fn output_within(cmd: &mut tokio::process::Command, dur: Duration) -> Result<Output> {
    match tokio::time::timeout(dur, cmd.output()).await {
        Err(_) => bail!("subprocess timed out after {dur:?}"),
        Ok(result) => result.context("spawn subprocess"),
    }
}

/// `bin args…` as a blocking [`std::process::Command`] under the scrubbed
/// environment — for the synchronous probes that run at provider
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

/// Blocking `output()` with a deadline — `std::process` has no timeout
/// primitive, so this polls `try_wait` and kills the child on expiry.
/// Returns `None` on spawn failure or timeout (callers treat both as
/// "helper unavailable").
pub fn std_output_within(cmd: &mut std::process::Command, dur: Duration) -> Option<Output> {
    use std::io::Read;

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + dur;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut stdout);
                }
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
        // PATH survives the scrub — children can still resolve helpers.
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

    #[test]
    fn std_timeout_kills_wedged_child() {
        let mut cmd = std_command(Path::new("/bin/sh"), &["-c", "sleep 30"]);
        let started = std::time::Instant::now();
        assert!(std_output_within(&mut cmd, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
