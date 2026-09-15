//! XDG Desktop Portal capture backend — the universal last-resort rung of
//! the capture fallback ladder (`wlr-screencopy` → `grim` → portal; ADR
//! 0004, ARCHITECTURE.md §5).
//!
//! Speaks `org.freedesktop.portal.Screenshot` on the session bus over
//! `zbus` (re-exported through `atspi`, already in the tree). This is the
//! only capture path that works on compositors that expose neither
//! `zwlr_screencopy_manager_v1` nor a `grim` binary — GNOME, KDE Plasma,
//! COSMIC — at the price of a **consent prompt**.
//!
//! ## Consent behavior (per backend — the spec leaves it implementation-
//! defined)
//!
//! `capture_frame` always calls `Screenshot` with `interactive: false` and
//! an empty `parent_window` — it never asks the portal for an interactive
//! selection dialog. What the user sees is still backend-dependent:
//!
//! - `xdg-desktop-portal-gnome` shows a one-shot "share screen" consent
//!   dialog on the first capture per app; the choice is remembered via
//!   the GNOME permission store where supported.
//! - `xdg-desktop-portal-kde` shows its own dialog with a "remember"
//!   option.
//! - `xdg-desktop-portal-hyprland`/`wlr` may answer non-interactively at
//!   once or decline `interactive: false` entirely — the failure surfaces
//!   as a structured `CaptureFailed`, never a retry loop.
//!
//! The Screenshot portal has **no `persist_mode`/restore token** (that is
//! a RemoteDesktop/ScreenCast feature), so there is nothing to persist
//! here — token persistence lives in [`super::portal_input`]. A user
//! cancelling the dialog produces a `Response` code `1`, mapped to an
//! error that names the cancellation explicitly.
//!
//! ## Request/response plumbing
//!
//! Every portal method returns a *request object path*; the real answer
//! arrives asynchronously as a `org.freedesktop.portal.Request::Response`
//! signal on that object. We subscribe to `Response` signals **before**
//! issuing the call and match on the returned request path, so a fast
//! non-interactive reply can never race past the subscription. Responses
//! are awaited with [`RESPONSE_TIMEOUT`] (120s) — consent dialogs block on
//! a human.
//!
//! ## Region capture
//!
//! The Screenshot portal has no region parameter: a region request is a
//! full capture cropped client-side via `image`.
//!
//! ## Limits
//!
//! `cursor_position`/`screen_info` have no portal equivalent; they reuse
//! the `hyprctl` helpers (live on Hyprland) and degrade to the last
//! captured frame's geometry / `ULTRANIX_SCREEN_SIZE` elsewhere.
//!
//! SAFETY: unit tests in this module never place a portal call — every
//! `Screenshot` invocation can raise a GUI consent dialog. Tests cover
//! the pure halves (URI handling, options, response mapping, cropping);
//! the `#[ignore]`d live test only exercises the name-ownership probe.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use atspi::zbus::{self, zvariant};
use futures_util::StreamExt;
use serde_json::{Value as JsonValue, json};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::traits::{CaptureProvider, Frame, Rect};

// ---------------------------------------------------------------------------
// Shared portal plumbing (`pub(crate)`: reused by portal_input)
// ---------------------------------------------------------------------------

/// Well-known name of the portal frontend on the session bus.
pub(crate) const PORTAL_BUS_NAME: &str = "org.freedesktop.portal.Desktop";
/// Object path of the portal frontend.
pub(crate) const PORTAL_DESKTOP_PATH: &str = "/org/freedesktop/portal/desktop";
/// Request objects emit their `Response(u32, a{sv})` on this interface.
pub(crate) const REQUEST_IFACE: &str = "org.freedesktop.portal.Request";
/// The Screenshot portal interface on [`PORTAL_DESKTOP_PATH`].
const SCREENSHOT_IFACE: &str = "org.freedesktop.portal.Screenshot";

/// Probe budget: a session bus that cannot answer `NameHasOwner` within
/// this window is treated as portal-less rather than stalling startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Budget for one portal request's `Response` signal. Generous on purpose:
/// the response may sit behind a consent dialog waiting for a human.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// Per-call D-Bus budget for portal plumbing (proxy build, method call,
/// signal subscription, `Get` property) — distinct from
/// [`RESPONSE_TIMEOUT`], which waits on a human at a consent dialog. A
/// wedged portal must not hang a tool call.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Run a D-Bus future under [`CALL_TIMEOUT`]; elapsed surfaces as an
/// error, keeping every portal interaction bounded.
pub(crate) async fn portal_call<F, T, E>(fut: F) -> Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout(CALL_TIMEOUT, fut).await {
        Err(_) => Err(anyhow!(
            "portal D-Bus call timed out after {CALL_TIMEOUT:?}"
        )),
        Ok(Err(e)) => Err(anyhow::Error::new(e)),
        Ok(Ok(v)) => Ok(v),
    }
}

/// `a{sv}` option dicts used throughout the portal API.
pub(crate) type Options = HashMap<&'static str, Value<'static>>;

/// Runtime probe shared by both portal providers: `true` only when the
/// session bus is reachable *and* `org.freedesktop.portal.Desktop` has an
/// owner (i.e. `xdg-desktop-portal` plus at least one backend is up).
///
/// The probe runs on a private thread + throwaway runtime, exactly like
/// `atspi::AtspiUi::new`: `zbus::Connection` binds to the ambient tokio
/// runtime, so a connection made here could not be reused anyway — the
/// real one is established lazily on first use via `OnceCell`.
pub(crate) fn portal_name_owned() -> bool {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(async {
            tokio::time::timeout(PROBE_TIMEOUT, async {
                let bus = zbus::Connection::session().await.ok()?;
                let reply = bus
                    .call_method(
                        Some("org.freedesktop.DBus"),
                        "/org/freedesktop/DBus",
                        Some("org.freedesktop.DBus"),
                        "NameHasOwner",
                        &PORTAL_BUS_NAME,
                    )
                    .await
                    .ok()?;
                reply.body().deserialize::<bool>().ok()
            })
            .await
            .ok()
            .flatten()
        })
    })
    .join()
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// Unique-per-call `handle_token`: object-path-safe charset
/// (`[A-Za-z0-9_]`), uniqueness via pid + random component.
pub(crate) fn new_handle_token() -> String {
    format!(
        "ultranix_mcp_{}_{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )
}

/// Whether `token` is legal inside a D-Bus object path element — the
/// portal copies our token into request/session paths verbatim.
/// (Used by tests to pin the `new_handle_token` charset.)
#[cfg(test)]
fn valid_handle_token(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `org.freedesktop.portal.Desktop` proxy for `iface`, no property
/// caching (portal objects need no `GetAll` roundtrip at build time).
pub(crate) async fn portal_proxy(
    conn: &zbus::Connection,
    iface: &'static str,
) -> Result<zbus::Proxy<'static>> {
    portal_call(zbus::Proxy::new(
        conn,
        PORTAL_BUS_NAME,
        PORTAL_DESKTOP_PATH,
        iface,
    ))
    .await
    .with_context(|| format!("build portal proxy for {iface}"))
}

/// Stream of `org.freedesktop.portal.Request::Response` signals from the
/// portal frontend — *any* request object. Created **before** the method
/// call it pairs with, so the reply cannot race the subscription; the
/// caller filters on the returned request path via [`await_response`].
pub(crate) async fn response_stream(conn: &zbus::Connection) -> Result<zbus::MessageStream> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(PORTAL_BUS_NAME)
        .map_err(|e| anyhow!("portal match rule sender: {e}"))?
        .interface(REQUEST_IFACE)
        .map_err(|e| anyhow!("portal match rule interface: {e}"))?
        .member("Response")
        .map_err(|e| anyhow!("portal match rule member: {e}"))?
        .build();
    portal_call(zbus::MessageStream::for_match_rule(
        rule.to_owned(),
        conn,
        Some(4),
    ))
    .await
    .context("subscribe to portal Response signals")
}

/// Wait for the `Response` signal belonging to `request` and return its
/// results dict. Non-matching signals (other in-flight requests) are
/// skipped. Response codes: `0` success, `1` user dismissed/cancelled,
/// `2`+ other failure.
pub(crate) async fn await_response(
    stream: &mut zbus::MessageStream,
    request: &OwnedObjectPath,
) -> Result<HashMap<String, OwnedValue>> {
    tokio::time::timeout(RESPONSE_TIMEOUT, async {
        while let Some(item) = stream.next().await {
            let msg = item.context("portal Response signal receive")?;
            if msg.header().path().map(|p| p.as_str()) != Some(request.as_str()) {
                continue;
            }
            let (code, results): (u32, HashMap<String, OwnedValue>) = msg
                .body()
                .deserialize()
                .context("deserialize portal Response body")?;
            return response_result(code, results);
        }
        Err(anyhow!("portal Response stream ended"))
    })
    .await
    .context("portal request timed out waiting for Response")?
}

/// Map a portal response code onto `Ok(results)` / a descriptive error.
/// Pure — unit-tested without a bus.
pub(crate) fn response_result(
    code: u32,
    results: HashMap<String, OwnedValue>,
) -> Result<HashMap<String, OwnedValue>> {
    match code {
        0 => Ok(results),
        1 => bail!("portal request cancelled by the user (consent declined)"),
        other => bail!("portal request failed (response code {other})"),
    }
}

/// String entry out of a results dict (`s`-typed variant).
pub(crate) fn get_string(results: &HashMap<String, OwnedValue>, key: &str) -> Result<String> {
    let v = results
        .get(key)
        .ok_or_else(|| anyhow!("portal response missing {key:?}"))?;
    <&str>::try_from(v)
        .map(str::to_string)
        .with_context(|| format!("portal response {key:?} is not a string"))
}

/// Optional `u32` entry out of a results dict.
pub(crate) fn get_u32(results: &HashMap<String, OwnedValue>, key: &str) -> Option<u32> {
    u32::try_from(results.get(key)?).ok()
}

// ---------------------------------------------------------------------------
// PortalCapture
// ---------------------------------------------------------------------------

/// XDG portal `Screenshot` backend for [`CaptureProvider`].
///
/// The `zbus::Connection` binds to whatever tokio runtime created it, so
/// it is established lazily on the ambient runtime at first capture — the
/// `new()` probe only answers "is a portal there".
pub struct PortalCapture {
    conn: tokio::sync::OnceCell<zbus::Connection>,
    /// Geometry of the last captured frame; `screen_info` degrades to it.
    last_frame: Mutex<Option<(u32, u32)>>,
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction — the `cursor_position`/`screen_info` helpers (S-1).
    hyprctl: Option<PathBuf>,
}

/// Compile-time contract: `CaptureProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PortalCapture>();
};

impl PortalCapture {
    /// `Some` only when the session bus is up and
    /// `org.freedesktop.portal.Desktop` is owned. Probe only — no portal
    /// method is invoked (those can raise consent dialogs).
    pub fn new() -> Option<Self> {
        if !portal_name_owned() {
            tracing::debug!("portal capture: org.freedesktop.portal.Desktop not owned");
            return None;
        }
        Some(Self {
            conn: tokio::sync::OnceCell::new(),
            last_frame: Mutex::new(None),
            hyprctl: crate::security::whitelist::resolve_binaries()
                .get("hyprctl")
                .map(std::path::Path::to_path_buf),
        })
    }

    /// Session-bus connection, created on first use on the ambient
    /// runtime (see struct docs).
    async fn conn(&self) -> Result<&zbus::Connection> {
        self.conn
            .get_or_try_init(|| async {
                portal_call(zbus::Connection::session())
                    .await
                    .context("session bus connect failed")
            })
            .await
    }

    /// One `Screenshot` round-trip → decoded PNG bytes + dimensions.
    async fn screenshot(&self) -> Result<(Vec<u8>, u32, u32)> {
        let conn = self.conn().await?;
        // Subscribe before calling: the non-interactive reply can land
        // within milliseconds.
        let mut responses = response_stream(conn).await?;
        let proxy = portal_proxy(conn, SCREENSHOT_IFACE).await?;

        let token = new_handle_token();
        let options = screenshot_options(&token);
        // `Screenshot(IN s handle_token, IN a{sv} options, OUT o request)`
        // — the token is the leading `s` arg (kept in the options dict as
        // well for backends that still read it from there).
        let request: OwnedObjectPath =
            portal_call(proxy.call("Screenshot", &(token.as_str(), &options)))
                .await
                .context("portal Screenshot call")?;
        let results = await_response(&mut responses, &request).await?;

        let uri = get_string(&results, "uri")?;
        let path = file_uri_to_path(&uri)?;
        let png = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read portal screenshot {}", path.display()))?;
        // The portal leaves the PNG in its own temp dir; removal is
        // best-effort (we may not own it under every backend).
        let _ = std::fs::remove_file(&path);

        let img = image::load_from_memory(&png).context("portal returned a non-PNG file")?;
        Ok((png, img.width(), img.height()))
    }
}

/// `Screenshot` options: non-interactive, no parent window, handle token.
/// `interactive: false` asks the backend to skip its selection UI —
/// consent may still be enforced by the backend (see module docs).
fn screenshot_options(token: &str) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(token.to_string()));
    o.insert("parent_window", Value::new(""));
    o.insert("interactive", Value::new(false));
    o
}

// ---------------------------------------------------------------------------
// file:// URI → path (pure)
// ---------------------------------------------------------------------------

/// Decode a `file://` URI to a local path. Handles the empty authority
/// (`file:///x`), `localhost`, and percent-escapes; rejects non-`file`
/// schemes, remote authorities and non-UTF-8 output.
fn file_uri_to_path(uri: &str) -> Result<PathBuf> {
    let rest = uri
        .strip_prefix("file://")
        .ok_or_else(|| anyhow!("portal URI {uri:?} is not file://"))?;
    let path_part = match rest.strip_prefix('/') {
        Some(p) => p, // file:///abs/path — empty authority
        None => match rest.find('/') {
            // file://host/abs/path — only localhost is meaningfully local.
            Some(i) if rest[..i].eq_ignore_ascii_case("localhost") => &rest[i + 1..],
            _ => bail!("portal URI {uri:?} has a non-local authority"),
        },
    };
    Ok(PathBuf::from(percent_decode(path_part)?))
}

/// RFC 3986 percent-decoding for URI path bytes; the decoded bytes must
/// form valid UTF-8.
fn percent_decode(s: &str) -> Result<String> {
    if !s.contains('%') {
        return Ok(format!("/{s}"));
    }
    let mut out = Vec::with_capacity(s.len() + 1);
    out.push(b'/');
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or_else(|| anyhow!("truncated %-escape in URI"))?;
            let h = (hex_val(hex[0]), hex_val(hex[1]));
            match h {
                (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
                _ => bail!("invalid %-escape in URI"),
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context("portal URI is not valid UTF-8")
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Region cropping (pure over PNG bytes)
// ---------------------------------------------------------------------------

/// Crop `png` to `r`, clamped into the image. Rejects regions entirely
/// outside the frame; a region covering the image is returned verbatim.
fn crop_png(png: &[u8], r: Rect) -> Result<Vec<u8>> {
    let img = image::load_from_memory(png).context("decode portal PNG")?;
    let (x0, y0) = (r.x.max(0) as u32, r.y.max(0) as u32);
    let (x1, y1) = (
        (r.x as i64 + r.w as i64).clamp(0, i64::from(img.width())) as u32,
        (r.y as i64 + r.h as i64).clamp(0, i64::from(img.height())) as u32,
    );
    ensure_nonempty(x0, y0, x1, y1)?;
    if x0 == 0 && y0 == 0 && x1 == img.width() && y1 == img.height() {
        return Ok(png.to_vec());
    }
    let cropped = img.crop_imm(x0, y0, x1 - x0, y1 - y0);
    let mut out = Vec::new();
    cropped
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .context("re-encode cropped frame as PNG")?;
    Ok(out)
}

fn ensure_nonempty(x0: u32, y0: u32, x1: u32, y1: u32) -> Result<()> {
    if x1 <= x0 || y1 <= y0 {
        bail!("capture region is entirely outside the frame");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// hyprctl helpers (same degraded-read pattern as grim_capture/uinput_input)
// ---------------------------------------------------------------------------

fn parse_cursorpos(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    if let Ok(v) = serde_json::from_str::<JsonValue>(t) {
        let x = v.get("x")?.as_i64()?;
        let y = v.get("y")?.as_i64()?;
        return Some((x as i32, y as i32));
    }
    let (xs, ys) = t.split_once(',')?;
    Some((xs.trim().parse().ok()?, ys.trim().parse().ok()?))
}

/// Pinned `hyprctl -j cursorpos`, scrubbed env, bounded wait.
async fn hyprctl_cursorpos(bin: &std::path::Path) -> Result<(i32, i32)> {
    let mut cmd = crate::security::spawn::command(bin, &["-j", "cursorpos"]);
    let out =
        crate::security::spawn::output_within(&mut cmd, crate::security::spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("run hyprctl cursorpos")?;
    if !out.status.success() {
        bail!("hyprctl cursorpos exited {}", out.status);
    }
    parse_cursorpos(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| anyhow!("unparseable hyprctl cursorpos output"))
}

/// Pinned `hyprctl -j monitors`, scrubbed env, bounded wait.
async fn hyprctl_monitors(bin: &std::path::Path) -> Result<JsonValue> {
    let mut cmd = crate::security::spawn::command(bin, &["-j", "monitors"]);
    let out =
        crate::security::spawn::output_within(&mut cmd, crate::security::spawn::SUBPROCESS_TIMEOUT)
            .await
            .context("run hyprctl monitors")?;
    if !out.status.success() {
        bail!("hyprctl monitors exited {}", out.status);
    }
    serde_json::from_slice(&out.stdout).context("parse hyprctl monitors JSON")
}

/// `"WxH"` (or `"W,H"`) → positive pixel dimensions; backs the
/// `ULTRANIX_SCREEN_SIZE`/`ULTRANIX_SCREEN_WIDTH`/`HEIGHT` fallback for
/// `screen_info` off-Hyprland.
fn parse_screen_size(s: &str) -> Option<(i32, i32)> {
    let (w, h) = s.trim().split_once(['x', 'X', ','])?;
    let (w, h) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

fn env_screen_size() -> Option<(i32, i32)> {
    if let Some(wh) = std::env::var("ULTRANIX_SCREEN_SIZE")
        .ok()
        .and_then(|v| parse_screen_size(&v))
    {
        return Some(wh);
    }
    let w: i32 = std::env::var("ULTRANIX_SCREEN_WIDTH")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let h: i32 = std::env::var("ULTRANIX_SCREEN_HEIGHT")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (w > 0 && h > 0).then_some((w, h))
}

// ---------------------------------------------------------------------------
// CaptureProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl CaptureProvider for PortalCapture {
    async fn capture_frame(&self, region: Option<Rect>) -> Result<Frame> {
        let (png, width, height) = self.screenshot().await?;
        let frame = match region {
            None => Frame { png, width, height },
            Some(r) => {
                let cropped = crop_png(&png, r)?;
                let img = image::load_from_memory(&cropped).context("decode cropped frame")?;
                Frame {
                    png: cropped,
                    width: img.width(),
                    height: img.height(),
                }
            }
        };
        *self.last_frame.lock().expect("portal_capture poisoned") =
            Some((frame.width, frame.height));
        Ok(frame)
    }

    /// No portal read channel exists: `hyprctl cursorpos` when on
    /// Hyprland, else a typed error (portal is the last-resort rung —
    /// on other compositors `InputProvider::cursor_position` may still
    /// answer via its own tracking).
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        match &self.hyprctl {
            Some(bin) => hyprctl_cursorpos(bin)
                .await
                .context("portal capture backend cannot read the cursor (hyprctl unavailable)"),
            None => Err(anyhow!(
                "portal capture backend cannot read the cursor (hyprctl unavailable)"
            )),
        }
    }

    /// `hyprctl monitors` verbatim on Hyprland; otherwise a synthesized
    /// single-monitor record from the last captured frame or
    /// `ULTRANIX_SCREEN_SIZE`, marked `"backend": "portal"`.
    async fn screen_info(&self) -> Result<JsonValue> {
        if let Some(bin) = &self.hyprctl
            && let Ok(v) = hyprctl_monitors(bin).await
        {
            return Ok(v);
        }
        let dims = self
            .last_frame
            .lock()
            .expect("portal_capture poisoned")
            .or_else(|| env_screen_size().map(|(w, h)| (w as u32, h as u32)));
        match dims {
            Some((w, h)) => Ok(json!({
                "backend": "portal",
                "monitors": [{
                    "name": "portal",
                    "x": 0, "y": 0,
                    "width": w, "height": h,
                    "focused": true
                }]
            })),
            None => Err(anyhow!(
                "portal backend cannot report outputs until a frame has been captured \
                 (set ULTRANIX_SCREEN_SIZE to pre-seed)"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: no test in this module places a portal method call — only the
// read-only `NameHasOwner` probe runs (and only `portal_name_owned`
// itself, never `Screenshot`). The ignored live test additionally
// requires ULTRANIX_MCP_LIVE_TESTS=1.

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(v: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(v.into()).unwrap()
    }

    #[test]
    fn handle_token_is_path_safe_and_unique() {
        let a = new_handle_token();
        let b = new_handle_token();
        assert_ne!(a, b);
        assert!(valid_handle_token(&a));
        assert!(a.starts_with("ultranix_mcp_"));
        // Would survive verbatim inside /org/freedesktop/portal/desktop/…
        assert!(!a.contains('/'));
    }

    #[test]
    fn valid_handle_token_charset() {
        assert!(valid_handle_token("abc_DEF_012"));
        assert!(!valid_handle_token(""));
        assert!(!valid_handle_token("has/slash"));
        assert!(!valid_handle_token("has space"));
        assert!(!valid_handle_token("has.dot"));
        assert!(!valid_handle_token("ünicode"));
    }

    #[test]
    fn screenshot_options_are_noninteractive() {
        let o = screenshot_options("tok");
        assert_eq!(o.len(), 3);
        assert!(matches!(o["handle_token"], Value::Str(_)));
        assert!(matches!(o["parent_window"], Value::Str(_)));
        assert!(matches!(o["interactive"], Value::Bool(false)));
    }

    #[test]
    fn file_uri_decodes_standard_forms() {
        assert_eq!(
            file_uri_to_path("file:///tmp/shot.png").unwrap(),
            PathBuf::from("/tmp/shot.png")
        );
        assert_eq!(
            file_uri_to_path("file://localhost/tmp/shot.png").unwrap(),
            PathBuf::from("/tmp/shot.png")
        );
        assert_eq!(
            file_uri_to_path("file:///tmp/my%20shot%21.png").unwrap(),
            PathBuf::from("/tmp/my shot!.png")
        );
        // UTF-8 escapes round-trip.
        assert_eq!(
            file_uri_to_path("file:///tmp/%C3%A9.png").unwrap(),
            PathBuf::from("/tmp/é.png")
        );
    }

    #[test]
    fn file_uri_rejects_bad_uris() {
        assert!(file_uri_to_path("https://x/f.png").is_err());
        assert!(file_uri_to_path("file://remote-host/f.png").is_err());
        assert!(file_uri_to_path("file:///tmp/%zz.png").is_err());
        assert!(file_uri_to_path("file:///tmp/%4").is_err());
        // %FF is not valid UTF-8.
        assert!(file_uri_to_path("file:///tmp/%FF.png").is_err());
    }

    #[test]
    fn response_result_maps_codes() {
        let ok = response_result(0, HashMap::new()).unwrap();
        assert!(ok.is_empty());
        let e = response_result(1, HashMap::new()).unwrap_err();
        assert!(e.to_string().contains("cancelled"), "{e}");
        let e = response_result(7, HashMap::new()).unwrap_err();
        assert!(e.to_string().contains("code 7"), "{e}");
    }

    #[test]
    fn results_extractors() {
        let mut r: HashMap<String, OwnedValue> = HashMap::new();
        r.insert("uri".into(), owned("file:///tmp/x.png"));
        r.insert("devices".into(), owned(3u32));
        assert_eq!(get_string(&r, "uri").unwrap(), "file:///tmp/x.png");
        assert_eq!(get_u32(&r, "devices"), Some(3));
        assert!(get_string(&r, "missing").is_err());
        assert_eq!(get_u32(&r, "missing"), None);
        // Type mismatch is an error, not a panic.
        assert!(get_string(&r, "devices").is_err());
        assert_eq!(get_u32(&r, "uri"), None);
    }

    /// Build a real PNG in memory so `crop_png` is exercised end-to-end.
    fn test_png(w: u32, h: u32) -> Vec<u8> {
        let img = image::DynamicImage::new_rgba8(w, h);
        let mut out = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn crop_png_clamps_and_crops() {
        let png = test_png(100, 80);
        let r = Rect {
            x: 10,
            y: 20,
            w: 30,
            h: 40,
        };
        let out = crop_png(&png, r).unwrap();
        let img = image::load_from_memory(&out).unwrap();
        assert_eq!((img.width(), img.height()), (30, 40));

        // Overhanging edge is clamped.
        let out = crop_png(
            &png,
            Rect {
                x: 90,
                y: 70,
                w: 50,
                h: 50,
            },
        )
        .unwrap();
        let img = image::load_from_memory(&out).unwrap();
        assert_eq!((img.width(), img.height()), (10, 10));

        // Full frame is returned untouched.
        let full = crop_png(
            &png,
            Rect {
                x: 0,
                y: 0,
                w: 100,
                h: 80,
            },
        )
        .unwrap();
        assert_eq!(full, png);

        // Fully outside → error.
        assert!(
            crop_png(
                &png,
                Rect {
                    x: 500,
                    y: 0,
                    w: 10,
                    h: 10
                }
            )
            .is_err()
        );
        assert!(
            crop_png(
                &png,
                Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0
                }
            )
            .is_err()
        );
    }

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn parse_screen_size_forms() {
        assert_eq!(parse_screen_size("1920x1080"), Some((1920, 1080)));
        assert_eq!(parse_screen_size("1024,768"), Some((1024, 768)));
        assert_eq!(parse_screen_size("garbage"), None);
        assert_eq!(parse_screen_size("0x100"), None);
    }

    #[test]
    fn new_probe_is_bounded_and_pure() {
        // Only NameHasOwner — no portal methods, no dialogs, ~3s cap.
        // Result is environment-dependent (None headless, maybe Some on a
        // desktop); the contract is "does not panic or hang".
        let _ = PortalCapture::new();
    }

    #[test]
    #[ignore = "requires a live session bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    fn live_probe_matches_name_owner() {
        if std::env::var("ULTRANIX_MCP_LIVE_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        // Probe only — deliberately NOT calling capture_frame: Screenshot
        // raises a GUI consent dialog.
        let p = PortalCapture::new();
        tracing::info!("portal capture probe: {:?}", p.is_some());
    }
}
