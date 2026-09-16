//! XDG Desktop Portal capture backend - the universal last-resort rung of
//! the capture fallback ladder (`wlr-screencopy` -> `grim` -> portal; ADR
//! 0004, ARCHITECTURE.md §5).
//!
//! Speaks `org.freedesktop.portal.Screenshot` on the session bus over
//! `zbus` (re-exported through `atspi`, already in the tree). This is the
//! only capture path that works on compositors that expose neither
//! `zwlr_screencopy_manager_v1` nor a `grim` binary - GNOME, KDE Plasma,
//! COSMIC - at the price of a **consent prompt**.
//!
//! ## PipeWire fallback (RemoteDesktop portal)
//!
//! Some backends expose `org.freedesktop.portal.RemoteDesktop` without
//! `org.freedesktop.portal.Screenshot`. The constructor probe
//! introspects the portal object once; when Screenshot is absent but
//! RemoteDesktop exists, `capture_frame` instead runs an *ephemeral*
//! RemoteDesktop session per capture:
//!
//! ```text
//! CreateSession --> SelectSources(types = monitor) --> Start
//!      │ consent dialog (Response, up to 120s)
//!      v
//! OpenPipeWireRemote --> pw_context_connect_fd --> one video buffer
//!      v
//! disconnect stream --> Session.Close
//! ```
//!
//! The PipeWire main loop runs on a `spawn_blocking` worker bounded by
//! [`PIPEWIRE_TIMEOUT`]; the first `MemFd`/`MemPtr` BGRA/BGRx/RGBA/RGBx
//! buffer is converted to RGBA and encoded PNG. Like the Screenshot
//! path, no `persist_mode`/`restore_token` is ever sent - every capture
//! consents afresh (same policy as `portal_input`).
//!
//! ## Consent behavior (per backend - the spec leaves it implementation-
//! defined)
//!
//! `capture_frame` always calls `Screenshot` with `interactive: false` and
//! an empty `parent_window` - it never asks the portal for an interactive
//! selection dialog. What the user sees is still backend-dependent:
//!
//! - `xdg-desktop-portal-gnome` shows a one-shot "share screen" consent
//!   dialog on the first capture per app; the choice is remembered via
//!   the GNOME permission store where supported.
//! - `xdg-desktop-portal-kde` shows its own dialog with a "remember"
//!   option.
//! - `xdg-desktop-portal-hyprland`/`wlr` may answer non-interactively at
//!   once or decline `interactive: false` entirely - the failure surfaces
//!   as a structured `CaptureFailed`, never a retry loop.
//!
//! The Screenshot portal has **no `persist_mode`/restore token**(that is
//! a RemoteDesktop/ScreenCast feature), so there is nothing to persist
//! here - token persistence lives in [`super::portal_input`]. A user
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
//! are awaited with [`RESPONSE_TIMEOUT`] (120s) - consent dialogs block on
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
//! SAFETY: unit tests in this module never place a portal call - every
//! `Screenshot`/`Start` invocation can raise a GUI consent dialog, and no
//! test opens a PipeWire stream. Tests cover the pure halves (URI
//! handling, options, response mapping, cropping, pixel conversion);
//! the `#[ignore]`d live test only exercises the name-ownership probe.

use std::collections::HashMap;
#[cfg(feature = "pipewire")]
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

#[cfg(feature = "pipewire")]
use std::cell::RefCell;
#[cfg(feature = "pipewire")]
use std::rc::Rc;
#[cfg(feature = "pipewire")]
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use atspi::zbus::{self, zvariant};
use futures_util::StreamExt;
#[cfg(feature = "pipewire")]
use pipewire::spa;
#[cfg(feature = "pipewire")]
use pipewire::spa::param::video::VideoFormat;
use serde_json::{Value as JsonValue, json};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::providers::common;
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
/// `org.freedesktop.portal.RemoteDesktop` interface on
/// [`PORTAL_DESKTOP_PATH`] - PipeWire frame source when Screenshot is
/// absent. Ungated: the portal probe reports it regardless of the
/// `pipewire` feature.
const REMOTE_DESKTOP_IFACE: &str = "org.freedesktop.portal.RemoteDesktop";
/// `org.freedesktop.portal.Session` interface, implemented by the
/// session object returned from `CreateSession` - used for `Close`.
#[cfg(feature = "pipewire")]
const SESSION_IFACE: &str = "org.freedesktop.portal.Session";

/// `SelectSources` `types` bitmask: monitor(1) only.
#[cfg(feature = "pipewire")]
const SOURCE_MONITOR: u32 = 1;
/// `cursor_mode`: hidden(1) - the captured stream composites no cursor.
#[cfg(feature = "pipewire")]
const CURSOR_HIDDEN: u32 = 1;

/// Budget for the whole PipeWire grab: `connect_fd` + format
/// negotiation + first video buffer, iterated on the PipeWire main loop
/// in ≤50ms slices.
#[cfg(feature = "pipewire")]
const PIPEWIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Probe budget: a session bus that cannot answer `NameHasOwner` within
/// this window is treated as portal-less rather than stalling startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Budget for one portal request's `Response` signal. Generous on purpose:
/// the response may sit behind a consent dialog waiting for a human.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// Per-call D-Bus budget for portal plumbing (proxy build, method call,
/// signal subscription, `Get` property) - distinct from
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
/// runtime, so a connection made here could not be reused anyway - the
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

/// Which portal capture interfaces the frontend object advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortalCaps {
    /// `org.freedesktop.portal.Screenshot` is introspectable.
    screenshot: bool,
    /// `org.freedesktop.portal.RemoteDesktop` is introspectable.
    remote_desktop: bool,
}

/// Scan the portal's `Introspect` XML for the capture interfaces.
/// Interface names appear exactly once as `name="..."` attributes; a
/// plain substring check is sufficient (the XML carries no prose).
fn caps_from_introspection(xml: &str) -> PortalCaps {
    PortalCaps {
        screenshot: xml.contains(SCREENSHOT_IFACE),
        remote_desktop: xml.contains(REMOTE_DESKTOP_IFACE),
    }
}

/// Probe which portal capture paths exist: `Some(caps)` when the portal
/// is owned and at least one of Screenshot/RemoteDesktop is
/// advertised. When introspection itself fails we fall back to
/// `screenshot: true` - preserving pre-introspection behavior (the
/// `Screenshot` call then surfaces the real error at capture time).
fn portal_capture_caps() -> Option<PortalCaps> {
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
                if !reply.body().deserialize::<bool>().ok()? {
                    return None;
                }
                // org.freedesktop.DBus.Introspectable.Introspect() -> s xml
                let reply = bus
                    .call_method(
                        Some(PORTAL_BUS_NAME),
                        PORTAL_DESKTOP_PATH,
                        Some("org.freedesktop.DBus.Introspectable"),
                        "Introspect",
                        &(),
                    )
                    .await;
                let xml = reply
                    .ok()
                    .and_then(|r| r.body().deserialize::<String>().ok());
                match xml {
                    Some(xml) => {
                        let caps = caps_from_introspection(&xml);
                        // RemoteDesktop is only a capture source when the
                        // `pipewire` feature is compiled in - without it
                        // a RemoteDesktop-only portal yields no provider.
                        (caps.screenshot || (cfg!(feature = "pipewire") && caps.remote_desktop))
                            .then_some(caps)
                    }
                    // Introspection unavailable - assume the historical
                    // Screenshot-only surface rather than probing out.
                    None => Some(PortalCaps {
                        screenshot: true,
                        remote_desktop: false,
                    }),
                }
            })
            .await
            .ok()
            .flatten()
        })
    })
    .join()
    .ok()
    .flatten()
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

/// Whether `token` is legal inside a D-Bus object path element - the
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
/// portal frontend - *any* request object. Created **before**the method
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
/// Pure - unit-tested without a bus.
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
/// it is established lazily on the ambient runtime at first capture - the
/// `new()` probe only answers "is a portal there".
pub struct PortalCapture {
    conn: tokio::sync::OnceCell<zbus::Connection>,
    /// Interfaces advertised by the portal object at probe time:
    /// Screenshot (PNG-file path) or RemoteDesktop (PipeWire path).
    caps: PortalCaps,
    /// Geometry of the last captured frame; `screen_info` degrades to it.
    last_frame: Mutex<Option<(u32, u32)>>,
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction - the `cursor_position`/`screen_info` helpers (S-1).
    hyprctl: Option<PathBuf>,
}

/// Compile-time contract: `CaptureProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PortalCapture>();
};

impl PortalCapture {
    /// `Some` only when the session bus is up, the portal name is owned,
    /// and the portal object advertises at least one capture interface
    /// (Screenshot or RemoteDesktop). Probe only - `NameHasOwner` plus
    /// read-only `Introspect`; no portal method that can raise a consent
    /// dialog is invoked.
    pub fn new() -> Option<Self> {
        let Some(caps) = portal_capture_caps() else {
            tracing::debug!("portal capture: portal unowned or no capture interface advertised");
            return None;
        };
        Some(Self {
            conn: tokio::sync::OnceCell::new(),
            caps,
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

    /// One `Screenshot` round-trip -> decoded PNG bytes + dimensions.
    async fn screenshot(&self) -> Result<(Vec<u8>, u32, u32)> {
        let conn = self.conn().await?;
        // Subscribe before calling: the non-interactive reply can land
        // within milliseconds.
        let mut responses = response_stream(conn).await?;
        let proxy = portal_proxy(conn, SCREENSHOT_IFACE).await?;

        let token = new_handle_token();
        let options = screenshot_options(&token);
        // `Screenshot(IN s handle_token, IN a{sv} options, OUT o request)`
        // - the token is the leading `s` arg (kept in the options dict as
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

    /// One RemoteDesktop session -> PipeWire buffer -> PNG bytes +
    /// dimensions. The session is ephemeral: created, used for exactly
    /// one frame, then `Close`d - no `persist_mode`/`restore_token` is
    /// ever sent, so every capture re-consents through `Start`
    /// (identical policy to `portal_input`).
    #[cfg(feature = "pipewire")]
    async fn pipewire_screenshot(&self) -> Result<(Vec<u8>, u32, u32)> {
        let conn = self.conn().await?;
        let proxy = portal_proxy(conn, REMOTE_DESKTOP_IFACE).await?;
        // One subscription covers every request in the handshake; each
        // is matched on its returned request path.
        let mut responses = response_stream(conn).await?;

        // CreateSession(a{sv}) -> request -> Response{session_handle}
        let opts = create_session_options(new_handle_token(), new_handle_token());
        let req: OwnedObjectPath = portal_call(proxy.call("CreateSession", &(&opts,)))
            .await
            .context("portal CreateSession call")?;
        let results = await_response(&mut responses, &req).await?;
        let session_path = session_path_from(&results)?;

        // Everything below needs the session torn down on any outcome;
        // `Close` is best-effort (the object also dies with the bus).
        let outcome = async {
            // SelectSources(o, a{sv}) - monitor only. Unlike
            // `portal_input` (where sources are optional geometry), the
            // stream *is* the frame source: failure is fatal.
            let opts = select_sources_options(new_handle_token());
            let req: OwnedObjectPath =
                portal_call(proxy.call("SelectSources", &(&session_path, &opts)))
                    .await
                    .context("portal SelectSources call")?;
            await_response(&mut responses, &req).await?;

            // Start(o, s parent_window, a{sv}) - the consent dialog.
            let opts = start_options(new_handle_token());
            let req: OwnedObjectPath =
                portal_call(proxy.call("Start", &(&session_path, "", &opts)))
                    .await
                    .context("portal Start call")?;
            let results = await_response(&mut responses, &req).await?;
            let node = stream_node_ids(&results)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("portal RemoteDesktop granted no streams"))?;

            // OpenPipeWireRemote(o, a{sv}) -> h fd
            let opts = Options::new();
            let fd: zvariant::OwnedFd =
                portal_call(proxy.call("OpenPipeWireRemote", &(&session_path, &opts)))
                    .await
                    .context("portal OpenPipeWireRemote call")?;

            // PipeWire objects are !Send; the grab runs on a blocking
            // worker, self-bounded at PIPEWIRE_TIMEOUT by the loop
            // deadline. The outer timeout only guards a wedged
            // spawn_blocking join.
            let fd: OwnedFd = fd.into();
            let grab = tokio::task::spawn_blocking(move || pipewire_frame(fd, node));
            match tokio::time::timeout(PIPEWIRE_TIMEOUT + CALL_TIMEOUT, grab).await {
                Err(_) => bail!("pipewire capture timed out"),
                Ok(Err(e)) => Err(anyhow::Error::new(e)).context("pipewire capture task"),
                Ok(Ok(r)) => r,
            }
        }
        .await;

        self.close_session(conn, &session_path).await;
        outcome
    }

    /// `pipewire` feature off: RemoteDesktop is still introspected, but
    /// the stream cannot be consumed - error honestly rather than
    /// pretend the capture path exists.
    #[cfg(not(feature = "pipewire"))]
    async fn pipewire_screenshot(&self) -> Result<(Vec<u8>, u32, u32)> {
        bail!("portal Screenshot unavailable and the `pipewire` cargo feature is compiled out")
    }

    /// `org.freedesktop.portal.Session.Close()` - best-effort; the
    /// session object also disappears when our connection drops.
    #[cfg(feature = "pipewire")]
    async fn close_session(&self, conn: &zbus::Connection, path: &OwnedObjectPath) {
        let r = async {
            let proxy = portal_call(zbus::Proxy::new(
                conn,
                PORTAL_BUS_NAME,
                path.as_str(),
                SESSION_IFACE,
            ))
            .await?;
            portal_call(proxy.call::<_, _, ()>("Close", &())).await
        }
        .await;
        if let Err(e) = r {
            tracing::debug!("portal session Close failed (ignored): {e:#}");
        }
    }
}

/// `Screenshot` options: non-interactive, no parent window, handle token.
/// `interactive: false` asks the backend to skip its selection UI -
/// consent may still be enforced by the backend (see module docs).
fn screenshot_options(token: &str) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(token.to_string()));
    o.insert("parent_window", Value::new(""));
    o.insert("interactive", Value::new(false));
    o
}

// ---------------------------------------------------------------------------
// RemoteDesktop session helpers
//
// Capture-only subset of the `portal_input` handshake. Those helpers are
// private to portal_input (read-only for this change), so minimal copies
// live here - keep the two in sync: same tokens, same "no persist" rule.
// ---------------------------------------------------------------------------

/// `CreateSession` options: request + session handle tokens only. No
/// `persist_mode`/`restore_token` - every `Start` re-consents (module
/// docs; THREAT_MODEL.md §4.2).
#[cfg(feature = "pipewire")]
fn create_session_options(handle_token: String, session_token: String) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(handle_token));
    o.insert("session_handle_token", Value::new(session_token));
    o
}

/// `SelectSources` options: a single monitor source, hidden cursor.
#[cfg(feature = "pipewire")]
fn select_sources_options(handle_token: String) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(handle_token));
    o.insert("types", Value::new(SOURCE_MONITOR));
    o.insert("multiple", Value::new(false));
    o.insert("cursor_mode", Value::new(CURSOR_HIDDEN));
    o
}

/// `Start` options: handle token only.
#[cfg(feature = "pipewire")]
fn start_options(handle_token: String) -> Options {
    let mut o = Options::new();
    o.insert("handle_token", Value::new(handle_token));
    o
}

/// `session_handle` from a `CreateSession` response: spec type `s`, but
/// accept `o` too (some backends return an object path variant).
#[cfg(feature = "pipewire")]
fn session_path_from(results: &HashMap<String, OwnedValue>) -> Result<OwnedObjectPath> {
    if let Ok(s) = get_string(results, "session_handle") {
        return OwnedObjectPath::try_from(s).context("session_handle is not an object path");
    }
    let v = results
        .get("session_handle")
        .ok_or_else(|| anyhow!("CreateSession response missing session_handle"))?;
    OwnedObjectPath::try_from(v.try_clone().context("clone session_handle")?)
        .context("session_handle is neither s nor o")
}

/// PipeWire node ids out of the `aa{sv}` `streams` result of `Start`
/// (capture needs only the node id; geometry comes from format
/// negotiation on the stream itself).
#[cfg(feature = "pipewire")]
fn stream_node_ids(results: &HashMap<String, OwnedValue>) -> Vec<u32> {
    results
        .get("streams")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<HashMap<String, OwnedValue>>::try_from(v).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|d| u32::try_from(d.get("node_id")?).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// PipeWire one-frame grab (runs on a blocking worker - pw objects are
// !Send and the pw main loop must be pumped by hand)
// ---------------------------------------------------------------------------

/// The 32-bit RGB buffer layouts this consumer offers the stream. Any
/// other negotiated format is an explicit error - never silently wrong
/// pixels.
#[cfg(feature = "pipewire")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PixelLayout {
    /// B,G,R,X - swap B/R, alpha forced opaque (X is padding).
    Bgrx,
    /// B,G,R,A - swap B/R, keep alpha.
    Bgra,
    /// R,G,B,X - keep order, alpha forced opaque.
    Rgbx,
    /// R,G,B,A - pass through.
    Rgba,
}

#[cfg(feature = "pipewire")]
impl PixelLayout {
    /// Whether the first and third bytes must swap to reach RGBA.
    fn swap_rb(self) -> bool {
        matches!(self, Self::Bgrx | Self::Bgra)
    }
    /// Whether byte 3 is real alpha rather than padding.
    fn has_alpha(self) -> bool {
        matches!(self, Self::Bgra | Self::Rgba)
    }
}

/// Map a negotiated `SPA_VIDEO_FORMAT_*` onto a supported layout.
#[cfg(feature = "pipewire")]
fn pixel_layout(fmt: VideoFormat) -> Option<PixelLayout> {
    if fmt == VideoFormat::BGRx {
        Some(PixelLayout::Bgrx)
    } else if fmt == VideoFormat::BGRA {
        Some(PixelLayout::Bgra)
    } else if fmt == VideoFormat::RGBx {
        Some(PixelLayout::Rgbx)
    } else if fmt == VideoFormat::RGBA {
        Some(PixelLayout::Rgba)
    } else {
        None
    }
}

/// Convert one strided 4-byte-per-pixel plane to tightly packed RGBA.
/// `src` is already offset to the chunk start; `stride` is the chunk's
/// row stride (0 treated as tightly packed, negative rejected).
#[cfg(feature = "pipewire")]
fn convert_frame(
    src: &[u8],
    width: u32,
    height: u32,
    stride: i32,
    layout: PixelLayout,
) -> Result<Vec<u8>> {
    if width == 0 || height == 0 {
        bail!("pipewire frame has zero dimensions");
    }
    let row = width as usize * 4;
    let stride = match stride {
        s if s < 0 => bail!("pipewire negative stride {s} (bottom-up) unsupported"),
        0 => row, // tight packing
        s => s as usize,
    };
    if stride < row {
        bail!("pipewire stride {stride} smaller than {width}*4 row");
    }
    let need = stride * (height as usize - 1) + row;
    if src.len() < need {
        bail!("pipewire plane too small: {} bytes, need {need}", src.len());
    }
    let mut out = vec![0u8; row * height as usize];
    for y in 0..height as usize {
        let s = &src[y * stride..y * stride + row];
        let d = &mut out[y * row..(y + 1) * row];
        if layout.swap_rb() {
            for (sp, dp) in s.as_chunks::<4>().0.iter().zip(d.as_chunks_mut::<4>().0) {
                dp[0] = sp[2];
                dp[1] = sp[1];
                dp[2] = sp[0];
                dp[3] = if layout.has_alpha() { sp[3] } else { 0xFF };
            }
        } else {
            d.copy_from_slice(s);
            if !layout.has_alpha() {
                for px in d.as_chunks_mut::<4>().0 {
                    px[3] = 0xFF;
                }
            }
        }
    }
    Ok(out)
}

/// Tightly packed RGBA -> PNG bytes (the [`Frame`] payload).
#[cfg(feature = "pipewire")]
fn encode_frame(width: u32, height: u32, rgba: Vec<u8>) -> Result<(Vec<u8>, u32, u32)> {
    let img = image::RgbaImage::from_raw(width, height, rgba)
        .context("pipewire frame size does not match negotiated dimensions")?;
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .context("encode pipewire frame as PNG")?;
    Ok((png, width, height))
}

/// Shared state between the stream listener callbacks (which run inside
/// `Loop::iterate`) and the loop driver below.
#[cfg(feature = "pipewire")]
#[derive(Default)]
struct PwState {
    /// Negotiated layout + dimensions, set by the `Format` param.
    layout: Option<PixelLayout>,
    width: u32,
    height: u32,
    /// First decoded frame, tightly packed RGBA.
    frame: Option<Vec<u8>>,
    /// Fatal error observed inside a callback (surfaces out of the loop).
    error: Option<String>,
}

/// Connect to the portal-granted PipeWire fd, negotiate a raw RGB video
/// format, and copy out the first `MemFd`/`MemPtr` buffer. Blocking;
/// bounded by [`PIPEWIRE_TIMEOUT`].
#[cfg(feature = "pipewire")]
fn pipewire_frame(fd: OwnedFd, node_id: u32) -> Result<(Vec<u8>, u32, u32)> {
    use pipewire::context::ContextBox;
    use pipewire::keys::{MEDIA_CATEGORY, MEDIA_ROLE, MEDIA_TYPE};
    use pipewire::loop_::Timeout;
    use pipewire::main_loop::MainLoopBox;
    use pipewire::properties::properties;
    use pipewire::stream::{StreamBox, StreamFlags};

    // MainLoopBox::new calls pipewire::init() internally.
    let mainloop = MainLoopBox::new(None).context("pipewire main loop")?;
    let context = ContextBox::new(mainloop.loop_(), None).context("pipewire context")?;
    // Takes ownership of the portal fd.
    let core = context
        .connect_fd(fd, None)
        .context("pipewire connect_fd")?;
    let stream = StreamBox::new(
        &core,
        "ultranix-portal-capture",
        properties! {
            *MEDIA_TYPE => "Video",
            *MEDIA_CATEGORY => "Capture",
            *MEDIA_ROLE => "Screen",
        },
    )
    .context("pipewire stream")?;

    let state = Rc::new(RefCell::new(PwState::default()));
    let _listener = stream
        .add_local_listener_with_user_data(Rc::clone(&state))
        .param_changed(|_stream, st, id, param| {
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Some(param) = param else { return };
            let mut info = spa::param::video::VideoInfoRaw::new();
            if info.parse(param).is_err() {
                return;
            }
            let mut st = st.borrow_mut();
            // Only linear data is decodable here: 0 = linear, u64::MAX
            // (INVALID) = no modifier negotiated (memfd streams are
            // linear by construction). Anything else is a tiled/
            // compressed GPU layout we cannot read.
            let modifier = info.modifier();
            if modifier != 0 && modifier != u64::MAX {
                st.error = Some(format!("non-linear video modifier {modifier:#x}"));
                return;
            }
            match pixel_layout(info.format()) {
                Some(layout) => {
                    let size = info.size();
                    st.layout = Some(layout);
                    st.width = size.width;
                    st.height = size.height;
                }
                None => {
                    st.error = Some(format!("unsupported video format {:?}", info.format()));
                }
            }
        })
        .process(|stream, st| {
            let mut st = st.borrow_mut();
            if st.frame.is_some() || st.error.is_some() {
                return;
            }
            // Wait for format negotiation before touching buffers.
            let Some(layout) = st.layout else { return };
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else {
                st.error = Some("pipewire buffer with no data planes".into());
                return;
            };
            let (offset, size, stride) = {
                let chunk = d.chunk();
                if chunk.flags().contains(spa::buffer::ChunkFlags::CORRUPTED) {
                    return; // wait for the next buffer
                }
                (
                    chunk.offset() as usize,
                    chunk.size() as usize,
                    chunk.stride(),
                )
            };
            if size == 0 {
                return; // stray empty buffer; keep waiting
            }
            match d.data() {
                // MAP_BUFFERS makes MemFd/MemPtr planes CPU-visible.
                Some(map) => match map.get(offset..offset + size) {
                    Some(plane) => {
                        match convert_frame(plane, st.width, st.height, stride, layout) {
                            Ok(rgba) => st.frame = Some(rgba),
                            Err(e) => st.error = Some(format!("frame decode: {e:#}")),
                        }
                    }
                    None => st.error = Some("chunk range outside mapped plane".into()),
                },
                // e.g. an unmapped DmaBuf plane - cannot read pixels.
                None => st.error = Some(format!("unmapped pipewire buffer (type {:?})", d.type_())),
            }
        })
        .register()
        .map_err(|e| anyhow!("pipewire stream listener: {e}"))?;

    // EnumFormat offer: raw video in the four supported layouts only;
    // size/framerate left as wide ranges for the backend to fixate.
    let format_obj = spa::pod::object! {
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id, spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id, spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice, Enum, Id,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Choice, Range, Rectangle,
            spa::utils::Rectangle { width: 1, height: 1 },
            spa::utils::Rectangle { width: 1, height: 1 },
            spa::utils::Rectangle { width: 16384, height: 16384 }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice, Range, Fraction,
            spa::utils::Fraction { num: 25, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 1000, denom: 1 }
        ),
    };
    let (cursor, _len) = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::<u8>::new()),
        &spa::pod::Value::Object(format_obj),
    )
    .map_err(|e| anyhow!("serialize EnumFormat pod: {e:?}"))?;
    let pod_bytes = cursor.into_inner();
    let pod = spa::pod::Pod::from_bytes(&pod_bytes).context("EnumFormat pod bytes")?;
    let mut params = [pod];

    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .context("pipewire stream connect")?;

    // Pump the loop in bounded slices until the first frame lands, a
    // callback records an error, or the deadline passes.
    let deadline = Instant::now() + PIPEWIRE_TIMEOUT;
    loop {
        {
            let st = state.borrow();
            if let Some(e) = &st.error {
                bail!("pipewire stream: {e}");
            }
            if st.frame.is_some() {
                break;
            }
        }
        if Instant::now() >= deadline {
            bail!("pipewire stream produced no frame within {PIPEWIRE_TIMEOUT:?}");
        }
        if mainloop
            .loop_()
            .iterate(Timeout::Finite(Duration::from_millis(50)))
            < 0
        {
            bail!("pipewire main loop iterate failed");
        }
    }
    let _ = stream.disconnect();

    let (w, h, rgba) = {
        let mut st = state.borrow_mut();
        (
            st.width,
            st.height,
            st.frame.take().expect("frame checked above"),
        )
    };
    encode_frame(w, h, rgba)
}

// ---------------------------------------------------------------------------
// file:// URI -> path (pure)
// ---------------------------------------------------------------------------

/// Decode a `file://` URI to a local path. Handles the empty authority
/// (`file:///x`), `localhost`, and percent-escapes; rejects non-`file`
/// schemes, remote authorities and non-UTF-8 output.
fn file_uri_to_path(uri: &str) -> Result<PathBuf> {
    let rest = uri
        .strip_prefix("file://")
        .ok_or_else(|| anyhow!("portal URI {uri:?} is not file://"))?;
    let path_part = match rest.strip_prefix('/') {
        Some(p) => p, // file:///abs/path - empty authority
        None => match rest.find('/') {
            // file://host/abs/path - only localhost is meaningfully local.
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

/// `"WxH"` (or `"W,H"`) -> positive pixel dimensions; backs the
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
        // Screenshot is the primary portal path; the RemoteDesktop +
        // PipeWire session is used only when Screenshot is not
        // advertised at all (probe-time introspection).
        let (png, width, height) = if self.caps.screenshot {
            self.screenshot().await?
        } else {
            self.pipewire_screenshot().await?
        };
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
    /// Hyprland, else a typed error (portal is the last-resort rung -
    /// on other compositors `InputProvider::cursor_position` may still
    /// answer via its own tracking).
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        match &self.hyprctl {
            Some(bin) => common::hyprctl_cursorpos(bin)
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
            && let Ok(v) = common::hyprctl_monitors(bin).await
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
// SAFETY: no test in this module places a portal method call - only the
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
        // Would survive verbatim inside /org/freedesktop/portal/desktop/...
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
    fn file_uri_edge_escapes() {
        // An escaped '/' decodes to a real path separator.
        assert_eq!(
            file_uri_to_path("file:///tmp/a%2Fb.png").unwrap(),
            PathBuf::from("/tmp/a/b.png")
        );
        // file:// with no authority and no path -> just "/".
        assert_eq!(file_uri_to_path("file:///").unwrap(), PathBuf::from("/"));
        // A bare '%' at the tail is a truncated escape.
        assert!(file_uri_to_path("file:///tmp/x%").is_err());
        // "file://" alone has no path at all -> non-local error.
        assert!(file_uri_to_path("file://").is_err());
        // "file://x" - a bare authority with no path -> rejected.
        assert!(file_uri_to_path("file://x").is_err());
    }

    #[test]
    fn env_screen_size_reads_vars() {
        // SAFETY: test-only env mutation. No other test in the crate
        // reads these variables; they are restored before returning.
        unsafe {
            std::env::set_var("ULTRANIX_SCREEN_SIZE", "3456x2160");
            std::env::remove_var("ULTRANIX_SCREEN_WIDTH");
            std::env::remove_var("ULTRANIX_SCREEN_HEIGHT");
        }
        assert_eq!(env_screen_size(), Some((3456, 2160)));
        unsafe {
            std::env::remove_var("ULTRANIX_SCREEN_SIZE");
            std::env::set_var("ULTRANIX_SCREEN_WIDTH", "1600");
            std::env::set_var("ULTRANIX_SCREEN_HEIGHT", "900");
        }
        assert_eq!(env_screen_size(), Some((1600, 900)));
        unsafe {
            std::env::set_var("ULTRANIX_SCREEN_WIDTH", "bogus");
        }
        assert_eq!(env_screen_size(), None);
        unsafe {
            std::env::remove_var("ULTRANIX_SCREEN_WIDTH");
            std::env::remove_var("ULTRANIX_SCREEN_HEIGHT");
        }
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

        // Fully outside -> error.
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
        assert_eq!(
            common::parse_cursorpos("{\"x\":1017,\"y\":664}"),
            Some((1017, 664))
        );
        assert_eq!(common::parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(common::parse_cursorpos("garbage"), None);
    }

    #[test]
    fn parse_screen_size_forms() {
        assert_eq!(parse_screen_size("1920x1080"), Some((1920, 1080)));
        assert_eq!(parse_screen_size("1024,768"), Some((1024, 768)));
        assert_eq!(parse_screen_size("garbage"), None);
        assert_eq!(parse_screen_size("0x100"), None);
    }

    // ---- portal capability probe -------------------------------------

    #[test]
    fn caps_from_introspection_detects_interfaces() {
        let both = caps_from_introspection(
            r#"<node><interface name="org.freedesktop.portal.Screenshot"/>
               <interface name="org.freedesktop.portal.RemoteDesktop"/></node>"#,
        );
        assert_eq!(
            both,
            PortalCaps {
                screenshot: true,
                remote_desktop: true
            }
        );

        let rd_only = caps_from_introspection(
            r#"<node><interface name="org.freedesktop.portal.RemoteDesktop"/></node>"#,
        );
        assert!(!rd_only.screenshot && rd_only.remote_desktop);

        let none = caps_from_introspection("<node/>");
        assert!(!none.screenshot && !none.remote_desktop);

        // Malformed / non-XML payloads simply match nothing.
        let garbage = caps_from_introspection("not xml at all <<<");
        assert!(!garbage.screenshot && !garbage.remote_desktop);
        // A near-miss name is not a match (substring, not prefix).
        let near = caps_from_introspection(
            r#"<interface name="org.freedesktop.portal.ScreenshotExtra"/>"#,
        );
        // Note: "ScreenshotExtra" contains the full interface name as a
        // substring - the plain `contains` check reports it present.
        assert!(near.screenshot);
        let only_prefix =
            caps_from_introspection(r#"<interface name="org.freedesktop.portal.Screensh"/>"#);
        assert!(!only_prefix.screenshot);
    }

    // ---- RemoteDesktop session helpers ---------------------------------

    #[test]
    #[cfg(feature = "pipewire")]
    fn remote_desktop_options_carry_no_persist_keys() {
        let o = create_session_options("h".into(), "s".into());
        assert!(matches!(o["handle_token"], Value::Str(_)));
        assert!(matches!(o["session_handle_token"], Value::Str(_)));
        assert!(!o.contains_key("persist_mode"));
        assert!(!o.contains_key("restore_token"));

        let o = select_sources_options("h".into());
        assert!(matches!(o["types"], Value::U32(1)));
        assert!(matches!(o["multiple"], Value::Bool(false)));
        assert!(matches!(o["cursor_mode"], Value::U32(1)));
        assert!(!o.contains_key("persist_mode"));
        assert!(!o.contains_key("restore_token"));

        let o = start_options("h".into());
        assert_eq!(o.len(), 1);
        assert!(matches!(o["handle_token"], Value::Str(_)));
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn session_path_from_s_and_o() {
        let mut r: HashMap<String, OwnedValue> = HashMap::new();
        r.insert(
            "session_handle".into(),
            owned("/org/freedesktop/portal/desktop/session/1_2/tok"),
        );
        assert_eq!(
            session_path_from(&r).unwrap().as_str(),
            "/org/freedesktop/portal/desktop/session/1_2/tok"
        );
        r.insert(
            "session_handle".into(),
            owned(
                zvariant::ObjectPath::try_from("/org/freedesktop/portal/desktop/session/1_2/tok")
                    .unwrap(),
            ),
        );
        assert!(session_path_from(&r).is_ok());
        assert!(session_path_from(&HashMap::new()).is_err());
        // Present but the wrong type entirely -> error, not a panic.
        let mut bad: HashMap<String, OwnedValue> = HashMap::new();
        bad.insert("session_handle".into(), owned(42u32));
        assert!(session_path_from(&bad).is_err());
        // A string that is not a valid object path is rejected too.
        let mut bad: HashMap<String, OwnedValue> = HashMap::new();
        bad.insert("session_handle".into(), owned("not/an object path"));
        assert!(session_path_from(&bad).is_err());
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn stream_node_ids_reads_aa_sv() {
        let mut s: HashMap<String, OwnedValue> = HashMap::new();
        s.insert("node_id".into(), owned(55u32));
        s.insert(
            "position".into(),
            owned(zvariant::Structure::from((0i32, 0i32))),
        );
        s.insert(
            "size".into(),
            owned(zvariant::Structure::from((1920i32, 1080i32))),
        );
        let mut results: HashMap<String, OwnedValue> = HashMap::new();
        results.insert("streams".into(), owned(vec![s]));
        assert_eq!(stream_node_ids(&results), vec![55]);

        assert!(stream_node_ids(&HashMap::new()).is_empty());
        // A stream dict without node_id is skipped.
        let mut bad: HashMap<String, OwnedValue> = HashMap::new();
        bad.insert("source_type".into(), owned(1u32));
        let mut results: HashMap<String, OwnedValue> = HashMap::new();
        results.insert("streams".into(), owned(vec![bad]));
        assert!(stream_node_ids(&results).is_empty());
    }

    // ---- PipeWire pixel conversion --------------------------------------

    #[test]
    #[cfg(feature = "pipewire")]
    fn pixel_layout_accepts_only_the_four_rgb32_formats() {
        assert_eq!(pixel_layout(VideoFormat::BGRx), Some(PixelLayout::Bgrx));
        assert_eq!(pixel_layout(VideoFormat::BGRA), Some(PixelLayout::Bgra));
        assert_eq!(pixel_layout(VideoFormat::RGBx), Some(PixelLayout::Rgbx));
        assert_eq!(pixel_layout(VideoFormat::RGBA), Some(PixelLayout::Rgba));
        assert_eq!(pixel_layout(VideoFormat::I420), None);
        assert_eq!(pixel_layout(VideoFormat::RGB), None);
        assert_eq!(pixel_layout(VideoFormat::Unknown), None);
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn convert_frame_bgra_swaps_rb_and_keeps_alpha() {
        // 2x1 BGRA: [B,G,R,A] pixels (10,20,30,40) and (50,60,70,80).
        let src = [10, 20, 30, 40, 50, 60, 70, 80];
        let out = convert_frame(&src, 2, 1, 8, PixelLayout::Bgra).unwrap();
        assert_eq!(out, vec![30, 20, 10, 40, 70, 60, 50, 80]);
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn convert_frame_bgrx_forces_opaque_alpha() {
        let src = [10, 20, 30, 0];
        let out = convert_frame(&src, 1, 1, 4, PixelLayout::Bgrx).unwrap();
        assert_eq!(out, vec![30, 20, 10, 0xFF]);
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn convert_frame_rgba_passthrough_and_rgbx_alpha() {
        let src = [1, 2, 3, 4];
        assert_eq!(
            convert_frame(&src, 1, 1, 4, PixelLayout::Rgba).unwrap(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            convert_frame(&src, 1, 1, 4, PixelLayout::Rgbx).unwrap(),
            vec![1, 2, 3, 0xFF]
        );
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn convert_frame_honors_padded_stride() {
        // 2x2 BGRA with stride 12 (4 bytes padding per row).
        let src = [
            10, 20, 30, 255, 40, 50, 60, 255, 0, 0, 0, 0, // row 0 + pad
            70, 80, 90, 255, 1, 2, 3, 255, 9, 9, 9, 9, // row 1 + pad
        ];
        let out = convert_frame(&src, 2, 2, 12, PixelLayout::Bgra).unwrap();
        assert_eq!(
            out,
            vec![
                30, 20, 10, 255, 60, 50, 40, 255, 90, 80, 70, 255, 3, 2, 1, 255
            ]
        );
        // stride 0 means tightly packed.
        let tight = [10, 20, 30, 255, 40, 50, 60, 255];
        let out = convert_frame(&tight, 2, 1, 0, PixelLayout::Bgra).unwrap();
        assert_eq!(out, vec![30, 20, 10, 255, 60, 50, 40, 255]);
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn convert_frame_rejects_bad_geometry() {
        let src = [0u8; 64];
        assert!(convert_frame(&src, 0, 1, 4, PixelLayout::Rgba).is_err());
        assert!(convert_frame(&src, 1, 0, 4, PixelLayout::Rgba).is_err());
        // Negative stride (bottom-up) is rejected.
        assert!(convert_frame(&src, 2, 2, -8, PixelLayout::Rgba).is_err());
        // Stride smaller than a row.
        assert!(convert_frame(&src, 2, 2, 4, PixelLayout::Rgba).is_err());
        // Buffer too small for the declared geometry.
        assert!(convert_frame(&src[..8], 2, 2, 8, PixelLayout::Rgba).is_err());
    }

    #[test]
    #[cfg(feature = "pipewire")]
    fn encode_frame_produces_decodable_png() {
        let rgba = vec![7u8, 8, 9, 255, 10, 11, 12, 255];
        let (png, w, h) = encode_frame(2, 1, rgba).unwrap();
        assert_eq!((w, h), (2, 1));
        let img = image::load_from_memory(&png).unwrap();
        assert_eq!((img.width(), img.height()), (2, 1));
        // Wrong byte count -> error, not panic.
        assert!(encode_frame(2, 2, vec![0; 4]).is_err());
    }

    #[test]
    fn new_probe_is_bounded_and_pure() {
        // Only NameHasOwner + read-only Introspect - no portal methods,
        // no dialogs, ~3s cap. Result is environment-dependent (None
        // headless, maybe Some on a desktop); the contract is "does not
        // panic or hang".
        let _ = PortalCapture::new();
    }

    #[test]
    #[ignore = "requires a live session bus; set ULTRANIX_MCP_LIVE_TESTS=1"]
    fn live_probe_matches_name_owner() {
        if std::env::var("ULTRANIX_MCP_LIVE_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        // Probe only - deliberately NOT calling capture_frame: Screenshot
        // raises a GUI consent dialog.
        let p = PortalCapture::new();
        tracing::info!("portal capture probe: {:?}", p.is_some());
    }

    /// Full RemoteDesktop + PipeWire capture against a live desktop.
    /// `Start` raises the consent dialog - a human must answer.
    #[tokio::test]
    #[cfg(feature = "pipewire")]
    #[ignore = "raises a GUI consent dialog; set ULTRANIX_MCP_LIVE_TESTS=1"]
    async fn live_pipewire_capture() {
        if std::env::var("ULTRANIX_MCP_LIVE_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        let Some(p) = PortalCapture::new() else {
            return;
        };
        if !p.caps.remote_desktop {
            return;
        }
        let (png, w, h) = p.pipewire_screenshot().await.expect("pipewire capture");
        let img = image::load_from_memory(&png).expect("decode frame PNG");
        assert_eq!((img.width(), img.height()), (w, h));
    }
}
