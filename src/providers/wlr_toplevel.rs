//! Window management via `zwlr_foreign_toplevel_manager_v1`
//! (wlr-foreign-toplevel-management-unstable-v1) - in-process, no external
//! binaries.
//!
//! One protocol covers every wlroots-family compositor: river and Wayfire
//! (whose native IPC is narrower or optional), plus niri/labwc/other
//! wlroots sessions that have no compositor IPC at all. Hyprland and sway
//! keep their richer native rungs first; this is the shared fallback.
//!
//! Stateless like `wlr_capture`: every call opens a short-lived Wayland
//! connection - the manager re-emits every toplevel on bind, so one
//! roundtrip yields a complete snapshot. Handles are per-connection, so
//! [`WindowInfo::id`] is a synthetic `wlr-toplevel-<index>` valid for the
//! duration of a snapshot; `dispatch` re-enumerates and resolves the index
//! (verified against app_id/title when the caller supplies them).
//!
//! The protocol exposes no geometry or workspace data - `rect` is zeroed
//! and `workspace`/`monitor`/`pid`/`floating` report `None`/`-1` honestly.
//! Dispatch covers `focus` (`activate`), `close`, `minimize`/`unminimize`,
//! `maximize`/`unmaximize`, `fullscreen`/`unfullscreen`; `move`/`resize`
//! fail with an honest error (no geometry verbs exist).

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;
use wayland_client::backend::ObjectId;
use wayland_client::protocol::{wl_registry, wl_seat::WlSeat};
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle, delegate_noop};
use wayland_client::{Proxy, event_created_child};
use wayland_protocols_wlr::foreign_toplevel::v1::client::{
    zwlr_foreign_toplevel_handle_v1::{self, ZwlrForeignToplevelHandleV1},
    zwlr_foreign_toplevel_manager_v1::{self, ZwlrForeignToplevelManagerV1},
};

use crate::traits::{Rect, WindowInfo, WindowProvider};

/// Selector token addressing the focused view - matches the `"focused"`
/// convention used by `window_control`'s focused-view path.
pub const FOCUSED_SELECTOR: &str = "focused";

/// Shared state for one short-lived connection's enumeration.
#[derive(Default)]
struct State {
    manager: Option<ZwlrForeignToplevelManagerV1>,
    seat: Option<WlSeat>,
    /// Insertion-ordered toplevels; the position becomes the synthetic
    /// `wlr-toplevel-<index>` id in snapshots.
    windows: Vec<Tracked>,
    /// `handle.id()` -> position in `windows` (handles arrive via events,
    /// so an id map replaces per-object udata plumbing).
    by_id: HashMap<ObjectId, usize>,
}

struct Tracked {
    handle: ZwlrForeignToplevelHandleV1,
    title: String,
    app_id: String,
    activated: bool,
    maximized: bool,
    minimized: bool,
    fullscreen: bool,
    closed: bool,
}

impl Tracked {
    fn new(handle: ZwlrForeignToplevelHandleV1) -> Self {
        Self {
            handle,
            title: String::new(),
            app_id: String::new(),
            activated: false,
            maximized: false,
            minimized: false,
            fullscreen: false,
            closed: false,
        }
    }
}

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match interface.as_str() {
                "zwlr_foreign_toplevel_manager_v1" => {
                    state.manager = Some(registry.bind(name, version.min(3), qh, ()));
                }
                "wl_seat" if state.seat.is_none() => {
                    state.seat = Some(registry.bind(name, version.min(1), qh, ()));
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<ZwlrForeignToplevelManagerV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwlrForeignToplevelManagerV1,
        event: zwlr_foreign_toplevel_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let zwlr_foreign_toplevel_manager_v1::Event::Toplevel { toplevel } = event {
            state.by_id.insert(toplevel.id(), state.windows.len());
            state.windows.push(Tracked::new(toplevel));
        }
    }

    // `toplevel` events create handle objects - give them `()` udata to
    // match `Dispatch<ZwlrForeignToplevelHandleV1, ()>` below.
    event_created_child!(State, ZwlrForeignToplevelManagerV1, [
        zwlr_foreign_toplevel_manager_v1::EVT_TOPLEVEL_OPCODE => (ZwlrForeignToplevelHandleV1, ())
    ]);
}

impl Dispatch<ZwlrForeignToplevelHandleV1, ()> for State {
    fn event(
        state: &mut Self,
        handle: &ZwlrForeignToplevelHandleV1,
        event: zwlr_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use zwlr_foreign_toplevel_handle_v1::Event;
        let Some(&idx) = state.by_id.get(&handle.id()) else {
            return;
        };
        let tracked = &mut state.windows[idx];
        match event {
            Event::Title { title } => tracked.title = title,
            Event::AppId { app_id } => tracked.app_id = app_id,
            // `state` is a raw wl_array (no enum attr in the XML) - u32
            // state values packed little-endian. See the protocol's
            // `enum state`: 0 max, 1 min, 2 activated, 3 fullscreen.
            Event::State { state: flags } => {
                let has = |v: u32| {
                    flags
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .any(|c| u32::from_ne_bytes(*c) == v)
                };
                tracked.maximized = has(0);
                tracked.minimized = has(1);
                tracked.activated = has(2);
                tracked.fullscreen = has(3);
            }
            Event::Closed => tracked.closed = true,
            _ => {}
        }
    }
}

delegate_noop!(State: ignore WlSeat);

/// Connection + queue + drained state. Two roundtrips: the first collects
/// globals (our `get_registry` reply), the second flushes the `bind`s and
/// collects the manager's toplevel burst + per-handle `done` events.
fn collect() -> Result<(Connection, EventQueue<State>, State)> {
    let conn = Connection::connect_to_env().context("wayland connect")?;
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let display = conn.display();
    let mut state = State::default();
    display.get_registry(&qh, ());
    queue.roundtrip(&mut state).context("registry roundtrip")?;
    if state.manager.is_none() {
        bail!("compositor does not advertise zwlr_foreign_toplevel_manager_v1");
    }
    queue.roundtrip(&mut state).context("toplevel roundtrip")?;
    Ok((conn, queue, state))
}

/// Probe: does the compositor advertise the manager?
pub fn probe() -> Result<()> {
    std::env::var_os("WAYLAND_DISPLAY").context("WAYLAND_DISPLAY unset")?;
    collect().map(|_| ())
}

/// One enumeration pass -> `WindowInfo` records in compositor order.
pub fn enumerate() -> Result<Vec<WindowInfo>> {
    let (_conn, _queue, state) = collect()?;
    Ok(state
        .windows
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.closed)
        .map(|(i, t)| WindowInfo {
            id: format!("wlr-toplevel-{i}"),
            title: t.title.clone(),
            class: t.app_id.clone(),
            workspace: -1,
            rect: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            focused: t.activated,
            floating: None,
            fullscreen: Some(t.fullscreen),
            pid: None,
            monitor: None,
        })
        .collect())
}

/// Resolve a selector to a tracked handle position. `"focused"` picks the
/// activated toplevel; `wlr-toplevel-N` picks by enumeration index (with
/// an optional app_id/title sanity check against the earlier snapshot).
fn resolve(state: &mut State, selector: &str, args: &Value) -> Result<usize> {
    if selector == FOCUSED_SELECTOR {
        return state
            .windows
            .iter()
            .position(|t| t.activated && !t.closed)
            .ok_or_else(|| anyhow!("no activated toplevel"));
    }
    let idx: usize = selector
        .strip_prefix("wlr-toplevel-")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| {
            anyhow!("unsupported selector `{selector}` (expected `wlr-toplevel-N` or `focused`)")
        })?;
    let tracked = state
        .windows
        .get(idx)
        .filter(|t| !t.closed)
        .ok_or_else(|| anyhow!("no toplevel at index {idx}"))?;
    // The index came from an earlier snapshot - verify it still names the
    // same window before acting on it (handles reorder as windows open).
    if let Some(title) = args.get("expect_title").and_then(Value::as_str)
        && tracked.title != title
    {
        bail!(
            "toplevel {idx} title mismatch (expected `{title}`, saw `{}`)",
            tracked.title
        );
    }
    if let Some(app_id) = args.get("expect_class").and_then(Value::as_str)
        && tracked.app_id != app_id
    {
        bail!(
            "toplevel {idx} app_id mismatch (expected `{app_id}`, saw `{}`)",
            tracked.app_id
        );
    }
    Ok(idx)
}

/// One dispatch pass: enumerate, resolve `selector`, send `action`, then
/// roundtrip so the request actually reaches the compositor before the
/// connection drops. `move`/`resize` are honest errors - the protocol
/// carries no geometry verbs.
pub fn dispatch_op(action: &str, selector: &str, args: &Value) -> Result<()> {
    let (_conn, mut queue, mut state) = collect()?;
    let seat = state.seat.clone();
    let idx = resolve(&mut state, selector, args)?;
    let tracked = &state.windows[idx];
    match action {
        "focus" => {
            let seat = seat.context("compositor advertised no wl_seat")?;
            tracked.handle.activate(&seat);
        }
        "close" => tracked.handle.close(),
        "minimize" => tracked.handle.set_minimized(),
        "unminimize" => tracked.handle.unset_minimized(),
        "maximize" => tracked.handle.set_maximized(),
        "unmaximize" => tracked.handle.unset_maximized(),
        "fullscreen" => tracked.handle.set_fullscreen(None),
        "unfullscreen" => tracked.handle.unset_fullscreen(),
        other => bail!("wlr-foreign-toplevel cannot `{other}` (no geometry ops in protocol)"),
    }
    queue.roundtrip(&mut state).context("dispatch roundtrip")?;
    Ok(())
}

/// wlroots foreign-toplevel window provider - the shared fallback rung
/// for compositors without richer native IPC.
pub struct WlrToplevelWindow {
    _private: (),
}

impl WlrToplevelWindow {
    /// Usable only when the session is Wayland and the compositor
    /// advertises `zwlr_foreign_toplevel_manager_v1`.
    pub fn new() -> Option<Self> {
        probe().ok()?;
        Some(Self { _private: () })
    }
}

#[async_trait]
impl WindowProvider for WlrToplevelWindow {
    async fn list_windows(&self) -> Result<Vec<WindowInfo>> {
        tokio::task::spawn_blocking(enumerate).await?
    }

    async fn active_window(&self) -> Result<Option<WindowInfo>> {
        let windows = tokio::task::spawn_blocking(enumerate).await??;
        Ok(windows.into_iter().find(|w| w.focused))
    }

    async fn dispatch(&self, action: &str, window_id: &str, args: &Value) -> Result<()> {
        let action = action.to_string();
        let window_id = window_id.to_string();
        let args = args.clone();
        tokio::task::spawn_blocking(move || dispatch_op(&action, &window_id, &args)).await?
    }

    /// `"focused"` resolves to the activated toplevel - every wlroots
    /// compositor reports `activated`, so the selector works universally.
    fn focused_view_selector(&self) -> Option<&'static str> {
        Some(FOCUSED_SELECTOR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live smoke against the running compositor - `cargo test -- --ignored`.
    /// Exercises real enumeration + focused selector on whatever wlroots
    /// session the test inherits.
    #[test]
    #[ignore = "needs a live wlroots Wayland session"]
    fn live_enumerate_and_focused_dispatch() {
        let windows = enumerate().expect("enumerate on live session");
        assert!(!windows.is_empty(), "expected at least one toplevel");
        assert!(
            windows.iter().any(|w| w.focused),
            "expected an activated toplevel"
        );
        // focus on the focused view is a harmless roundtrip.
        dispatch_op("focus", FOCUSED_SELECTOR, &Value::Null).expect("activate focused");
        // A bogus index must error, never act.
        assert!(dispatch_op("focus", "wlr-toplevel-999", &Value::Null).is_err());
        assert!(dispatch_op("explode", FOCUSED_SELECTOR, &Value::Null).is_err());
    }
}
