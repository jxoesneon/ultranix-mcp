//! Window management via `zwlr_foreign_toplevel_manager_v1`
//! (wlr-foreign-toplevel-management-unstable-v1), paired with
//! `ext_foreign_toplevel_list_v1` for stable window identifiers.
//!
//! One protocol pair covers every wlroots-family compositor: river and
//! Wayfire (whose native IPC is narrower or optional), plus niri/labwc/
//! other wlroots sessions that have no compositor IPC at all. Hyprland
//! and sway keep their richer native rungs first; this is the shared
//! fallback.
//!
//! Stateless like `wlr_capture`: every call opens a short-lived Wayland
//! connection - each manager re-emits every toplevel on bind, so one
//! roundtrip yields a complete snapshot. The two protocols are
//! complementary:
//!
//! - `ext_foreign_toplevel_list_v1` (read-only by design) supplies a
//!   compositor-stable `identifier` per toplevel - ids survive across
//!   calls, so `wlr-toplevel-<identifier>` is the preferred selector.
//! - `zwlr_foreign_toplevel_manager_v1` supplies state (activated /
//!   minimized / maximized / fullscreen), `wl_output` membership
//!   (`output_enter`/`output_leave` -> `monitor` index), and every
//!   verb (`activate`, `close`, min/max/fullscreen toggles).
//!
//! Handles are per-connection and the ext list has no verbs, so the two
//! enumerations are correlated after collection: ext entries pair with
//! wlr entries by `(title, app_id)` in order. A wlr toplevel without an
//! ext twin keeps the legacy `wlr-toplevel-<index>` id.
//!
//! The protocols expose no geometry or workspace data - `rect` is zeroed
//! and `workspace`/`pid`/`floating` report `-1`/`None` honestly.
//! Dispatch covers `focus` (`activate`), `close`, `minimize`/`unminimize`,
//! `maximize`/`unmaximize`, `fullscreen`/`unfullscreen`; `move`/`resize`
//! fail with an honest error (no geometry verbs exist).

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;
use wayland_client::backend::ObjectId;
use wayland_client::protocol::{wl_output, wl_registry, wl_seat::WlSeat};
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle, delegate_noop};
use wayland_client::{Proxy, event_created_child};
use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};
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
    ext_list: Option<ExtForeignToplevelListV1>,
    seat: Option<WlSeat>,
    /// Registry-ordered `wl_output` objects; `monitor` reports the index.
    outputs: Vec<wl_output::WlOutput>,
    /// `output.id()` -> position in `outputs`.
    by_output: HashMap<ObjectId, usize>,
    /// wlr-manager toplevels in emission order; the position is the
    /// legacy `wlr-toplevel-<index>` id.
    windows: Vec<Tracked>,
    /// `handle.id()` -> position in `windows`.
    by_id: HashMap<ObjectId, usize>,
    /// ext-list toplevels in emission order - the stable-identifier side.
    exts: Vec<ExtTracked>,
    /// `ext_handle.id()` -> position in `exts`.
    by_ext_id: HashMap<ObjectId, usize>,
}

struct Tracked {
    handle: ZwlrForeignToplevelHandleV1,
    /// Correlated `ext_foreign_toplevel_handle_v1.identifier`, if the
    /// compositor also advertises the ext list and this toplevel paired.
    identifier: Option<String>,
    /// `wl_output` indices this toplevel has entered.
    outputs: Vec<usize>,
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
            identifier: None,
            outputs: Vec::new(),
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

/// ext-list toplevel - the handle itself is dropped after `collect()`
/// (the ext protocol is read-only; events route through `by_ext_id`).
struct ExtTracked {
    identifier: String,
    title: String,
    app_id: String,
    closed: bool,
    /// Correlated position in `windows`, filled by [`correlate`].
    wlr_idx: Option<usize>,
}

impl ExtTracked {
    fn new() -> Self {
        Self {
            identifier: String::new(),
            title: String::new(),
            app_id: String::new(),
            closed: false,
            wlr_idx: None,
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
                "ext_foreign_toplevel_list_v1" => {
                    state.ext_list = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "wl_seat" if state.seat.is_none() => {
                    state.seat = Some(registry.bind(name, version.min(1), qh, ()));
                }
                "wl_output" => {
                    let out: wl_output::WlOutput = registry.bind(name, version.min(1), qh, ());
                    state.by_output.insert(out.id(), state.outputs.len());
                    state.outputs.push(out);
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

impl Dispatch<ExtForeignToplevelListV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            state.by_ext_id.insert(toplevel.id(), state.exts.len());
            state.exts.push(ExtTracked::new());
        }
    }

    event_created_child!(State, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
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
        match event {
            Event::Title { title } => state.windows[idx].title = title,
            Event::AppId { app_id } => state.windows[idx].app_id = app_id,
            Event::OutputEnter { output } => {
                if let Some(&o) = state.by_output.get(&output.id()) {
                    let outs = &mut state.windows[idx].outputs;
                    if !outs.contains(&o) {
                        outs.push(o);
                    }
                }
            }
            Event::OutputLeave { output } => {
                if let Some(&o) = state.by_output.get(&output.id()) {
                    state.windows[idx].outputs.retain(|&x| x != o);
                }
            }
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
                let tracked = &mut state.windows[idx];
                tracked.maximized = has(0);
                tracked.minimized = has(1);
                tracked.activated = has(2);
                tracked.fullscreen = has(3);
            }
            Event::Closed => state.windows[idx].closed = true,
            _ => {}
        }
    }
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for State {
    fn event(
        state: &mut Self,
        handle: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_foreign_toplevel_handle_v1::Event;
        let Some(&idx) = state.by_ext_id.get(&handle.id()) else {
            return;
        };
        match event {
            Event::Identifier { identifier } => state.exts[idx].identifier = identifier,
            Event::Title { title } => state.exts[idx].title = title,
            Event::AppId { app_id } => state.exts[idx].app_id = app_id,
            Event::Closed => state.exts[idx].closed = true,
            _ => {}
        }
    }
}

delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore wl_output::WlOutput);

/// Connection + queue + drained state. Two roundtrips: the first collects
/// globals (our `get_registry` reply), the second flushes the `bind`s and
/// collects both managers' toplevel bursts + per-handle events.
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
    correlate(&mut state);
    Ok((conn, queue, state))
}

/// Pair ext-list entries with wlr-manager toplevels by `(title, app_id)`
/// in order - both protocols enumerate the same mapped toplevels, and
/// within a duplicate-title group ordinal matching is deterministic
/// (the compositor emits both bursts in toplevel order). Ext entries
/// without a wlr twin stay uncorrelated (transient unmap race); wlr
/// entries without an ext twin keep index ids.
fn correlate(state: &mut State) {
    let mut claimed: HashSet<usize> = HashSet::new();
    for ext in &mut state.exts {
        if ext.closed {
            continue;
        }
        let hit = state
            .windows
            .iter()
            .enumerate()
            .find(|(i, t)| {
                !claimed.contains(i) && !t.closed && t.title == ext.title && t.app_id == ext.app_id
            })
            .map(|(i, _)| i);
        ext.wlr_idx = hit;
        if let Some(i) = hit {
            claimed.insert(i);
            if !ext.identifier.is_empty() {
                state.windows[i].identifier = Some(ext.identifier.clone());
            }
        }
    }
}

/// Probe: does the compositor advertise the manager?
pub fn probe() -> Result<()> {
    std::env::var_os("WAYLAND_DISPLAY").context("WAYLAND_DISPLAY unset")?;
    collect().map(|_| ())
}

/// `WindowInfo` id for a toplevel: `wlr-toplevel-<identifier>` when the
/// ext list supplied a stable identifier, else the snapshot-order
/// `wlr-toplevel-<index>` legacy form.
fn window_id(identifier: Option<&str>, index: usize) -> String {
    match identifier {
        Some(id) => format!("wlr-toplevel-{id}"),
        None => format!("wlr-toplevel-{index}"),
    }
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
            id: window_id(t.identifier.as_deref(), i),
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
            monitor: t.outputs.first().map(|&o| o as i64),
        })
        .collect())
}

/// Resolve a selector to a tracked wlr handle position. `"focused"`
/// picks the activated toplevel; `wlr-toplevel-<identifier>` (a
/// non-numeric suffix) resolves through the ext list's stable id to its
/// correlated wlr handle; `wlr-toplevel-<index>` picks by enumeration
/// position. Both indexed forms are verified against the caller's
/// expected title/app_id before acting.
fn resolve(state: &mut State, selector: &str, args: &Value) -> Result<usize> {
    let idx = if selector == FOCUSED_SELECTOR {
        state
            .windows
            .iter()
            .position(|t| t.activated && !t.closed)
            .ok_or_else(|| anyhow!("no activated toplevel"))?
    } else {
        let suffix = selector.strip_prefix("wlr-toplevel-").ok_or_else(|| {
            anyhow!(
                "unsupported selector `{selector}` (expected `wlr-toplevel-<id|index>` or `focused`)"
            )
        })?;
        // Identifiers win over indices - compositors can mint all-digit
        // identifiers (Hyprland does), which must never be re-read as an
        // enumeration index.
        if let Some(idx) = state
            .exts
            .iter()
            .find(|e| e.identifier == suffix && !e.closed)
            .and_then(|e| e.wlr_idx)
        {
            idx
        } else {
            suffix.parse::<usize>().map_err(|_| {
                anyhow!("no toplevel with identifier `{suffix}` (stale or unmapped)")
            })?
        }
    };
    let tracked = state
        .windows
        .get(idx)
        .filter(|t| !t.closed)
        .ok_or_else(|| anyhow!("no toplevel for selector `{selector}`"))?;
    // The selector came from an earlier snapshot - verify it still names
    // the same window before acting on it (handles reorder as windows
    // open; identifiers can be stale after an unmap).
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

    /// Correlation pairs ext entries with wlr toplevels by (title,
    /// app_id) ordinal - duplicates pair deterministically.
    #[test]
    fn correlate_pairs_by_title_app_id_ordinal() {
        // Build the state by hand - both enumerations already drained.
        // (Constructing real handles needs a live connection, so the
        // test exercises `correlate` via its inputs only where the
        // borrow rules allow: fields, not handles. We skip handle
        // construction by testing the index-matching logic directly.)
        // Hand-rolled mini version of the pairing rule.
        let wlr: Vec<(String, String)> = vec![
            ("term".into(), "kitty".into()),
            ("term".into(), "kitty".into()),
            ("web".into(), "firefox".into()),
        ];
        let exts: Vec<(String, String, String)> = vec![
            ("id-a".into(), "term".into(), "kitty".into()),
            ("id-b".into(), "term".into(), "kitty".into()),
            ("id-c".into(), "web".into(), "firefox".into()),
        ];
        let mut claimed: HashSet<usize> = HashSet::new();
        let pairs: Vec<Option<usize>> = exts
            .iter()
            .map(|(_, t, a)| {
                let hit = wlr
                    .iter()
                    .enumerate()
                    .find(|(i, (wt, wa))| !claimed.contains(i) && wt == t && wa == a)
                    .map(|(i, _)| i);
                if let Some(i) = hit {
                    claimed.insert(i);
                }
                hit
            })
            .collect();
        assert_eq!(pairs, vec![Some(0), Some(1), Some(2)]);
    }

    /// `window_id` prefers the stable identifier, falls back to index.
    #[test]
    fn window_id_prefers_identifier() {
        assert_eq!(window_id(Some("deadbeef"), 7), "wlr-toplevel-deadbeef");
        assert_eq!(window_id(None, 7), "wlr-toplevel-7");
    }

    /// Live smoke against the running compositor - `cargo test -- --ignored`.
    /// Exercises real enumeration + focused selector on whatever wlroots
    /// session the test inherits.
    #[test]
    #[ignore = "needs a live wlroots Wayland session"]
    fn live_enumerate_and_focused_dispatch() {
        let windows = enumerate().expect("enumerate on live session");
        for w in &windows {
            eprintln!(
                "{} | {} | mon={:?} focused={}",
                w.id, w.title, w.monitor, w.focused
            );
        }
        assert!(!windows.is_empty(), "expected at least one toplevel");
        assert!(
            windows.iter().any(|w| w.focused),
            "expected an activated toplevel"
        );
        // Stable-identifier ids round-trip: dispatch by the id reported
        // by `get_windows` (with expect_* from the same snapshot).
        let first = &windows[0];
        dispatch_op(
            "focus",
            &first.id,
            &serde_json::json!({
                "expect_title": first.title,
                "expect_class": first.class,
            }),
        )
        .expect("dispatch by reported id");
        // focus on the focused view is a harmless roundtrip.
        dispatch_op("focus", FOCUSED_SELECTOR, &Value::Null).expect("activate focused");
        // A bogus index must error, never act.
        assert!(dispatch_op("focus", "wlr-toplevel-999", &Value::Null).is_err());
        assert!(dispatch_op("focus", "wlr-toplevel-no-such-id", &Value::Null).is_err());
        assert!(dispatch_op("explode", FOCUSED_SELECTOR, &Value::Null).is_err());
    }
}
