//! Wayland-native input injection via `zwlr_virtual_pointer_v1`
//! (wlr-virtual-pointer-unstable-v1) + `zwp_virtual_keyboard_v1`
//! (virtual-keyboard-unstable-v1) — in-process, no external binaries.
//!
//! Connects to `$WAYLAND_DISPLAY`, binds `wl_seat` + `wl_output` (the latter
//! for layout geometry, needed by `motion_absolute`), creates one virtual
//! pointer and one virtual keyboard, and uploads an `xkbcommon`-compiled
//! keymap so key names resolve to evdev keycodes locally.
//!
//! A single persistent `Connection`/`EventQueue` is kept behind a `Mutex`;
//! every injection call flushes pending requests and performs one roundtrip
//! so the compositor has processed the batch before we return. Blocking
//! roundtrips always run inside `spawn_blocking`, off the async executor.
//!
//! `cursor_position` prefers `hyprctl` (live on Hyprland); the virtual
//! pointer protocol offers no read channel of its own.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use wayland_client::protocol::{
    wl_keyboard, wl_output, wl_pointer, wl_registry,
    wl_seat::{self, WlSeat},
};
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, delegate_noop};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::{
    zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1,
    zwp_virtual_keyboard_v1::{self, ZwpVirtualKeyboardV1},
};
use wayland_protocols_wlr::virtual_pointer::v1::client::{
    zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1,
    zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1,
};
use xkbcommon::xkb::{self, Keysym};

use crate::traits::InputProvider;

/// XKB keycodes are offset from evdev (Linux input-event) codes by 8.
const XKB_EVDEV_OFFSET: u32 = 8;
/// Axis value emitted per wheel step (libinput convention: one wheel
/// detent reports 15 units of axis motion).
const AXIS_VALUE_PER_STEP: f64 = 15.0;

/// In-process wlr virtual input backend.
///
/// One persistent Wayland connection guarded by a mutex; the provider is
/// `Send + Sync` and safe to share behind `Arc<dyn InputProvider>`.
pub struct WlrInput {
    inner: Arc<Mutex<Inner>>,
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction — the `cursor_position` helper (S-1). Spawned under
    /// the scrubbed environment + timeout of [`crate::security::spawn`].
    hyprctl: Option<std::path::PathBuf>,
}

/// Compile-time contract: `InputProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WlrInput>();
};

/// Everything behind the lock: the event queue (blocking roundtrips),
/// protocol state, and the locally-resolved keysym → keycode table.
struct Inner {
    queue: wayland_client::EventQueue<State>,
    state: State,
    /// Monotonic epoch for protocol `time` args (ms since connect).
    started: Instant,
    /// Keysym raw value → evdev keycode + level. Precomputed because
    /// `xkb::Keymap` is `!Send` and cannot live in the provider.
    keys: HashMap<u32, KeyBinding>,
    /// evdev code of `Shift_L`, cached for level-1 (shifted) keysyms.
    shift_evdev: Option<u32>,
}

/// A resolved key: evdev keycode plus whether `Shift` must be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyBinding {
    evdev: u32,
    shifted: bool,
}

/// Per-connection protocol state, owned by the persistent `EventQueue`.
#[derive(Default)]
struct State {
    seat: Option<WlSeat>,
    ptr_mgr: Option<ZwlrVirtualPointerManagerV1>,
    kbd_mgr: Option<ZwpVirtualKeyboardManagerV1>,
    pointer: Option<ZwlrVirtualPointerV1>,
    keyboard: Option<ZwpVirtualKeyboardV1>,
    outputs: Vec<wl_output::WlOutput>,
    output_info: Vec<OutputInfo>,
}

#[derive(Clone, Default)]
struct OutputInfo {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

// ---------------------------------------------------------------------------
// Dispatch impls
// ---------------------------------------------------------------------------

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
                "wl_seat" => {
                    if state.seat.is_none() {
                        state.seat = Some(registry.bind(name, version.min(7), qh, ()));
                    }
                }
                "wl_output" => {
                    let idx = state.output_info.len();
                    let out: wl_output::WlOutput = registry.bind(name, version.min(4), qh, idx);
                    state.outputs.push(out);
                    state.output_info.push(OutputInfo::default());
                }
                "zwlr_virtual_pointer_manager_v1" => {
                    state.ptr_mgr = Some(registry.bind(name, version.min(2), qh, ()));
                }
                "zwp_virtual_keyboard_manager_v1" => {
                    state.kbd_mgr = Some(registry.bind(name, version.min(1), qh, ()));
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_output::WlOutput, usize> for State {
    fn event(
        state: &mut Self,
        _: &wl_output::WlOutput,
        event: wl_output::Event,
        idx: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(info) = state.output_info.get_mut(*idx) else {
            return;
        };
        match event {
            wl_output::Event::Geometry { x, y, .. } => {
                info.x = x;
                info.y = y;
            }
            wl_output::Event::Mode {
                flags,
                width,
                height,
                ..
            } => {
                let current = flags
                    .into_result()
                    .map(|f| f.contains(wl_output::Mode::Current))
                    .unwrap_or(false);
                if current || info.width == 0 {
                    info.width = width;
                    info.height = height;
                }
            }
            _ => {}
        }
    }
}

// `delegate_noop!` panics (`unreachable!()`) if the object ever emits an
// event — and `wl_seat` emits `capabilities` on bind while
// `zwp_virtual_keyboard_v1` receives the compositor's `keymap` event.
// Those two get explicit swallow-everything `Dispatch` impls; the
// request-only interfaces keep `delegate_noop!`.
impl Dispatch<WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlSeat,
        _: wl_seat::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwpVirtualKeyboardV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwpVirtualKeyboardV1,
        _: zwp_virtual_keyboard_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ZwlrVirtualPointerManagerV1);
delegate_noop!(State: ZwlrVirtualPointerV1);
delegate_noop!(State: ZwpVirtualKeyboardManagerV1);

// ---------------------------------------------------------------------------
// Name → code mappings
// ---------------------------------------------------------------------------

/// evdev button code for a button name (`linux/input-event-codes.h`).
/// `InputProvider` callers pass "left" | "right" | "middle"; the extra
/// entries cover the common navigation buttons.
fn button_code(name: &str) -> Option<u32> {
    Some(match name.to_ascii_lowercase().as_str() {
        "left" | "lmb" => 0x110,     // BTN_LEFT
        "right" | "rmb" => 0x111,    // BTN_RIGHT
        "middle" | "mmb" => 0x112,   // BTN_MIDDLE
        "side" | "thumb" => 0x113,   // BTN_SIDE
        "extra" | "thumb2" => 0x114, // BTN_EXTRA
        "forward" | "fwd" => 0x115,  // BTN_FORWARD
        "back" => 0x116,             // BTN_BACK
        _ => return None,
    })
}

/// Resolve a key name to an XKB keysym.
///
/// Order: friendly alias → exact keysym name → case-insensitive keysym
/// name → single printable character (Unicode codepoint → keysym).
fn keysym_for_name(name: &str) -> Option<Keysym> {
    let alias = match name.to_ascii_lowercase().as_str() {
        "ctrl" | "control" | "ctl" | "lctrl" => "Control_L",
        "rctrl" => "Control_R",
        "shift" | "lshift" => "Shift_L",
        "rshift" => "Shift_R",
        "alt" | "lalt" => "Alt_L",
        "ralt" | "altgr" => "ISO_Level3_Shift",
        "super" | "win" | "cmd" | "meta" | "lsuper" => "Super_L",
        "rsuper" => "Super_R",
        "hyper" => "Hyper_L",
        "enter" | "ret" | "newline" => "Return",
        "esc" => "Escape",
        "spc" | "spacebar" => "space",
        "bksp" | "bs" => "BackSpace",
        "del" => "Delete",
        "ins" => "Insert",
        "pgup" | "pageup" => "Page_Up",
        "pgdn" | "pgdown" | "pagedown" => "Page_Down",
        "caps" | "capslock" => "Caps_Lock",
        "numlock" => "Num_Lock",
        "scrolllock" => "Scroll_Lock",
        "printscreen" | "prtsc" | "sysrq" => "Print",
        "break" => "Pause",
        _ => name,
    };
    let sym = xkb::keysym_from_name(alias, xkb::KEYSYM_NO_FLAGS);
    if sym.raw() != xkb::keysyms::KEY_NoSymbol {
        return Some(sym);
    }
    let sym = xkb::keysym_from_name(alias, xkb::KEYSYM_CASE_INSENSITIVE);
    if sym.raw() != xkb::keysyms::KEY_NoSymbol {
        return Some(sym);
    }
    let mut chars = alias.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        let sym = xkb::utf32_to_keysym(c as u32);
        if sym.raw() != xkb::keysyms::KEY_NoSymbol {
            return Some(sym);
        }
    }
    None
}

/// Keysym a literal `type_text` character should emit.
fn char_keysym(c: char) -> Keysym {
    match c {
        '\n' | '\r' => Keysym::new(xkb::keysyms::KEY_Return),
        '\t' => Keysym::new(xkb::keysyms::KEY_Tab),
        _ => xkb::utf32_to_keysym(c as u32),
    }
}

/// Compile the session keymap (env defaults: `XKB_DEFAULT_RULES` etc.,
/// else libxkbcommon defaults) and return its text form plus the
/// keysym → keybinding lookup.
fn build_keymap() -> Option<(String, HashMap<u32, KeyBinding>)> {
    build_keymap_rmlvo("", "", "", "")
}

fn build_keymap_rmlvo(
    rules: &str,
    model: &str,
    layout: &str,
    variant: &str,
) -> Option<(String, HashMap<u32, KeyBinding>)> {
    let ctx = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
    let keymap = xkb::Keymap::new_from_names(
        &ctx,
        rules,
        model,
        layout,
        variant,
        None,
        xkb::KEYMAP_COMPILE_NO_FLAGS,
    )?;
    let text = keymap.get_as_string(xkb::KEYMAP_FORMAT_TEXT_V1);
    if text.is_empty() {
        return None;
    }
    Some((text, build_keycode_map(&keymap)))
}

/// Map every keysym reachable at level 0 (unshifted) or level 1 (shifted)
/// to its evdev keycode. Level 0 wins when a keysym exists at both.
fn build_keycode_map(keymap: &xkb::Keymap) -> HashMap<u32, KeyBinding> {
    let mut map = HashMap::new();
    for level in [0u32, 1] {
        for raw in keymap.min_keycode().raw()..=keymap.max_keycode().raw() {
            let Some(evdev) = raw.checked_sub(XKB_EVDEV_OFFSET) else {
                continue;
            };
            let kc = xkb::Keycode::new(raw);
            for sym in keymap.key_get_syms_by_level(kc, 0, level) {
                map.entry(sym.raw()).or_insert(KeyBinding {
                    evdev,
                    shifted: level == 1,
                });
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Blocking protocol plumbing
// ---------------------------------------------------------------------------

impl Inner {
    /// Milliseconds since the provider connected — a monotonic,
    /// compositor-acceptable source for protocol `time` arguments.
    fn now_ms(&self) -> u32 {
        self.started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32
    }

    /// Flush pending requests and block until the compositor has
    /// processed them (implicit `wl_display.sync`).
    fn sync(&mut self) -> Result<()> {
        self.queue.flush().context("wayland flush")?;
        self.queue
            .roundtrip(&mut self.state)
            .context("wayland roundtrip")?;
        Ok(())
    }

    fn pointer(&self) -> Result<ZwlrVirtualPointerV1> {
        self.state
            .pointer
            .clone()
            .ok_or_else(|| anyhow!("zwlr_virtual_pointer_v1 unavailable"))
    }

    fn keyboard(&self) -> Result<ZwpVirtualKeyboardV1> {
        self.state
            .keyboard
            .clone()
            .ok_or_else(|| anyhow!("zwp_virtual_keyboard_v1 unavailable"))
    }

    /// Bounding box of all outputs in layout coordinates — the frame
    /// `motion_absolute` maps `[0, x_extent] x [0, y_extent]` onto.
    fn layout_box(&self) -> Result<(i32, i32, i32, i32)> {
        let mut it = self
            .state
            .output_info
            .iter()
            .filter(|o| o.width > 0 && o.height > 0);
        let first = it
            .next()
            .ok_or_else(|| anyhow!("compositor advertised no usable wl_output geometry"))?;
        let (mut x0, mut y0, mut x1, mut y1) = (
            first.x,
            first.y,
            first.x + first.width,
            first.y + first.height,
        );
        for o in it {
            x0 = x0.min(o.x);
            y0 = y0.min(o.y);
            x1 = x1.max(o.x + o.width);
            y1 = y1.max(o.y + o.height);
        }
        Ok((x0, y0, x1 - x0, y1 - y0))
    }

    fn move_to(&mut self, x: i32, y: i32) -> Result<()> {
        let (bx, by, bw, bh) = self.layout_box()?;
        let px = (x - bx).clamp(0, bw) as u32;
        let py = (y - by).clamp(0, bh) as u32;
        let ptr = self.pointer()?;
        // x_extent = layout box width maps px back to exactly `x`.
        ptr.motion_absolute(self.now_ms(), px, py, bw as u32, bh as u32);
        ptr.frame();
        self.sync()
    }

    fn emit_button(&mut self, button: &str, down: bool) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        let ptr = self.pointer()?;
        let state = if down {
            wl_pointer::ButtonState::Pressed
        } else {
            wl_pointer::ButtonState::Released
        };
        ptr.button(self.now_ms(), code, state);
        ptr.frame();
        self.sync()
    }

    fn click(&mut self, x: i32, y: i32, button: &str) -> Result<()> {
        // Validate before moving so a bad button name never moves the pointer.
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        let (bx, by, bw, bh) = self.layout_box()?;
        let px = (x - bx).clamp(0, bw) as u32;
        let py = (y - by).clamp(0, bh) as u32;
        let ptr = self.pointer()?;
        let t = self.now_ms();
        ptr.motion_absolute(t, px, py, bw as u32, bh as u32);
        ptr.button(t, code, wl_pointer::ButtonState::Pressed);
        ptr.button(t, code, wl_pointer::ButtonState::Released);
        ptr.frame();
        self.sync()
    }

    /// `dx`/`dy` are wheel steps; positive scrolls right / down.
    fn scroll(&mut self, dx: f64, dy: f64) -> Result<()> {
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let ptr = self.pointer()?;
        let t = self.now_ms();
        ptr.axis_source(wl_pointer::AxisSource::Wheel);
        for (axis, delta) in [
            (wl_pointer::Axis::VerticalScroll, dy),
            (wl_pointer::Axis::HorizontalScroll, dx),
        ] {
            if delta == 0.0 {
                continue;
            }
            if ptr.version() >= 2 {
                ptr.axis_discrete(t, axis, delta * AXIS_VALUE_PER_STEP, delta.round() as i32);
            }
            ptr.axis(t, axis, delta * AXIS_VALUE_PER_STEP);
        }
        ptr.frame();
        self.sync()
    }

    /// Press or release the key named `key`. Keysym names are resolved
    /// against the uploaded keymap; a keysym living at level 1 is wrapped
    /// in a `Shift_L` hold (shift down before, shift up after on release).
    fn key_event(&mut self, key: &str, down: bool) -> Result<()> {
        let sym = keysym_for_name(key).ok_or_else(|| anyhow!("unknown key name {key:?}"))?;
        self.emit_keysym(sym, down)
    }

    fn emit_keysym(&mut self, sym: Keysym, down: bool) -> Result<()> {
        let binding = *self.keys.get(&sym.raw()).ok_or_else(|| {
            anyhow!(
                "keysym {:?} has no keycode in keymap",
                xkb::keysym_get_name(sym)
            )
        })?;
        let kbd = self.keyboard()?;
        let t = self.now_ms();
        let (press, release) = (
            wl_keyboard::KeyState::Pressed as u32,
            wl_keyboard::KeyState::Released as u32,
        );
        if binding.shifted {
            let shift = self
                .shift_evdev
                .ok_or_else(|| anyhow!("Shift_L has no keycode in keymap"))?;
            if down {
                kbd.key(t, shift, press);
                kbd.key(t, binding.evdev, press);
            } else {
                kbd.key(t, binding.evdev, release);
                kbd.key(t, shift, release);
            }
        } else {
            kbd.key(t, binding.evdev, if down { press } else { release });
        }
        self.sync()
    }

    /// Type a literal string. All characters are resolved to keycodes
    /// *before* any event is emitted so an unsupported character can never
    /// leave a half-typed string behind.
    fn type_text(&mut self, text: &str) -> Result<()> {
        let mut seq = Vec::with_capacity(text.len());
        for c in text.chars() {
            let sym = char_keysym(c);
            let binding = *self.keys.get(&sym.raw()).ok_or_else(|| {
                anyhow!(
                    "no keycode for {c:?} (keysym {})",
                    xkb::keysym_get_name(sym)
                )
            })?;
            seq.push(binding);
        }
        if seq.is_empty() {
            return Ok(());
        }
        // Fail before emitting if a shifted char could not be wrapped —
        // part of the no-partial-typing guarantee above.
        let shift = if seq.iter().any(|b| b.shifted) {
            Some(
                self.shift_evdev
                    .ok_or_else(|| anyhow!("Shift_L has no keycode in keymap"))?,
            )
        } else {
            None
        };
        let kbd = self.keyboard()?;
        let t = self.now_ms();
        let (press, release) = (
            wl_keyboard::KeyState::Pressed as u32,
            wl_keyboard::KeyState::Released as u32,
        );
        for b in seq {
            if b.shifted {
                let s = shift.expect("validated above");
                kbd.key(t, s, press);
                kbd.key(t, b.evdev, press);
                kbd.key(t, b.evdev, release);
                kbd.key(t, s, release);
            } else {
                kbd.key(t, b.evdev, press);
                kbd.key(t, b.evdev, release);
            }
        }
        self.sync()
    }
}

/// Upload a compiled keymap to the virtual keyboard via an anonymous
/// temp file (`format` = `wl_keyboard.keymap_format.xkb_v1` = 1).
fn upload_keymap(kbd: &ZwpVirtualKeyboardV1, text: &str) -> Result<()> {
    let mut file = tempfile::tempfile().context("create keymap file")?;
    file.write_all(text.as_bytes()).context("write keymap")?;
    file.write_all(&[0]).context("write keymap NUL")?;
    let size = (text.len() + 1) as u32;
    kbd.keymap(wl_keyboard::KeymapFormat::XkbV1 as u32, file.as_fd(), size);
    Ok(())
}

impl WlrInput {
    /// Probe the session: `WAYLAND_DISPLAY` must resolve and the compositor
    /// must advertise `zwlr_virtual_pointer_manager_v1`,
    /// `zwp_virtual_keyboard_manager_v1`, a `wl_seat` and at least one
    /// `wl_output` (needed to frame `motion_absolute`). `None` otherwise.
    pub fn new() -> Option<Self> {
        std::env::var_os("WAYLAND_DISPLAY")?;
        match Self::connect() {
            Ok(this) => Some(this),
            Err(e) => {
                tracing::debug!("wlr virtual input unavailable: {e:#}");
                None
            }
        }
    }

    /// Persistent connect + device creation + keymap upload.
    fn connect() -> Result<Self> {
        let conn = Connection::connect_to_env().context("connect to WAYLAND_DISPLAY")?;
        let mut queue = conn.new_event_queue();
        let qh = queue.handle();
        let mut state = State::default();
        conn.display().get_registry(&qh, ());
        queue.roundtrip(&mut state).context("registry roundtrip")?;

        if state.ptr_mgr.is_none() {
            bail!("zwlr_virtual_pointer_manager_v1 not advertised");
        }
        if state.kbd_mgr.is_none() {
            bail!("zwp_virtual_keyboard_manager_v1 not advertised");
        }
        let seat = state
            .seat
            .clone()
            .ok_or_else(|| anyhow!("wl_seat not advertised"))?;
        if state.outputs.is_empty() {
            bail!("no wl_output advertised");
        }

        state.pointer = Some(
            state
                .ptr_mgr
                .as_ref()
                .expect("checked above")
                .create_virtual_pointer(Some(&seat), &qh, ()),
        );
        let keyboard = state
            .kbd_mgr
            .as_ref()
            .expect("checked above")
            .create_virtual_keyboard(&seat, &qh, ());
        state.keyboard = Some(keyboard.clone());

        let (keymap_text, keys) =
            build_keymap().ok_or_else(|| anyhow!("xkbcommon failed to compile session keymap"))?;
        let shift_evdev = keys.get(&xkb::keysyms::KEY_Shift_L).map(|b| b.evdev);
        upload_keymap(&keyboard, &keymap_text)?;

        // Second roundtrip: delivers wl_output geometry/mode events and
        // lets the compositor ack device creation + the keymap upload.
        queue
            .roundtrip(&mut state)
            .context("device init roundtrip")?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                queue,
                state,
                started: Instant::now(),
                keys,
                shift_evdev,
            })),
            hyprctl: crate::security::whitelist::resolve_binaries()
                .get("hyprctl")
                .map(std::path::Path::to_path_buf),
        })
    }
}

// ---------------------------------------------------------------------------
// hyprctl helpers
// ---------------------------------------------------------------------------

/// Parse `hyprctl cursorpos` output — modern JSON `{"x":N,"y":M}` or the
/// legacy `x, y` pair.
fn parse_cursorpos(s: &str) -> Option<(i32, i32)> {
    let t = s.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
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

// ---------------------------------------------------------------------------
// InputProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl InputProvider for WlrInput {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("wlr input poisoned").move_to(x, y))
            .await
            .context("wlr input task")?
    }

    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("wlr input poisoned")
                .click(x, y, &button)
        })
        .await
        .context("wlr input task")?
    }

    async fn mouse_button(&self, button: &str, down: bool) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("wlr input poisoned")
                .emit_button(&button, down)
        })
        .await
        .context("wlr input task")?
    }

    async fn scroll(&self, dx: f64, dy: f64) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("wlr input poisoned").scroll(dx, dy)
        })
        .await
        .context("wlr input task")?
    }

    async fn key_event(&self, key: &str, down: bool) -> Result<()> {
        let key = key.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("wlr input poisoned")
                .key_event(&key, down)
        })
        .await
        .context("wlr input task")?
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        let text = text.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("wlr input poisoned").type_text(&text)
        })
        .await
        .context("wlr input task")?
    }

    async fn cursor_position(&self) -> Result<(i32, i32)> {
        match &self.hyprctl {
            Some(bin) => hyprctl_cursorpos(bin).await,
            None => Err(anyhow!("hyprctl unavailable (not pinned at startup)")),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: these tests are structurally incapable of injecting input — none
// of them open a Wayland connection or dispatch a pointer/keyboard request.
// The only `new()` test removes WAYLAND_DISPLAY first, so it exits through
// the early-`None` path before any socket is touched.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_code_maps_mouse_buttons() {
        assert_eq!(button_code("left"), Some(0x110));
        assert_eq!(button_code("right"), Some(0x111));
        assert_eq!(button_code("middle"), Some(0x112));
        assert_eq!(button_code("LEFT"), Some(0x110)); // case-insensitive
        assert_eq!(button_code("back"), Some(0x116));
        assert_eq!(button_code("forward"), Some(0x115));
    }

    #[test]
    fn button_code_rejects_unknown() {
        assert_eq!(button_code("primary"), None);
        assert_eq!(button_code(""), None);
    }

    #[test]
    fn keysym_for_name_resolves_named_keys() {
        assert_eq!(
            keysym_for_name("Return").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Return)
        );
        assert_eq!(
            keysym_for_name("F5").map(Keysym::raw),
            Some(xkb::keysyms::KEY_F5)
        );
        assert_eq!(
            keysym_for_name("page_up").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Page_Up)
        );
        assert_eq!(
            keysym_for_name("kp_5").map(Keysym::raw),
            Some(xkb::keysyms::KEY_KP_5)
        );
    }

    #[test]
    fn keysym_for_name_resolves_aliases() {
        assert_eq!(
            keysym_for_name("ctrl").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Control_L)
        );
        assert_eq!(
            keysym_for_name("ret").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Return)
        );
        assert_eq!(
            keysym_for_name("super").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Super_L)
        );
        assert_eq!(
            keysym_for_name("esc").map(Keysym::raw),
            Some(xkb::keysyms::KEY_Escape)
        );
    }

    #[test]
    fn keysym_for_name_resolves_single_chars() {
        assert_eq!(
            keysym_for_name("a").map(Keysym::raw),
            Some(xkb::keysyms::KEY_a)
        );
        assert_eq!(
            keysym_for_name("A").map(Keysym::raw),
            Some(xkb::keysyms::KEY_A)
        );
        assert_eq!(
            keysym_for_name(";").map(Keysym::raw),
            Some(xkb::keysyms::KEY_semicolon)
        );
    }

    #[test]
    fn keysym_for_name_rejects_garbage() {
        assert_eq!(keysym_for_name("definitely-not-a-keysym"), None);
        assert_eq!(keysym_for_name(""), None);
    }

    #[test]
    fn char_keysym_maps_controls_to_keys() {
        assert_eq!(char_keysym('\n').raw(), xkb::keysyms::KEY_Return);
        assert_eq!(char_keysym('\r').raw(), xkb::keysyms::KEY_Return);
        assert_eq!(char_keysym('\t').raw(), xkb::keysyms::KEY_Tab);
        assert_eq!(char_keysym('x').raw(), xkb::keysyms::KEY_x);
    }

    #[test]
    fn keymap_builds_text_and_keycode_map() {
        // Pinned RMLVO so the assertion set is deterministic.
        let (text, keys) = build_keymap_rmlvo("evdev", "pc105", "us", "")
            .expect("libxkbcommon must compile evdev/pc105/us");
        assert!(text.contains("xkb_keymap"));

        let a = keys.get(&xkb::keysyms::KEY_a).expect("us keymap has 'a'");
        assert!(!a.shifted);
        let big_a = keys.get(&xkb::keysyms::KEY_A).expect("us keymap has 'A'");
        assert!(big_a.shifted);
        // Same physical key, different level → same evdev code.
        assert_eq!(a.evdev, big_a.evdev);

        let shift = keys
            .get(&xkb::keysyms::KEY_Shift_L)
            .expect("us keymap has Shift_L");
        assert!(!shift.shifted);
        let ret = keys
            .get(&xkb::keysyms::KEY_Return)
            .expect("us keymap has Return");
        assert!(!ret.shifted);
    }

    #[test]
    fn keycode_map_prefers_unshifted_level() {
        // '1' is level 0 on AE01; '!' is level 1 on the same key.
        let (_text, keys) = build_keymap_rmlvo("evdev", "pc105", "us", "").unwrap();
        assert!(!keys[&xkb::keysyms::KEY_1].shifted);
        assert!(keys[&xkb::keysyms::KEY_exclam].shifted);
        assert_eq!(
            keys[&xkb::keysyms::KEY_1].evdev,
            keys[&xkb::keysyms::KEY_exclam].evdev
        );
    }

    #[test]
    fn parse_cursorpos_json_and_pair() {
        assert_eq!(parse_cursorpos("{\"x\":1017,\"y\":664}"), Some((1017, 664)));
        assert_eq!(parse_cursorpos("1234, 567"), Some((1234, 567)));
        assert_eq!(parse_cursorpos("garbage"), None);
    }

    #[test]
    fn new_is_none_without_wayland_display() {
        // SAFETY: test-only env mutation. No other test in this crate reads
        // WAYLAND_DISPLAY concurrently (live compositor tests are #[ignore]d),
        // and the variable is restored before returning.
        let saved = std::env::var_os("WAYLAND_DISPLAY");
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        assert!(WlrInput::new().is_none());
        if let Some(v) = saved {
            unsafe { std::env::set_var("WAYLAND_DISPLAY", v) };
        }
    }
}
