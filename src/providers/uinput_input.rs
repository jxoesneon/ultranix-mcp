//! Kernel-level input injection via `/dev/uinput` - rung two of the input
//! fallback ladder (wlr virtual input -> uinput -> portal).
//!
//! Unlike [`super::wlr_input`], this backend is display-protocol agnostic:
//! the virtual device it creates injects `input_event`s straight into the
//! kernel input layer, so it works under Wayland, X11 and even the
//! framebuffer console. The trade-off is that there is no compositor-side
//! context - no keymap, no read channel for the cursor, and no output
//! layout. Specifically:
//!
//! - `mouse_move` is *absolute*: `EV_ABS`/`ABS_X`/`ABS_Y` are registered at
//!   device-creation time with range `0..=width` / `0..=height`, and
//!   libinput/compositors map that rectangle onto the desktop. Bounds come
//!   from `ULTRANIX_SCREEN_SIZE` (`"WxH"`), else
//!   `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT`, else
//!   `hyprctl -j monitors` (best effort), else `1920x1080`.
//!   [`UinputInput::with_screen_size`] forces the bounds explicitly.
//! - `type_text`/`key_event` resolve names and characters against a fixed
//!   evdev (US-layout) code table - there is no xkb keymap at this level.
//!   Characters without a binding fail *before* any event is emitted, so a
//!   bad string can never leave a half-typed prefix behind.
//! - `cursor_position` tries `hyprctl` first (live on Hyprland), then falls
//!   back to the last absolute position this provider emitted.
//!
//! ## Permissions
//!
//! `/dev/uinput` is `root:root 0660` on most distributions. The supported
//! setup is a dedicated group via `99-ultranix-mcp-uinput.rules`:
//!
//! ```text
//! # /etc/udev/rules.d/99-ultranix-mcp-uinput.rules
//! SUBSYSTEM=="misc", KERNEL=="uinput", ACTION=="add", \
//!   MODE="0660", GROUP="ultranix-input", TAG+="uaccess"
//! ```
//!
//! Never grant `GROUP="input"`: that group can *read* every real input
//! device (`/dev/input/event*`), which turns the daemon into a keylogger.
//!
//! SAFETY: unit tests in this module never call [`UinputInput::new`],
//! [`UinputInput::with_screen_size`] or `create_device` - creating a real
//! uinput device injects kernel-level input on the host desktop. Tests
//! cover only the pure mapping/parsing functions and the writability
//! probe, which opens but never creates a device.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use uinput::event::{self, Event, Keyboard};

use crate::traits::InputProvider;

use super::common::{
    KEY_LEFTSHIFT, KeyBinding, button_code, char_binding, detents, hyprctl_cursorpos, key_binding,
    screen_size_from_env,
};

/// Path of the kernel uinput control node.
const UINPUT_PATH: &str = "/dev/uinput";

/// Last-resort ABS range when nothing can report the real desktop extent.
const DEFAULT_SCREEN: (i32, i32) = (1920, 1080);

// evdev event types / axis / key codes, from linux/input-event-codes.h.
// Emitted through `Device::write` (doc-hidden but public) because the
// crate's typed `send()` API cannot express arbitrary event codes.
const EV_KEY: i32 = 0x01;
const EV_REL: i32 = 0x02;
const EV_ABS: i32 = 0x03;

const ABS_X: i32 = 0x00;
const ABS_Y: i32 = 0x01;
const REL_HWHEEL: i32 = 0x06;
const REL_WHEEL: i32 = 0x08;

/// `/dev/uinput` virtual input backend.
///
/// One virtual device behind a mutex (`Device` methods take `&mut self`);
/// the provider is `Send + Sync` and safe to share behind
/// `Arc<dyn InputProvider>`. Dropping the device issues `UI_DEV_DESTROY`,
/// removing the kernel node.
pub struct UinputInput {
    inner: Arc<Mutex<Inner>>,
    /// Pinned `hyprctl` absolute path, when it was on `PATH` at
    /// construction - the `cursor_position` helper (S-1). Spawned under
    /// the scrubbed environment + timeout of [`crate::security::spawn`].
    hyprctl: Option<PathBuf>,
}

/// Compile-time contract: `InputProvider` requires `Send + Sync`.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UinputInput>();
};

/// Everything behind the lock: the device plus per-provider bookkeeping
/// (uinput gives no read channel, so we track what we emitted).
struct Inner {
    device: uinput::Device,
    /// ABS range registered at creation; `mouse_move` clamps into it.
    width: i32,
    height: i32,
    /// Last absolute position emitted - `cursor_position` fallback.
    last_pos: Option<(i32, i32)>,
    /// Sub-detent wheel remainders, so repeated fractional scrolls of
    /// e.g. 0.4 steps still accumulate into whole `REL_WHEEL` detents.
    wheel_acc: f64,
    hwheel_acc: f64,
}

// ---------------------------------------------------------------------------
// Screen-size resolution
// ---------------------------------------------------------------------------

/// Best-effort desktop extent via `hyprctl -j monitors` (sync; used only
/// at construction time). `None` off Hyprland - the binary is the pinned
/// whitelisted path under a scrubbed env, and the wait is bounded so a
/// wedged helper cannot stall provider detection.
fn hyprctl_screen_size() -> Option<(i32, i32)> {
    let bin = crate::security::whitelist::resolve_binaries()
        .get("hyprctl")?
        .to_path_buf();
    super::common::hyprctl_screen_size(&bin)
}

// ---------------------------------------------------------------------------
// Device creation / probe
// ---------------------------------------------------------------------------

/// Returns true when `path` can be opened `O_WRONLY`. Opening the uinput
/// control node for write does NOT create a device - `UI_DEV_CREATE`
/// happens only in [`create_device`].
fn uinput_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// Open `path` and create the virtual device: every keyboard key
/// (`Keyboard::All` sets `EV_KEY` + all `KEY_*` bits), the mouse buttons,
/// `REL_X`/`REL_Y`/`REL_WHEEL`/`REL_HWHEEL`, and `ABS_X`/`ABS_Y` bounded
/// to `0..=width`/`0..=height` for absolute pointer moves.
fn create_device(path: &Path, width: i32, height: i32) -> Result<uinput::Device> {
    use event::{absolute, controller, relative};

    let mut builder = uinput::open(path)
        .context("open uinput")?
        .name("ultranix-mcp virtual input")
        .context("uinput set name")?
        .bus(0x06) // BUS_VIRTUAL - honest provenance for a uinput device
        .vendor(0x0001)
        .product(0x0001)
        .version(1);

    let events = [
        Event::Keyboard(Keyboard::All),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Left)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Right)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Middle)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Side)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Extra)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Forward)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Back)),
        Event::Controller(controller::Controller::Mouse(controller::Mouse::Task)),
        Event::Relative(relative::Relative::Position(relative::Position::X)),
        Event::Relative(relative::Relative::Position(relative::Position::Y)),
        Event::Relative(relative::Relative::Wheel(relative::Wheel::Vertical)),
        Event::Relative(relative::Relative::Wheel(relative::Wheel::Horizontal)),
    ];
    for ev in events {
        builder = builder.event(ev).context("uinput register event")?;
    }

    // Absolute axes take their range from the *previously* registered
    // event - min()/max() apply to `self.abs`, so they must immediately
    // follow each absolute `event()` call.
    builder = builder
        .event(absolute::Absolute::Position(absolute::Position::X))
        .context("uinput register ABS_X")?
        .min(0)
        .max(width);
    builder = builder
        .event(absolute::Absolute::Position(absolute::Position::Y))
        .context("uinput register ABS_Y")?
        .min(0)
        .max(height);

    builder.create().context("uinput create device")
}

impl UinputInput {
    /// Probe `/dev/uinput` (writable `O_WRONLY`) and create the virtual
    /// device. Returns `None` when the node is missing or not writable -
    /// i.e. no `ultranix-input` group membership / udev rule.
    ///
    /// Screen bounds for the ABS range come from `ULTRANIX_SCREEN_SIZE`,
    /// `ULTRANIX_SCREEN_WIDTH`/`ULTRANIX_SCREEN_HEIGHT`,
    /// `hyprctl -j monitors`, then a 1920x1080 default.
    pub fn new() -> Option<Self> {
        let (w, h) = screen_size_from_env(|k| std::env::var(k).ok())
            .or_else(hyprctl_screen_size)
            .unwrap_or(DEFAULT_SCREEN);
        Self::open(Path::new(UINPUT_PATH), w, h)
    }

    /// Like [`Self::new`] but with an explicit ABS range - for callers
    /// that already know the desktop extent (e.g. `wlr_input` output
    /// layout or a `grim`/`xdpyinfo` measurement upstream).
    pub fn with_screen_size(width: i32, height: i32) -> Option<Self> {
        Self::open(Path::new(UINPUT_PATH), width, height)
    }

    /// Shared constructor: probe writability first (cheap, never creates
    /// a device), then build. Any failure is a debug-level `None`, not a
    /// hard error - this is a fallback rung.
    fn open(path: &Path, width: i32, height: i32) -> Option<Self> {
        if !uinput_writable(path) {
            tracing::debug!(path = %path.display(), "uinput: node not writable, backend unavailable");
            return None;
        }
        if width <= 0 || height <= 0 {
            tracing::debug!(
                width,
                height,
                "uinput: invalid screen bounds, backend unavailable"
            );
            return None;
        }
        match create_device(path, width, height) {
            Ok(device) => Some(Self {
                inner: Arc::new(Mutex::new(Inner {
                    device,
                    width,
                    height,
                    last_pos: None,
                    wheel_acc: 0.0,
                    hwheel_acc: 0.0,
                })),
                hyprctl: crate::security::whitelist::resolve_binaries()
                    .get("hyprctl")
                    .map(Path::to_path_buf),
            }),
            Err(e) => {
                tracing::debug!("uinput backend unavailable: {e:#}");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking device plumbing
// ---------------------------------------------------------------------------

impl Inner {
    /// Write one `input_event` (kind/code/value) to the device fd.
    fn emit(&mut self, kind: i32, code: i32, value: i32) -> Result<()> {
        self.device
            .write(kind, code, value)
            .context("uinput write event")
    }

    /// `EV_SYN`/`SYN_REPORT` - flush the buffered frame.
    fn sync(&mut self) -> Result<()> {
        self.device.synchronize().context("uinput synchronize")
    }

    fn move_to(&mut self, x: i32, y: i32) -> Result<()> {
        let px = x.clamp(0, self.width);
        let py = y.clamp(0, self.height);
        self.emit(EV_ABS, ABS_X, px)?;
        self.emit(EV_ABS, ABS_Y, py)?;
        self.sync()?;
        self.last_pos = Some((px, py));
        Ok(())
    }

    fn emit_button(&mut self, button: &str, down: bool) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        self.emit(EV_KEY, i32::from(code), i32::from(down))?;
        self.sync()
    }

    /// Validate the button *before* moving so a bad name never repositions
    /// the pointer (same ordering as `wlr_input::click`).
    fn click(&mut self, x: i32, y: i32, button: &str) -> Result<()> {
        let code = button_code(button).ok_or_else(|| anyhow!("unknown button name {button:?}"))?;
        let px = x.clamp(0, self.width);
        let py = y.clamp(0, self.height);
        self.emit(EV_ABS, ABS_X, px)?;
        self.emit(EV_ABS, ABS_Y, py)?;
        self.emit(EV_KEY, i32::from(code), 1)?;
        self.emit(EV_KEY, i32::from(code), 0)?;
        self.sync()?;
        self.last_pos = Some((px, py));
        Ok(())
    }

    /// `dx`/`dy` are wheel steps; positive scrolls right / down.
    ///
    /// Sign convention: wl_pointer axis positive = down/right, while
    /// evdev `REL_WHEEL` positive = up (wheel away from user) - so
    /// vertical is inverted. `REL_HWHEEL` positive = right already.
    /// Sub-detent remainders carry across calls via `detents`.
    fn scroll(&mut self, dx: f64, dy: f64) -> Result<()> {
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let wheel = detents(-dy, &mut self.wheel_acc);
        let hwheel = detents(dx, &mut self.hwheel_acc);
        if wheel != 0 {
            self.emit(EV_REL, REL_WHEEL, wheel)?;
        }
        if hwheel != 0 {
            self.emit(EV_REL, REL_HWHEEL, hwheel)?;
        }
        self.sync()
    }

    /// Press or release one key binding; a level-1 (shifted) binding wraps
    /// the key in a `KEY_LEFTSHIFT` hold, mirroring `wlr_input`.
    fn emit_key(&mut self, binding: KeyBinding, down: bool) -> Result<()> {
        if binding.shifted {
            if down {
                self.emit(EV_KEY, KEY_LEFTSHIFT, 1)?;
                self.emit(EV_KEY, i32::from(binding.code), 1)?;
            } else {
                self.emit(EV_KEY, i32::from(binding.code), 0)?;
                self.emit(EV_KEY, KEY_LEFTSHIFT, 0)?;
            }
        } else {
            self.emit(EV_KEY, i32::from(binding.code), i32::from(down))?;
        }
        self.sync()
    }

    fn key_event(&mut self, key: &str, down: bool) -> Result<()> {
        let binding = key_binding(key).ok_or_else(|| anyhow!("unknown key name {key:?}"))?;
        self.emit_key(binding, down)
    }

    /// Type a literal string. Every character is resolved to a binding
    /// *before* any event is emitted, so an unsupported character can
    /// never leave a half-typed string behind.
    fn type_text(&mut self, text: &str) -> Result<()> {
        let mut seq = Vec::with_capacity(text.len());
        for c in text.chars() {
            seq.push(char_binding(c).ok_or_else(|| anyhow!("no evdev key binding for {c:?}"))?);
        }
        for b in seq {
            if b.shifted {
                self.emit(EV_KEY, KEY_LEFTSHIFT, 1)?;
                self.emit(EV_KEY, i32::from(b.code), 1)?;
                self.emit(EV_KEY, i32::from(b.code), 0)?;
                self.emit(EV_KEY, KEY_LEFTSHIFT, 0)?;
            } else {
                self.emit(EV_KEY, i32::from(b.code), 1)?;
                self.emit(EV_KEY, i32::from(b.code), 0)?;
            }
        }
        self.sync()
    }
}

// ---------------------------------------------------------------------------
// InputProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl InputProvider for UinputInput {
    async fn mouse_move(&self, x: i32, y: i32) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").move_to(x, y))
            .await
            .context("uinput input task")?
    }

    async fn mouse_click(&self, x: i32, y: i32, button: &str) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("uinput poisoned").click(x, y, &button)
        })
        .await
        .context("uinput input task")?
    }

    async fn mouse_button(&self, button: &str, down: bool) -> Result<()> {
        let button = button.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("uinput poisoned")
                .emit_button(&button, down)
        })
        .await
        .context("uinput input task")?
    }

    async fn scroll(&self, dx: f64, dy: f64) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").scroll(dx, dy))
            .await
            .context("uinput input task")?
    }

    async fn key_event(&self, key: &str, down: bool) -> Result<()> {
        let key = key.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.lock().expect("uinput poisoned").key_event(&key, down)
        })
        .await
        .context("uinput input task")?
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        let text = text.to_string();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.lock().expect("uinput poisoned").type_text(&text))
            .await
            .context("uinput input task")?
    }

    /// uinput has no read channel: prefer live `hyprctl cursorpos`, else
    /// the last absolute position this provider emitted, else an error.
    async fn cursor_position(&self) -> Result<(i32, i32)> {
        if let Some(bin) = &self.hyprctl
            && let Ok(pos) = hyprctl_cursorpos(bin).await
        {
            return Ok(pos);
        }
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("uinput poisoned")
                .last_pos
                .ok_or_else(|| anyhow!("cursor position unknown (uinput has no read channel)"))
        })
        .await
        .context("uinput input task")?
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// SAFETY: these tests are structurally incapable of injecting input -
// none of them call `new()`, `with_screen_size()` or `create_device()`,
// and `uinput_writable`/`open` only ever *open* a path (never
// `UI_DEV_CREATE`). The `open` tests point at paths that cannot be a
// uinput node (a missing path, a directory), so no device is ever
// created even on a fully-permissioned host.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::common;

    #[test]
    fn button_code_maps_mouse_buttons() {
        assert_eq!(button_code("left"), Some(0x110));
        assert_eq!(button_code("right"), Some(0x111));
        assert_eq!(button_code("middle"), Some(0x112));
        assert_eq!(button_code("LEFT"), Some(0x110)); // case-insensitive
        assert_eq!(button_code("back"), Some(0x116));
        assert_eq!(button_code("forward"), Some(0x115));
        assert_eq!(button_code("side"), Some(0x113));
        assert_eq!(button_code("extra"), Some(0x114));
    }

    #[test]
    fn button_code_rejects_unknown() {
        assert_eq!(button_code("primary"), None);
        assert_eq!(button_code(""), None);
    }

    #[test]
    fn named_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("enter"), Some(28));
        assert_eq!(code("ret"), Some(28));
        assert_eq!(code("escape"), Some(1));
        assert_eq!(code("esc"), Some(1));
        assert_eq!(code("ctrl"), Some(29));
        assert_eq!(code("rightctrl"), Some(97));
        assert_eq!(code("shift"), Some(42));
        assert_eq!(code("altgr"), Some(100));
        assert_eq!(code("super"), Some(125));
        assert_eq!(code("tab"), Some(15));
        assert_eq!(code("pageup"), Some(104));
        assert_eq!(code("Page_Up"), Some(104)); // normalized
        assert_eq!(code("pgdn"), Some(109));
        assert_eq!(code("delete"), Some(111));
        assert_eq!(code("printscreen"), Some(99));
        assert_eq!(code("pause"), Some(119));
        assert_eq!(code("menu"), Some(139));
        assert_eq!(code("compose"), Some(127));
    }

    #[test]
    fn fn_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("f1"), Some(59));
        assert_eq!(code("F5"), Some(63)); // case-insensitive
        assert_eq!(code("f10"), Some(68));
        assert_eq!(code("f11"), Some(87));
        assert_eq!(code("f12"), Some(88));
        assert_eq!(code("f13"), Some(183));
        assert_eq!(code("f24"), Some(194));
        assert_eq!(code("f25"), None);
        assert_eq!(code("f0"), None);
    }

    #[test]
    fn keypad_keys_resolve() {
        let code = |n: &str| key_binding(n).map(|b| b.code);
        assert_eq!(code("kp5"), Some(76));
        assert_eq!(code("KP_5"), Some(76)); // normalized
        assert_eq!(code("numpad0"), Some(82));
        assert_eq!(code("kpenter"), Some(96));
        assert_eq!(code("kpslash"), Some(98));
        assert_eq!(code("kpminus"), Some(74));
        assert_eq!(code("numlock"), Some(69));
    }

    #[test]
    fn single_chars_carry_shift_state() {
        // Parity with wlr_input's level-1 keysym handling: "A" must
        // produce Shift+a, not a bare "a".
        assert_eq!(
            key_binding("a"),
            Some(KeyBinding {
                code: 30,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("A"),
            Some(KeyBinding {
                code: 30,
                shifted: true
            })
        );
        assert_eq!(
            key_binding(";"),
            Some(KeyBinding {
                code: 39,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("1"),
            Some(KeyBinding {
                code: 2,
                shifted: false
            })
        );
        assert_eq!(
            key_binding("!"),
            Some(KeyBinding {
                code: 2,
                shifted: true
            })
        );
    }

    #[test]
    fn key_binding_rejects_garbage() {
        assert_eq!(key_binding("definitely-not-a-key"), None);
        assert_eq!(key_binding(""), None);
        assert_eq!(key_binding("hyper"), None); // no KEY_HYPER in evdev
        assert_eq!(key_binding("é"), None); // non-ASCII, no keymap
    }

    #[test]
    fn char_binding_maps_ascii() {
        let b = |c: char| char_binding(c);
        assert_eq!(
            b('\n'),
            Some(KeyBinding {
                code: 28,
                shifted: false
            })
        );
        assert_eq!(
            b('\r'),
            Some(KeyBinding {
                code: 28,
                shifted: false
            })
        );
        assert_eq!(
            b('\t'),
            Some(KeyBinding {
                code: 15,
                shifted: false
            })
        );
        assert_eq!(
            b(' '),
            Some(KeyBinding {
                code: 57,
                shifted: false
            })
        );
        assert_eq!(
            b('z'),
            Some(KeyBinding {
                code: 44,
                shifted: false
            })
        );
        assert_eq!(
            b('Z'),
            Some(KeyBinding {
                code: 44,
                shifted: true
            })
        );
        assert_eq!(
            b('~'),
            Some(KeyBinding {
                code: 41,
                shifted: true
            })
        );
        assert_eq!(
            b(')'),
            Some(KeyBinding {
                code: 11,
                shifted: true
            })
        );
        assert_eq!(
            b('/'),
            Some(KeyBinding {
                code: 53,
                shifted: false
            })
        );
        assert_eq!(
            b('?'),
            Some(KeyBinding {
                code: 53,
                shifted: true
            })
        );
        assert_eq!(b('é'), None);
        assert_eq!(b('\u{2190}'), None);
    }

    #[test]
    fn detents_carry_sub_step_remainder() {
        let mut acc = 0.0;
        assert_eq!(detents(0.4, &mut acc), 0);
        assert_eq!(detents(0.4, &mut acc), 1); // 0.8 -> one detent
        assert_eq!(detents(0.4, &mut acc), 0); // 0.2 left
        assert_eq!(detents(-3.0, &mut acc), -3);
        assert_eq!(detents(2.5, &mut acc), 3); // rounds to nearest
    }

    #[test]
    fn parse_screen_size_accepts_common_forms() {
        assert_eq!(common::parse_screen_size("1920x1080"), Some((1920, 1080)));
        assert_eq!(common::parse_screen_size("3840X2160"), Some((3840, 2160)));
        assert_eq!(common::parse_screen_size("1024,768"), Some((1024, 768)));
        assert_eq!(
            common::parse_screen_size(" 2560 x 1440 "),
            Some((2560, 1440))
        );
        assert_eq!(common::parse_screen_size("garbage"), None);
        assert_eq!(common::parse_screen_size("1920x"), None);
        assert_eq!(common::parse_screen_size("0x1080"), None);
        assert_eq!(common::parse_screen_size("-1x10"), None);
    }

    #[test]
    fn screen_size_from_env_prefers_combined_then_pair() {
        let env = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            move |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };
        assert_eq!(
            screen_size_from_env(env(&[("ULTRANIX_SCREEN_SIZE", "3440x1440")])),
            Some((3440, 1440))
        );
        assert_eq!(
            screen_size_from_env(env(&[
                ("ULTRANIX_SCREEN_WIDTH", "2560"),
                ("ULTRANIX_SCREEN_HEIGHT", "1440"),
            ])),
            Some((2560, 1440))
        );
        // Combined wins over the per-axis pair.
        assert_eq!(
            screen_size_from_env(env(&[
                ("ULTRANIX_SCREEN_SIZE", "1920x1080"),
                ("ULTRANIX_SCREEN_WIDTH", "9999"),
                ("ULTRANIX_SCREEN_HEIGHT", "9999"),
            ])),
            Some((1920, 1080))
        );
        assert_eq!(screen_size_from_env(env(&[])), None);
        assert_eq!(
            screen_size_from_env(env(&[("ULTRANIX_SCREEN_SIZE", "bogus")])),
            None
        );
    }

    #[test]
    fn parse_monitors_takes_layout_bounding_box() {
        let json = br#"[
            {"x":0,"y":0,"width":1920,"height":1080},
            {"x":1920,"y":-300,"width":2560,"height":1440}
        ]"#;
        assert_eq!(common::parse_monitors_extent(json), Some((4480, 1140)));
        assert_eq!(common::parse_monitors_extent(b"[]"), None);
        assert_eq!(common::parse_monitors_extent(b"not json"), None);
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
    fn uinput_writable_probe() {
        // Missing node -> not writable.
        assert!(!uinput_writable(Path::new(
            "/dev/ultranix-nonexistent-uinput-node"
        )));
        // A directory can never be opened O_WRONLY (EISDIR) - reliable
        // even when tests run as root.
        assert!(!uinput_writable(Path::new("/tmp")));
        // A plain writable file opens fine (it is never created into a
        // device - this probe only tests open() success).
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(uinput_writable(f.path()));
    }

    #[test]
    fn open_returns_none_for_unwritable_paths() {
        // Exits through the early-probe path: `create_device` is never
        // reached, so no kernel device can be created.
        assert!(UinputInput::open(Path::new("/dev/ultranix-nonexistent"), 1920, 1080).is_none());
        assert!(UinputInput::open(Path::new("/tmp"), 1920, 1080).is_none());
    }

    #[test]
    fn open_rejects_nonpositive_bounds() {
        // A writable path with an invalid ABS range -> None through the
        // bounds gate, before `create_device` is ever reached.
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(UinputInput::open(f.path(), 0, 1080).is_none());
        assert!(UinputInput::open(f.path(), 1920, 0).is_none());
        assert!(UinputInput::open(f.path(), -1, -1).is_none());
    }

    #[test]
    fn open_returns_none_for_non_uinput_file() {
        // A plain writable file passes the open-for-write probe, then
        // `create_device` fails on the first uinput ioctl (ENOTTY) -
        // UI_DEV_CREATE is never reached, so no device can exist.
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(UinputInput::open(f.path(), 1920, 1080).is_none());
    }
}
