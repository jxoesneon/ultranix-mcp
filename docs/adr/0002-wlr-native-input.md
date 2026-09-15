# ADR 0002: wlroots-Native Virtual Input as the Primary Input Path

- **Status:** Accepted
- **Date:** Phase 1 (Hyprland I/O)
- **Deciders:** ultranix-mcp architecture council
- **Related:** ADR 0004 (backend fallback chain)

## Context

`InputProvider` needs a mechanism to inject pointer and keyboard events on Linux.
The verified target environment is Hyprland (wlroots family) on Wayland. Candidate
mechanisms:

1. **wlroots virtual input protocols** — `zwlr_virtual_pointer_v1`
   (wlr-virtual-pointer-unstable-v1) and `virtual-keyboard-unstable-v1`. These are
   compositor-side protocols: the client creates virtual devices over the Wayland
   socket, and the compositor dispatches events into the session exactly like
   hardware input.
2. **uinput/evdev** — kernel-level virtual input devices via `/dev/uinput`.
   Requires the device node to be writable (udev rule + dedicated group
   membership) and works on any session type, Wayland or X11.
3. **ydotool** — a uinput wrapper requiring the `ydotoold` daemon running as a
   privileged service.
4. **XDG Desktop Portal `RemoteDesktop`** — cross-compositor, permission-mediated
   input injection via D-Bus; requires a portal round-trip and (on most backends)
   a persistent session grant.
5. **xdotool** — X11 only (XWayland at best); cannot inject into native Wayland
   surfaces.

Constraints:

- The server runs as an unprivileged `--user` systemd service. Any path
  requiring root, a setuid helper, or a privileged daemon is a deployment tax.
- Input dispatch must hit <10ms for `mouse_click` on the fast path.
- Hyprland implements the wlroots virtual-input protocols natively — no
  compositor plugin, no portal prompt, no permission dialog on the fast path.

## Decision

- **Primary input path: wlroots-native protocols.** `WlrInput` implements
  `InputProvider` over `zwlr_virtual_pointer_v1` + `virtual-keyboard-unstable-v1`,
  in-process over the existing Wayland connection.
- **uinput/evdev** is the first fallback (`UinputInput`), gated by a documented
  udev rule — `SUBSYSTEM=="uinput", MODE="0660", GROUP="ultranix-input"` with
  only the service user in the dedicated `ultranix-input` group — never a root
  daemon, and never the broad `input` group: per the threat model, `input`
  membership grants read access to every evdev node, i.e. keylogger
  permission, which an automation server must not require.
- **Portal `RemoteDesktop`** (zbus) is the last-resort fallback for compositors
  exposing neither wlroots protocols nor writable uinput.
- **ydotool is rejected** — it adds a privileged daemon dependency with no
  capability gain over direct uinput access.
- **xdotool** is retained only inside the X11 fallback chain (XWayland sessions)
  — *post-v1 rung: the X11-native providers are not shipped at v1.0.0.*

## Consequences

**Positive:**

- **No root, no daemon** on the primary path — the `--user` service and
  `NoNewPrivileges=true` hardening remain intact on Hyprland.
- **Latency:** protocol dispatch is a single Wayland round-trip — comfortably
  under the <10ms `mouse_click` target; no device-node setup cost at runtime.
- **Correctness:** virtual-pointer events go through the compositor's own input
  pipeline, so focus, pointer constraints, and seat semantics behave identically
  to hardware input — avoiding the class of "synthetic event ignored" bugs
  portal/X11 injection can hit.
- **Symmetry with capture:** screencopy + virtual input share one Wayland
  connection and one capability probe.

**Negative / accepted trade-offs:**

- **wlroots-only fast path.** Non-wlroots compositors (KDE KWin, GNOME Mutter)
  do not implement these protocols; there `InputProvider` falls back to uinput
  or portal per ADR 0004 — correct but slower and, for portal, permission-gated.
- Protocol availability is a runtime property: detection must query the Wayland
  registry, not just `XDG_CURRENT_DESKTOP` (a wlroots session can mask the
  globals). The startup probe binds the globals and fails to `None` cleanly.
- `virtual-keyboard-unstable-v1` requires delivering a keymap before key events;
  the provider must keep a cached keymap and handle `keymap`/`modifiers` state —
  modest implementation complexity owned inside `WlrInput`.

**Follow-ups:**

- Ship the udev rule in `packaging/` and surface a `get_action_history`-adjacent
  diagnostic when uinput is probed but `/dev/uinput` is not writable.
- Add integration coverage for both paths: real Hyprland session (wlr-native)
  and Xvfb+xdotool (X11 chain — post-v1) per TESTING_STRATEGY.md.
