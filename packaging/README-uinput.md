# ultranix-mcp - opt-in `/dev/uinput` access

The evdev/uinput `InputProvider` is a **fallback**for sessions where the
compositor-native input paths (wlr-virtual-pointer / virtual-keyboard on
Hyprland and other wlroots compositors) are unavailable. It needs write
access to `/dev/uinput`, which is a persistent, system-level permission -
so it ships as an explicit opt-in, never auto-enabled.

If you are on Hyprland/wlroots you do **not**need any of this.

## Threat model (why the dedicated group)

`99-ultranix-mcp-uinput.rules` grants `/dev/uinput` to a **dedicated**
`ultranix-input` group that must contain *only* the account running the
server. Never change the rule to `GROUP="input"`: the `input` group can
read real input devices - membership is effectively a keylogger
permission (see `docs/THREAT_MODEL.md` §4.1).

## Setup (copy-paste)

```bash
# 1. Install the rule (already done if you installed the distro package;
# otherwise copy it into place):
sudo install -Dm0644 99-ultranix-mcp-uinput.rules \
  /etc/udev/rules.d/99-ultranix-mcp-uinput.rules

# 2. Load the kernel module at boot and now:
echo uinput | sudo tee /etc/modules-load.d/uinput.conf
sudo modprobe uinput

# 3. Dedicated group holding ONLY the service user:
sudo groupadd ultranix-input
sudo usermod -aG ultranix-input "$USER"

# 4. Apply the rule:
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=uinput
# (on some systems the node is static: re-trigger via
# `sudo udevadm trigger --subsystem-match=uinput` or reboot)

# 5. Re-login - group membership only applies to new sessions.
```

## Verify

```bash
ls -l /dev/uinput        # crw-rw---- root ultranix-input
groups | grep ultranix-input
test -w /dev/uinput && echo "uinput writable"
ultranix-mcp --transport stdio   # probe log: InputProvider=UinputInput
```

## Seat-scoped alternative (single-seat workstations)

Instead of group membership, grant the seat's *active* user via logind by
replacing the rule with:

```
SUBSYSTEM=="uinput", TAG+="uaccess", OPTIONS+="static_node=uinput"
```

Only pick one variant - the group rule and the uaccess rule are
alternatives, not complements.

## Removing access

```bash
sudo gpasswd -d <user> ultranix-input   # or: groupdel ultranix-input
sudo rm /etc/udev/rules.d/99-ultranix-mcp-uinput.rules
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=uinput
```

The server degrades gracefully - without `/dev/uinput` write access the
uinput rung resolves to `None` and the remaining input backends (wlroots
virtual input, portal RemoteDesktop) keep working.
