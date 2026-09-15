#!/usr/bin/env bash
# nested-test.sh — Phase-5 nested-compositor integration rig
# (ROADMAP Phase 5 "Nested-Hyprland integration test rig for real-Wayland CI";
# docs/TESTING_STRATEGY.md §2.2 "Tier 2 — session integration").
#
# Spawns a disposable Wayland compositor, launches
# `ultranix-mcp --transport stdio` bound to it, and drives the read-only
# MCP flow over JSON-RPC:
#
#   initialize → tools/list (assert exactly 32 tools) → get_windows
#   → screen_info → screenshot (assert PNG magic bytes) → get_ui_tree
#   → stdin EOF (shutdown; stdio MCP has no `shutdown` method — EOF is
#   the spec'd teardown and rmcp exits 0 on it)
#
# Compositor selection (first found on PATH; override with --compositor
# or ULTRANIX_NESTED_COMPOSITOR):
#
#   hyprland  `Hyprland -c <minimal>` — nested under the running Wayland
#             session when the parent WAYLAND_DISPLAY resolves, else
#             WLR_BACKENDS=headless (CI runners). Full assertion set.
#   sway      `WLR_BACKENDS=headless sway -c <minimal>`; a HEADLESS output
#             is created via `swaymsg create_output`. wlroots screencopy
#             works, so the PNG assertion is fully exercised; the window
#             provider is hyprctl-only, so get_windows must return the
#             structured -32010 ProviderUnavailable error.
#   weston    `weston --backend=headless-backend.so` — last resort:
#             weston lacks wlr-screencopy, so screenshot/screen_info
#             accept -32010 / isError instead of a PNG (documented
#             degradation).
#
# SAFETY
#   * Read-only tools only — the rig never calls input-injection tools
#     (no mouse_*, type_text, key_control, window_control, invoke_*).
#   * The compositor gets a PRIVATE XDG_RUNTIME_DIR ($WORK/runtime): its
#     hypr/<HIS>/ dir and wayland-* socket are the only entries there, so
#     the ambient session's sockets are unreachable by construction. The
#     spawned server likewise gets that private runtime dir + the nested
#     HYPRLAND_INSTANCE_SIGNATURE — never the ambient value — and a
#     scratch HOME so ~/.ultranix-mcp state lands in the workdir.
#   * The trap kills only the compositor PID it spawned.
#
# Usage:
#   scripts/nested-test.sh [--compositor hyprland|sway|weston] [--bin PATH]
#
# Env:
#   ULTRANIX_MCP_BIN           server binary (default: cargo build → target/debug)
#   ULTRANIX_NESTED_COMPOSITOR same as --compositor
#   ULTRANIX_NESTED_TIMEOUT    per-stage wait budget, seconds (default 20)
#   ULTRANIX_NESTED_KEEP=1     preserve the workdir (compositor/server logs)
#
# Requires: bash, find, plus python3 for the JSON-RPC driver (ubiquitous
# on dev machines and every GH-hosted runner; a stdio MCP client is far
# more robust in it than in sed/grep shell plumbing).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMEOUT="${ULTRANIX_NESTED_TIMEOUT:-20}"
MODE="${ULTRANIX_NESTED_COMPOSITOR:-}"
BIN="${ULTRANIX_MCP_BIN:-}"

log() { printf '[nested-test] %s\n' "$*" >&2; }
die() {
    log "FAIL: $*"
    exit 1
}

usage() {
    # Print the leading comment block (everything between `#!` and the
    # first non-comment line).
    awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' \
        "${BASH_SOURCE[0]}" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --compositor)
            MODE="${2:?--compositor needs a value}"
            shift 2
            ;;
        --bin)
            BIN="${2:?--bin needs a path}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage
            die "unknown argument: $1"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Scratch workdir + private runtime dir (0700 as libwayland requires).
#
# The path must stay SHORT: Hyprland builds
# `$XDG_RUNTIME_DIR/hypr/<HIS>/.socket2.sock` — the ~64-char HIS plus a
# long prefix overflows the ~108-byte unix sockaddr limit and Hyprland
# silently disables IPC ("Socket2 path is too long"). `uxn.XXXXXX` keeps
# RUNTIME ≈ 18 bytes so the composed socket path stays ≈ 100.
# ---------------------------------------------------------------------------
WORK="$(mktemp -d /tmp/uxn.XXXXXX)"
RUNTIME="$WORK/rt"
mkdir -p "$RUNTIME" "$WORK/home"
chmod 700 "$RUNTIME" "$WORK/home"
COMP_LOG="$WORK/compositor.log"
SERVER_LOG="$WORK/server.log"
COMP_PID=""

cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n ${COMP_PID} ]] && kill -0 "${COMP_PID}" 2>/dev/null; then
        kill "${COMP_PID}" 2>/dev/null || true
        for _ in $(seq 1 15); do
            kill -0 "${COMP_PID}" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "${COMP_PID}" 2>/dev/null || true
        wait "${COMP_PID}" 2>/dev/null || true
    fi
    if ((rc != 0)); then
        log "---- compositor log (tail) ----"
        tail -n 60 "${COMP_LOG}" >&2 2>/dev/null || true
        log "---- server log (tail) ----"
        tail -n 60 "${SERVER_LOG}" >&2 2>/dev/null || true
    fi
    if [[ ${ULTRANIX_NESTED_KEEP:-0} == 1 ]]; then
        log "kept workdir: ${WORK}"
    else
        rm -rf "${WORK}"
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# wait_for <description> <cmd...> — poll cmd each 200ms up to $TIMEOUT,
# bailing early if the spawned compositor already died.
# ---------------------------------------------------------------------------
wait_for() {
    local desc="$1"
    shift
    local deadline=$((SECONDS + TIMEOUT))
    while ((SECONDS < deadline)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        if [[ -n ${COMP_PID} ]] && ! kill -0 "${COMP_PID}" 2>/dev/null; then
            die "compositor exited while waiting for ${desc} (log: ${COMP_LOG})"
        fi
        sleep 0.2
    done
    die "timeout (${TIMEOUT}s) waiting for ${desc}"
}

any_wayland_socket() {
    find "$RUNTIME" -maxdepth 1 -name 'wayland-*' -type s -print -quit | grep -q .
}

first_wayland_socket() {
    basename "$(find "$RUNTIME" -maxdepth 1 -name 'wayland-*' -type s | head -n1)"
}

any_hypr_instance() {
    find "$RUNTIME/hypr" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null | grep -q .
}

any_sway_ipc() {
    find "$RUNTIME" -maxdepth 1 -name 'sway-ipc.*.sock' -type s -print -quit | grep -q .
}

first_hypr_instance() {
    basename "$(find "$RUNTIME/hypr" -mindepth 1 -maxdepth 1 -type d | head -n1)"
}

# Absolute path to the parent session's Wayland socket, or "" when there is
# no display to nest under (CI → headless backend).
parent_wayland_socket() {
    local wl="${WAYLAND_DISPLAY:-}"
    [[ -z ${wl} ]] && return 1
    if [[ ${wl} == /* && -S ${wl} ]]; then
        printf '%s\n' "${wl}"
    elif [[ -n ${XDG_RUNTIME_DIR:-} && -S ${XDG_RUNTIME_DIR}/${wl} ]]; then
        printf '%s/%s\n' "${XDG_RUNTIME_DIR}" "${wl}"
    elif [[ -S /run/user/$(id -u)/${wl} ]]; then
        printf '/run/user/%s/%s\n' "$(id -u)" "${wl}"
    else
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Compositor launchers. Every one runs with the private XDG_RUNTIME_DIR and
# with HYPRLAND_INSTANCE_SIGNATURE explicitly stripped from the launch env —
# the nested instance generates its own signature and ambient inheritance
# must never alias the real session.
# ---------------------------------------------------------------------------
launch_hyprland() {
    local cfg="$WORK/hyprland.conf"
    cat >"$cfg" <<'EOF'
# Minimal nested-test config: no exec-once, no autostart, no keybinds
# that could collide with the host session (and the rig never injects
# input anyway). The monitor rule covers whichever output backend the
# nested instance picks (WL-1 windowed / HEADLESS-1 headless).
monitor = ,preferred,auto,1
misc {
    force_default_wallpaper = 0
    disable_hyprland_logo = true
}
animations {
    enabled = false
}
EOF

    local -a env_args=(
        "XDG_RUNTIME_DIR=${RUNTIME}"
        "XDG_SESSION_TYPE=wayland"
    )
    local parent
    if parent="$(parent_wayland_socket)"; then
        # Absolute path: libwayland uses it verbatim, so the nested client
        # side reaches the parent even though XDG_RUNTIME_DIR is private.
        env_args+=("WAYLAND_DISPLAY=${parent}")
        log "nesting Hyprland under parent socket ${parent}"
    else
        env_args+=("WLR_BACKENDS=headless" "WLR_RENDERER=pixman")
        log "no parent Wayland session — Hyprland headless backend"
    fi

    env -u HYPRLAND_INSTANCE_SIGNATURE -u DISPLAY "${env_args[@]}" \
        Hyprland -c "$cfg" >"$COMP_LOG" 2>&1 &
    COMP_PID=$!

    wait_for "Hyprland instance dir under ${RUNTIME}/hypr" any_hypr_instance
    HIS="$(first_hypr_instance)"
    [[ -n ${HIS} ]] || die "empty HYPRLAND_INSTANCE_SIGNATURE discovered"
    # Never alias the real session (should be impossible — private dir).
    if [[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} && ${HIS} == "${HYPRLAND_INSTANCE_SIGNATURE}" ]]; then
        die "nested HIS collides with the ambient session signature"
    fi
    # Guard the unix sockaddr limit: if <RUNTIME>/hypr/<HIS>/.socket2.sock
    # exceeds ~108 bytes Hyprland disables IPC entirely (and the wait below
    # would just time out). Fail fast with the reason instead.
    local socklen=$((${#RUNTIME} + 6 + ${#HIS} + 14))
    if ((socklen > 107)); then
        die "composed Hyprland IPC path is ${socklen}B (>107): shorten the workdir"
    fi
    wait_for "Hyprland IPC socket (.socket.sock)" test -S "${RUNTIME}/hypr/${HIS}/.socket.sock"
    wait_for "nested wayland-* socket" any_wayland_socket
    WL="$(first_wayland_socket)"

    # Headless backend starts with zero outputs; screencopy needs one.
    if [[ -z ${parent} ]] && command -v hyprctl >/dev/null 2>&1; then
        XDG_RUNTIME_DIR="${RUNTIME}" HYPRLAND_INSTANCE_SIGNATURE="${HIS}" \
            hyprctl output create headless >>"$COMP_LOG" 2>&1 ||
            log "WARN: 'hyprctl output create headless' failed — capture assertions may fail"
    fi
}

launch_sway() {
    command -v swaymsg >/dev/null 2>&1 ||
        log "WARN: swaymsg not found — cannot create a headless output; capture assertions may fail"
    local cfg="$WORK/sway.conf"
    printf '# Minimal nested-test config: defaults, no exec lines.\n' >"$cfg"

    # Always headless: deterministic on CI, and never opens a window in
    # the user's session even when a parent Wayland exists.
    env -u WAYLAND_DISPLAY -u DISPLAY -u HYPRLAND_INSTANCE_SIGNATURE \
        XDG_RUNTIME_DIR="${RUNTIME}" XDG_SESSION_TYPE=wayland \
        WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1 \
        sway -c "$cfg" >"$COMP_LOG" 2>&1 &
    COMP_PID=$!

    wait_for "nested wayland-* socket" any_wayland_socket
    WL="$(first_wayland_socket)"
    HIS=""

    # wlroots headless starts with zero outputs — create one via IPC.
    local sway_sock=""
    wait_for "sway IPC socket" any_sway_ipc
    sway_sock="$(find "$RUNTIME" -maxdepth 1 -name 'sway-ipc.*.sock' -type s | head -n1)"
    if command -v swaymsg >/dev/null 2>&1; then
        SWAYSOCK="${sway_sock}" swaymsg create_output >>"$COMP_LOG" 2>&1 ||
            log "WARN: 'swaymsg create_output' failed — capture assertions may fail"
    fi
}

launch_weston() {
    local sock="ultranix-nested"
    # --socket names the wayland socket explicitly; headless backend
    # creates one output by itself.
    env -u WAYLAND_DISPLAY -u DISPLAY -u HYPRLAND_INSTANCE_SIGNATURE \
        XDG_RUNTIME_DIR="${RUNTIME}" XDG_SESSION_TYPE=wayland \
        weston --backend=headless-backend.so --socket="${sock}" \
        --idle-time=0 --width=1280 --height=720 >"$COMP_LOG" 2>&1 &
    COMP_PID=$!

    wait_for "weston socket ${sock}" test -S "${RUNTIME}/${sock}"
    WL="${sock}"
    HIS=""
}

# ---------------------------------------------------------------------------
# Compositor detection.
# ---------------------------------------------------------------------------
case "${MODE}" in
    "") ;;
    hyprland) command -v Hyprland >/dev/null 2>&1 || die "Hyprland not on PATH" ;;
    sway) command -v sway >/dev/null 2>&1 || die "sway not on PATH" ;;
    weston) command -v weston >/dev/null 2>&1 || die "weston not on PATH" ;;
    *) die "unknown --compositor '${MODE}' (hyprland|sway|weston)" ;;
esac
if [[ -z ${MODE} ]]; then
    if command -v Hyprland >/dev/null 2>&1; then
        MODE=hyprland
    elif command -v sway >/dev/null 2>&1; then
        MODE=sway
    elif command -v weston >/dev/null 2>&1; then
        MODE=weston
    else
        die "no usable compositor on PATH (looked for Hyprland, sway, weston)"
    fi
fi

log "compositor: ${MODE}"
HIS=""
WL=""
"launch_${MODE}"
log "nested session up: WAYLAND_DISPLAY=${WL} HIS=${HIS:-<none>} runtime=${RUNTIME}"

# ---------------------------------------------------------------------------
# Server binary.
# ---------------------------------------------------------------------------
if [[ -z ${BIN} ]]; then
    log "building ultranix-mcp (cargo build --bin ultranix-mcp)"
    cargo build --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" --bin ultranix-mcp
    BIN="${REPO_ROOT}/target/debug/ultranix-mcp"
fi
[[ -x ${BIN} ]] || die "server binary not found/executable: ${BIN}"
log "server: ${BIN}"

command -v python3 >/dev/null 2>&1 ||
    die "python3 is required for the JSON-RPC stdio driver"

export ULTRANIX_MCP_BIN="${BIN}"
export ULTRANIX_NESTED_RUNTIME="${RUNTIME}"
export ULTRANIX_NESTED_WAYLAND_DISPLAY="${WL}"
export ULTRANIX_NESTED_HIS="${HIS}"
export ULTRANIX_NESTED_COMPOSITOR="${MODE}"
export ULTRANIX_NESTED_HOME="${WORK}/home"
export ULTRANIX_NESTED_SERVER_LOG="${SERVER_LOG}"
export ULTRANIX_NESTED_TIMEOUT="${TIMEOUT}"

# ---------------------------------------------------------------------------
# JSON-RPC driver. Speaks MCP-over-stdio: newline-delimited JSON-RPC on
# stdin/stdout (server diagnostics are on stderr → $SERVER_LOG).
#
# Step expectations are mode-aware: the window provider only exists under
# Hyprland (hyprctl IPC), and capture only where wlr-screencopy/grim can
# work (hyprland, sway). Under weston those calls must still fail
# *cleanly* — structured -32010 or an isError result, never a transport
# failure. get_ui_tree is informational: AT-SPI2 availability depends on
# the session bus, not the compositor.
# ---------------------------------------------------------------------------
python3 - <<'PYEOF'
import base64
import json
import os
import select
import subprocess
import sys
import time

BIN = os.environ["ULTRANIX_MCP_BIN"]
RUNTIME = os.environ["ULTRANIX_NESTED_RUNTIME"]
WL = os.environ["ULTRANIX_NESTED_WAYLAND_DISPLAY"]
HIS = os.environ.get("ULTRANIX_NESTED_HIS", "")
MODE = os.environ["ULTRANIX_NESTED_COMPOSITOR"]
HOME_DIR = os.environ["ULTRANIX_NESTED_HOME"]
SERVER_LOG = os.environ["ULTRANIX_NESTED_SERVER_LOG"]
TIMEOUT = float(os.environ.get("ULTRANIX_NESTED_TIMEOUT", "20"))

EXPECT_WINDOW = MODE == "hyprland"
EXPECT_CAPTURE = MODE in ("hyprland", "sway")
DESKTOP = {"hyprland": "Hyprland", "sway": "sway:wlroots", "weston": "weston"}.get(MODE, MODE)
PROVIDER_UNAVAILABLE = -32010

env = os.environ.copy()
env.update({
    "XDG_RUNTIME_DIR": RUNTIME,
    "WAYLAND_DISPLAY": WL,
    "XDG_SESSION_TYPE": "wayland",
    "XDG_CURRENT_DESKTOP": DESKTOP,
    "HOME": HOME_DIR,
    "ULTRANIX_MCP_LOG_LEVEL": "info",
})
env.pop("DISPLAY", None)
if HIS:
    env["HYPRLAND_INSTANCE_SIGNATURE"] = HIS
else:
    # Never let the server bind to the ambient session's IPC socket.
    env.pop("HYPRLAND_INSTANCE_SIGNATURE", None)
for key in list(env):
    if key.startswith("ULTRANIX_NESTED_") or key == "ULTRANIX_MCP_BIN":
        env.pop(key)

logf = open(SERVER_LOG, "w", encoding="utf-8")
proc = subprocess.Popen(
    [BIN, "--transport", "stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=logf,
    text=True,
    bufsize=1,
    env=env,
)

results = []


def step(ok, name, detail=""):
    results.append((ok, name))
    tag = "PASS" if ok else "FAIL"
    print(f"[nested-test] {tag} {name}" + (f" — {detail}" if detail else ""), flush=True)


def send(msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def read_reply(want_id, timeout=TIMEOUT):
    """Read stdout lines until the response for want_id arrives (server
    notifications are skipped). Raises on EOF or timeout."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"no reply for id={want_id} within {timeout}s")
        r, _, _ = select.select([proc.stdout], [], [], left)
        if not r:
            raise TimeoutError(f"no reply for id={want_id} within {timeout}s")
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        msg = json.loads(line)
        if msg.get("id") == want_id:
            return msg


def rpc_error_code(msg):
    err = msg.get("error") or {}
    return err.get("code")


def tool_result(msg):
    """result payload if the call produced one, else None."""
    return msg.get("result")


def is_error_result(res):
    return bool(res) and res.get("isError") is True


def first_text(res):
    for item in (res or {}).get("content", []):
        if item.get("type") == "text":
            return item.get("text", "")
    return ""


try:
    # --- initialize -------------------------------------------------------
    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ultranix-nested-test", "version": "0"},
        },
    })
    r = read_reply(1)
    info = (r.get("result") or {}).get("serverInfo") or {}
    step(info.get("name") == "ultranix-mcp", "initialize",
         f"serverInfo={info.get('name')!r} protocol={(r.get('result') or {}).get('protocolVersion')!r}")

    send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    # --- tools/list --------------------------------------------------------
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    r = read_reply(2)
    tools = (r.get("result") or {}).get("tools") or []
    names = sorted(t.get("name") for t in tools)
    step(len(tools) == 32, "tools/list", f"{len(tools)} tools")
    for needed in ("get_windows", "screen_info", "screenshot", "get_ui_tree"):
        step(needed in names, f"tools/list contains {needed}")

    def call(rid, name, arguments):
        send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
              "params": {"name": name, "arguments": arguments}})
        return read_reply(rid, timeout=max(TIMEOUT, 30))

    # --- get_windows -------------------------------------------------------
    r = call(3, "get_windows", {})
    if EXPECT_WINDOW:
        res = tool_result(r)
        ok = res is not None and not is_error_result(res)
        detail = ""
        if ok:
            try:
                wins = json.loads(first_text(res))
                ok = isinstance(wins, list)
                detail = f"{len(wins)} window(s) in nested session"
            except ValueError:
                ok = False
                detail = "non-JSON payload"
        step(ok, "get_windows (hyprctl provider)", detail or json.dumps(r)[:160])
    else:
        step(rpc_error_code(r) == PROVIDER_UNAVAILABLE or is_error_result(tool_result(r)),
             "get_windows → structured unavailable (no hyprctl under non-Hyprland)",
             f"code={rpc_error_code(r)}")

    # --- screen_info --------------------------------------------------------
    r = call(4, "screen_info", {})
    if EXPECT_CAPTURE:
        res = tool_result(r)
        ok = res is not None and not is_error_result(res)
        detail = ""
        if ok:
            try:
                json.loads(first_text(res))
                detail = "output geometry returned"
            except ValueError:
                ok = False
                detail = "non-JSON payload"
        step(ok, "screen_info (wlr capture)", detail or json.dumps(r)[:160])
    else:
        step(rpc_error_code(r) == PROVIDER_UNAVAILABLE or is_error_result(tool_result(r)),
             "screen_info → structured unavailable (weston has no wlr-screencopy)",
             f"code={rpc_error_code(r)}")

    # --- screenshot ---------------------------------------------------------
    r = call(5, "screenshot", {})
    if EXPECT_CAPTURE:
        res = tool_result(r)
        img = next((c for c in (res or {}).get("content", [])
                    if c.get("type") == "image"), None)
        ok = False
        detail = json.dumps(r)[:160]
        if res is not None and not is_error_result(res) and img:
            try:
                raw = base64.b64decode(img.get("data", ""), validate=True)
                ok = (img.get("mimeType") == "image/png"
                      and raw[:8] == b"\x89PNG\r\n\x1a\n")
                detail = f"{len(raw)}B PNG, magic ok"
            except Exception as exc:  # noqa: BLE001 — report, not crash
                detail = f"bad image payload: {exc}"
        step(ok, "screenshot (PNG magic)", detail)
    else:
        step(rpc_error_code(r) == PROVIDER_UNAVAILABLE or is_error_result(tool_result(r)),
             "screenshot → structured unavailable (weston has no wlr-screencopy)",
             f"code={rpc_error_code(r)}")

    # --- get_ui_tree (informational) ----------------------------------------
    # AT-SPI2 hangs off the session bus, not the compositor: either a real
    # tree or -32010 is a valid outcome. A transport/protocol break is not.
    r = call(6, "get_ui_tree", {"depth": 1})
    res = tool_result(r)
    ok = (res is not None) or rpc_error_code(r) == PROVIDER_UNAVAILABLE
    step(ok, "get_ui_tree (session-bus dependent, informational)",
         f"code={rpc_error_code(r)}" if res is None else "tree returned")

    # --- shutdown ------------------------------------------------------------
    # stdio MCP has no `shutdown` method: closing stdin is the spec'd
    # teardown and rmcp must exit 0.
    proc.stdin.close()
    try:
        rc = proc.wait(timeout=10)
        step(rc == 0, "shutdown on stdin EOF", f"exit={rc}")
    except subprocess.TimeoutExpired:
        step(False, "shutdown on stdin EOF", "server did not exit within 10s")

except Exception as exc:  # noqa: BLE001 — any driver failure = rig failure
    step(False, "driver", f"{type(exc).__name__}: {exc}")
finally:
    if proc.poll() is None:
        proc.kill()
    logf.close()

failed = [n for ok, n in results if not ok]
print(f"[nested-test] {len(results) - len(failed)}/{len(results)} steps passed"
      + (f" — failed: {', '.join(failed)}" if failed else ""), flush=True)
sys.exit(1 if failed else 0)
PYEOF

log "PASS — compositor=${MODE} wayland=${WL} his=${HIS:-none} (read-only flow, nested session only)"
