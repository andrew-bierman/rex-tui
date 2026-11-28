#!/usr/bin/env python3
"""Verify rex-tui mouse interactions through a packaged launcher and disposable Rex."""

import argparse
import base64
import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import subprocess
import tempfile
import termios
import time

CLIPBOARD = re.compile(rb"\x1b\]52;c;([A-Za-z0-9+/=]+)\x1b\\")
CAPTURE_ON = b"\x1b[?1002h\x1b[?1006h"
CAPTURE_OFF = b"\x1b[?1006l\x1b[?1002l"
SETTINGS_HINT = b"R Reload  Tab Help"


def exercise(launcher, root, env, api, mouse_actions):
    settings = root / "config" / "rex-tui" / "settings.toml"
    settings.write_text("[sidebar]\nwidth = 20\n")
    master, slave = pty.openpty()
    try:
        termios.tcsetwinsize(slave, (24, 80))
        app = subprocess.Popen([launcher], env=env, stdin=slave, stdout=slave, stderr=slave)
    finally:
        os.close(slave)
    output = bytearray()

    def pump():
        if select.select([master], [], [], .05)[0]:
            try:
                output.extend(os.read(master, 65536))
            except OSError as error:
                # Linux PTY masters report EIO when the last slave closes.
                if error.errno != errno.EIO:
                    raise

    def wait_for(predicate, description):
        deadline = time.monotonic() + 10
        while not predicate():
            if time.monotonic() >= deadline or app.poll() is not None:
                raise AssertionError(f"{description}: {bytes(output[-1200:])!r}")
            pump()

    def send(data):
        os.write(master, data)

    def open_settings(description):
        start = len(output)
        send(b"\x1bOP")  # F1 opens Help.
        wait_for(lambda: b"Tab Settings" in output[start:], "open Help")
        start = len(output)
        send(b"\t")
        wait_for(lambda: SETTINGS_HINT in output[start:], description)

    def clipboard():
        return [base64.b64decode(match) for match in CLIPBOARD.findall(output)]

    try:
        wait_for(lambda: b"F2 Create session" in output, "connected to private Rex")
        assert CAPTURE_ON not in output, "mouse capture was enabled by default"
        send(b"\x1bOQ")
        wait_for(
            lambda: b"Waiting for terminal" in output or b"rex-selection-private>" in output,
            "opening a shell",
        )
        send(b"\x1b[19~")
        wait_for(
            lambda: len(api("session.list")["sessions"]) == 1
            and len(blocks(api, api("session.list")["sessions"][0]["session_id"])) == 2,
            "right split",
        )
        sid = api("session.list")["sessions"][0]["session_id"]
        for pane, marker in zip(blocks(api, sid), ("LEFT_PANE_ONLY", "RIGHT_PANE_ONLY"), strict=True):
            command = f"export TEST_PANE={marker}; printf '\\033[2J\\033[H{marker}\\n'"
            api("block.event", session_id=sid, block_id=pane,
                event={"type": "paste", "payload": {"text": command}})
            api("block.event", session_id=sid, block_id=pane,
                event={"type": "key", "payload": {"key": "enter", "action": "press", "mods": ""}})
        wait_for(lambda: b"LEFT_PANE_ONLY" in output and b"RIGHT_PANE_ONLY" in output, "both pane markers")

        settings.write_text("[sidebar]\nwidth = 20\n[selection]\nmouse = true\n")
        open_settings("open Settings")
        send(b"r")
        wait_for(lambda: CAPTURE_ON in output, "enable mouse capture on reload")
        send(b"\x1b")
        time.sleep(.15)

        def drag_and_copy(start, end, expected):
            count = len(clipboard())
            x1, y1 = start
            x2, y2 = end
            send(f"\x1b[<0;{x1};{y1}M\x1b[<32;{x2};{y2}M\x1b[<0;{x2};{y2}m".encode())
            send(b"\x1b[24~")
            wait_for(lambda: len(clipboard()) == count + 1, "copy after release acknowledgement")
            assert clipboard()[-1] == expected, clipboard()

        # One-based SGR coordinates, both ends on the first and last letters.
        drag_and_copy((22, 5), (35, 5), b"LEFT_PANE_ONLY")
        drag_and_copy((35, 5), (22, 5), b"LEFT_PANE_ONLY")
        drag_and_copy((35, 5), (2, 5), b"LEFT_PANE_ONLY")

        # Drag out through the *other* pane. Fresh clipboard content is still
        # exactly the left marker and cannot include the right marker.
        copy_count = len(clipboard())
        send(b"\x1b[<0;22;5M\x1b[<32;76;5M\x1b[<0;76;5m")
        send(b"\x1b[24~")
        wait_for(lambda: len(clipboard()) == copy_count + 1, "copy clipped across other pane")
        assert clipboard()[-1] == b"LEFT_PANE_ONLY", clipboard()

        left = blocks(api, sid)[0]
        columns = root / "pane-columns"
        seed = (
            "import os; from pathlib import Path; "
            "width=os.get_terminal_size().columns; "
            f"Path({str(columns)!r}).write_text(str(width)); "
            "print(chr(27)+'[2J'+chr(27)+'[H'+'A'*(width-2)+'XY界Z')"
        )
        start = len(output)
        api("block.event", session_id=sid, block_id=left,
            event={"type": "paste", "payload": {"text": f"python3 -c {shlex.quote(seed)}"}})
        api("block.event", session_id=sid, block_id=left,
            event={"type": "key", "payload": {"key": "enter", "action": "press", "mods": ""}})
        wait_for(lambda: columns.exists() and b"\x1b[6;24HZ" in output[start:],
                 "wide text wrapped inside the pane")
        width = int(columns.read_text())
        wrapped = ("A" * (width - 2) + "XY界Z").encode()
        drag_and_copy((22, 5), (24, 6), wrapped)
        drag_and_copy((24, 6), (22, 5), wrapped)
        drag_and_copy((24, 6), (23, 6), "界Z".encode())
        api("block.event", session_id=sid, block_id=left,
            event={"type": "paste", "payload": {"text": "printf '\\033[2J\\033[HLEFT_PANE_ONLY\\n'"}})
        api("block.event", session_id=sid, block_id=left,
            event={"type": "key", "payload": {"key": "enter", "action": "press", "mods": ""}})

        open_settings("reopen Settings")
        copy_count = len(clipboard())
        send(b"\x1b[24~")
        pump()
        assert len(clipboard()) == copy_count, "modal leaked copy shortcut"
        if mouse_actions:
            settings.write_text("[sidebar]\nwidth = 20\n[selection]\nmouse = false\n"
                                "[experimental]\nmouse_actions = true\n")
            send(b"r\x1b")
            time.sleep(.15)

            def proof(name, expected):
                path = root / name
                command = f"""printf '%s' "$TEST_PANE" > '{path}'""".encode()
                send(b"\x1b[200~" + command + b"\x1b[201~\r")
                wait_for(lambda: path.exists() and bool(path.read_text()), name)
                assert path.read_text() == expected, (name, path.read_text())

            # Click the left pane without dragging; input reaches the acknowledged
            # pane. Dragging in the right pane keeps the left pane's input focus.
            send(b"\x1b[<0;24;5M\x1b[<0;24;5m")
            wait_for(lambda: b"Terminal" in output, "focus left pane by click")
            proof("after-click", "LEFT_PANE_ONLY")
            count = len(clipboard())
            send(b"\x1b[<0;52;5M\x1b[<32;76;5M\x1b[<0;76;5m\x1b[24~")
            wait_for(lambda: len(clipboard()) == count + 1, "copy right-pane drag")
            assert clipboard()[-1] == b"RIGHT_PANE_ONLY"
            proof("after-drag", "LEFT_PANE_ONLY")

            # An unfocused pane's menu exposes Focus but disables Split until
            # selection has been acknowledged. Opening the menu is nonmutating.
            start = len(output)
            send(b"\x1b[<2;60;5M\x1b[<2;60;5m")
            wait_for(lambda: b"Split right (unavailable)" in output[start:], "inactive pane menu")
            send(b"\x1b[<0;62;8M\x1b[<0;62;8m")
            pump()
            assert len(blocks(api, sid)) == 2
            send(b"\x1b[<0;62;6M\x1b[<0;62;6m")
            time.sleep(.2)
            proof("after-menu-focus", "RIGHT_PANE_ONLY")

            start = len(output)
            send(b"\x1b[<2;60;5M\x1b[<2;60;5m")
            wait_for(lambda: b"Esc Dismiss" in output[start:], "open focused pane menu")
            send(b"\x1b[<0;62;9M\x1b[<0;62;9m")
            wait_for(lambda: len(blocks(api, sid)) == 3, "split down through pane menu")

            # Sidebar mouse navigation and keyboard share row identity and
            # folding state. Opening a tab changes the server's active window.
            def active_window():
                return api("session.view", session_id=sid)["active_window_id"]

            first = active_window()
            send(b"\x1b[15~")
            wait_for(lambda: active_window() != first, "create second tab")
            second = active_window()
            time.sleep(.2)
            send(b"\x1b[<0;4;2M\x1b[<0;4;2m")  # Host disclosure.
            send(b"\x1b[<0;12;4M\x1b[<0;12;4m")  # Hidden first tab.
            time.sleep(.2)
            assert active_window() == second
            send(b"\x1b[<0;4;2M\x1b[<0;4;2m")
            send(b"\x1b[<0;12;4M\x1b[<0;12;4m")
            wait_for(lambda: active_window() == first, "open first tab by sidebar click")
            send(b"\x1bOF\r")  # End, Enter.
            wait_for(lambda: active_window() == second, "open second tab by keyboard")

            # The second tab's recent output supplies a known live tail and
            # older lines missing from the visible grid. Test real wheel events
            # and modified keyboard shortcuts against those marker transitions.
            send(b"\x1b[17~")
            time.sleep(.2)
            command = b"i=1; while [ \"$i\" -le 59 ]; do if [ \"$i\" -le 35 ]; then printf '%s\\n' EARLY'ZZZ'; else printf '%s\\n' BBBB'BBBB'; fi; i=$((i+1)); done; printf '%s\\n' LIVE'TAIL'"
            send(b"\x1b[200~" + command + b"\x1b[201~\r")
            wait_for(lambda: b"LIVETAIL" in output, "scrollback live tail")
            older = b"EARLYZZZ"
            wheel_up = b"\x1b[<64;24;5M"
            wheel_down = b"\x1b[<65;24;5M"
            start = len(output)
            send(wheel_up * 10)
            wait_for(lambda: older in output[start:], "pane wheel reveals older output")
            start = len(output)
            send(wheel_down * 10)
            wait_for(lambda: b"LIVETAIL" in output[start:], "pane wheel returns to live tail")
            start = len(output)
            send(b"\x1b[5;3~" * 10)
            wait_for(lambda: older in output[start:], "Alt+PageUp scrolls the terminal")
            start = len(output)
            send(b"\x1b[6;3~" * 10)
            wait_for(lambda: b"LIVETAIL" in output[start:], "Alt+PageDown scrolls the terminal")
            start = len(output)
            send(b"\x1b[5;3~" * 10)
            wait_for(lambda: older in output[start:], "scroll back before Alt+End")
            start = len(output)
            send(b"\x1b[1;3F")
            wait_for(lambda: b"LIVETAIL" in output[start:], "Alt+End jumps directly to the live tail")
            start = len(output)
            send(wheel_up * 10)
            wait_for(lambda: older in output[start:], "scroll before the next shell key")
            start = len(output)
            send(b"x")
            wait_for(lambda: b"LIVETAIL" in output[start:], "typing returns to the live tail")

            open_settings("reopen Settings after mouse actions")
        settings.write_text("[sidebar]\nwidth = 20\n")
        send(b"r")
        wait_for(lambda: CAPTURE_OFF in output, "disable mouse capture on reload")
        send(b"\x1b")
        time.sleep(.15)
        send(b"\x1b[21~")
        assert app.wait(timeout=4) == 0
        pump()
        print("Pane-only selection copied exact left-pane text across sidebar and split boundaries.")
        if mouse_actions:
            print("Pane clicks, drag and copy, pane menu, and sidebar mouse/keyboard passed.")
    finally:
        if app.poll() is None:
            app.kill()
            app.wait()
        os.close(master)


def blocks(api, session):
    view = api("session.view", session_id=session)
    return [block["block_id"] for window in view["windows"] for layer in window["layers"]
            for block in layer["blocks"] if block.get("creator_name") == "com.superlogical.terminal"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("launcher", type=Path, help="Path to the packaged rex-tui launcher")
    parser.add_argument("--mouse-actions", action="store_true", help="Also check opt-in focus and menu")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rex-tui-selection-") as temp:
        root = Path(temp)
        profile = root / "config" / "rex-tui" / "workspace.json"
        profile.parent.mkdir(parents=True)
        endpoint = f"unix://{root / 'rex.sock'}"
        profile.write_text(json.dumps({"hosts": [{"label": "Private Sidebar", "endpoint": endpoint}]}))
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("REX_", "HERDR_"))}
        env.update(HOME=temp, XDG_CONFIG_HOME=str(root / "config"),
                   XDG_STATE_HOME=str(root / "state"), XDG_RUNTIME_DIR=temp,
                   TERM="xterm-256color", SHELL="/bin/sh", PS1="rex-selection-private> ")
        rex = os.environ.get("REX_BIN", "rex")

        def api(method, **payload):
            command = [rex, "--autostart=false", "--server", endpoint, "api", "call",
                       method, json.dumps(payload)]
            return json.loads(subprocess.check_output(command, env=env, timeout=4))

        with (root / "server.log").open("wb") as log:
            server = subprocess.Popen([rex, "server", "run", "--listen", endpoint,
                                       "--restore=false", "--config", "/dev/null",
                                       "--state-dir", str(root / "server")],
                                      env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while not (root / "rex.sock").exists():
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Disposable Rex socket did not open")
                    time.sleep(.05)
                exercise(args.launcher.resolve(), root, env, api, args.mouse_actions)
            finally:
                server.terminate()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()
