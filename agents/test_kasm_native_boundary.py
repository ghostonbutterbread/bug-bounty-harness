"""Opt-in actual KasmVNC input boundary probe, not native idle authorization.

Set BBH_KASMVNC_ROOT to an unprivileged dpkg-deb extraction. Only a private
server and disposable Chromium profile are used; no routes or accounts.
"""
import asyncio
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "skills/chromium-test/scripts"))
from browser_control import PipeBrowser, activity_control, rotate_control


class NativeClient:
    """Minimal Kasm RFB client; only handshake and synthetic local input."""
    def __init__(self, port):
        import websocket
        self.ws = websocket.create_connection(
            f"ws://127.0.0.1:{port}/websockify", subprotocols=["binary"], timeout=5)
        self.buffer = b""
        version = self.read(12)
        assert version.startswith(b"RFB "), version
        self.ws.send_binary(b"RFB 003.008\n")
        types = self.read(self.read(1)[0])
        assert 1 in types, types
        self.ws.send_binary(b"\x01")
        assert self.read(4) == b"\0" * 4
        self.ws.send_binary(b"\x01")
        header = self.read(24)
        self.read(struct.unpack("!I", header[20:24])[0])

    def read(self, size):
        while len(self.buffer) < size:
            chunk = self.ws.recv()
            assert isinstance(chunk, bytes) and chunk
            self.buffer += chunk
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def key(self, value):
        for down in (1, 0):
            self.ws.send_binary(struct.pack("!BBHI", 4, down, 0, ord(value)))

    def click(self, x, y):
        for mask in (1, 0):
            self.ws.send_binary(struct.pack("!BHHHhh", 5, mask, x, y, 0, 0))

    def close(self):
        self.ws.close()


@pytest.mark.skipif(not os.environ.get("BBH_KASMVNC_ROOT"), reason="disposable KasmVNC extraction opt-in")
def test_actual_native_input_is_not_fenced_by_cdp(tmp_path):
    root = Path(os.environ["BBH_KASMVNC_ROOT"]).resolve()
    executable = next((p for p in (root / "usr/bin/Xkasmvnc", root / "usr/bin/Xvnc") if p.is_file()), None)
    assert executable, "KasmVNC server executable required"
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    assert chrome
    receipt = {"native_idle_authorized": False, "native_live_transfer_authorized": False}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    reader, writer = os.pipe()
    log = (tmp_path / "server.log").open("wb")
    server = subprocess.Popen([
        str(executable), "-displayfd", str(writer), "-geometry", "1024x768", "-depth", "24",
        "-nolisten", "tcp", "-interface", "127.0.0.1", "-UseIPv6", "0",
        "-websocketPort", str(port), "-httpd", str(root / "usr/share/kasmvnc/www"),
        "-DisableBasicAuth", "1", "-SecurityTypes", "None", "-publicIP", "127.0.0.1",
        "-DLP_Log", "off", "-AlwaysShared", "1",
    ], pass_fds=(writer,), stdout=log, stderr=log)
    os.close(writer)
    browser = native = None
    display = None
    try:
        assert select.select([reader], [], [], 15)[0], "KasmVNC display startup deadline"
        display = os.read(reader, 64).decode().strip()
        assert display.isdigit() and server.poll() is None, (tmp_path / "server.log").read_text()
        receipt.update(server_pid=server.pid, display=":" + display, web_port=port)
        html = "data:text/html,<textarea autofocus style='position:fixed;inset:0;width:100%;height:100%'></textarea><script>window.clicks=0;document.onclick=()=>window.clicks++</script>"
        browser = PipeBrowser([
            chrome, "--ozone-platform=x11", "--remote-debugging-pipe", "--no-first-run", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--user-data-dir=" + str(tmp_path / "profile"),
            "--kiosk", html,
        ], env={**os.environ, "DISPLAY": ":" + display}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        control = tmp_path / "control.sock"
        browser.serve(0, control)

        def call(method, params=None, session=None):
            return asyncio.run_coroutine_threadsafe(browser.call(method, params, session), browser.loop).result(10)["result"]

        targets = call("Target.getTargets")["targetInfos"]
        page = next(t for t in targets if t["type"] == "page")
        session = call("Target.attachToTarget", {"targetId": page["targetId"], "flatten": True})["sessionId"]

        def value():
            return call("Runtime.evaluate", {"expression": "JSON.stringify({text:document.querySelector('textarea')?.value,clicks:window.clicks})", "returnByValue": True}, session)["result"]["value"]

        def wait_text(expected):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = json.loads(value())
                if result.get("text") == expected:
                    return result
                time.sleep(.05)
            raise AssertionError((expected, value()))

        wait_text("")
        call("Page.bringToFront", session=session)
        window = call("Browser.getWindowForTarget", {"targetId": page["targetId"]})
        assert window["bounds"]["width"] <= 1024
        assert window["bounds"]["height"] <= 768
        native = NativeClient(port)
        # DOM readiness precedes X window mapping/hit-test readiness. Establish
        # actual native focus, bounded, before the lifecycle boundary probe.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            native.click(150, 150)
            if json.loads(value()).get("clicks", 0):
                break
            time.sleep(.05)
        assert json.loads(value())["clicks"] > 0, "native window not ready"
        native.key("a")
        first = wait_text("a")
        assert first["clicks"] >= 1
        original = browser.last_use
        # Only this fixture stages its adapter clock; there is no clock endpoint.
        async def stage():
            browser.last_use = time.monotonic() - 7201
        asyncio.run_coroutine_threadsafe(stage(), browser.loop).result(5)
        assert activity_control(control, "freeze", idle_seconds=7200)["frozen"]
        native.click(160, 160)
        native.key("b")
        second = wait_text("ab")
        assert second["clicks"] > first["clicks"]
        assert browser.last_use < original
        receipt.update(native_key_and_mouse_delivered=True, native_input_survives_cdp_freeze=True,
                       native_input_does_not_update_cdp_clock=True)
        rotate_control(control)
        native.key("c")
        wait_text("abc")
        receipt["established_native_controller_survives_cdp_rotation"] = True
        # A simultaneous manager freeze and native key can both succeed: this is
        # a regression probe for the missing hook, NOT an enabled cleanup path.
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        asyncio.run_coroutine_threadsafe(stage(), browser.loop).result(5)
        gate = Barrier(2)
        def freeze_concurrently():
            gate.wait(timeout=5)
            return activity_control(control, "freeze", idle_seconds=7200)
        def input_concurrently():
            gate.wait(timeout=5)
            native.key("d")
        with ThreadPoolExecutor(max_workers=2) as executor:
            freezing = executor.submit(freeze_concurrently)
            sending = executor.submit(input_concurrently)
            sending.result(timeout=10)
            assert freezing.result(timeout=10)["frozen"]
        wait_text("abcd")
        receipt["concurrent_native_input_and_cdp_freeze_both_succeed"] = True
    finally:
        try:
            if native:
                native.close()
            if browser:
                browser.close()
                receipt["chromium_reaped"] = browser.process.poll() is not None
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Exact task-owned child only; never kill by process name.
                server.kill()
                server.wait(timeout=10)
            finally:
                os.close(reader)
                log.close()
                receipt["server_reaped"] = server.poll() is not None
                with socket.socket() as s:
                    receipt["web_listener_closed"] = s.connect_ex(("127.0.0.1", port)) != 0
                receipt["display_socket_removed"] = bool(display) and not Path(f"/tmp/.X11-unix/X{display}").exists()
                output = os.environ.get("BBH_KASMVNC_RECEIPT")
                if output:
                    Path(output).write_text(json.dumps(receipt, indent=2) + "\n")
        assert receipt["server_reaped"] and receipt["web_listener_closed"] and receipt["display_socket_removed"]
        if receipt.get("chromium_reaped"):
            shutil.rmtree(tmp_path / "profile")
            receipt["profile_removed"] = not (tmp_path / "profile").exists()
            if output:
                Path(output).write_text(json.dumps(receipt, indent=2) + "\n")


@pytest.mark.parametrize("modern", [None, "/task/bin/kasmvncserver"])
def test_kasm_server_names_share_start_and_stop_resolution(monkeypatch, tmp_path, modern):
    import kasmvnc_session as kasm
    monkeypatch.setattr(kasm.shutil, "which", lambda name: modern if name == "kasmvncserver" else None)
    expected = modern or "vncserver"
    assert kasm.build_start_command(91, 8491)[0] == expected
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(kasm.subprocess, "run", run)
    assert kasm.stop_session(91, tmp_path)["status"] == "stopped"
    assert commands == [[expected, "-kill", ":91"]]
