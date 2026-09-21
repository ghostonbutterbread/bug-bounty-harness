"""Local-only pipe fencing fixture; never loads real account state."""

import json
import os
from pathlib import Path
import shutil
import sys
import urllib.error
import urllib.request

import pytest

SCRIPTS = Path(__file__).parents[1] / "skills/chromium-test/scripts"
sys.path.insert(0, str(SCRIPTS))
from browser_lifecycle import owner_state, process_identity


def test_pid_identity_and_reuse():
    identity = process_identity(os.getpid())
    assert owner_state(identity) == "active"
    assert owner_state({**identity, "start": "not-this-process"}) == "terminal"
    assert owner_state({**identity, "node": "another-node"}) == "unknown"
    assert owner_state(None) == "unknown"


def test_failed_detach_cannot_acknowledge_fence():
    import asyncio
    from browser_control import PipeBrowser

    browser = PipeBrowser.__new__(PipeBrowser)

    async def failed(*_):
        return {"error": {"code": -32000, "message": "Cannot detach active session"}}

    browser.call = failed
    with pytest.raises(RuntimeError, match="detach failed"):
        asyncio.run(browser.detach("owned-session"))


def test_node_mutations_are_serialized(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import time
    from browser_lifecycle import node_lock

    order = []

    def run(identifier):
        with node_lock(tmp_path / "state.sqlite"):
            order.append(("enter", identifier))
            time.sleep(0.02)
            order.append(("exit", identifier))

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(run, (1, 2)))
    assert order[0][1] == order[1][1]
    assert order[2][1] == order[3][1]
    assert order[0][0] == order[2][0] == "enter"


@pytest.fixture(params=["headless", "xvfb"])
def local_display(request):
    """Private headed X11 fixture, not evidence of KasmVNC native telemetry."""
    if request.param == "headless":
        yield ["--headless=new"], None
        return
    import select
    import subprocess
    if not shutil.which("Xvfb"):
        pytest.skip("disposable headed Xvfb unavailable")
    reader, writer = os.pipe()
    server = subprocess.Popen(["Xvfb", "-displayfd", str(writer), "-screen", "0", "1024x768x24", "-nolisten", "tcp"],
                              pass_fds=(writer,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(writer)
    try:
        assert select.select([reader], [], [], 15)[0], "private Xvfb startup deadline"
        display = os.read(reader, 64).decode().strip()
        assert display.isdigit() and server.poll() is None
        yield ["--ozone-platform=x11"], {**os.environ, "DISPLAY": ":" + display}
    finally:
        os.close(reader)
        server.terminate()
        server.wait(timeout=10)
        assert server.poll() is not None


@pytest.mark.skipif(
    os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1",
    reason="explicit disposable local Chromium opt-in",
)
def test_live_pipe_handoff_preserves_process_tabs_and_state(tmp_path, local_display):
    import websocket
    from browser_control import PipeBrowser, rotate_control, activity_control

    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    assert chrome, "local Chromium required"
    display_flags, display_env = local_display
    browser = PipeBrowser(
        [
            chrome,
            "--remote-debugging-pipe",
            *display_flags,
            "--no-first-run",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--user-data-dir=" + str(tmp_path / "profile"),
            "about:blank",
        ],
        stdout=__import__("subprocess").DEVNULL,
        stderr=__import__("subprocess").DEVNULL,
        env=display_env,
    )
    ws = new_ws = None

    def get(url):
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.load(response)

    def call(connection, method, params=None):
        call.serial += 1
        connection.send(
            json.dumps({"id": call.serial, "method": method, "params": params or {}})
        )
        while True:
            value = json.loads(connection.recv())
            if value.get("id") == call.serial:
                assert "error" not in value, value
                return value["result"]

    call.serial = 0
    try:
        url = browser.serve(0, tmp_path / "control.sock")
        pid = browser.process.pid
        page = next(t for t in get(url + "/json/list") if t["type"] == "page")
        ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=5)
        # One slow CDP command must not block the following independent one.
        for identifier, expression, await_promise in [
            (801, "new Promise(r => setTimeout(() => r(1), 500))", True),
            (802, "2", False),
        ]:
            ws.send(
                json.dumps(
                    {
                        "id": identifier,
                        "method": "Runtime.evaluate",
                        "params": {
                            "expression": expression,
                            "awaitPromise": await_promise,
                        },
                    }
                )
            )
        replies = []
        while len(replies) < 2:
            message = json.loads(ws.recv())
            if message.get("id") in (801, 802):
                replies.append(message["id"])
        assert replies == [802, 801]
        call(ws, "Runtime.evaluate", {"expression": 'window.fixture = "survived"'})
        malformed = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=5)
        malformed.send(json.dumps({"id": 800}))
        assert malformed.recv() == ""
        malformed.close()
        assert activity_control(tmp_path / "control.sock")["inflight"] == 0
        activity = activity_control(tmp_path / "control.sock")
        get(url + "/json/version")
        get(url + "/json/list")
        assert activity_control(tmp_path / "control.sock")["last_activity"] == activity["last_activity"]
        # Deterministic in-flight race: the promise remains pending until this
        # fixture explicitly resolves it through a second multiplexed command.
        ws.send(json.dumps({"id": 901, "method": "Runtime.evaluate", "params": {
            "expression": "new Promise(r => window.finishFixture = r)", "awaitPromise": True}}))
        ws.send(json.dumps({"id": 902, "method": "Runtime.evaluate", "params": {
            "expression": "typeof window.finishFixture"}}))
        while json.loads(ws.recv()).get("id") != 902:
            pass
        assert activity_control(tmp_path / "control.sock")["inflight"] == 1
        assert not activity_control(tmp_path / "control.sock", "freeze", idle_seconds=0)["frozen"]
        ws.send(json.dumps({"id": 903, "method": "Runtime.evaluate", "params": {
            "expression": "window.finishFixture(1)"}}))
        received = set()
        while received != {901, 903}:
            reply = json.loads(ws.recv())
            if reply.get("id") in {901, 903}:
                received.add(reply["id"])
        activity_control(tmp_path / "control.sock", "reserve", seconds=30)
        assert not activity_control(tmp_path / "control.sock", "freeze", idle_seconds=0)["frozen"]
        activity_control(tmp_path / "control.sock", "reserve", seconds=0)
        # Only this disposable in-process fixture advances the adapter's idle
        # clock; production has no endpoint to forge activity/age.
        import asyncio
        import time
        async def age_fixture():
            browser.last_use = time.monotonic() - 7201
        asyncio.run_coroutine_threadsafe(age_fixture(), browser.loop).result(5)
        assert activity_control(tmp_path / "control.sock", "freeze", idle_seconds=7200)["frozen"]
        rotation = rotate_control(tmp_path / "control.sock")
        assert rotation["fenced"]
        assert browser.process.pid == pid and browser.process.poll() is None
        with pytest.raises(urllib.error.HTTPError) as gone:
            get(url + "/json/version")
        assert gone.value.code == 410
        # The old established channel cannot send another mutation.
        try:
            ws.send(
                json.dumps(
                    {
                        "id": 999,
                        "method": "Runtime.evaluate",
                        "params": {"expression": 'window.fixture="wrong"'},
                    }
                )
            )
            assert ws.recv() == ""
        except (websocket.WebSocketConnectionClosedException, BrokenPipeError):
            pass
        new_page = next(
            t for t in get(rotation["cdp_url"] + "/json/list") if t["id"] == page["id"]
        )
        new_ws = websocket.create_connection(
            new_page["webSocketDebuggerUrl"], timeout=5
        )
        result = call(new_ws, "Runtime.evaluate", {"expression": "window.fixture"})
        assert result["result"]["value"] == "survived"
    finally:
        for connection in (ws, new_ws):
            if connection:
                connection.close()
        browser.close()
    assert browser.process.poll() is not None
