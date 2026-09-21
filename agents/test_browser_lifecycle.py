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


@pytest.mark.skipif(
    os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1",
    reason="explicit disposable local Chromium opt-in",
)
def test_live_pipe_handoff_preserves_process_tabs_and_state(tmp_path):
    import websocket
    from browser_control import PipeBrowser, rotate_control

    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    assert chrome, "local Chromium required"
    browser = PipeBrowser(
        [
            chrome,
            "--remote-debugging-pipe",
            "--headless=new",
            "--no-first-run",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--user-data-dir=" + str(tmp_path / "profile"),
            "about:blank",
        ],
        stdout=__import__("subprocess").DEVNULL,
        stderr=__import__("subprocess").DEVNULL,
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
