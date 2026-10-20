"""Optional real-browser regression against an *already provisioned* task browser.

Set XSS_FIXTURE_CDP_LAUNCH to that owned browser's private launch receipt.
The test does not provision/release the browser or contact a target. Its caller
must release the exact lease through the normal provisioner lifecycle.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

import pytest

FIXTURE = Path(__file__).resolve().parent / "fixtures/xss_composition.html"


def _command(ws, number: int, method: str, params: dict | None = None) -> dict:
    ws.send(json.dumps({"id": number, "method": method, "params": params or {}}))
    while True:
        response = json.loads(ws.recv())
        if response.get("id") == number:
            if "error" in response:
                raise RuntimeError(f"CDP {method} failed")
            return response["result"]


def _json(base: str, suffix: str) -> dict | list:
    with urlopen(base + suffix, timeout=10) as reply:
        return json.load(reply)


def test_offline_composition_in_owned_browser() -> None:
    launch_file = os.environ.get("XSS_FIXTURE_CDP_LAUNCH")
    if not launch_file:
        pytest.skip("needs explicit task-owned provisioner launch receipt")
    import websocket  # only required when this opt-in browser test runs

    launch = json.loads(Path(launch_file).read_text(encoding="utf-8"))
    base = launch["cdp_url"].rstrip("/")
    parsed = urlsplit(base)
    assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
    assert launch["program"] == "task-owned" and launch["proxy_server"] is None
    version = _json(base, "/json/version")
    assert isinstance(version, dict)
    browser = websocket.create_connection(
        version["webSocketDebuggerUrl"],
        timeout=10, suppress_origin=True,
    )
    target = None
    try:
        target = _command(browser, 1, "Target.createTarget", {"url": "about:blank"})[
            "targetId"
        ]
        pages = _json(base, "/json/list")
        assert isinstance(pages, list)
        page = next(p for p in pages if isinstance(p, dict) and p.get("id") == target)
        tab = websocket.create_connection(
            page["webSocketDebuggerUrl"], timeout=10, suppress_origin=True
        )
        try:
            _command(tab, 2, "Page.enable")
            _command(tab, 3, "Page.navigate", {"url": FIXTURE.as_uri()})
            observed = None
            # Image-error execution is asynchronous; an attribute in the DOM
            # is not execution proof. Observe the marker after the event fires.
            for number in range(10, 30):
                time.sleep(0.2)
                result = _command(tab, number, "Runtime.evaluate", {
                    "expression": "JSON.stringify(window.__xssFixture || null)",
                    "returnByValue": True,
                })
                value = result.get("result", {}).get("value")
                if value and value != "null":
                    observed = json.loads(value)
                    if observed.get("proof") == 1:
                        break
            assert observed is not None, "fixture did not load"
            states = observed["states"]
            assert states["individualA"] is False
            assert states["individualB"] is False
            assert states["joined"] is True
            assert states["safeAttribute"] is False
            assert states["safeText"] is False
            assert observed["proof"] == 1, "event did not execute"
        finally:
            tab.close()
    finally:
        if target is not None:
            _command(browser, 40, "Target.closeTarget", {"targetId": target})
        browser.close()
