import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "skills" / "chromium-handoff" / "scripts" / "cdp_handoff_server.js"


def run_server(receipt_path: Path):
    env = os.environ | {
        "BROWSER_LAUNCH_RECEIPT": str(receipt_path),
        "CDP_URL": "http://127.0.0.1:9224",
        "LISTEN_PORT": "9567",
    }
    return subprocess.run(
        ["timeout", "2s", "node", str(SERVER)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def trusted_fallback_receipt():
    return {
        "cdp_url": "http://127.0.0.1:9224",
        "display_fallback": {
            "from": "kasmvnc",
            "to": "default",
            "reason": "KasmVNC CDP readiness failed",
        },
        "proxy_cert_mode": "import",
        "proxy_cert_status": {"status": "trusted"},
    }


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (lambda receipt: receipt.pop("display_fallback"), "display_fallback"),
        (lambda receipt: receipt.update(proxy_cert_mode="auto"), "proxy_cert_mode"),
        (lambda receipt: receipt.update(proxy_cert_status={"status": "ignored-by-flag"}), "proxy_cert_status"),
        (lambda receipt: receipt.update(cdp_url="http://127.0.0.1:9225"), "cdp_url"),
        (lambda receipt: None, "live browser pid"),
    ],
)
def test_cdp_handoff_rejects_unqualified_fallback_receipts(tmp_path, mutate, expected_error):
    receipt = trusted_fallback_receipt()
    mutate(receipt)
    receipt_path = tmp_path / "launch.json"
    receipt_path.write_text(json.dumps(receipt))

    result = run_server(receipt_path)

    assert result.returncode == 1
    assert expected_error in result.stderr


def test_cdp_handoff_rejects_receipt_not_bound_to_live_browser(tmp_path):
    receipt_path = tmp_path / "launch.json"
    receipt = trusted_fallback_receipt() | {
        "pid": os.getpid(),
        "profile_dir": "/tmp/not-the-browser-profile",
    }
    receipt_path.write_text(json.dumps(receipt))

    result = run_server(receipt_path)

    assert result.returncode == 1
    assert "does not match the receipt CDP endpoint and profile" in result.stderr


# Synthetic process/receipt fixtures test authorization gates without claiming
# that a real KasmVNC failure or certificate import occurred.
import contextlib
import http.server
import select
import socket
import sys
import threading
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(ROOT / "skills/chromium-test/scripts"))
from browser_lifecycle import process_identity


@contextlib.contextmanager
def fake_pipe(tmp_path):
    proc = subprocess.Popen([
        sys.executable, "-c", "import time; time.sleep(60)",
        "--remote-debugging-pipe", f"--user-data-dir={tmp_path / 'profile'}",
    ])
    path = tmp_path / "control.sock"
    receipt = trusted_fallback_receipt() | {
        "pid": proc.pid, "profile_dir": str(tmp_path / "profile"),
        "control_mode": "pipe-fenced", "process_identity": process_identity(proc.pid),
        "control_socket": str(path), "cdp_url": "http://127.0.0.1:9224/" + "a" * 43,
        "instance_id": str(uuid.uuid4()),
    }
    receipt["pane_id"] = receipt["instance_id"]
    identity = {"process_identity": receipt["process_identity"].copy(),
                "cdp_url": receipt["cdp_url"], "available": True}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/identity" else 404)
            self.end_headers()
            self.wfile.write(json.dumps(identity).encode())

        def log_message(self, *args):
            pass

    class UnixServer(http.server.HTTPServer):
        address_family = socket.AF_UNIX

        def server_bind(self):
            self.socket.bind(self.server_address)

    server = UnixServer(str(path), Handler)
    path.chmod(0o600)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield receipt, identity
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        proc.terminate()
        proc.wait(5)


@pytest.fixture
def playwright_stub(tmp_path):
    module = tmp_path / "playwright.cjs"
    module.write_text("""
const {EventEmitter} = require('events');
const browser = new EventEmitter();
const pages = (process.env.TEST_PAGE_IDS ?? 'intended').split(',').filter(Boolean).map(id => {
 const page = new EventEmitter();
 page.url = () => 'about:blank'; page.isClosed = () => false; page.id = id;
 page.screenshot = async () => Buffer.from('fixture-jpeg');
 page.mouse = {click: async () => {}}; page.keyboard = {type:async () => {}};
 page.reload = page.goBack = async () => {};
 return page;
});
browser.contexts = () => [{pages:() => pages, newCDPSession:async page => ({
 send:async () => ({targetInfo:{targetId:page.id}}), detach:async () => {}
})}];
exports.chromium = {connectOverCDP:async () => browser};
""")
    return module


def handoff_env(tmp_path, receipt, module=None, **extra):
    record = tmp_path / (str(uuid.uuid4()) + ".json")
    record.write_text(json.dumps(receipt))
    env = os.environ | {"BROWSER_LAUNCH_RECEIPT": str(record),
                        "CDP_URL": receipt["cdp_url"], "LISTEN_HOST": "127.0.0.1",
                        "LISTEN_PORT": "auto"}
    if module:
        env["PLAYWRIGHT_MODULE"] = str(module)
    env.update(extra)
    return env


@contextlib.contextmanager
def running_handoff(env):
    proc = subprocess.Popen(["node", str(SERVER)], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([proc.stdout], [], [], 20)[0], "handoff readiness deadline"
        line = proc.stdout.readline()
        assert line, proc.stderr.read()
        ready = json.loads(line)
        yield proc, ready, f"http://127.0.0.1:{ready['listen_port']}"
    finally:
        proc.terminate()
        proc.wait(5)


def get(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read()


@pytest.mark.parametrize("field,value,error", [
    ("start", "wrong", "process_identity"), ("boot", "wrong", "process_identity"),
    ("node", "wrong", "process_identity"), ("pid", 1, "process_identity"),
    ("profile_dir", "/tmp/wrong-profile", "profile/control mode"),
    ("pane_id", "wrong", "instance_id and pane_id"),
    ("control_mode", "unknown", "CDP endpoint and profile"),
    ("control_socket", "relative", "absolute control_socket"),
])
def test_pipe_receipt_rejects_mismatch(tmp_path, playwright_stub, field, value, error):
    with fake_pipe(tmp_path) as (receipt, identity):
        if field in {"start", "boot", "node", "pid"}:
            receipt["process_identity"][field] = value
        else:
            receipt[field] = value
        result = subprocess.run(["node", str(SERVER)],
                                env=handoff_env(tmp_path, receipt, playwright_stub),
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 1
        assert error in result.stderr


@pytest.mark.parametrize("change", ["url", "identity", "frozen", "public-socket", "nonloopback"])
def test_pipe_control_rejects_wrong_adapter(tmp_path, playwright_stub, change):
    with fake_pipe(tmp_path) as (receipt, identity):
        extra = {}
        if change == "url":
            identity["cdp_url"] += "wrong"
        elif change == "identity":
            identity["process_identity"]["start"] = "wrong"
        elif change == "frozen":
            identity["available"] = False
        elif change == "public-socket":
            Path(receipt["control_socket"]).chmod(0o666)
        else:
            extra["LISTEN_HOST"] = "0.0.0.0"
        result = subprocess.run(["node", str(SERVER)],
                                env=handoff_env(tmp_path, receipt, playwright_stub, **extra),
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 1
        assert "cdp_handoff_ready" not in result.stdout


def test_pipe_safe_identity_and_revocation_is_terminal(tmp_path, playwright_stub):
    with fake_pipe(tmp_path) as (receipt, identity):
        env = handoff_env(tmp_path, receipt, playwright_stub,
                          TEST_PAGE_IDS="other,intended", HANDOFF_PAGE_ID="intended")
        with running_handoff(env) as (_, ready, url):
            assert ready["pane_id"] == receipt["pane_id"]
            assert ready["page_id"] == "intended"
            assert "cdp_url" not in ready
            safe = json.loads(get(url + "/identity"))
            assert set(safe) == {"instance_id", "pane_id", "page_id", "control_mode"}
            html = get(url + "/").decode()
            assert "setInterval(identity, 5000)" in html
            assert "setInterval(load" not in html
            assert get(url + "/screenshot.jpg") == b"fixture-jpeg"
            identity["available"] = False
            for path in ("/identity", "/screenshot.jpg"):
                with pytest.raises(urllib.error.HTTPError) as gone:
                    get(url + path)
                assert gone.value.code == 410
                assert receipt["cdp_url"].encode() not in gone.value.read()
            identity["available"] = True
            Path(env["BROWSER_LAUNCH_RECEIPT"]).write_text(json.dumps(
                receipt | {"cdp_url": receipt["cdp_url"] + "replacement"}))
            # Neither restored adapter nor rewritten receipt can revive this UI.
            with pytest.raises(urllib.error.HTTPError) as gone:
                get(url + "/identity")
            assert gone.value.code == 410


@pytest.mark.parametrize("pages,page_id", [("one,two", ""), ("one", "missing"), ("", "")])
def test_never_selects_unrelated_or_creates_page(tmp_path, playwright_stub, pages, page_id):
    with fake_pipe(tmp_path) as (receipt, _):
        result = subprocess.run(["node", str(SERVER)], env=handoff_env(
            tmp_path, receipt, playwright_stub, TEST_PAGE_IDS=pages, HANDOFF_PAGE_ID=page_id),
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 1
        assert "HANDOFF_PAGE_ID" in result.stderr


def test_private_bridge_identity_is_passive():
    import asyncio
    from types import SimpleNamespace
    from browser_control import PipeBrowser

    bridge = SimpleNamespace(process=SimpleNamespace(pid=os.getpid()), port=9224,
                             token="fixture-generation", rotating=False, frozen=False)
    result = json.loads(asyncio.run(PipeBrowser.identity(bridge, None)).text)
    assert result == {"process_identity": process_identity(os.getpid()),
                      "cdp_url": "http://127.0.0.1:9224/fixture-generation", "available": True}
    # No activity or browser-call methods exist on this fixture: identity must
    # be a passive process/generation observation, never a liveness heartbeat.
    bridge.token = "next-generation"
    bridge.frozen = True
    result = json.loads(asyncio.run(PipeBrowser.identity(bridge, None)).text)
    assert not result["available"]
    assert result["cdp_url"].endswith("/next-generation")
    bridge.frozen = False
    bridge.rotating = True
    assert not json.loads(asyncio.run(PipeBrowser.identity(bridge, None)).text)["available"]


def test_legacy_raw_port_compatibility(tmp_path, playwright_stub):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                             "--remote-debugging-port=9224", "--remote-debugging-address=127.0.0.1",
                             f"--user-data-dir={tmp_path}"])
    try:
        receipt = trusted_fallback_receipt() | {"pid": proc.pid, "profile_dir": str(tmp_path)}
        with running_handoff(handoff_env(tmp_path, receipt, playwright_stub)) as (_, ready, url):
            assert ready["control_mode"] == "legacy"
            assert ready["pane_id"] is None
            assert get(url + "/screenshot.jpg") == b"fixture-jpeg"
    finally:
        proc.terminate()
        proc.wait(5)
