"""Opt-in real local systemd/Chrome stopped-resume with default task MITM."""
import contextlib
import hashlib
import http.server
import ipaddress
import json
import threading
import time
import websocket
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

import pytest

from agents.test_browser_lifecycle_systemd import disposable_fixture_root, PROVISIONER
from browser_lifecycle import owner_state


@contextlib.contextmanager
def local_https_fixture(root):
    """Serve only this host's non-loopback address; trust its cert in a private MITM shim."""
    addresses = json.loads(subprocess.run(["ip", "-j", "-4", "addr", "show", "scope", "global"],
                                            capture_output=True, text=True, check=True).stdout)
    ip = next((entry["local"] for iface in addresses
               if iface["ifname"] == "docker0" and "NO-CARRIER" in iface["flags"]
               for entry in iface["addr_info"] if entry["family"] == "inet"
               and ipaddress.ip_address(entry["local"]).is_private), None)
    if ip is None or ipaddress.ip_address(ip).is_loopback:
        pytest.skip("local non-loopback fixture interface unavailable")
    cert, key = root / "upstream.pem", root / "upstream.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=local-fixture", "-addext", f"subjectAltName=IP:{ip}",
                    "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True, timeout=20)
    class LocalOnly(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/mitm-resume-fixture":
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"local-mitm-resume-ok")
        def log_message(self, format, *args):
            pass
    server = http.server.ThreadingHTTPServer((ip, 0), LocalOnly)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Default --proxy mitm; only upstream trust is fixture-specific.
        real = Path(subprocess.run(["which", "mitmdump"], capture_output=True, text=True, check=True).stdout.strip()).resolve()
        interpreter = real.open("rb").readline().decode().strip()[2:]
        bin_dir = root / "bin"
        bin_dir.mkdir()
        shim = bin_dir / "mitmdump"
        shim.write_text(f"#!{interpreter}\nimport os, sys\nos.execv({str(real)!r}, [{str(real)!r}, *sys.argv[1:], '--set', 'ssl_verify_upstream_trusted_ca={cert}'])\n")
        shim.chmod(0o700)
        yield f"https://{ip}:{server.server_port}/mitm-resume-fixture", bin_dir
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1", reason="local Chrome/systemd opt-in")
def test_stopped_resume_default_task_mitm():
    agent = "mitm-resume-fixture-" + uuid.uuid4().hex[:12]
    run = "mitm-resume-" + uuid.uuid4().hex[:12]
    operator_store = Path.home() / ".local/share/ghost/proxy-store/proxy_store.sqlite"
    def operator_identity():
        return tuple((str(path), path.stat().st_dev, path.stat().st_ino,
                      path.stat().st_size, path.stat().st_mtime_ns)
                     for path in (operator_store, Path(str(operator_store) + "-wal"),
                                  Path(str(operator_store) + "-shm")) if path.exists())
    before = operator_identity()
    with disposable_fixture_root() as (root, evidence):
        home = root / "home"
        home.mkdir(mode=0o700)
        state = root / "state/manager.sqlite"
        fixture_store = home / ".local/share/ghost/proxy-store/proxy_store.sqlite"
        https_fixture = local_https_fixture(root)
        local_url, fixture_bin = https_fixture.__enter__()
        env = {**os.environ, "HOME": str(home), "PATH": str(fixture_bin) + os.pathsep + os.environ["PATH"],
               "BROWSER_PROVISIONER_STATE": str(state),
               "HARNESS_BOUNTY_ARTIFACT_ROOT": str(root / "artifacts"),
               "HARNESS_SHARED_BASE": str(root / "shared"), "BROWSER_STARTUP_DIAGNOSTICS": "1"}
        records = []
        proxy = None
        # Default task MITM leases a shared-range port only while this fixture runs.
        def listener_ports():
            return {port for port in range(8081, 8096) if socket_open(port)}

        def command(*args, expected=0):
            result = subprocess.run([sys.executable, str(PROVISIONER), *map(str, args)], env=env,
                                    capture_output=True, text=True, timeout=100)
            assert result.returncode == expected, (args, result.stdout, result.stderr)
            return json.loads(result.stdout)

        def row(receipt):
            with sqlite3.connect(state) as db:
                db.row_factory = sqlite3.Row
                return dict(db.execute("select * from browsers where lease_id=?", (receipt["lease_id"],)).fetchone())

        def proxy_row():
            with sqlite3.connect(state) as db:
                db.row_factory = sqlite3.Row
                found = db.execute("select * from task_proxies where agent_id=? and run_id=?", (agent, run)).fetchone()
                return dict(found) if found else None

        def socket_open(port):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    return True
            except (ConnectionRefusedError, TimeoutError, OSError):
                return False

        def live(receipt):
            owned = row(receipt)
            info = json.loads(Path(owned["launch_file"]).read_text())
            assert owner_state(info["process_identity"]) == "active"
            assert owned["unit"] in Path(f"/proc/{info['pid']}/cgroup").read_text()
            with urllib.request.urlopen(info["cdp_url"] + "/json/version", timeout=5) as response:
                assert json.load(response)["Browser"]
            return owned, info

        def trust(info, owned, expected_hash, ca):
            assert info["proxy_cert_mode"] == "import"
            cert = info["proxy_cert_status"]
            assert cert["status"] == "trusted"
            assert cert["ca_cert"] == str(ca) and cert["ca_sha256"] == expected_hash
            assert info["proxy_server"] == proxy["proxy_server"]
            assert "--proxy-server=" + proxy["proxy_server"] in info["command"]
            nss = Path(owned["profile_dir"])
            result = subprocess.run(["certutil", "-d", f"sql:{nss}", "-L", "-n", "mitmproxy", "-a"],
                                    capture_output=True, text=True, check=True, timeout=10)
            assert ssl.PEM_cert_to_DER_cert(result.stdout) == ssl.PEM_cert_to_DER_cert(ca.read_text())

        def browser_get(info):
            with urllib.request.urlopen(info["cdp_url"] + "/json", timeout=5) as response:
                pages = json.load(response)
            page = next(item for item in pages if item["type"] == "page")
            with contextlib.closing(websocket.create_connection(page["webSocketDebuggerUrl"], timeout=8)) as ws:
                ws.send(json.dumps({"id": 1, "method": "Page.navigate", "params": {"url": local_url}}))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    message = json.loads(ws.recv())
                    if message.get("id") == 1:
                        assert not message.get("result", {}).get("errorText"), message
                        break
                else:
                    pytest.fail("local HTTPS navigation timed out")
                for attempt in range(30):
                    ws.send(json.dumps({"id": attempt + 2, "method": "Runtime.evaluate", "params": {
                        "expression": "document.body && document.body.innerText", "returnByValue": True}}))
                    while True:
                        message = json.loads(ws.recv())
                        if message.get("id") == attempt + 2:
                            break
                    if "local-mitm-resume-ok" in str(message.get("result", {})):
                        return
                    time.sleep(.1)
                pytest.fail("browser did not render local HTTPS response")

        def release(receipt):
            result = command("release", "--lease-id", receipt["lease_id"], "--agent-id", agent,
                             "--disposition", "completed", "--profile-health", "healthy")
            assert result["status"] == "released"

        def closed(owned, info):
            assert row({"lease_id": owned["lease_id"]})["state"] == "stopped"
            assert owner_state(info["process_identity"]) == "terminal"
            unit = subprocess.run(["systemctl", "--user", "show", owned["unit"],
                                   "--property=ActiveState", "--value"], capture_output=True,
                                  text=True, check=True, timeout=10)
            assert unit.stdout.strip() in {"inactive", "failed"}

        ports_before = listener_ports()
        try:
            # DEFAULT_STORE is frozen at import; inspect the fixture subprocess.
            probe = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                "from proxy_store import DEFAULT_STORE; print(DEFAULT_STORE)", str(PROVISIONER.parent)],
                env=env, text=True, capture_output=True, check=True, timeout=10)
            assert Path(probe.stdout.strip()) == fixture_store
            assert fixture_store.is_relative_to(root)
            options = ("--task-owned", "--agent-id", agent, "--run-id", run,
                       "--purpose", "local stopped resume MITM fixture", "--url", "about:blank",
                       "--headless", "--ttl-seconds", "120", "--idle-seconds", "30",
                       "--min-ram-available-mib", "1", "--min-swap-free-mib", "0",
                       "--memory-high", "384M", "--memory-max", "512M", "--wait-seconds", "0")
            first = command("request", *options)
            assert first["status"] == "started"
            records.append(first)
            proxy = first["task_proxy"]
            ca = Path(proxy["ca_cert"])
            assert ca.is_relative_to(root) and ca.is_file()
            assert proxy["state"] == "running" and proxy_row()["state"] == "running"
            assert proxy_row()["invocation"] and socket_open(proxy_row()["port"])
            def started_at(unit):
                result = subprocess.run(["systemctl", "--user", "show", unit,
                                         "--property=ActiveEnterTimestampMonotonic", "--value"],
                                        capture_output=True, text=True, check=True, timeout=10)
                return int(result.stdout.strip())
            assert 0 < started_at(proxy["unit"])
            old, old_info = live(first)
            assert started_at(proxy["unit"]) < started_at(old["unit"])
            fingerprint = hashlib.sha256(ca.read_bytes()).hexdigest()
            trust(old_info, old, fingerprint, ca)
            assert proxy_row()["updated"] <= old["updated"]  # Proxy ready before browser publication.
            release(first)
            closed(old, old_info)
            assert proxy_row()["lane"] == proxy["lane"] and socket_open(proxy_row()["port"])
            resumed = command("resume", "--browser-id", first["browser_id"],
                              "--agent-id", agent, "--run-id", run)
            assert resumed["status"] == "started" and resumed["browser_id"] != first["browser_id"]
            assert resumed["lease_id"] != first["lease_id"] and resumed["replaces_browser_id"] == first["browser_id"]
            records.append(resumed)
            new, new_info = live(resumed)
            assert new["unit"] != old["unit"] and new["profile_dir"] == old["profile_dir"]
            assert new_info["cdp_url"] != old_info["cdp_url"]
            assert new_info["launch_recipe"]["physical_profile"] == old_info["launch_recipe"]["physical_profile"]
            assert resumed["task_proxy"]["lane"] == proxy["lane"]
            assert proxy_row()["invocation"] and hashlib.sha256(ca.read_bytes()).hexdigest() == fingerprint
            trust(new_info, new, fingerprint, ca)
            browser_get(new_info)
            closed(old, old_info)
            from urllib.parse import urlsplit
            old_port = urlsplit(old_info["cdp_url"]).port
            if old_port == urlsplit(new_info["cdp_url"]).port:
                with pytest.raises(urllib.error.HTTPError) as stale:
                    urllib.request.urlopen(old_info["cdp_url"] + "/json/version", timeout=5)
                assert stale.value.code == 410
            else:
                assert not socket_open(old_port)
            release(resumed)
            closed(new, new_info)
            assert socket_open(proxy_row()["port"])
            replay = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "",
                                     "--cacert", str(ca), "-x", proxy["proxy_server"], local_url],
                                    capture_output=True, text=True, timeout=10)
            assert replay.returncode == 0 and replay.stdout == "local-mitm-resume-ok", replay.stderr
            result = command("task-proxy-finish", "--agent-id", agent, "--run-id", run)
            assert result["status"] == "finished" and result["lane"] == proxy["lane"]
            assert proxy_row() is None and not socket_open(int(proxy["proxy_server"].rsplit(":", 1)[1]))
            assert listener_ports() == ports_before
            stopped_proxy = subprocess.run(["systemctl", "--user", "show", proxy["unit"],
                                            "--property=ActiveState", "--value"],
                                           capture_output=True, text=True, check=True, timeout=10)
            assert stopped_proxy.stdout.strip() in {"inactive", "failed"}
            assert command("task-proxy-finish", "--agent-id", agent, "--run-id", run)["already_finished"] is True
            cert_check = subprocess.run(["certutil", "-d", f"sql:{old['profile_dir']}", "-L", "-n", "mitmproxy"],
                                        capture_output=True, text=True, timeout=10)
            assert cert_check.returncode != 0
            assert fixture_store.exists() and fixture_store.is_relative_to(root)
            with sqlite3.connect(fixture_store) as db:
                assert db.execute("select count(*) from lanes where lane=?", (proxy["lane"],)).fetchone()[0] == 1
                from urllib.parse import urlsplit
                target = urlsplit(local_url)
                assert db.execute("select count(*) from requests where lane=? and scheme='https' and host=? and path=? and status_code=200", (proxy["lane"], target.hostname, target.path)).fetchone()[0] >= 2
        finally:
            try:
                for receipt in reversed(records):
                    if row(receipt)["state"] == "running":
                        release(receipt)
                current = proxy_row() if state.exists() else None
                if current is not None and not any(row(receipt)["state"] == "running" for receipt in records):
                    # Exact run only; a failed stop keeps the fixture root for recovery.
                    action = "task-proxy-recover" if current["state"] != "running" else "task-proxy-finish"
                    cleanup = command(action, "--agent-id", agent, "--run-id", run)
                    assert cleanup["status"] == "finished"
                if state.exists():
                    assert proxy_row() is None
            finally:
                https_fixture.__exit__(None, None, None)
    assert not root.exists() and operator_identity() == before
