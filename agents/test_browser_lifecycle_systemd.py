"""Opt-in disposable user-systemd browser lifecycle fixture (loopback only)."""

import contextlib
import http.server
import threading
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = Path(__file__).parents[1]
PROVISIONER = ROOT / "skills/chromium-test/scripts/browser_provisioner.py"
sys.path.insert(0, str(PROVISIONER.parent))


def preserve_startup_evidence(root, destination, *, failed, cleanup_verified):
    """Project only the closed metadata schema, never copy private launch files."""
    from browser_lifecycle import StartupDiagnostics, private_json
    snapshots = []
    attempts = {}
    for path in sorted((root / "state/startup").glob("*/*.json"))[:48]:
        if path.name not in {"manager.json", "launcher.json", "exec.json"}:
            continue
        try:
            with path.open() as stream:
                data = json.loads(stream.read(16385))
            events = []
            for event in data.get("events", [])[:32]:
                if (event.get("phase") not in StartupDiagnostics.PHASES
                    or event.get("outcome") not in {"begin", "ready", "failed"}
                    or event.get("error_category") not in {"none", "timeout", "connection", "os-error", "unexpected"}
                    or type(event.get("elapsed_ms")) is not int):
                    continue
                events.append({key: event[key] for key in
                               ("phase", "outcome", "error_category", "elapsed_ms")})
                if type(event.get("returncode")) is int:
                    events[-1]["returncode"] = event["returncode"]
            count = data.get("stderr_bytes_observed", 0)
            started = data.get("started_monotonic_ms", 0)
            attempt = attempts.setdefault(path.parent.name, len(attempts) + 1)
            snapshots.append({"attempt": attempt, "component": path.stem, "events": events,
                              "started_monotonic_ms": started if type(started) is int else 0,
                              "stderr_bytes_observed": min(65536, max(0, count)) if type(count) is int else 0})
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    private_json(destination / "startup.json", {
        "schema": 1, "fixture_failed": failed, "cleanup_verified": cleanup_verified,
        "snapshots": snapshots, "stderr_content": "not-collected",
    })


def stop_fixture_units(root):
    """Include launches that failed before registry insertion; never global stop."""
    import uuid
    ids = {path.name for path in (root / "state/startup").glob("*")}
    ids.update(path.name.removesuffix(".launch.json") for path in (root / "state").glob("*.launch.json"))
    state = root / "state/manager.sqlite"
    if state.exists():
        with sqlite3.connect(state) as connection:
            ids.update(row[0] for row in connection.execute("SELECT browser_id FROM browsers"))
    from browser_lifecycle import owner_state
    import socket
    from urllib.parse import urlsplit
    identities, ports = [], []
    for path in (root / "state").glob("*.launch.json"):
        try:
            info = json.loads(path.read_text())
        except (OSError, ValueError):
            continue  # Pre-publication failure still has unit + root checks.
        if info.get("process_identity"):
            identities.append(info["process_identity"])
        endpoint = urlsplit(info.get("cdp_url", ""))
        if endpoint.hostname:
            assert endpoint.hostname == "127.0.0.1" and endpoint.port
            ports.append(endpoint.port)
    for bid in ids:
        assert str(uuid.UUID(bid)) == bid
        for unit in ("browser-" + bid, "browser-owner-" + bid):
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=15)
            result = subprocess.run(
                ["systemctl", "--user", "show", unit, "--property=ActiveState", "--value"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == 0 and result.stdout.strip() in {"inactive", "failed"}, "fixture unit stop unverified"
    assert all(owner_state(identity) == "terminal" for identity in identities), "fixture root stop unverified"
    for port in ports:
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=1)
        except ConnectionRefusedError:
            continue
        else:
            connection.close()
            raise AssertionError("fixture CDP port remains open; retaining profiles")
    # Read only to match this disposable root; never persist raw argv or kill by name.
    for proc in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            command = proc.read_bytes()
        except FileNotFoundError:
            continue
        except PermissionError:
            continue  # Other users are not this fixture's task processes.
        assert os.fsencode(root) not in command, "fixture process remains; retaining profiles"


@contextlib.contextmanager
def disposable_fixture_root():
    import shutil
    root = Path(tempfile.mkdtemp(prefix="bbh-life-"))
    evidence = Path(tempfile.mkdtemp(prefix="bbh-startup-evidence-"))
    failed = True
    try:
        yield root, evidence
        failed = False
    finally:
        # Preserve before teardown as well as after it; a cleanup failure must
        # never erase the original startup failure or delete a running profile.
        preserve_startup_evidence(root, evidence, failed=failed, cleanup_verified=False)
        try:
            stop_fixture_units(root)
        except BaseException:
            preserve_startup_evidence(root, evidence, failed=True, cleanup_verified=False)
            print(f"Fixture cleanup unverified; retained root: {root}; evidence: {evidence}")
            raise
        preserve_startup_evidence(root, evidence, failed=failed, cleanup_verified=True)
        shutil.rmtree(root)
        print(f"Private startup evidence: {evidence}")


@pytest.mark.skipif(
    os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1",
    reason="explicit local systemd smoke opt-in",
)
def test_systemd_lifecycle_fixture():
    import urllib.request
    import urllib.error
    import websocket

    receipts = {}
    with disposable_fixture_root() as (root, evidence):
        receipts["startup_evidence"] = str(evidence / "startup.json")
        state = root / "state/manager.sqlite"
        env = {
            **os.environ,
            "BROWSER_PROVISIONER_STATE": str(state),
            "BROWSER_STARTUP_DIAGNOSTICS": "1",
            "HARNESS_BOUNTY_ARTIFACT_ROOT": str(root / "artifacts"),
            "HARNESS_SHARED_BASE": str(root / "shared"),
        }
        owners = [subprocess.Popen(["sleep", "infinity"]) for _ in range(3)]

        def command(*parts, expect=0):
            result = subprocess.run(
                [sys.executable, str(PROVISIONER), *map(str, parts)],
                env=env,
                capture_output=True,
                text=True,
                timeout=75,
            )
            assert result.returncode == expect, (parts, result.stdout, result.stderr)
            return json.loads(result.stdout)

        common = [
            "--agent-id",
            "fixture-agent",
            "--purpose",
            "local fixture",
            "--ttl-seconds",
            "30",
            "--min-ram-available-mib",
            "1",
            "--min-swap-free-mib",
            "0",
            "--headless",
            "--idle-seconds",
            "15",
            "--proxy-cert-mode",
            "none",
            "--proxy-server",
            "http://127.0.0.1:9",
            "--proxy-ownership",
            "browser",
        ]

        def start(index, task=False, ownership="browser", key="primary"):
            selector = (
                ["--task-owned"]
                if task
                else ["fixture", "anon", "--auth-domain", "fixture.invalid", "--instance-key", key]
            )
            return command(
                "request",
                *selector,
                "--run-id",
                "fixture-" + str(index),
                *([] if task else ["--owner-pid", owners[index].pid]),
                "--wait-seconds",
                "0",
                *common,
                "--proxy-ownership",
                ownership,
            )

        def row(lid):
            with sqlite3.connect(state) as connection:
                connection.row_factory = sqlite3.Row
                return dict(
                    connection.execute(
                        "select * from browsers where lease_id=?", (lid,)
                    ).fetchone()
                )

        def info(lid):
            return json.loads(Path(row(lid)["launch_file"]).read_text())

        def get(url):
            with urllib.request.urlopen(url, timeout=5) as response:
                return json.load(response)

        def wait_idle(lid):
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                out = command("status", "--lease-id", lid, "--agent-id", "fixture-agent")
                if out["owner_state"] == "idle":
                    return
                time.sleep(0.3)
            pytest.fail("fixture did not reach configured idle claim window")

        leases = []
        try:
            first = start(0)
            leases.append(first["lease_id"])
            assert first["status"] == "started"
            sibling = start(0, key="secondary")
            leases.append(sibling["lease_id"])
            assert sibling["status"] == "started"
            assert info(sibling["lease_id"])["profile_dir"] != info(first["lease_id"])["profile_dir"]
            assert sibling["pane_id"] != first["pane_id"]
            command("release", "--lease-id", sibling["lease_id"], "--agent-id", "fixture-agent",
                    "--disposition", "completed", "--profile-health", "healthy")
            receipts["parallel_instances"] = "same-account-distinct-profiles-and-panes"
            old = info(first["lease_id"])
            pid = old["pid"]
            assert "--remote-debugging-pipe" in old["command"]
            assert not any(
                flag.startswith("--remote-debugging-port") for flag in old["command"]
            )
            page = next(
                p for p in get(old["cdp_url"] + "/json/list") if p["type"] == "page"
            )
            client = websocket.create_connection(
                page["webSocketDebuggerUrl"], timeout=5
            )
            client.send(
                json.dumps(
                    {
                        "id": 1,
                        "method": "Runtime.evaluate",
                        "params": {"expression": 'window.fixture="kept"'},
                    }
                )
            )
            assert "error" not in json.loads(client.recv())
            denied = command(
                "start",
                "fixture",
                "anon",
                "--auth-domain",
                "fixture.invalid",
                "--instance-key",
                "primary",
                "--run-id",
                "fixture-1",
                "--owner-pid",
                owners[1].pid,
                *common,
                expect=2,
            )
            assert denied["status"] == "locked"
            # Verify automatic heartbeat (no agent touch).
            with sqlite3.connect(
                state.parent / "browser_profile_leases.sqlite"
            ) as connection:
                before = connection.execute(
                    "select heartbeat_at from browser_profile_leases where lease_id=?",
                    (first["lease_id"],),
                ).fetchone()[0]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with sqlite3.connect(
                    state.parent / "browser_profile_leases.sqlite"
                ) as connection:
                    after = connection.execute(
                        "select heartbeat_at from browser_profile_leases where lease_id=?",
                        (first["lease_id"],),
                    ).fetchone()[0]
                if after > before:
                    break
                time.sleep(0.3)
            assert after > before
            wait_idle(first["lease_id"])
            assert owners[0].poll() is None
            second = start(1)
            leases.append(second["lease_id"])
            assert second["status"] == "reused" and second["fenced"]
            current = info(second["lease_id"])
            assert current["pid"] == pid
            assert second["pane_id"] == first["pane_id"]
            try:
                client.send(
                    json.dumps(
                        {
                            "id": 2,
                            "method": "Runtime.evaluate",
                            "params": {"expression": 'window.fixture="bad"'},
                        }
                    )
                )
                assert client.recv() == ""
            except (websocket.WebSocketConnectionClosedException, BrokenPipeError):
                pass
            client.close()
            with pytest.raises(urllib.error.HTTPError) as gone:
                get(old["cdp_url"] + "/json/version")
            assert gone.value.code == 410
            new_page = next(
                p
                for p in get(current["cdp_url"] + "/json/list")
                if p["id"] == page["id"]
            )
            with contextlib.closing(
                websocket.create_connection(new_page["webSocketDebuggerUrl"], timeout=5)
            ) as client:
                client.send(
                    json.dumps(
                        {
                            "id": 3,
                            "method": "Runtime.evaluate",
                            "params": {"expression": "window.fixture"},
                        }
                    )
                )
                assert json.loads(client.recv())["result"]["result"]["value"] == "kept"
            for action, extra in [
                ("touch", []),
                (
                    "release",
                    ["--disposition", "completed", "--profile-health", "healthy"],
                ),
            ]:
                stale = command(
                    action,
                    "--lease-id",
                    first["lease_id"],
                    "--agent-id",
                    "fixture-agent",
                    *extra,
                    expect=2,
                )
                assert stale["status"] == "not-owner"
            wait_idle(second["lease_id"])
            assert owners[1].poll() is None
            replacement = start(2, ownership="task")
            leases.append(replacement["lease_id"])
            assert replacement["status"] == "started"
            replacement_info = info(replacement["lease_id"])
            assert replacement_info["pid"] != pid
            assert replacement_info["profile_dir"] == current["profile_dir"]
            receipts["task_proxy_handoff"] = "verified-restart-same-profile"
            released = command(
                "release",
                "--lease-id",
                replacement["lease_id"],
                "--agent-id",
                "fixture-agent",
                "--disposition",
                "completed",
                "--profile-health",
                "healthy",
            )
            assert released["status"] == "released"
            assert Path(current["profile_dir"]).exists()
            receipts.update(
                live_handoff="same-pid-and-page-state",
                old_channel="closed",
                old_url="410",
                old_lease_mutations="denied",
                automatic_renewal=True,
                chromium_control="pipe-only-no-raw-debugging-port",
                persistent_profile_preserved=True,
            )
            task = start(2, task=True)
            leases.append(task["lease_id"])
            task_info = info(task["lease_id"])
            assert task_info["account_resolution"]["status"] == "task-owned"

            # Two ordinary local fixture logins in one task-owned profile.
            class Login(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    if self.path == "/login":
                        self.send_header(
                            "Set-Cookie", "fixture_session=owned; Path=/; SameSite=Lax"
                        )
                    self.end_headers()
                    self.wfile.write(b"<title>local login fixture</title>")

                def log_message(self, *_):
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Login)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            task_page = next(
                p
                for p in get(task_info["cdp_url"] + "/json/list")
                if p["type"] == "page"
            )
            try:
                with contextlib.closing(
                    websocket.create_connection(
                        task_page["webSocketDebuggerUrl"], timeout=60
                    )
                ) as tab:
                    sequence = 10

                    def cdp(method, params):
                        nonlocal sequence
                        sequence += 1
                        tab.send(
                            json.dumps(
                                {"id": sequence, "method": method, "params": params}
                            )
                        )
                        while True:
                            result = json.loads(tab.recv())
                            if result.get("id") == sequence:
                                assert "error" not in result
                                return result["result"]

                    for host, path in [
                        ("127.0.0.1", "/login"),
                        ("localhost", "/login"),
                        ("127.0.0.1", "/check"),
                        ("localhost", "/check"),
                    ]:
                        url = f"http://{host}:{server.server_port}{path}"
                        try:
                            cdp("Page.navigate", {"url": url})
                        except Exception as exc:
                            pytest.fail(
                                f"loopback fixture navigation failed at {host}{path}: {type(exc).__name__}"
                            )
                        end = time.monotonic() + 5
                        while time.monotonic() < end:
                            result = cdp(
                                "Runtime.evaluate",
                                {"expression": 'location.href + "|" + document.cookie'},
                            )
                            if (
                                result.get("result", {}).get("value")
                                == url + "|fixture_session=owned"
                            ):
                                break
                            time.sleep(0.1)
                        else:
                            pytest.fail("local fixture session was not retained")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            receipts["multi_site_profile"] = "two-loopback-host-login-cookies-retained"
            current_task = command("status", "--lease-id", task["lease_id"], "--agent-id", "fixture-agent")
            assert current_task["owner_state"] == "active"
            assert current_task["owner_process_state"] == "unknown"
            enrolled = command("request", "--task-owned", "--run-id", "fixture-2",
                               "--owner-pid", owners[2].pid, "--wait-seconds", "0", *common)
            assert enrolled["status"] == "already-running"
            owners[2].terminate()
            owners[2].wait()
            deadline = time.monotonic() + 50
            while time.monotonic() < deadline and row(task["lease_id"])["state"] != "stopped":
                time.sleep(0.3)
            assert row(task["lease_id"])["state"] == "stopped"
            assert Path(task_info["profile_dir"]).exists()
            receipts.update(
                task_owned="no-inventory-auth",
                terminal_cleanup="automatic-after-explicit-supervisor-enrollment; two-hour boundary tested with fake clock",
                fixture="loopback/about:blank only",
            )
            with sqlite3.connect(state) as connection:
                connection.execute(
                    "update browsers set updated=? where state='stopped'",
                    (time.time() - 15 * 86400,),
                )
                connection.commit()
            preview = command("sweep-stale")
            assert preview["removed"], preview
            assert all(item["dry_run"] for item in preview["removed"])
            assert Path(task_info["profile_dir"]).exists()
            swept = command("sweep-stale", "--confirm")
            assert swept["removed"] and not Path(task_info["profile_dir"]).exists()
            receipts["retention_sweep"] = "14-day-manifest-dry-run-and-confirmed"

        finally:
            for owner in owners:
                if owner.poll() is None:
                    owner.terminate()
                owner.wait()
        receipt_path = os.environ.get("BBH_BROWSER_SMOKE_RECEIPT")
        if receipt_path:
            Path(receipt_path).write_text(json.dumps(receipts, indent=2) + "\n")
