"""Disposable ordinary producer acceptance; no external pages/accounts."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

from agents.test_browser_lifecycle import local_display  # noqa: F401
from agents.test_browser_lifecycle_systemd import disposable_fixture_root, PROVISIONER


@pytest.mark.skipif(os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1", reason="local browser opt-in")
def test_real_manager_idle_cleanup_with_bounded_hold(monkeypatch, tmp_path, local_display):  # noqa: F811
    """Real pipe/root/CDP; unit dispatcher is a fixture, systemd tested below."""
    import asyncio
    from browser_control import PipeBrowser, activity_control
    from browser_lifecycle import process_identity, owner_state
    from agents.test_browser_lease_recovery import provisioner, record

    flags, env = local_display
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    assert chrome
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    profile = Path(row["profile_dir"])
    browser = PipeBrowser([chrome, *flags, "--remote-debugging-pipe", "--no-first-run",
                           "--disable-background-networking", "--disable-component-update",
                           "--disable-sync", "--user-data-dir=" + str(profile), "about:blank"],
                          env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = tmp_path / "control.sock"
    try:
        url = browser.serve(0, sock)
        identity = process_identity(browser.process.pid)
        Path(row["launch_file"]).write_text(json.dumps({
            "driving_mode": "agent-driven", "activity_tracking": True,
            "control_mode": "pipe-fenced", "control_socket": str(sock),
            "process_identity": identity, "cdp_url": url}))
        # Dispatch only our in-process fixture, never a host unit. All production
        # stopped() root identity and CDP closure checks still run unchanged.
        monkeypatch.setattr(m, "unit_active", lambda *_: False)
        monkeypatch.setattr(m, "stop_unit", lambda *_: browser.close())
        monkeypatch.setattr(m, "release_lease", lambda *_args, **_kw: {"status": "released"})

        async def age(seconds):
            browser.last_use = time.monotonic() - seconds
        def age_clock(seconds):
            asyncio.run_coroutine_threadsafe(age(seconds), browser.loop).result(5)

        age_clock(7199)
        assert m.cleanup_unused(c) == []
        age_clock(7201)
        activity_control(sock, "reserve", seconds=30)
        assert m.lifecycle_state(c, row) == "active"
        assert m.cleanup_unused(c) == []
        assert owner_state(identity) == "active"
        activity_control(sock, "reserve", seconds=0)
        assert m.lifecycle_state(c, row) == "idle"
        assert m.cleanup_unused(c) == [row["browser_id"]]
        assert m.stopped(row) and owner_state(identity) == "terminal"
        assert profile.exists()
        assert c.execute("select state from browsers").fetchone()[0] == "stopped"
    finally:
        # close() is a one-shot adapter shutdown, already called by retirement.
        if browser.thread.is_alive():
            browser.close()


@pytest.mark.skipif(os.environ.get("BBH_LOCAL_BROWSER_SMOKE") != "1", reason="local browser opt-in")
def test_real_ordinary_driving_contract(local_display):  # noqa: F811
    import urllib.request
    import websocket
    from browser_lifecycle import owner_state

    flags, display_env = local_display
    headed = not any(f.startswith("--headless") for f in flags)
    with disposable_fixture_root() as (root, evidence):
        # An executable fixture wrapper forces the private X11 display, never
        # the ambient Wayland desktop. Production launcher is otherwise unchanged.
        chrome = shutil.which("google-chrome") or shutil.which("chromium")
        assert chrome
        wrapper = root / "fixture-chromium"
        import shlex
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(chrome) + " " + " ".join(flags) + ' "$@"\n')
        wrapper.chmod(0o700)
        state = root / "state/manager.sqlite"
        env = {**(display_env or os.environ), "CHROMIUM_TEST_CHROME": str(wrapper),
               "BROWSER_PROVISIONER_STATE": str(state), "BROWSER_STARTUP_DIAGNOSTICS": "1",
               "HARNESS_BOUNTY_ARTIFACT_ROOT": str(root / "artifacts"),
               "HARNESS_SHARED_BASE": str(root / "shared")}
        common = ["--agent-id", "fixture", "--purpose", "ordinary blank fixture",
                  "--idle-seconds", "2", "--display-backend", "default",
                  "--proxy-cert-mode", "none", "--min-ram-available-mib", "1",
                  "--min-swap-free-mib", "0", *([] if headed else ["--headless"])]

        def command(*parts, expect=0):
            p = subprocess.run([sys.executable, str(PROVISIONER), *map(str, parts)],
                               env=env, capture_output=True, text=True, timeout=75)
            assert p.returncode == expect, (p.stdout, p.stderr)
            return json.loads(p.stdout)

        def request(run, *extra, expect=0):
            return command("request", "fixture", "anon", "--auth-domain", "fixture.invalid",
                           "--run-id", run, "--wait-seconds", "0", *common, *extra, expect=expect)

        def policy(mode):
            p = subprocess.run([sys.executable, str(PROVISIONER.with_name("browser_profile_lease.py")),
                "--state-dir", str(state.parent), "set-browser-policy", "fixture", "anon",
                "--auth-domain", "fixture.invalid", "--mode", mode],
                env=env, capture_output=True, text=True, timeout=10)
            assert p.returncode == 0 and json.loads(p.stdout)["status"] == "policy-set"

        def info(lid):
            with sqlite3.connect(state) as c:
                path = c.execute("select launch_file from browsers where lease_id=?", (lid,)).fetchone()[0]
            return json.loads(Path(path).read_text())

        def status(lid):
            return command("status", "--lease-id", lid, "--agent-id", "fixture")

        def touch(lid, work, seconds=30, expect=0):
            return command("touch", "--lease-id", lid, "--agent-id", "fixture",
                           "--work-state", work, "--awaiting-seconds", seconds, expect=expect)

        def wait_idle(lid):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if status(lid)["owner_state"] == "idle":
                    return
                time.sleep(.1)
            pytest.fail("ordinary browser did not become idle")

        first = request("first")
        lid = first["lease_id"]
        original = info(lid)
        assert original["driving_mode"] == first["driving_mode"] == "agent-driven"
        assert original["activity_tracking"] and original["activity_coverage"] == "CDP-only"
        assert status(lid)["owner_process_state"] == "unknown"
        assert request("first")["lease_id"] == lid
        mismatch = request("first", "--driving-mode", "manual", expect=2)
        assert mismatch["reason"] == "driving-mode-mismatch"
        assert owner_state(original["process_identity"]) == "active"
        touch(lid, "awaiting-input")
        before = status(lid)["activity"]
        touch(lid, "awaiting-input", 3600)
        assert status(lid)["activity"]["reserved_seconds"] <= before["reserved_seconds"]
        denied = request("other", "--instance-key", first["instance_key"], expect=2)
        assert denied["status"] == "locked"
        assert command("reap-idle")["idle_stopped"] == []
        assert status(lid)["activity"]["last_activity"] == before["last_activity"]
        touch(lid, "active")
        assert status(lid)["activity"]["reserved_seconds"] == 0
        touch(lid, "awaiting-input", 1)
        deadline = time.monotonic() + 5
        while status(lid)["activity"]["reserved_seconds"] and time.monotonic() < deadline:
            time.sleep(.1)
        assert touch(lid, "awaiting-input", expect=2)["status"] == "reservation-expired"
        assert touch(lid, "active")["status"] == "touched"
        with urllib.request.urlopen(original["cdp_url"] + "/json/list", timeout=5) as r:
            page = next(p for p in json.load(r) if p["type"] == "page")
        ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=5)
        try:
            ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate", "params": {"expression": "1"}}))
            assert "error" not in json.loads(ws.recv())
            active = status(lid)
            assert active["owner_state"] == "active"
            assert active["activity"]["last_activity"] > before["last_activity"]
        finally:
            ws.close()
        wait_idle(lid)
        parallel = request("parallel")
        assert parallel["status"] == "started" and parallel["instance_key"] != first["instance_key"]
        assert owner_state(original["process_identity"]) == "active"
        command("release", "--lease-id", parallel["lease_id"], "--agent-id", "fixture",
                "--disposition", "completed", "--profile-health", "healthy")
        policy("single")
        second = request("second")
        current = info(second["lease_id"])
        # Task-owned route (and all headed native displays) requires restart.
        assert second["status"] == "started"
        assert second["instance_key"] == first["instance_key"]
        assert current["pid"] != original["pid"]
        assert current["profile_dir"] == original["profile_dir"]
        assert owner_state(original["process_identity"]) == "terminal"
        from browser_profile_lease import local_cdp_version
        assert local_cdp_version(original["cdp_url"])["status"] != "ready"
        assert Path(current["profile_dir"]).exists()
        touch(second["lease_id"], "awaiting-input")
        queued = request("blocked", expect=2)
        assert queued["status"] == "queued-timeout"
        policy("multiple")
        stale = request("first")
        assert stale["status"] == "started" and stale["instance_key"] != first["instance_key"]
        assert command("touch", "--lease-id", lid, "--agent-id", "fixture", expect=2)["status"] == "not-owner"
        for lease in (second, stale):
            released = command("release", "--lease-id", lease["lease_id"], "--agent-id", "fixture",
                               "--disposition", "completed", "--profile-health", "healthy")
            assert released["status"] == "released"
        assert Path(current["profile_dir"]).exists()
        manual = request("manual", "--driving-mode", "manual")
        assert manual["status"] == "started"
        assert manual["instance_key"] in {second["instance_key"], stale["instance_key"]}
        manual_info = info(manual["lease_id"])
        assert manual_info["driving_mode"] == "manual" and not manual_info["activity_tracking"]
        assert status(manual["lease_id"])["activity"] is None
        assert request("manual")["lease_id"] == manual["lease_id"]  # omitted retry preserves mode
        command("release", "--lease-id", manual["lease_id"], "--agent-id", "fixture",
                "--disposition", "completed", "--profile-health", "healthy")
