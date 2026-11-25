"""Recovery-lease adoption, unpacked extensions, and provably stale legacy rows.

Offline fixtures only: temporary registries, a fake systemd/launcher and
short-lived local helper processes. No browser is launched.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from agents.test_browser_lease_recovery import provisioner, args as legacy_args
from agents.test_browser_provisioner import load, start_args
from agents.test_browser_safe_resume import prepared_resume
import browser_profile_lease as profiles
from browser_lifecycle import process_identity
import chromium_test

BROWSER_ID = "fixture-browser"


# --------------------------------------------------------------------------
# shared helpers

def lease_request(m, **overrides):
    request = argparse.Namespace(
        program="demo", account="anon", auth_domain=None, agent_id="agent", run_id="run",
        purpose="test", ttl_seconds=600, state_dir=str(m.STATE.parent), recover_profile=False,
        manager_id=None)
    for key, value in overrides.items():
        setattr(request, key, value)
    return request


def canonical(m, lease_id):
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        return dict(leases.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (lease_id,)).fetchone())


def release_with(m, lease_id, health):
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        leases.execute("BEGIN IMMEDIATE")
        row = leases.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (lease_id,)).fetchone()
        profiles.release_owned_in_transaction(leases, row, disposition="completed", profile_health=health)
        leases.commit()


def unhealthy_with_standalone_recovery_lease(m, health="needs-refresh"):
    """A released unhealthy profile plus the owner's own standalone recovery lease."""
    first = profiles.cmd_acquire(lease_request(m))
    assert first["status"] == "leased"
    release_with(m, first["lease"]["lease_id"], health)
    assert profiles.cmd_acquire(lease_request(m))["status"] == "account-unavailable"
    recovery = profiles.cmd_acquire(lease_request(m, recover_profile=True))
    assert recovery["status"] == "leased"
    assert canonical(m, recovery["lease"]["lease_id"])["manager_id"] is None
    return recovery["lease"]


def drive_start(m, monkeypatch, args, *, dispatch_rc=0, record=None):
    """Run start() with a fake systemd/launcher; acquisition uses the real lease CLI."""
    real_run = subprocess.run
    launch = m.STATE.parent / (BROWSER_ID + ".launch.json")
    state = {"dispatched": False, "shell": None}

    def fake_run(command, **kwargs):
        if command[:2] == [sys.executable, str(m.LEASE)]:
            if "register-browser" in command:
                return argparse.Namespace(returncode=0, stdout='{"status": "registered"}', stderr="")
            return real_run(command, **kwargs)
        if command[0] == "systemd-run" and "--unit=browser-" + BROWSER_ID in command:
            state["shell"] = command[-1]
            if dispatch_rc:
                return argparse.Namespace(returncode=dispatch_rc, stdout="", stderr="fixture dispatch failure")
            tokens = shlex.split(command[-1])
            Path(tokens[tokens.index("--profile-dir") + 1]).mkdir(parents=True, exist_ok=True)
            launch.write_text(json.dumps(record or {"cdp_url": "http://127.0.0.1:9"}))
            state["dispatched"] = True
        if command[0] not in ("systemd-run", "systemctl"):
            return real_run(command, **kwargs)  # e.g. read-only findmnt filesystem checks
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "unit_active", lambda _unit: state["dispatched"])
    monkeypatch.setattr(m, "unit_inactive", lambda _unit: True)
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m.uuid, "uuid4", lambda: BROWSER_ID)
    monkeypatch.setattr(m.time, "sleep", lambda _seconds: None)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    return exc.value.code, state


def full_start_args(**overrides):
    """start() arguments as main() would supply them for an anonymous profile."""
    args = start_args()
    values = dict(account="anon", headless=False, graphics_backend="auto", driving_mode=None,
                  owner_pid=None, legacy_profile=False, instance_key=None, task_owned=False,
                  recover_profile=False, load_extension=[])
    values.update(overrides)
    for key, value in values.items():
        setattr(args, key, value)
    return args


def recovery_start_args():
    return full_start_args(recover_profile=True)


def extension_dir(tmp_path, name="ext", manifest=True):
    path = tmp_path / name
    path.mkdir()
    if manifest:
        (path / "manifest.json").write_text(json.dumps(
            {"manifest_version": 3, "name": "fixture", "version": "1.0"}))
    return path


# --------------------------------------------------------------------------
# Papercut 1: the request path honours an exact recovery lease/mode

def test_unavailable_profile_guidance_points_to_provisioner_recovery_and_honest_release(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    first = profiles.cmd_acquire(lease_request(m))
    release_with(m, first["lease"]["lease_id"], "needs-refresh")
    result = profiles.cmd_acquire(lease_request(m, manager_id=m.manager_id()))
    assert result["status"] == "account-unavailable"
    assert "browser_provisioner.py request" in result["next"] and "--recover-profile" in result["next"]
    assert "record a healthy release" not in result["next"]


def test_recovery_request_adopts_own_standalone_lease_and_launches_that_profile(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    standalone = unhealthy_with_standalone_recovery_lease(m)
    code, state = drive_start(m, monkeypatch, recovery_start_args())
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result["status"] == "started"
    # The exact standalone lease is now manager-owned; no second lease exists.
    assert result["lease_id"] == standalone["lease_id"]
    adopted = canonical(m, standalone["lease_id"])
    assert adopted["status"] == "active" and adopted["manager_id"] == m.manager_id()
    tokens = shlex.split(state["shell"])
    assert tokens[tokens.index("--profile-dir") + 1] == standalone["profile_dir"]
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        assert leases.execute("SELECT count(*) FROM browser_profile_leases WHERE status='active'").fetchone()[0] == 1


def test_failed_recovery_launch_keeps_profile_gated_instead_of_recording_healthy(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    standalone = unhealthy_with_standalone_recovery_lease(m, "needs-cleanup")
    code, _ = drive_start(m, monkeypatch, recovery_start_args(), dispatch_rc=1)
    assert code == 2 and json.loads(capsys.readouterr().out)["status"] == "launch-failed"
    released = canonical(m, standalone["lease_id"])
    assert released["status"] == "released" and released["profile_health"] == "needs-cleanup"
    assert profiles.cmd_acquire(lease_request(m, agent_id="next", run_id="next"))["status"] == "account-unavailable"


@pytest.mark.parametrize("case", ["no-recover-flag", "browser-registered", "other-run"])
def test_recovery_adoption_is_exact_and_never_moves_a_foreign_or_launched_lease(monkeypatch, tmp_path, case):
    m = load(monkeypatch, tmp_path)
    if case == "other-run":
        first = profiles.cmd_acquire(lease_request(m))
        release_with(m, first["lease"]["lease_id"], "needs-refresh")
        standalone = profiles.cmd_acquire(lease_request(m, recover_profile=True, run_id="other"))["lease"]
    else:
        standalone = unhealthy_with_standalone_recovery_lease(m)
    if case == "browser-registered":
        with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
            leases.execute("UPDATE browser_profile_leases SET cdp_url='http://127.0.0.1:9', browser_status='running' "
                           "WHERE lease_id=?", (standalone["lease_id"],))
    result = profiles.cmd_acquire(lease_request(m, manager_id=m.manager_id(),
                                                recover_profile=case != "no-recover-flag"))
    expected = {"no-recover-flag": "account-unavailable", "browser-registered": "managed-by-provisioner",
                "other-run": "locked"}[case]
    assert result["status"] == expected
    assert canonical(m, standalone["lease_id"])["manager_id"] is None


# --------------------------------------------------------------------------
# Papercut 2: first-class unpacked-extension launch

def test_extension_dirs_are_validated_resolved_and_described(tmp_path):
    ext = extension_dir(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(ext, target_is_directory=True)
    entries = chromium_test.validate_extension_dirs([str(alias), str(ext)])
    assert [e["path"] for e in entries] == [str(ext.resolve())]
    assert entries[0]["manifest_version"] == 3 and entries[0]["name"] == "fixture"
    assert len(entries[0]["manifest_sha256"]) == 64


@pytest.mark.parametrize("bad", ["relative", "missing", "no-manifest", "comma", "manifest-is-dir"])
def test_extension_dirs_refuse_unusable_paths(tmp_path, bad):
    if bad == "relative":
        value = "ext"
    elif bad == "missing":
        value = str(tmp_path / "absent")
    elif bad == "no-manifest":
        value = str(extension_dir(tmp_path, manifest=False))
    elif bad == "comma":
        value = str(extension_dir(tmp_path, name="a,b"))
    else:
        path = extension_dir(tmp_path, manifest=False)
        (path / "manifest.json").mkdir()
        value = str(path)
    with pytest.raises(ValueError):
        chromium_test.validate_extension_dirs([value])


def launcher_args(extensions):
    return argparse.Namespace(chrome_binary="/opt/fixture/chrome", proxy_server=None, remote_allow_origins="*",
                              url=None, headless=True, graphics_backend="auto",
                              _load_extensions=extensions)


def test_launcher_replaces_disable_extensions_with_exact_load_flags(tmp_path, monkeypatch):
    monkeypatch.setattr(chromium_test, "find_chrome_binary", lambda explicit=None: "/opt/fixture/chrome")
    first, second = extension_dir(tmp_path, "one"), extension_dir(tmp_path, "two")
    entries = chromium_test.validate_extension_dirs([str(first), str(second)])
    command = chromium_test.build_command(launcher_args(entries), 9223, tmp_path / "profile")
    joined = f"{first.resolve()},{second.resolve()}"
    assert "--disable-extensions" not in command
    assert f"--disable-extensions-except={joined}" in command and f"--load-extension={joined}" in command
    plain = chromium_test.build_command(launcher_args([]), 9223, tmp_path / "profile")
    assert "--disable-extensions" in plain and not any("load-extension" in flag for flag in plain)


@pytest.mark.parametrize("version,ignored", [
    ("Google Chrome 150.0.7871.181", True),
    ("Google Chrome for Testing 148.0.7778.96", False),
    ("Chromium 148.0.7778.96", False),
    ("Google Chrome 120.0.1", False),
])
def test_only_branded_chrome_137_plus_is_refused_for_extensions(tmp_path, version, ignored):
    binary = tmp_path / "chrome"
    binary.write_text(f"#!/bin/sh\necho '{version}'\n")
    binary.chmod(0o755)
    assert chromium_test.branded_chrome_ignores_extensions(str(binary)) is ignored


class LaunchReached(Exception):
    pass


@pytest.mark.parametrize("explicit", [False, True])
def test_launcher_refuses_only_an_auto_selected_branded_chrome(monkeypatch, tmp_path, explicit):
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))
    monkeypatch.delenv("CHROMIUM_TEST_CHROME", raising=False)
    monkeypatch.delenv("CHROMIUM_TEST_PROXY_SERVER", raising=False)
    monkeypatch.setenv("CHROMIUM_TEST_PROXY_CERT_MODE", "none")
    monkeypatch.setattr(chromium_test, "assert_browser_launch_authorization", lambda _args: None)
    monkeypatch.setattr(chromium_test, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(chromium_test, "current_runtime", lambda: "unrouted")
    monkeypatch.setattr(chromium_test, "load_runtime_route", lambda _runtime: {})
    monkeypatch.setattr(chromium_test, "find_chrome_binary", lambda explicit=None: "/opt/fixture/google-chrome")
    probed = []
    monkeypatch.setattr(chromium_test, "branded_chrome_ignores_extensions", lambda binary: probed.append(binary) or True)
    monkeypatch.setattr(chromium_test.subprocess, "Popen", lambda *_a, **_k: (_ for _ in ()).throw(LaunchReached()))
    monkeypatch.setenv("HARNESS_BOUNTY_ARTIFACT_ROOT", str(tmp_path / "bounty"))
    argv = ["chromium_test.py", "demo", "smoke", "--json", "--headless", "--proxy-cert-mode", "none",
            "--profile-dir", str(tmp_path / "profile"), "--load-extension", str(extension_dir(tmp_path))]
    if explicit:
        argv += ["--chrome-binary", "/opt/fixture/wrapper"]
    monkeypatch.setattr(sys, "argv", argv)
    if explicit:
        with pytest.raises(LaunchReached):
            chromium_test.main()
        assert probed == []
    else:
        with pytest.raises(SystemExit, match="branded Google Chrome"):
            chromium_test.main()
        assert probed == ["/opt/fixture/google-chrome"]


@pytest.mark.parametrize("bad", ["relative", "no-manifest"])
def test_provisioner_cli_refuses_invalid_extension_before_any_state(monkeypatch, tmp_path, capsys, bad):
    m = load(monkeypatch, tmp_path)
    value = "relative/ext" if bad == "relative" else str(extension_dir(tmp_path, manifest=False))
    monkeypatch.setattr(sys, "argv", ["browser_provisioner.py", "request", "--task-owned", "--agent-id", "a",
                                      "--run-id", "r", "--purpose", "p", "--load-extension", value])
    monkeypatch.setattr(m, "request", lambda _args: pytest.fail("invalid extension must not reach request"))
    with pytest.raises(SystemExit) as exc:
        m.main()
    assert exc.value.code == 2 and "--load-extension" in capsys.readouterr().err
    assert not m.STATE.exists()


def test_provisioner_cli_accepts_valid_extension_as_resolved_path(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    ext = extension_dir(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(ext, target_is_directory=True)
    seen = {}
    monkeypatch.setattr(sys, "argv", ["browser_provisioner.py", "request", "--task-owned", "--agent-id", "a",
                                      "--run-id", "r", "--purpose", "p", "--load-extension", str(alias)])
    monkeypatch.setattr(m, "request", lambda parsed: seen.setdefault("extensions", parsed.load_extension))
    m.main()
    assert seen["extensions"] == [str(ext.resolve())]


def test_request_forwards_each_extension_to_start(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(m.subprocess, "run", lambda command, **_: captured.setdefault(
        "command", command) and argparse.Namespace(stdout='{"status":"started"}', returncode=0))
    monkeypatch.setattr(m, "maintain", lambda _args: None)
    args = argparse.Namespace(**{**vars(start_args()), "wait_seconds": 0, "load_extension": ["/x/one", "/x/two"]})
    with pytest.raises(SystemExit):
        m.request(args)
    command = captured["command"]
    assert [command[i + 1] for i, v in enumerate(command) if v == "--load-extension"] == ["/x/one", "/x/two"]


def test_start_passes_extensions_to_launcher_and_records_them(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    ext = str(extension_dir(tmp_path).resolve())
    args = full_start_args(load_extension=[ext])
    code, state = drive_start(m, monkeypatch, args, record={
        "cdp_url": "http://127.0.0.1:9", "load_extensions": [{"path": ext, "manifest_version": 3}]})
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result["status"] == "started"
    tokens = shlex.split(state["shell"])
    assert tokens[tokens.index("--load-extension") + 1] == ext
    assert result["load_extensions"][0]["path"] == ext
    info = json.loads((m.STATE.parent / (BROWSER_ID + ".launch.json")).read_text())
    assert info["launch_recipe"]["load_extensions"] == [ext]


def test_start_fails_closed_when_launcher_does_not_confirm_extensions(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = full_start_args(load_extension=[str(extension_dir(tmp_path).resolve())])
    code, _ = drive_start(m, monkeypatch, args, record={"cdp_url": "http://127.0.0.1:9"})
    result = json.loads(capsys.readouterr().out)
    assert code == 2 and result["status"] == "launch-failed" and "extensions" in result["detail"]
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        assert [tuple(r) for r in leases.execute("SELECT status FROM browser_profile_leases")] == [("released",)]


def test_resume_replays_recorded_extensions_for_a_stopped_browser(monkeypatch, tmp_path, capsys):
    m, _c, _row, recipe = prepared_resume(monkeypatch, tmp_path)
    recipe["load_extensions"] = ["/opt/fixture/ext"]
    record = tmp_path / "browser-0.json"
    record.write_text(json.dumps({**json.loads(record.read_text()), "launch_recipe": recipe}))
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda command, **_: calls.append(command) or SimpleNamespace(
        returncode=2, stdout=json.dumps({"status": "queued", "reason": "no-capacity"})))
    with pytest.raises(SystemExit):
        m.resume(argparse.Namespace(browser_id="browser-0", agent_id="agent", run_id="run"))
    assert json.loads(capsys.readouterr().out)["status"] == "queued"
    assert [calls[0][i + 1] for i, v in enumerate(calls[0]) if v == "--load-extension"] == ["/opt/fixture/ext"]


def test_running_browser_with_other_extension_set_is_not_reused(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    ext = str(extension_dir(tmp_path).resolve())
    args = full_start_args(load_extension=[ext])
    drive_start(m, monkeypatch, args, record={"cdp_url": "http://127.0.0.1:9", "load_extensions": [{"path": ext}]})
    capsys.readouterr()
    monkeypatch.setattr(m, "healthy", lambda _row: True)
    monkeypatch.setattr(m, "lifecycle_state", lambda *_: "active")
    retry = full_start_args()
    with pytest.raises(SystemExit) as exc:
        m.start(retry)
    result = json.loads(capsys.readouterr().out)
    assert exc.value.code == 2 and result.get("reason") == "extension-mismatch", result


# --------------------------------------------------------------------------
# Papercut 3: provably stale legacy rows no longer block named accounts

def dead_identity():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    identity = process_identity(child.pid)
    child.kill()
    child.wait()
    assert identity and process_identity(identity["pid"]) is None
    return identity


def legacy_row(m, tmp_path, *, domain="legacy-global", identity=None, created=None, lease_id="legacy",
               profile=None, record=None, state="stopped"):
    c = m.db()
    profile = profile or tmp_path / f"artifacts/demo/web/browser-profiles/{domain}/anon"
    profile.mkdir(parents=True, exist_ok=True)
    launch = tmp_path / f"{lease_id}.launch.json"
    if record is not False:
        launch.write_text(json.dumps(record if record is not None else {
            "instance_key": "", "instance_selection": "legacy", "process_identity": identity,
            "cdp_url": "http://127.0.0.1:9"}))
    t = created or time.time() - 1000
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        lease_id, lease_id + "-browser", "demo", "anon", domain, "old-agent", "old-run", "fixture",
        "browser-" + lease_id + "-browser", str(profile), str(launch), state, 0, t, t, t))
    c.commit()
    return c, c.execute("select * from browsers where lease_id=?", (lease_id,)).fetchone()


def quiet_systemd(m, monkeypatch):
    monkeypatch.setattr(m, "unit_active", lambda _unit: False)
    monkeypatch.setattr(m, "unit_inactive", lambda _unit: True)


def test_stale_singleton_lock_of_recorded_dead_root_is_not_live_ownership(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    quiet_systemd(m, monkeypatch)
    identity = dead_identity()
    c, row = legacy_row(m, tmp_path, identity=identity)
    (Path(row["profile_dir"]) / "SingletonLock").symlink_to(f"{identity['node']}-{identity['pid']}")
    assert m.quiescent_legacy(c, [row], row) is True
    assert (Path(row["profile_dir"]) / "SingletonLock").is_symlink()  # never removed here


@pytest.mark.parametrize("lock", ["live-pid", "other-host", "unrecorded-dead-pid", "root-alive"])
def test_singleton_lock_without_terminal_recorded_root_still_blocks(monkeypatch, tmp_path, lock):
    m = provisioner(monkeypatch, tmp_path)
    quiet_systemd(m, monkeypatch)
    identity = dead_identity()
    live = None
    if lock == "root-alive":
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        identity = process_identity(live.pid)
    c, row = legacy_row(m, tmp_path, identity=identity)
    target = {"live-pid": f"{identity['node']}-{os.getpid()}", "other-host": f"elsewhere-{identity['pid']}",
              "unrecorded-dead-pid": f"{identity['node']}-{dead_identity()['pid']}",
              "root-alive": f"{identity['node']}-{identity['pid']}"}[lock]
    (Path(row["profile_dir"]) / "SingletonLock").symlink_to(target)
    try:
        assert m.quiescent_legacy(c, [row], row) is False
    finally:
        if live:
            live.kill()
            live.wait()


def test_stale_lock_never_overrides_a_process_that_references_the_profile(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    quiet_systemd(m, monkeypatch)
    identity = dead_identity()
    c, row = legacy_row(m, tmp_path, identity=identity)
    (Path(row["profile_dir"]) / "SingletonLock").symlink_to(f"{identity['node']}-{identity['pid']}")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)",
                               "--user-data-dir=" + row["profile_dir"]])
    try:
        time.sleep(0.2)
        assert m.quiescent_legacy(c, [row], row) is False
    finally:
        holder.kill()
        holder.wait()


def test_unannotated_interrupted_slot_start_is_not_mistaken_for_the_legacy_profile(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    quiet_systemd(m, monkeypatch)
    c, legacy = legacy_row(m, tmp_path, identity=dead_identity())
    slot = tmp_path / "artifacts/demo/web/browser-instances/legacy-global/anon/d04-legal2"
    # Interrupted start: newer row, no launch record, keyed slot directory.
    _, interrupted = legacy_row(m, tmp_path, lease_id="interrupted", profile=slot, record=False,
                                created=time.time())
    assert m.row_instance_key(interrupted) == "d04-legal2" and m.row_instance_key(legacy) == ""
    assert m.selected_browser(c, "demo", "anon", "legacy-global", "")["lease_id"] == "legacy"
    assert m.selected_browser(c, "demo", "anon", "legacy-global", "d04-legal2")["lease_id"] == "interrupted"
    assert m.automatic_instance(c, legacy_args(), "anon", "legacy-global") == ""
    assert capsys.readouterr().out == ""


def test_unannotated_pre_instance_row_of_another_directory_still_blocks(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    quiet_systemd(m, monkeypatch)
    c, legacy = legacy_row(m, tmp_path, identity=dead_identity())
    other = tmp_path / "artifacts/demo/web/browser-profiles/anon"  # pre-domain, not a slot layout
    legacy_row(m, tmp_path, lease_id="older", profile=other, record={"cdp_url": "http://127.0.0.1:9"},
               created=time.time() - 5000)
    with pytest.raises(SystemExit):
        m.automatic_instance(c, legacy_args(), "anon", "legacy-global")
    assert json.loads(capsys.readouterr().out)["reason"] == "legacy-profile-not-quiescent"


class _ReadyCDP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b'{"Browser": "fixture", "Protocol-Version": "1.3"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - quiet fixture server
        pass


def stopped_domain_legacy(m, tmp_path, domain="hub.example.test"):
    """A manager-released stopped legacy profile for a non-global auth domain."""
    c, row = legacy_row(m, tmp_path, domain=domain, identity=dead_identity())
    got = profiles.cmd_acquire(lease_request(m, auth_domain=domain, agent_id="old-agent", run_id="old-run",
                                             instance_key="", manager_id=m.manager_id()))
    assert got["status"] == "leased" and got["lease"]["profile_dir"] == row["profile_dir"]
    release_with(m, got["lease"]["lease_id"], "healthy")
    c.execute("UPDATE browsers SET lease_id=? WHERE lease_id=?", (got["lease"]["lease_id"], row["lease_id"]))
    c.commit()
    return c.execute("select * from browsers").fetchone()


def pre_domain_history(m, profile, *, status="released", cdp_url=None, service_unit=None):
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        leases.execute(
            "INSERT INTO browser_profile_leases(lease_id,program,account_alias,auth_domain,owner_agent_id,"
            "owner_run_id,purpose,profile_dir,status,browser_status,created_at,heartbeat_at,expires_at,"
            "released_at,cdp_url,service_unit,instance_key) VALUES ('pre-domain','demo','anon',NULL,'a','r','p',?,?,"
            "'not-started',1,1,2,1,?,?,'')", (str(profile), status, cdp_url, service_unit))


def inherit(m, row, domain="hub.example.test"):
    request = lease_request(m, auth_domain=domain, agent_id="new-owner", run_id="new-owner", instance_key="",
                            manager_id=m.manager_id(), stopped_legacy_lease_id=row["lease_id"],
                            stopped_legacy_profile_dir=row["profile_dir"],
                            stopped_legacy_agent_id=row["agent_id"], stopped_legacy_run_id=row["run_id"])
    return profiles.cmd_acquire(request)


def test_terminal_pre_domain_history_of_another_directory_does_not_block_inheritance(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    row = stopped_domain_legacy(m, tmp_path)
    old = tmp_path / "artifacts/demo/web/browser-profiles/anon"
    old.mkdir(parents=True)
    pre_domain_history(m, old, cdp_url="http://127.0.0.1:9")  # dangling, closed endpoint
    result = inherit(m, row)
    assert result["status"] == "leased" and result["lease"]["profile_dir"] == row["profile_dir"]


@pytest.mark.parametrize("case", ["same-directory", "service-unit", "live-cdp", "global-domain"])
def test_pre_domain_history_still_blocks_without_absence_proof(monkeypatch, tmp_path, case):
    m = provisioner(monkeypatch, tmp_path)
    domain = "legacy-global" if case == "global-domain" else "hub.example.test"
    row = stopped_domain_legacy(m, tmp_path, domain)
    old = tmp_path / "artifacts/demo/web/browser-profiles/anon"
    old.mkdir(parents=True, exist_ok=True)
    server = None
    if case == "same-directory":
        alias = tmp_path / "alias"
        alias.symlink_to(row["profile_dir"], target_is_directory=True)
        pre_domain_history(m, alias)
    elif case == "service-unit":
        pre_domain_history(m, old, service_unit="browser-old")
    elif case == "live-cdp":
        server = http.server.HTTPServer(("127.0.0.1", 0), _ReadyCDP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        pre_domain_history(m, old, cdp_url=f"http://127.0.0.1:{server.server_address[1]}")
    else:
        pre_domain_history(m, old)
    try:
        result = inherit(m, row, domain)
    finally:
        if server:
            server.shutdown()
    assert result["status"] in ("locked", "profile-unavailable")
    assert result.get("reason", "legacy-profile-history-mismatch") == "legacy-profile-history-mismatch"
