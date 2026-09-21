"""Ordinary resource management: temporary registries, fake clocks, no sites."""
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import threading

import pytest

from agents.test_browser_lease_recovery import provisioner, record, args
import browser_profile_lease as profiles
from browser_control import PipeBrowser, meaningful
from browser_lifecycle import process_identity


def test_automatic_fresh_selection_is_stable_and_owner_isolated(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    c, a = m.db(), args()
    first = m.automatic_instance(c, a, "anon", "local.test")
    assert first.startswith("auto-")
    assert first == m.automatic_instance(c, a, "anon", "local.test")
    a.run_id = "another-run"
    assert first != m.automatic_instance(c, a, "anon", "local.test")


@pytest.mark.parametrize("boundary", ["canonical", "old-shared", "pre-domain", "lease"])
def test_auto_preserves_legacy_disk_and_registry_boundaries(monkeypatch, tmp_path, boundary):
    m = provisioner(monkeypatch, tmp_path)
    a = args()
    if boundary == "canonical":
        profiles.profile_dir("demo", "local.test", "anon").mkdir(parents=True)
    elif boundary == "old-shared":
        (profiles.shared_base() / "demo/ghost/chromium-test/profiles/anon").mkdir(parents=True)
    elif boundary == "pre-domain":
        (profiles.artifact_base() / "demo/web/browser-profiles/anon").mkdir(parents=True)
    else:
        acquire(m.STATE.parent, "")
    assert m.automatic_instance(m.db(), a, "anon", "local.test") == ""


def pooled_record(m, tmp_path):
    c, row = record(m, tmp_path, process_identity(os.getpid()))
    Path(row["profile_dir"]).rmdir()  # no legacy profile in this fixture
    Path(row["launch_file"]).write_text(json.dumps({"instance_key": "auto-fixture", "instance_selection": "automatic"}))
    return c, row


@pytest.mark.parametrize("selection", ["explicit", "automatic"])
def test_auto_does_not_select_explicit_or_active_transferred_hash(monkeypatch, tmp_path, selection):
    m = provisioner(monkeypatch, tmp_path)
    key = m.automatic_instance(m.db(), args(), "anon", "legacy-global")
    c, row = pooled_record(m, tmp_path)
    Path(row["launch_file"]).write_text(json.dumps({"instance_key": key, "instance_selection": selection}))
    monkeypatch.setattr(m, "lifecycle_state", lambda *_: "active")
    assert m.automatic_instance(c, args(), "anon", "legacy-global") != key
    if selection == "explicit":
        monkeypatch.setattr(m, "lifecycle_state", lambda *_: "idle")
        assert m.automatic_instance(c, args(), "anon", "legacy-global") != key


@pytest.mark.parametrize("state", ["active", "unknown", "activity-unavailable", "idle"])
def test_auto_only_selects_observable_idle_pool(monkeypatch, tmp_path, state):
    m = provisioner(monkeypatch, tmp_path)
    c, row = pooled_record(m, tmp_path)
    monkeypatch.setattr(m, "lifecycle_state", lambda *_: state)
    key = m.automatic_instance(c, args(), "anon", "legacy-global")
    assert (key == "auto-fixture") == (state == "idle")
    a = args()
    a.agent_id, a.run_id = row["agent_id"], row["run_id"]
    assert m.automatic_instance(c, a, "anon", "legacy-global") == "auto-fixture"


def test_auto_idle_selection_cannot_bypass_freeze_race(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = pooled_record(m, tmp_path)
    monkeypatch.setattr(m, "cleanup_unused", lambda *_: [])
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "lifecycle_state", lambda *_: "idle")
    monkeypatch.setattr(m, "freeze_idle", lambda *_: False)
    monkeypatch.setattr(m, "retire", lambda *_: pytest.fail("activity won; no stop"))
    monkeypatch.setattr(m, "lease", lambda *_: pytest.fail("activity won; no acquisition"))
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)["reason"] == "activity-changed"


def test_auto_single_policy_still_arbitrates_concurrent_acquisition(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="local.test",
                                          state_dir=str(m.STATE.parent), mode="single"))
    a, b = args(), args()
    b.run_id = "second"
    keys = [m.automatic_instance(m.db(), request, "anon", "local.test") for request in (a, b)]
    barrier = threading.Barrier(2)
    def run(key):
        barrier.wait(timeout=5)
        return acquire(m.STATE.parent, key, key)["status"]
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(run, keys)) == ["leased", "locked"]


def test_display_selection_preserves_owned_display_and_port(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    c, row = pooled_record(m, tmp_path)
    Path(row["launch_file"]).write_text(json.dumps({"kasmvnc": {"display": ":20", "web_port": 8463}}))
    monkeypatch.setattr("kasmvnc_session.can_bind_localhost", lambda _: True)
    a = args()
    m.select_display(c, a)
    assert a.kasmvnc_display != 20 and a.kasmvnc_web_port == 8464
    a.kasmvnc_display = 20
    from kasmvnc_session import KasmVNCSessionError
    with pytest.raises(KasmVNCSessionError):
        m.select_display(c, a)


@pytest.mark.parametrize("command,backend", [(["chromium", "--headless=new"], "auto"), (["chromium"], "kasmvnc")])
def test_same_owner_cannot_silently_reuse_wrong_display(monkeypatch, tmp_path, capsys, command, backend):
    m = provisioner(monkeypatch, tmp_path)
    c, row = pooled_record(m, tmp_path)
    Path(row["launch_file"]).write_text(json.dumps({"instance_key": "auto-fixture", "instance_selection": "automatic", "command": command}))
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "healthy", lambda *_: True)
    monkeypatch.setattr(m, "retire", lambda *_: pytest.fail("do not stop active owner"))
    a = args()
    a.agent_id, a.run_id = row["agent_id"], row["run_id"]
    a.display_backend = backend
    with pytest.raises(SystemExit):
        m.start(a)
    assert json.loads(capsys.readouterr().out)["reason"] == "display-mode-mismatch"


@pytest.mark.parametrize("kasm", [False, True])
def test_untracked_native_control_never_transfers_live(monkeypatch, tmp_path, capsys, kasm):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, {**process_identity(os.getpid()), "start": "dead"})
    info = {"control_mode": "pipe-fenced", "proxy_server": "http://127.0.0.1:9",
            "proxy_cert_mode": "none", "activity_tracking": False}
    if kasm:
        info["kasmvnc"] = {"display": ":20"}
    Path(row["launch_file"]).write_text(json.dumps(info))
    m.save_metadata(c, row["lease_id"], {"owner": {**process_identity(os.getpid()), "start": "dead"},
                                       "proxy_ownership": "browser"})
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "healthy", lambda *_: True)
    monkeypatch.setattr("browser_control.rotate_control", lambda *_: pytest.fail("native controller is not revocable"))
    stopped = []
    monkeypatch.setattr(m, "retire", lambda *_: stopped.append(True) or True)
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "queued"})
    a = args()
    a.proxy_ownership = "browser"
    with pytest.raises(SystemExit):
        m.start(a)
    assert stopped == [True]
    assert json.loads(capsys.readouterr().out)["reason"] == "no-capacity"


def test_display_failure_precedes_lease_mutation(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    from kasmvnc_session import KasmVNCSessionError
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    def unavailable(*_):
        raise KasmVNCSessionError("fixture")
    monkeypatch.setattr(m, "select_display", unavailable)
    monkeypatch.setattr(m, "lease", lambda *_: pytest.fail("display queue must not mutate lease"))
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)["reason"] == "display-unavailable"


def acquire(tmp_path, key, agent="owner"):
    return profiles.cmd_acquire(argparse.Namespace(
        program="demo", account="anon", auth_domain="local.test", agent_id=agent,
        run_id=agent, purpose="ordinary fixture", ttl_seconds=60,
        state_dir=str(tmp_path), recover_profile=False, instance_key=key,
        manager_id="manager"))


def test_instances_are_isolated_and_exact_same_slot_is_exclusive(monkeypatch, tmp_path):
    monkeypatch.setenv("HARNESS_BOUNTY_ARTIFACT_ROOT", str(tmp_path / "profiles"))
    one = acquire(tmp_path, "one")
    two = acquire(tmp_path, "two")
    assert one["status"] == two["status"] == "leased"
    assert one["lease"]["profile_dir"] != two["lease"]["profile_dir"]
    assert one["lease"]["account_alias"] == two["lease"]["account_alias"] == "anon"
    assert acquire(tmp_path, "one", "other")["status"] == "locked"
    assert acquire(tmp_path, "", "other")["status"] == "locked"


def test_null_domain_legacy_lock_has_priority(tmp_path):
    first = acquire(tmp_path, "one")["lease"]
    with profiles.connect(tmp_path / "browser_profile_leases.sqlite") as c:
        values = dict(c.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (first["lease_id"],)).fetchone())
        values.update(lease_id="legacy", auth_domain=None, instance_key="", owner_agent_id="other", created_at=1)
        c.execute("INSERT INTO browser_profile_leases (" + ",".join(values) + ") VALUES (" + ",".join("?" for _ in values) + ")", tuple(values.values()))
    assert acquire(tmp_path, "one")["status"] == "locked"


def test_self_managed_release_does_not_claim_verified_stop(tmp_path):
    first = acquire(tmp_path, "one")["lease"]
    with profiles.connect(tmp_path / "browser_profile_leases.sqlite") as c:
        c.execute("UPDATE browser_profile_leases SET manager_id=NULL,cdp_url='http://127.0.0.1:9',browser_status='running'")
    request = argparse.Namespace(state_dir=str(tmp_path), lease_id=first["lease_id"], agent_id="owner",
                                 disposition="completed", profile_health="healthy")
    assert profiles.cmd_release(request)["lease"]["browser_status"] == "unverified-after-release"


def test_same_account_color_can_have_multiple_isolated_slots(monkeypatch, tmp_path):
    account = {"alias": "ordinary-account", "pwnfox_color": "green",
               "browser_lease_enabled": True, "lifecycle": "active"}
    monkeypatch.setattr(profiles, "resolve_account", lambda *_: (account, {"accounts": [account]}))
    one, two = acquire(tmp_path, "one"), acquire(tmp_path, "two")
    assert one["status"] == two["status"] == "leased"
    assert one["lease"]["account_color"] == two["lease"]["account_color"] == "green"
    assert one["lease"]["profile_dir"] != two["lease"]["profile_dir"]


def test_legacy_slot_prevents_silent_parallel_migration(tmp_path):
    assert acquire(tmp_path, "")["status"] == "leased"
    assert acquire(tmp_path, "new", "other")["status"] == "locked"


def test_manual_single_browser_policy_is_atomic_and_domain_local(tmp_path):
    policy = argparse.Namespace(program="demo", account="anon", auth_domain="local.test",
                                state_dir=str(tmp_path), mode="single")
    assert profiles.cmd_policy(policy)["status"] == "policy-set"
    barrier = threading.Barrier(2)
    def run(key):
        barrier.wait(timeout=5)
        return acquire(tmp_path, key, key)["status"]
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(run, ["one", "two"])) == ["leased", "locked"]
    policy.auth_domain = "another.test"
    policy.mode = "multiple"
    profiles.cmd_policy(policy)
    assert acquire(tmp_path, "third", "third")["status"] == "locked"


def test_reports_are_passive_and_stale_release_status_is_honest(tmp_path):
    one = acquire(tmp_path, "one")["lease"]
    report = argparse.Namespace(state_dir=str(tmp_path), lease_id=one["lease_id"],
                                agent_id="owner", reason="user-observed")
    result = profiles.cmd_report_logout(report)
    assert not result["automatic_auth_retry"] and not result["policy_changed"]
    assert acquire(tmp_path, "two", "other")["status"] == "leased"
    with profiles.connect(tmp_path / "browser_profile_leases.sqlite") as c:
        assert c.execute("SELECT reason FROM browser_logout_reports WHERE report_id=?", (result["report_id"],)).fetchone()[0] == "user-observed"
    report.manager_id = "manager"
    report.disposition = "completed"
    report.profile_health = "healthy"
    released = profiles.cmd_release(report)["lease"]
    assert released["browser_status"] == "stopped"
    assert released["cdp_url"] is None and released["service_unit"] is None


@pytest.mark.parametrize("key", ["../other", "UPPER", "with space", "/absolute", "x" * 65])
def test_instance_keys_are_not_silently_normalized(tmp_path, key):
    with pytest.raises(ValueError):
        acquire(tmp_path, key)


def bridge(monkeypatch):
    b = PipeBrowser.__new__(PipeBrowser)
    b.last_use = 0
    b.last_activity = 0
    b.inflight = 0
    b.reserved_until = 0
    b.frozen = False
    monkeypatch.setattr("browser_control.time.monotonic", lambda: 7200)
    return b


class Request:
    def __init__(self, **data):
        self.data = data
    async def json(self):
        return self.data


def result(coroutine):
    return json.loads(asyncio.run(coroutine).text)


@pytest.mark.parametrize("method", ["Browser.getVersion", "Target.getTargets", "Page.enable", "Target.attachToTarget"])
def test_polling_and_transport_are_not_activity(method):
    assert not meaningful(method)


@pytest.mark.parametrize("method", ["Page.navigate", "Input.dispatchMouseEvent", "Runtime.evaluate", "Page.captureScreenshot"])
def test_user_commands_are_activity(method):
    assert meaningful(method)


def test_atomic_freeze_rechecks_inflight_reservation_and_activity(monkeypatch):
    b = bridge(monkeypatch)
    b.inflight = 1
    assert not result(b.freeze(Request(idle_seconds=7200)))["frozen"]
    b.inflight = 0
    result(b.reserve(Request(seconds=30)))
    assert not result(b.freeze(Request(idle_seconds=7200)))["frozen"]
    result(b.reserve(Request(seconds=0)))
    b.mark_activity()
    assert not result(b.freeze(Request(idle_seconds=7200)))["frozen"]
    b.last_use = 0
    assert result(b.freeze(Request(idle_seconds=7200)))["frozen"]
    assert b.frozen


def test_reservation_wins_concurrent_freeze_recheck(monkeypatch):
    b = bridge(monkeypatch)
    async def race():
        checking, resume = asyncio.Event(), asyncio.Event()
        class DelayedRequest:
            async def json(self):
                checking.set()
                await resume.wait()
                return {"idle_seconds": 7200}
        freezing = asyncio.create_task(b.freeze(DelayedRequest()))
        await checking.wait()
        await b.reserve(Request(seconds=30))
        resume.set()
        assert not json.loads((await freezing).text)["frozen"]
    asyncio.run(race())


def test_freeze_winner_rejects_late_reservation(monkeypatch):
    from aiohttp import web
    b = bridge(monkeypatch)
    assert result(b.freeze(Request(idle_seconds=7200)))["frozen"]
    with pytest.raises(web.HTTPConflict):
        result(b.reserve(Request(seconds=30)))


def test_pipe_backpressure_has_deadline_and_fails_closed(monkeypatch):
    b = bridge(monkeypatch)
    b.write_fd = 123
    stopped = []
    b.process = argparse.Namespace(terminate=lambda: stopped.append(True))
    monkeypatch.setattr("browser_control.select.select", lambda *_: ([], [], []))
    with pytest.raises(TimeoutError, match="pipe write deadline"):
        b._write(b"not-a-real-pipe")
    assert stopped == [True]


def test_reservation_does_not_slide(monkeypatch):
    b = bridge(monkeypatch)
    result(b.reserve(Request(seconds=30)))
    until = b.reserved_until
    monkeypatch.setattr("browser_control.time.monotonic", lambda: 7210)
    result(b.reserve(Request(seconds=3600)))
    assert b.reserved_until == until


@pytest.mark.parametrize("healthy", [True, False])
def test_failed_stop_restores_only_exact_healthy_browser(monkeypatch, tmp_path, healthy):
    m = provisioner(monkeypatch, tmp_path)
    _, row = record(m, tmp_path, None)
    monkeypatch.setattr(m, "healthy", lambda _: healthy)
    monkeypatch.setattr(m, "record_info", lambda _: {"control_socket": "fixture"})
    calls = []
    monkeypatch.setattr("browser_control.activity_control", lambda socket, action: calls.append(action) or {"frozen": False})
    assert m.restore_failed_stop(row) == healthy
    assert calls == (["thaw"] if healthy else [])


def test_explicit_terminal_supervisor_respects_operation_reservation(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    dead = {**process_identity(os.getpid()), "start": "old"}
    c, row = record(m, tmp_path, dead)
    activity = dict(idle_seconds=0, last_activity=0, inflight=0, reserved_seconds=0)
    monkeypatch.setattr(m, "activity_snapshot", lambda _: activity)
    assert m.lifecycle_state(c, row) == "terminal"
    activity["inflight"] = 1
    assert m.lifecycle_state(c, row) == "active"
    activity["inflight"] = 0
    activity["reserved_seconds"] = 1
    assert m.lifecycle_state(c, row) == "active"


def test_idle_owner_is_independent_of_live_pid(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, process_identity(os.getpid()))
    monkeypatch.setattr(m, "activity_snapshot", lambda _: dict(idle_seconds=901, inflight=0, reserved_seconds=0))
    assert m.lifecycle_state(c, row) == "idle"
    monkeypatch.setattr(m, "activity_snapshot", lambda _: dict(idle_seconds=901, inflight=1, reserved_seconds=0))
    assert m.lifecycle_state(c, row) == "active"


@pytest.mark.parametrize("idle,frozen,stop,expected", [(7199, True, True, []), (7200, False, True, []), (7200, True, False, []), (7200, True, True, ["browser-id"])])
def test_cleanup_threshold_recheck_and_verified_stop(monkeypatch, tmp_path, idle, frozen, stop, expected):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, process_identity(os.getpid()))
    monkeypatch.setattr(m, "activity_snapshot", lambda _: dict(idle_seconds=idle, inflight=0, reserved_seconds=0))
    monkeypatch.setattr(m, "freeze_idle", lambda r, seconds: frozen)
    calls = []
    monkeypatch.setattr(m, "restore_failed_stop", lambda *_: False)
    monkeypatch.setattr(m, "retire", lambda *_: calls.append("stop") or stop)
    assert m.cleanup_unused(c) == expected
    assert Path(row["profile_dir"]).exists()
    assert bool(calls) == (idle >= 7200 and frozen)


def test_request_performs_idle_cleanup_before_capacity(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(m, "cleanup_unused", lambda *_: calls.append("cleanup"))
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: calls.append("admission") or {"status": "rejected"})
    with pytest.raises(SystemExit):
        m.start(args())
    assert calls == ["cleanup", "admission"]
    assert json.loads(capsys.readouterr().out)["status"] == "queued"


def test_idle_claim_rechecks_before_any_stop_or_transfer(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    record(m, tmp_path, process_identity(os.getpid()))
    monkeypatch.setattr(m, "cleanup_unused", lambda *_: [])
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "lifecycle_state", lambda *_: "idle")
    monkeypatch.setattr(m, "freeze_idle", lambda *_: False)
    monkeypatch.setattr(m, "retire", lambda *_: pytest.fail("operation won recheck"))
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)["reason"] == "activity-changed"


def test_same_owner_can_enroll_pid_and_sees_missing_watcher(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    request = args()
    request.agent_id, request.run_id = row["agent_id"], row["run_id"]
    monkeypatch.setattr(m, "cleanup_unused", lambda *_: [])
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "healthy", lambda *_: True)
    monkeypatch.setattr(m, "unit_active", lambda *_: False)
    with pytest.raises(SystemExit):
        m.start(request)
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "already-running" and not out["watcher_healthy"]
    assert m.metadata(c, row)["owner"] == process_identity(os.getpid())
    assert out["instance_id"] == out["pane_id"] == row["browser_id"]


def test_task_owned_requires_no_supervisor_or_inventory(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True
    request.owner_pid = None
    request.headless = True
    request.program = request.account = request.auth_domain = None
    monkeypatch.setattr(profiles, "load_inventory", lambda *_: pytest.fail("no accounts"))
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "rejected"})
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["status"] == "queued"
