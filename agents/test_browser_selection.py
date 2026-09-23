"""Deterministic admission/policy selection; private registries, no live accounts."""
import argparse
import json
from pathlib import Path

import pytest

from agents.test_browser_lease_recovery import args, provisioner
from agents.test_browser_resources import pooled_record, canonical_record, acquire
import browser_profile_lease as profiles


def setup_pool(monkeypatch, tmp_path, *, idle=300, capacity=True, single=False):
    m = provisioner(monkeypatch, tmp_path)
    c, row = pooled_record(m, tmp_path)
    canonical_record(m, row, "auto-fixture")
    info = m.record_info(row)
    info.update(activity_tracking=True, driving_mode="agent-driven", control_mode="pipe-fenced",
                command=["chromium", "--headless=new"], proxy_server="http://127.0.0.1:9",
                proxy_cert_mode="none", control_socket="fixture", cdp_url="http://127.0.0.1:9/old")
    Path(row["launch_file"]).write_text(json.dumps(info))
    m.save_metadata(c, row["lease_id"], {"proxy_ownership": "browser"})
    if single:
        profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="legacy-global",
                                              state_dir=str(m.STATE.parent), mode="single"))
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "activity_snapshot", lambda *_: dict(idle_seconds=idle, last_activity=0, inflight=0, reserved_seconds=0))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted" if capacity else "rejected"})
    monkeypatch.setattr(m, "healthy", lambda *_: True)
    monkeypatch.setattr(m, "unit_active", lambda *_: True)
    monkeypatch.setattr(m, "select_display", lambda *_: None)
    request = args()
    request.headless, request.proxy_ownership = True, "browser"
    freezes = []
    monkeypatch.setattr(m, "freeze_idle", lambda row, threshold: freezes.append(threshold) or True)
    monkeypatch.setattr("browser_control.rotate_control", lambda *_: {"fenced": True, "cdp_url": "http://127.0.0.1:9/new"})
    real_lease = m.lease
    def lease(request, *parts):
        if parts[0] == "register-browser":
            return {"status": "registered"}
        got = real_lease(request, *parts)
        if got["status"] == "leased":
            # Stop at the actual canonical transaction; no fake Chromium launch.
            m.emit({"status": "selected", "instance_key": got["lease"]["instance_key"]})
        return got
    monkeypatch.setattr(m, "lease", lease)
    return m, c, row, request, freezes


@pytest.mark.parametrize("single,capacity,idle,status", [
    (False, True, 300, "selected"),
    (False, True, 299, "selected"),
    (True, True, 299, "queued"),
    (True, True, 300, "reused"),
    (False, False, 299, "queued"),
    (False, False, 300, "reused"),
    (True, False, 300, "reused"),
])
def test_selection_matrix(monkeypatch, tmp_path, capsys, single, capacity, idle, status):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, idle=idle, capacity=capacity, single=single)
    monkeypatch.setattr(m, "retire", lambda *_: pytest.fail("headless fixed route must not stop"))
    with pytest.raises(SystemExit):
        m.start(request)
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == status
    assert freezes == ([300] if status == "reused" else [])
    if status == "selected":
        assert out["instance_key"] != "auto-fixture"
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        active = leases.execute("SELECT * FROM browser_profile_leases WHERE status='active'").fetchall()
        assert len(active) == (2 if status == "selected" else 1)
        if status == "queued":
            assert active[0]["owner_agent_id"] == row["agent_id"]
            assert leases.execute("SELECT count(*) FROM browser_profile_leases").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["owner_agent_id", "owner_run_id", "profile_dir", "instance_key", "manager_id"])
def test_stale_projection_never_revokes_control(monkeypatch, tmp_path, capsys, field):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, capacity=False)
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        leases.execute(f"UPDATE browser_profile_leases SET {field}='different'")
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["reason"] == "canonical-claim-conflict"
    assert freezes == []


def test_existing_owner_threshold_cannot_be_shortened(monkeypatch, tmp_path, capsys):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, idle=599, single=True)
    m.save_metadata(c, row["lease_id"], {"idle_claim_seconds": 600, "proxy_ownership": "browser"})
    request.idle_seconds = 1
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["status"] == "queued"
    assert freezes == []


@pytest.mark.parametrize("capacity", [False, True])
def test_same_owner_retry_precedes_resource_rejection(monkeypatch, tmp_path, capsys, capacity):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, capacity=capacity, single=True)
    request.agent_id, request.run_id = row["agent_id"], row["run_id"]
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["status"] == "already-running"
    assert freezes == []


@pytest.mark.parametrize("verified,capacity_after,status", [
    (False, False, "recovery-blocked"), (True, False, "queued"), (True, True, "selected")])
def test_low_memory_headed_restart_is_bounded(monkeypatch, tmp_path, capsys, verified, capacity_after, status):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, capacity=False)
    info = m.record_info(row)
    info["command"] = ["chromium"]
    Path(row["launch_file"]).write_text(json.dumps(info))
    stops = []
    def retire(*_):
        stops.append(row["lease_id"])
        if verified:
            assert m.release_lease(row["lease_id"], row["agent_id"])["status"] == "released"
            c.execute("UPDATE browsers SET state='stopped'")
            c.commit()
            monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted" if capacity_after else "rejected"})
        return verified
    monkeypatch.setattr(m, "retire", retire)
    monkeypatch.setattr(m, "restore_failed_stop", lambda *_: True)
    with pytest.raises(SystemExit):
        m.start(request)
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == status
    assert stops == [row["lease_id"]] and freezes == [300]
    if status == "queued":
        assert out["retryable"] is False
        with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
            last = leases.execute("SELECT * FROM browser_profile_leases").fetchall()
            assert len(last) == 1 and last[0]["profile_health"] == "healthy"


def test_single_policy_grandfathered_conflict_does_not_evict(monkeypatch, tmp_path, capsys):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path)
    # Policy changed after multiple leases existed: do not stop one in vain.
    got = profiles.cmd_acquire(argparse.Namespace(program="demo", account="anon", auth_domain="legacy-global",
        agent_id="third", run_id="third", purpose="fixture", ttl_seconds=60,
        state_dir=str(m.STATE.parent), recover_profile=False, instance_key="other", manager_id="other"))
    assert got["status"] == "leased"
    profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="legacy-global",
                                          state_dir=str(m.STATE.parent), mode="single"))
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["reason"] == "canonical-claim-conflict"
    assert freezes == []


def test_policy_is_exact_resolved_account_and_domain(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="one.test",
                                          state_dir=str(m.STATE.parent), mode="single"))
    assert m.account_policy("demo", "anon", "one.test")
    assert not m.account_policy("demo", "anon", "two.test")
    assert not m.account_policy("demo", "anon2", "one.test")
    assert not m.account_policy("another", "anon", "one.test")


def test_request_stops_retrying_after_one_retirement(monkeypatch, tmp_path, capsys):
    from agents.test_browser_provisioner import start_args
    m = provisioner(monkeypatch, tmp_path)
    request = start_args()
    request.wait_seconds = 120
    calls = []
    def run(*_args, **_kw):
        calls.append(True)
        return argparse.Namespace(returncode=2, stdout=json.dumps({"status": "queued", "retryable": False}))
    monkeypatch.setattr(m.subprocess, "run", run)
    monkeypatch.setattr(m.time, "sleep", lambda *_: pytest.fail("must not evict a second candidate"))
    with pytest.raises(SystemExit):
        m.request(request)
    assert json.loads(capsys.readouterr().out)["attempts"] == 1
    assert calls == [True]


def test_explicit_color_resolves_before_policy_and_instance_selection(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    account = {"alias": "account-a", "pwnfox_color": "blue", "auth_host_filter": "login.test",
               "browser_lease_enabled": True, "lifecycle": "active"}
    seen = []
    monkeypatch.setattr(profiles, "resolve_account", lambda program, selector: seen.append(selector) or (account, {}))
    monkeypatch.setattr(m, "account_policy", lambda *parts: seen.append(parts) or False)
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "rejected"})
    monkeypatch.setattr(m, "lease", lambda *_: pytest.fail("rejection precedes canonical acquisition"))
    request = args()
    request.account = "Blue"
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["reason"] == "no-capacity"
    assert seen == ["Blue", ("demo", "account-a", "login.test")]
    assert not (m.STATE.parent / "browser_profile_leases.sqlite").exists()


@pytest.mark.parametrize("protection", ["inflight", "reserved_seconds", "unavailable"])
def test_pressure_never_takes_protected_browser(monkeypatch, tmp_path, capsys, protection):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, capacity=False)
    activity = dict(idle_seconds=600, last_activity=0, inflight=0, reserved_seconds=0)
    activity[protection] = 1
    monkeypatch.setattr(m, "activity_snapshot", lambda *_: activity)
    with pytest.raises(SystemExit):
        m.start(request)
    assert json.loads(capsys.readouterr().out)["status"] == "queued"
    assert freezes == []


def test_rejected_transfer_fences_without_acquiring_another_profile(monkeypatch, tmp_path, capsys):
    m, c, row, request, freezes = setup_pool(monkeypatch, tmp_path, single=True)
    monkeypatch.setattr(profiles, "transfer_managed_lease", lambda *_args, **_kw: {"status": "locked"})
    with pytest.raises(SystemExit):
        m.start(request)
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "recovery-blocked" and out["control_frozen"]
    assert freezes == [300, 0]
    assert "pending_transfer" not in m.metadata(c, row)
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        assert leases.execute("SELECT lease_id FROM browser_profile_leases WHERE status='active'").fetchone()[0] == row["lease_id"]


def test_concurrent_single_requests_have_one_canonical_winner(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    m = provisioner(monkeypatch, tmp_path)
    profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="legacy-global",
                                          state_dir=str(m.STATE.parent), mode="single"))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m, "select_display", lambda *_: None)
    class Receipt(Exception):
        def __init__(self, result):
            self.result = result
    def emit(result, *_):
        raise Receipt(result)
    monkeypatch.setattr(m, "emit", emit)
    real_lease = m.lease
    def lease(request, *parts):
        got = real_lease(request, *parts)
        if got["status"] == "leased":
            emit({"status": "selected"})
        return got
    monkeypatch.setattr(m, "lease", lease)
    barrier = threading.Barrier(2)
    def run(label):
        request = args()
        request.agent_id = request.run_id = label
        barrier.wait(timeout=5)
        try:
            m.start(request)
        except Receipt as out:
            return out.result["status"]
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(run, ["one", "two"])) == ["queued", "selected"]
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        assert leases.execute("SELECT count(*) FROM browser_profile_leases").fetchone()[0] == 1


def test_transactional_transfer_honors_new_single_policy(tmp_path):
    first = acquire(tmp_path, "first")["lease"]
    acquire(tmp_path, "second", "other")
    profiles.cmd_policy(argparse.Namespace(program="demo", account="anon", auth_domain="local.test",
                                          state_dir=str(tmp_path), mode="single"))
    assert profiles.transfer_managed_lease(tmp_path / "browser_profile_leases.sqlite", first["lease_id"],
        "manager", "new", "new", "fixture", 60, "http://127.0.0.1:9/new")["status"] == "locked"
    assert acquire(tmp_path, "first")["status"] == "locked"
