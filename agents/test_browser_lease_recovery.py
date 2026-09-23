"""Failure and ownership regressions using only temporary registries."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

import pytest

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills/chromium-test/scripts"
sys.path.insert(0, str(SCRIPTS))
import browser_profile_lease as profiles
from browser_lifecycle import process_identity


def provisioner(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "BROWSER_PROVISIONER_STATE", str(tmp_path / "state/manager.sqlite")
    )
    monkeypatch.setenv("HARNESS_BOUNTY_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))
    spec = importlib.util.spec_from_file_location(
        "recovery_provisioner", SCRIPTS / "browser_provisioner.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args():
    return argparse.Namespace(
        program="demo",
        account="anon",
        auth_domain=None,
        agent_id="new",
        run_id="new-run",
        purpose="fixture",
        ttl_seconds=30,
        idle_seconds=1,
        min_ram_available_mib=1,
        min_swap_free_mib=0,
        owner_pid=os.getpid(),
        task_owned=False,
        proxy_ownership="task",
        proxy_server="http://127.0.0.1:9",
        proxy_cert_mode="none",
        recover_profile=False,
    )


def record(m, tmp_path, owner):
    c = m.db()
    t = time.time() - 100000
    path = tmp_path / "artifacts/demo/web/browser-profiles/legacy-global/anon"
    path.mkdir(parents=True)
    c.execute(
        "insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "old",
            "browser-id",
            "demo",
            "anon",
            "legacy-global",
            "old-agent",
            "old-run",
            "fixture",
            "fixture-unit",
            str(path),
            str(tmp_path / "record.json"),
            "running",
            0,
            t,
            t,
            t,
        ),
    )
    c.commit()
    m.save_metadata(c, "old", {"owner": owner, "ttl": 30})
    return c, c.execute("select * from browsers").fetchone()


@pytest.mark.parametrize(
    "identity,reason", [("active", "owner-active"), ("unknown", "owner-unknown")]
)
def test_idle_or_unknown_never_reclaimed(
    monkeypatch, tmp_path, capsys, identity, reason
):
    m = provisioner(monkeypatch, tmp_path)
    record(m, tmp_path, process_identity(os.getpid()) if identity == "active" else None)
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(
        m, "stop_unit", lambda *_: pytest.fail("must not stop protected owner")
    )
    with pytest.raises(SystemExit):
        m.start(args())
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "locked" and result["reason"] == reason


def test_legacy_idle_reaper_protects_live_owner(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    record(m, tmp_path, process_identity(os.getpid()))
    monkeypatch.setattr(m, "unit_active", lambda *_: True)
    monkeypatch.setattr(m, "lease", lambda *_: {"status": "renewed"})
    monkeypatch.setattr(m, "stop_unit", lambda *_: pytest.fail("idle is not terminal"))
    with pytest.raises(SystemExit):
        m.reap(argparse.Namespace(idle_seconds=1))
    assert json.loads(capsys.readouterr().out)["idle_stopped"] == []


def test_awaiting_input_has_absolute_bound(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, process_identity(os.getpid()))
    m.save_metadata(
        c, "old", {"owner": process_identity(os.getpid()), "awaiting_until": 1}
    )
    monkeypatch.setattr(
        m, "lease", lambda *_: pytest.fail("expired owner must not renew")
    )
    with pytest.raises(SystemExit):
        m.touch(
            argparse.Namespace(
                lease_id="old",
                agent_id="old-agent",
                work_state="active",
                ttl_seconds=30,
            )
        )
    assert json.loads(capsys.readouterr().out)["status"] == "owner-terminal"


def test_old_service_incarnation_is_not_stopped(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    _, row = record(m, tmp_path, None)
    Path(row["launch_file"]).write_text(
        json.dumps({"unit_invocation": "old-incarnation"})
    )
    monkeypatch.setattr(m, "unit_active", lambda *_: True)
    monkeypatch.setattr(m, "unit_identity", lambda *_: "new-incarnation")
    monkeypatch.setattr(m, "stop_unit", lambda *_: pytest.fail("unit was replaced"))
    assert not m.stop_recorded(row)


def test_task_proxy_forces_verified_restart(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    _, row = record(m, tmp_path, {**process_identity(os.getpid()), "start": "old"})
    Path(row["launch_file"]).write_text(
        json.dumps(
            {"control_mode": "pipe-fenced", "proxy_server": "http://127.0.0.1:9"}
        )
    )
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    seen = []
    monkeypatch.setattr(m, "retire", lambda *_: seen.append("verified-stop") or True)
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "rejected"})
    with pytest.raises(SystemExit):
        m.start(args())
    assert seen == ["verified-stop"]
    assert json.loads(capsys.readouterr().out)["status"] == "queued"


def test_recovery_does_not_proceed_when_stop_unverified(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    record(m, tmp_path, {**process_identity(os.getpid()), "start": "old"})
    monkeypatch.setattr(m, "sweep_rows", lambda *_: ([], []))
    monkeypatch.setattr(m, "retire", lambda *_: False)
    monkeypatch.setattr(
        m, "lease", lambda *_: pytest.fail("must not acquire overlapping profile")
    )
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)["status"] == "recovery-blocked"


def test_task_mode_refuses_program_and_inventory(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True
    monkeypatch.setattr(
        profiles, "load_inventory", lambda *_: pytest.fail("no inventory access")
    )
    with pytest.raises(SystemExit):
        m.start(request)
    assert (
        json.loads(capsys.readouterr().out)["status"]
        == "task-owned-conflicts-with-program"
    )


def acquire(tmp_path):
    return profiles.cmd_acquire(
        argparse.Namespace(
            program="demo",
            account="anon",
            auth_domain=None,
            agent_id="old",
            run_id="run",
            purpose="fixture",
            ttl_seconds=1,
            state_dir=str(tmp_path),
            recover_profile=False,
            manager_id="manager",
        )
    )


def test_managed_expiry_stays_locked_until_lifecycle_reconciles(tmp_path):
    first = acquire(tmp_path)
    with profiles.connect(tmp_path / "browser_profile_leases.sqlite") as c:
        profiles.expire_leases(c, time.time() + 100)
        row = profiles.active_lease(
            c, "demo", "anon", "legacy-global", time.time() + 100
        )
        assert row["lease_id"] == first["lease"]["lease_id"]


def test_transfer_rotates_atomically_and_old_mutations_fail(tmp_path):
    first = acquire(tmp_path)
    database = tmp_path / "browser_profile_leases.sqlite"
    new = profiles.transfer_managed_lease(
        database,
        first["lease"]["lease_id"],
        "manager",
        "new",
        "new-run",
        "fixture",
        30,
        "http://127.0.0.1:9/new",
    )
    assert (
        new["status"] == "leased"
        and new["lease"]["lease_id"] != first["lease"]["lease_id"]
    )
    with profiles.connect(database) as c:
        assert (
            c.execute(
                "select count(*) from browser_profile_leases where status='active'"
            ).fetchone()[0]
            == 1
        )
    stale = argparse.Namespace(
        state_dir=str(tmp_path),
        lease_id=first["lease"]["lease_id"],
        agent_id="old",
        manager_id="manager",
        ttl_seconds=30,
        work_state="active",
        disposition="completed",
        profile_health="healthy",
    )
    assert profiles.cmd_renew(stale)["status"] == "not-owner-or-expired"
    assert profiles.cmd_release(stale)["status"] == "not-owner-or-missing"
    assert (
        profiles.transfer_managed_lease(
            database,
            first["lease"]["lease_id"],
            "manager",
            "third",
            "third-run",
            "fixture",
            30,
            "http://127.0.0.1:9/third",
        )["status"]
        == "not-owner-or-expired"
    )


def test_managed_lease_cannot_be_released_by_legacy_cli(tmp_path):
    first = acquire(tmp_path)
    request = argparse.Namespace(
        state_dir=str(tmp_path),
        lease_id=first["lease"]["lease_id"],
        agent_id="old",
        disposition="completed",
        profile_health="healthy",
    )
    assert profiles.cmd_release(request)["status"] == "not-owner-or-missing"


def test_concurrent_transfers_have_one_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    first = acquire(tmp_path)
    database = tmp_path / "browser_profile_leases.sqlite"

    def transfer(index):
        return profiles.transfer_managed_lease(
            database,
            first["lease"]["lease_id"],
            "manager",
            str(index),
            str(index),
            "fixture",
            30,
            "http://127.0.0.1:9/new",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(transfer, range(2)))
    assert sorted(result["status"] for result in results) == [
        "leased",
        "not-owner-or-expired",
    ]


def test_permission_error_is_unknown_not_dead(monkeypatch):
    import browser_lifecycle

    identity = process_identity(os.getpid())

    def denied(_):
        raise PermissionError("denied")

    monkeypatch.setattr(browser_lifecycle, "process_identity", denied)
    assert browser_lifecycle.owner_state(identity) == "unknown"


def test_pending_projection_recovers_before_old_owner_can_release(
    monkeypatch, tmp_path, capsys
):
    m = provisioner(monkeypatch, tmp_path)
    # Set up a canonical lease then simulate interruption after its transfer.
    c, row = record(m, tmp_path, {**process_identity(os.getpid()), "start": "old"})
    database = m.STATE.parent / "browser_profile_leases.sqlite"
    request = argparse.Namespace(
        program="demo",
        account="anon",
        auth_domain=None,
        agent_id="old-agent",
        run_id="old-run",
        purpose="fixture",
        ttl_seconds=30,
        state_dir=str(m.STATE.parent),
        recover_profile=False,
        manager_id="manager",
    )
    first = profiles.cmd_acquire(request)
    c.execute(
        "update browsers set lease_id=? where lease_id=?",
        (first["lease"]["lease_id"], "old"),
    )
    c.commit()
    # The paths must match; the profile helper owns the canonical path.
    c.execute("update browsers set profile_dir=?", (first["lease"]["profile_dir"],))
    c.commit()
    info = {"cdp_url": "http://127.0.0.1:9/new"}
    Path(row["launch_file"]).write_text(json.dumps(info))
    m.save_metadata(
        c,
        first["lease"]["lease_id"],
        {
            "pending_transfer": {
                "agent_id": "new",
                "run_id": "new-run",
                "metadata": {"owner": process_identity(os.getpid()), "ttl": 30},
            }
        },
    )
    second = profiles.transfer_managed_lease(
        database,
        first["lease"]["lease_id"],
        "manager",
        "new",
        "new-run",
        "fixture",
        30,
        info["cdp_url"],
    )
    monkeypatch.setattr(
        m,
        "stop_unit",
        lambda *_: pytest.fail("old owner cannot stop transferred browser"),
    )
    with pytest.raises(SystemExit):
        m.release(
            argparse.Namespace(
                lease_id=first["lease"]["lease_id"],
                agent_id="old-agent",
                disposition="completed",
                profile_health="healthy",
            )
        )
    assert json.loads(capsys.readouterr().out)["status"] == "not-owner"
    assert (
        c.execute(
            "select agent_id from browsers where lease_id=?",
            (second["lease"]["lease_id"],),
        ).fetchone()[0]
        == "new"
    )


@pytest.mark.parametrize(
    "same_lock,pid_reused,expected",
    [(True, False, True), (False, False, False), (True, True, False)],
)
def test_retention_stale_lock_requires_exact_dead_pid(
    monkeypatch, tmp_path, same_lock, pid_reused, expected
):
    m = provisioner(monkeypatch, tmp_path)
    identity = process_identity(os.getpid())
    _, row = record(m, tmp_path, identity)
    Path(row["launch_file"]).write_text(json.dumps({"process_identity": identity}))
    lock = Path(row["profile_dir"]) / "SingletonLock"
    lock.symlink_to(
        f"{identity['node']}-{identity['pid']}" if same_lock else "unknown-node-999"
    )
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(
        m, "process_identity", lambda _: {"start": "different"} if pid_reused else None
    )
    assert m.stale_singleton_lock(lock, row) is expected


def test_terminal_task_proxy_has_no_live_reuse_grace(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    record(m, tmp_path, {**process_identity(os.getpid()), "start": "old"})
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    retired = []
    monkeypatch.setattr(
        m, "retire", lambda *a: retired.append(a[1]["lease_id"]) or True
    )
    m.maintain(argparse.Namespace())
    assert retired == ["old"]


def test_task_lease_cannot_alias_program_profile(tmp_path):
    request = argparse.Namespace(
        task_owned=True, program="real-program", account="anon", auth_domain="task"
    )
    assert profiles.cmd_acquire(request)["status"] == "invalid-task-profile"
