"""Synthetic, offline regressions for task proxy generation receipts."""
import argparse
import contextlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "skills/chromium-test/scripts/browser_provisioner.py"


@pytest.fixture
def fixture(monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_PROVISIONER_STATE", str(tmp_path / "state/manager.sqlite"))
    spec = importlib.util.spec_from_file_location("receipt_provisioner", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    conn = module.db()
    conn.execute("insert into finished_proxies values(?,?,?,?)", ("agent", "run", "old-lane", 1))
    conn.commit()
    monkeypatch.setattr(module, "port_open", lambda _: False)
    monkeypatch.setattr(module, "unit_active", lambda _: False)
    args = argparse.Namespace(agent_id="agent", run_id="run", program="demo", account="fixture", purpose="test")
    return module, conn, args


def result(module, args, capsys, recovery=False):
    with pytest.raises(SystemExit) as exc:
        module.finish_proxy(args, recovery=recovery)
    return exc.value.code, json.loads(capsys.readouterr().out)


class Interrupted(BaseException):
    pass


def test_reap_keeps_old_receipt_while_new_attempt_is_unfinished(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    def interrupt():
        raise Interrupted()
    monkeypatch.setattr(module, "mitm_runtime", interrupt)
    with pytest.raises(Interrupted):
        module.start_proxy(conn, args)
    conn.execute("insert into finished_proxies values(?,?,?,?)", ("other", "run", "expired", 1))
    conn.commit()
    monkeypatch.setattr(module, "maintain", lambda _: None)
    monkeypatch.setattr(module, "cleanup_unused", lambda _: [])
    with pytest.raises(SystemExit) as exc:
        module.reap(argparse.Namespace())
    assert exc.value.code == 0
    capsys.readouterr()
    assert [r[0] for r in conn.execute("select lane from finished_proxies")] == ["old-lane"]
    assert result(module, args, capsys, recovery=True)[1]["status"] == "aborted"
    with pytest.raises(SystemExit):
        module.reap(argparse.Namespace())
    capsys.readouterr()
    assert [r[0] for r in conn.execute("select lane from finished_proxies")] == ["old-lane"]


def test_recover_unadmitted_start_preserves_previous_receipt(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    def interrupt():
        raise Interrupted()
    monkeypatch.setattr(module, "mitm_runtime", interrupt)
    with pytest.raises(Interrupted):
        module.start_proxy(conn, args)
    lane = module.proxy_row(conn, args)["lane"]
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"], output["lane"]) == (0, "aborted", lane)
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    code, retry = result(module, args, capsys)
    assert (code, retry["status"], retry["lane"]) == (0, "aborted", lane)


def test_reuse_rejects_different_process_owner(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    args.owner_pid = 10
    monkeypatch.setattr(module, "process_identity", lambda pid: {"pid": pid, "start": 1})
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = module.start_proxy(conn, args)
    args.owner_pid = 11
    with pytest.raises(SystemExit) as exc:
        module.start_proxy(conn, args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "proxy-conflict"
    assert module.proxy_row(conn, args)["lane"] == row["lane"]


def test_reuse_cannot_omit_recorded_owner(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    args.owner_pid = 10
    monkeypatch.setattr(module, "process_identity", lambda pid: {"pid": pid, "start": 1})
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = module.start_proxy(conn, args)
    same, created = module.start_proxy(conn, args)
    assert not created and same["lane"] == row["lane"]
    args.owner_pid = None
    with pytest.raises(SystemExit) as exc:
        module.start_proxy(conn, args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "proxy-conflict"


def test_failed_running_transition_rolls_back_before_cleanup(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    conn.execute("create trigger reject_admission before update of state on task_proxies "
                 "when new.state='running' begin select raise(abort,'fixture transition failure'); end")
    conn.commit()
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    original = module.rollback_proxy
    observed = []
    def cleanup(c, row):
        observed.append((c.in_transaction, row["state"]))
        return original(c, row)
    monkeypatch.setattr(module, "rollback_proxy", cleanup)
    with pytest.raises(module.ProxyStartupError, match="reconcile"):
        module.start_proxy(conn, args)
    assert observed == [(False, "starting")]
    row = module.proxy_row(conn, args)
    assert row["state"] == "cleanup-failed" and row["flow_path"] and row["capture_identity"]
    assert conn.execute("select outcome from proxy_attempts where lane=?", (row["lane"],)).fetchone()[0] == "capture-uncertain"
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    code, output = result(module, args, capsys, recovery=True)
    assert code == 2 and output["status"] == "proxy-capture-unavailable" and output["lane"] == row["lane"]


def test_clean_failed_start_is_not_previous_finished_generation(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    def fail():
        raise RuntimeError("fixture startup failure")
    monkeypatch.setattr(module, "mitm_runtime", fail)
    with pytest.raises(RuntimeError, match="fixture startup failure"):
        module.start_proxy(conn, args)
    assert module.proxy_row(conn, args) is None
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    code, output = result(module, args, capsys)
    assert code == 0 and output["status"] == "aborted" and output["lane"] != "old-lane"


def test_cleanup_failure_recovery_does_not_publish_unadmitted_receipt(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    calls = 0
    def port(_):
        nonlocal calls
        calls += 1
        return calls > 1
    monkeypatch.setattr(module, "port_open", port)
    monkeypatch.setattr(module, "mitm_runtime", lambda: (_ for _ in ()).throw(RuntimeError("startup")))
    with pytest.raises(RuntimeError, match="startup"):
        module.start_proxy(conn, args)
    row = module.proxy_row(conn, args)
    assert row["state"] == "cleanup-failed"
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"]) == (2, "proxy-conflict")
    monkeypatch.setattr(module, "port_open", lambda _: False)
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"], output["lane"]) == (0, "aborted", row["lane"])
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"


def test_admitted_generation_keeps_receipt_until_finish(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, created = module.start_proxy(conn, args)
    assert created and row["admitted"] == 1
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    code, output = result(module, args, capsys)
    assert (code, output["status"], output["lane"]) == (0, "finished", row["lane"])
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == row["lane"]
    code, output = result(module, args, capsys)
    assert (code, output["status"], output["lane"], output["already_finished"]) == (0, "finished", row["lane"], True)


def test_failed_finish_receipt_transaction_is_rolled_back(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = module.start_proxy(conn, args)
    conn.execute("create trigger reject_receipt before insert on proxy_attempts "
                 "when new.outcome='finished' begin select raise(abort,'fixture finish failure'); end")
    conn.commit()
    finish_conn = module.db()
    monkeypatch.setattr(module, "db", lambda: finish_conn)
    with pytest.raises(Exception, match="fixture finish failure"):
        module.finish_proxy(args)
    assert not finish_conn.in_transaction
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    assert module.proxy_row(conn, args)["state"] == "stopped"
    conn.execute("drop trigger reject_receipt")
    conn.commit()
    code, output = result(module, args, capsys)
    assert (code, output["status"], output["lane"]) == (0, "finished", row["lane"])


def test_recovery_of_admitted_cleanup_failure_finishes_new_generation(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = module.start_proxy(conn, args)
    conn.execute("update task_proxies set state='cleanup-failed' where lane=?", (row["lane"],))
    conn.commit()
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"], output["lane"]) == (0, "finished", row["lane"])
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == row["lane"]


def test_mismatched_finished_receipt_is_not_reported_as_latest(fixture, capsys):
    module, conn, args = fixture
    conn.execute("insert into proxy_attempts values(?,?,?,?)", ("agent", "run", "new-lane", "finished"))
    conn.commit()
    code, output = result(module, args, capsys)
    assert (code, output["status"]) == (2, "proxy-conflict")
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"


@pytest.mark.parametrize("state", ["cleanup-failed", "finishing", "stopped", "stop-failed"])
def test_legacy_ambiguous_admission_is_not_asserted(fixture, capsys, state):
    module, conn, args = fixture
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) "
                 "values(?,?,?,?,?,?,?,?,?,?)",
                 ("agent", "run", "demo", "fixture", "test", "legacy-lane", 8081,
                  "fixture-unit", str(module.STATE.parent / "legacy-lane"), state))
    conn.commit()
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"], output["lane"]) == (0, "admission-unknown", "legacy-lane")
    assert conn.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    code, output = result(module, args, capsys)
    assert (code, output["status"], output["lane"]) == (0, "admission-unknown", "legacy-lane")


@pytest.mark.parametrize("recovery,state", [(False, "running"), (True, "cleanup-failed")])
def test_expected_lane_rejects_stale_caller_before_any_side_effect(fixture, monkeypatch, capsys, recovery, state):
    module, conn, args = fixture
    directory = Path(module.STATE.parent) / "synthetic-new"
    directory.mkdir(parents=True)
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
                 ("agent", "run", "demo", "fixture", "test", "new-lane", 8081, "synthetic", str(directory), state))
    conn.execute("insert into proxy_attempts values(?,?,?,?)", ("agent", "run", "new-lane", "starting"))
    conn.commit()
    args.expected_lane = "old-lane"
    monkeypatch.setattr(module, "unit_active", lambda _: pytest.fail("stale caller examined unit"))
    code, output = result(module, args, capsys, recovery=recovery)
    assert (code, output["status"]) == (2, "proxy-conflict")
    assert module.proxy_row(conn, args)["state"] == state
    assert conn.execute("select lane from proxy_attempts").fetchone()[0] == "new-lane"


@pytest.mark.parametrize("outcome", ["finished", "aborted", "admission-unknown", "starting"])
def test_expected_lane_fences_latest_receipt_and_attempt(fixture, capsys, outcome):
    module, conn, args = fixture
    conn.execute("insert into proxy_attempts values(?,?,?,?)", ("agent", "run", "new-lane", outcome))
    if outcome == "finished":
        conn.execute("update finished_proxies set lane='new-lane'")
    conn.commit()
    args.expected_lane = "old-lane"
    code, output = result(module, args, capsys)
    assert (code, output["status"]) == (2, "proxy-conflict")
    args.expected_lane = "new-lane"
    code, output = result(module, args, capsys)
    assert output["status"] == ("proxy-conflict" if outcome == "starting" else outcome)
    assert code == (2 if outcome == "starting" else 0)


def test_expected_lane_exact_finish_and_retry(fixture, monkeypatch, capsys):
    module, conn, args = fixture
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = module.start_proxy(conn, args)
    assert module.proxy_metadata(row)["lane"] == row["lane"]
    args.expected_lane = row["lane"]
    assert result(module, args, capsys)[1]["status"] == "finished"
    assert result(module, args, capsys)[1]["already_finished"] is True
    args.expected_lane = "old-lane"
    assert result(module, args, capsys)[1]["status"] == "proxy-conflict"


def test_legacy_retry_can_finish_new_generation(fixture, monkeypatch, capsys):
    """Document the compatibility limitation with a real synthetic state transition."""
    module, conn, args = fixture
    directory = Path(module.STATE.parent) / "synthetic-new"
    directory.mkdir(parents=True)
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
                 ("agent", "run", "demo", "fixture", "test", "new-lane", 8081, "synthetic", str(directory), "running"))
    conn.commit()
    code, output = result(module, args, capsys)
    assert (code, output["status"], output["lane"]) == (0, "finished", "new-lane")
    assert module.proxy_row(conn, args) is None


def test_expected_lane_allows_exact_recovery(fixture, capsys):
    module, conn, args = fixture
    directory = Path(module.STATE.parent) / "synthetic-new"
    directory.mkdir(parents=True)
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state,admitted) values(?,?,?,?,?,?,?,?,?,?,?)",
                 ("agent", "run", "demo", "fixture", "test", "new-lane", 8081, "synthetic", str(directory), "cleanup-failed", 0))
    conn.commit()
    args.expected_lane = "new-lane"
    code, output = result(module, args, capsys, recovery=True)
    assert (code, output["status"], output["lane"]) == (0, "aborted", "new-lane")
    assert result(module, args, capsys, recovery=True)[1]["status"] == "aborted"


@pytest.mark.parametrize("replace_generation", [False, True])
def test_reaper_pins_generation_across_lock_gap(fixture, monkeypatch, capsys, replace_generation):
    module, conn, args = fixture
    directory = Path(module.STATE.parent) / "synthetic-new"
    directory.mkdir(parents=True)
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state,updated,owner) values(?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("agent", "run", "demo", "fixture", "test", "old-active", 8081, "synthetic", str(directory), "running", 1, '{}'))
    conn.commit()
    monkeypatch.setattr(module, "maintain", lambda _: None)
    monkeypatch.setattr(module, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(module, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(module, "proxy_quiet", lambda _: True)
    locks = 0
    @contextlib.contextmanager
    def lock(_):
        nonlocal locks
        locks += 1
        yield
        if locks == 1 and replace_generation:
            conn.execute("update task_proxies set lane='new-active'")
            conn.commit()
    monkeypatch.setattr(module, "node_lock", lock)
    seen = []
    def finish(receipt, **kwargs):
        seen.append((receipt.expected_lane, kwargs["orphan_proven"]))
        raise SystemExit(0)
    monkeypatch.setattr(module, "finish_proxy", finish)
    with pytest.raises(SystemExit) as exc:
        module.reap(argparse.Namespace())
    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    assert seen == ([] if replace_generation else [("old-active", True)])
    assert output["proxy_recovered"] == ([] if replace_generation else [["agent", "run"]])


@pytest.mark.parametrize("command", ["task-proxy-finish", "task-proxy-recover"])
def test_cli_exposes_expected_lane(command, monkeypatch, capsys):
    import subprocess, sys
    # argparse exits before opening state or reaching service operations.
    completed = subprocess.run([sys.executable, str(SCRIPT), command, "--help"],
                               capture_output=True, text=True, check=True)
    assert "--expected-lane" in completed.stdout


@pytest.mark.parametrize("command,handler", [("task-proxy-finish", "task_proxy_finish"), ("task-proxy-recover", "task_proxy_recover")])
@pytest.mark.parametrize("expected_lane", ["original-lane", None])
def test_cli_forwards_generation_and_preserves_legacy(fixture, monkeypatch, command, handler, expected_lane):
    import sys
    module, _, _ = fixture
    argv = ["browser_provisioner.py", command, "--agent-id", "agent", "--run-id", "run"]
    if expected_lane is not None:
        argv.extend(["--expected-lane", expected_lane])
    monkeypatch.setattr(sys, "argv", argv)
    seen = []
    def dispatch(args):
        seen.append((args.agent_id, args.run_id, args.expected_lane))
        raise SystemExit(0)
    monkeypatch.setattr(module, handler, dispatch)
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 0
    assert seen == [("agent", "run", expected_lane)]
