"""Offline regressions adapted from the independent receipt review fixtures."""
import argparse
import importlib.util
import json
import sqlite3
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def load(monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_PROVISIONER_STATE", str(tmp_path / "state/db.sqlite"))
    spec = importlib.util.spec_from_file_location(
        "review_provisioner", ROOT / "skills/chromium-test/scripts/browser_provisioner.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("stored_owner,request_pid,expected", [
    ('{"pid": 10, "start": 1}', None, "proxy-conflict"),
    ('{"pid": 10, "start": 1}', 10, "already-running"),
    ('{"pid": 10, "start": 1}', 11, "proxy-conflict"),
    (None, None, "already-running"),
    (None, 10, "proxy-conflict"),
    ("invalid", None, "proxy-conflict"),
    ("null", None, "proxy-conflict"),
])
def test_running_browser_reuse_checks_proxy_owner(
    monkeypatch, tmp_path, capsys, stored_owner, request_pid, expected
):
    m = load(monkeypatch, tmp_path)
    c = m.db()
    t = time.time()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        "lease", "browser", "demo", "fixture", "legacy-global", "agent", "run", "test",
        "browser-unit", str(tmp_path / "profile"), str(tmp_path / "launch"), "running", 0, t, t, t,
    ))
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,"
              "run_dir,state,owner,exact_program,admitted) values(?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        "agent", "run", "demo", "fixture", "test", "new-lane", 8081, "proxy-unit",
        str(tmp_path / "proxy"), "running", stored_owner, "demo", 1,
    ))
    c.commit()
    import browser_profile_lease as profiles
    monkeypatch.setattr(profiles, "resolve_account", lambda *a: (None, {}))
    monkeypatch.setattr(profiles, "auth_domain_for", lambda *a: "legacy-global")
    monkeypatch.setattr(profiles, "instance_key", lambda *a: "")
    stubs = {
        "sweep_rows": lambda *a: ([], []),
        "require_safe_running_profile": lambda *a: None,
        "cleanup_unused": lambda *a: [],
        "admission": lambda *a: {"status": "admitted"},
        "account_policy": lambda *a: False,
        "selected_browser": lambda *a: c.execute("select * from browsers").fetchone(),
        "lifecycle_state": lambda *a: "active",
        "healthy": lambda *a: True,
        "proxy_ready": lambda *a: True,
        "activity_snapshot": lambda *a: None,
        "metadata": lambda *a: {"owner": None},
        "safe": lambda *a: {},
        "unit_active": lambda *a: True,
        "ca_fingerprint": lambda *a: "hash",
        "process_identity": lambda pid: {"pid": pid, "start": 1},
    }
    for name, value in stubs.items():
        monkeypatch.setattr(m, name, value)
    task = c.execute("select * from task_proxies").fetchone()
    proxy = m.proxy_metadata(task)
    monkeypatch.setattr(m, "record_info", lambda *a: {
        "proxy_server": proxy["proxy_server"], "proxy_cert_mode": "import",
        "proxy_cert_status": {"status": "trusted", "ca_cert": proxy["ca_cert"], "ca_sha256": "hash"},
    })
    args = argparse.Namespace(
        program="demo", account="fixture", auth_domain=None, agent_id="agent", run_id="run",
        purpose="test", ttl_seconds=60, idle_seconds=60, min_ram_available_mib=1,
        min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy="mitm",
        proxy_ownership="task", proxy_cert_mode="import", proxy_server=None, mitm_ca_cert=None,
        url=None, display_backend=None, kasmvnc_display=None, kasmvnc_web_port=None,
        owner_pid=request_pid,
    )
    with pytest.raises(SystemExit) as exc:
        m.start.__wrapped__(args)
    result = json.loads(capsys.readouterr().out)
    assert (exc.value.code, result["status"]) == (0 if expected == "already-running" else 2, expected)
    if expected == "already-running":
        assert result["task_proxy"]["lane"] == "new-lane"


def test_running_proxy_owner_rechecks_pid_generation(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    c = m.db()
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,"
              "run_dir,state,owner) values(?,?,?,?,?,?,?,?,?,?,?)", (
        "agent", "run", "demo", "fixture", "test", "lane", 8081, "unit", str(tmp_path),
        "running", json.dumps({"pid": 10, "start": 1}),
    ))
    c.commit()
    monkeypatch.setattr(m, "process_identity", lambda pid: {"pid": pid, "start": 2})
    args = argparse.Namespace(agent_id="agent", run_id="run", proxy="mitm", owner_pid=10)
    assert not m.request_proxy_owner_matches(c, args, {"pid": 10, "start": 1})


def test_cleanup_transaction_rolls_back_on_attempt_write_failure(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    c = m.db()
    c.execute("insert into finished_proxies values(?,?,?,?)", ("agent", "run", "old-lane", 1))
    c.execute("create trigger reject_abort before update on proxy_attempts "
              "when new.outcome='aborted' begin select raise(abort,'reject abort'); end")
    c.commit()
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    def fail_start():
        raise RuntimeError("startup failed")
    monkeypatch.setattr(m, "mitm_runtime", fail_start)
    args = argparse.Namespace(agent_id="agent", run_id="run", program="demo", account="fixture", purpose="test")
    with pytest.raises(sqlite3.IntegrityError, match="reject abort"):
        m.start_proxy(c, args)
    assert not c.in_transaction and m.proxy_row(c, args)["state"] == "starting"
    # The real failed-browser path calls release_lease, whose first action commits c.
    assert not m.release_lease(c, "missing", "agent")
    observer = m.db()
    assert observer.execute("select count(*) from task_proxies").fetchone()[0] == 1
    assert observer.execute("select outcome from proxy_attempts").fetchone()[0] == "starting"
    assert observer.execute("select lane from finished_proxies").fetchone()[0] == "old-lane"
    observer.execute("drop trigger reject_abort")
    observer.commit()
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args, recovery=True)
    out = json.loads(capsys.readouterr().out)
    assert (exc.value.code, out["status"]) == (0, "aborted")
    assert observer.execute("select count(*) from task_proxies").fetchone()[0] == 0
    assert observer.execute("select outcome from proxy_attempts").fetchone()[0] == "aborted"
