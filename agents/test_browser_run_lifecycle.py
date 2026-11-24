"""Run-end browser reclamation, run-scoped release and swap-aware admission.

Temporary registries, fake /proc trees and mocked systemd only; no sites.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import textwrap

import pytest

from agents.test_browser_lease_recovery import canonical_record, profiles, provisioner, record
import browser_lifecycle
from browser_lifecycle import agent_supervisor_identity, process_identity


# --- agent-ancestor lifecycle owner -------------------------------------------------

def fake_proc(root, pid, ppid, comm, argv):
    directory = root / str(pid)
    directory.mkdir(parents=True)
    (directory / "comm").write_text(comm + "\n")
    (directory / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (directory / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1\n")


@pytest.fixture
def proc_tree(monkeypatch, tmp_path):
    root = tmp_path / "proc"
    monkeypatch.setattr(browser_lifecycle, "_PROC", root)
    monkeypatch.setattr(browser_lifecycle, "process_identity", lambda pid: {"pid": pid, "start": "s", "boot": "b",
                                                                           "node": socket.gethostname()})
    return root


@pytest.mark.parametrize("comm,argv", [
    ("claude", ["claude", "--resume"]),
    ("node", ["node", "/usr/lib/node_modules/@openai/codex/bin/codex.js", "exec"]),
    ("python3", ["/usr/bin/python3.12", "/home/u/.local/bin/hermes", "chat"]),
    ("omp", ["/home/u/.bun/bin/omp"]),
])
def test_nearest_agent_runtime_ancestor_is_the_owner(proc_tree, comm, argv):
    fake_proc(proc_tree, 100, 1, "tmux: server", ["tmux"])
    fake_proc(proc_tree, 200, 100, comm, argv)
    fake_proc(proc_tree, 300, 200, "bash", ["/bin/bash", "-c", "bbh browser_provisioner.py request"])
    fake_proc(proc_tree, 400, 300, "python3", ["python3", "browser_provisioner.py", "request"])
    fake_proc(proc_tree, 500, 400, "python3", ["python3", "browser_provisioner.py", "start"])
    assert agent_supervisor_identity(500)["pid"] == 200


def test_nearest_of_nested_agents_wins(proc_tree):
    fake_proc(proc_tree, 200, 1, "hermes", ["hermes", "gateway"])
    fake_proc(proc_tree, 300, 200, "codex", ["codex", "exec"])
    fake_proc(proc_tree, 400, 300, "bash", ["bash"])
    assert agent_supervisor_identity(400)["pid"] == 300


@pytest.mark.parametrize("chain", ["ssh-one-shot", "unreadable"])
def test_requests_without_a_provable_agent_ancestor_stay_ownerless(proc_tree, chain):
    fake_proc(proc_tree, 100, 1, "sshd", ["sshd: ryushe@notty"])
    fake_proc(proc_tree, 200, 100, "bash", ["bash", "-c", "bbh request"])
    fake_proc(proc_tree, 300, 200, "python3", ["python3", "browser_provisioner.py", "start"])
    if chain == "unreadable":
        (proc_tree / "200" / "stat").unlink()
    assert agent_supervisor_identity(300) is None


def test_interpreter_flags_and_unrelated_scripts_are_not_agents(proc_tree):
    fake_proc(proc_tree, 200, 1, "python3", ["python3", "-m", "pytest"])
    fake_proc(proc_tree, 300, 200, "node", ["node", "/srv/pipeline.js"])
    fake_proc(proc_tree, 400, 300, "bash", ["bash"])
    assert agent_supervisor_identity(400) is None


def test_live_process_tree_resolves_the_agent_runtime(tmp_path):
    scripts = Path(browser_lifecycle.__file__).parent
    agent = tmp_path / "claude"
    agent.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, subprocess, sys
        probe = "import json, sys; sys.path.insert(0, {str(scripts)!r}); " \\
                "import browser_lifecycle as b; print(json.dumps(b.agent_supervisor_identity()))"
        out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True).stdout
        print(json.dumps({{"agent_pid": __import__("os").getpid(), "owner": json.loads(out)}}))
    """))
    agent.chmod(0o700)
    result = json.loads(subprocess.run([str(agent)], capture_output=True, text=True, check=True).stdout)
    assert result["owner"]["pid"] == result["agent_pid"]
    assert result["owner"]["node"] == socket.gethostname()


# --- start records the lifecycle owner ---------------------------------------------

def start_fixture(monkeypatch, tmp_path, *, owner_pid=None, fake_admission=True):
    m = provisioner(monkeypatch, tmp_path)
    request = argparse.Namespace(
        program="demo", account="fixture", auth_domain=None, agent_id="agent", run_id="run",
        purpose="test", ttl_seconds=60, idle_seconds=60, min_ram_available_mib=1, min_swap_free_mib=0,
        memory_high="256M", memory_max="512M", proxy="none", proxy_ownership="task",
        proxy_cert_mode="none", proxy_server=None, mitm_ca_cert=None, url=None, display_backend=None,
        kasmvnc_display=None, kasmvnc_web_port=None, owner_pid=owner_pid)
    profile = tmp_path / "artifacts/demo/web/browser-profiles/default/fixture"
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "cleanup_unused", lambda *a: [])
    if fake_admission:
        monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m, "automatic_instance", lambda *_a, **_k: "")
    monkeypatch.setattr(m, "lease", lambda _args, action, *_rest: (
        {"status": "leased", "lease": {"lease_id": "new", "account_alias": "fixture",
                                      "auth_domain": "default", "profile_dir": str(profile)}}
        if action == "acquire" else {"status": "registered"}))
    dispatched = []
    monkeypatch.setattr(m, "unit_active", lambda _unit: bool(dispatched))
    monkeypatch.setattr(m, "start_watcher", lambda _bid: None)
    monkeypatch.setattr(m, "unit_identity", lambda _unit: "invocation")
    launch = m.STATE.parent / "new-browser.launch.json"
    launch.parent.mkdir(parents=True, exist_ok=True)

    def dispatch(*_args, **_kwargs):
        dispatched.append(True)
        launch.write_text('{"cdp_url": "http://127.0.0.1:9223"}')
        return argparse.Namespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(m.subprocess, "run", dispatch)
    monkeypatch.setattr(m.uuid, "uuid4", lambda: "new-browser")
    return m, request


def started_metadata(m, request, capsys):
    with pytest.raises(SystemExit) as exit_info:
        m.start(request)
    assert exit_info.value.code == 0, capsys.readouterr().out
    assert json.loads(capsys.readouterr().out)["status"] == "started"
    c = m.db()
    return m.metadata(c, c.execute("select * from browsers where lease_id='new'").fetchone())


def test_start_without_owner_pid_binds_new_browser_to_requesting_agent(monkeypatch, tmp_path, capsys):
    m, request = start_fixture(monkeypatch, tmp_path)
    agent = {"pid": 4242, "start": "77", "boot": "boot", "node": socket.gethostname()}
    monkeypatch.setattr(m, "agent_supervisor_identity", lambda: agent)
    meta = started_metadata(m, request, capsys)
    assert meta["owner"] == agent and meta["owner_source"] == "agent-ancestor"


def test_start_without_agent_ancestor_keeps_legacy_ownerless_contract(monkeypatch, tmp_path, capsys):
    m, request = start_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "agent_supervisor_identity", lambda: None)
    meta = started_metadata(m, request, capsys)
    assert meta["owner"] is None and "owner_source" not in meta


def test_explicit_owner_pid_is_never_replaced_by_derivation(monkeypatch, tmp_path, capsys):
    m, request = start_fixture(monkeypatch, tmp_path, owner_pid=os.getpid())
    monkeypatch.setattr(m, "agent_supervisor_identity", lambda: pytest.fail("explicit owner wins"))
    meta = started_metadata(m, request, capsys)
    assert meta["owner"] == process_identity(os.getpid()) and "owner_source" not in meta


# --- run end: terminal derived owner is reclaimed by maintain -------------------------

def exited_process_identity():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    identity = process_identity(child.pid)
    child.kill()
    child.wait()
    return identity


def live_browser(monkeypatch, tmp_path, owner):
    """A running, canonically owned browser whose unit stops only on request."""
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    canonical_record(m, row)
    m.save_metadata(c, "old", {**({"owner": owner, "owner_source": "agent-ancestor"} if owner else {}),
                               "ttl": 30})
    Path(row["launch_file"]).write_text(json.dumps({
        "unit_invocation": "exact-unit", "cdp_url": "http://127.0.0.1:9301",
        "process_identity": {**process_identity(os.getpid()), "start": "browser-root"}}))
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        leases.execute("UPDATE browser_profile_leases SET browser_status='running',cdp_url=? WHERE lease_id=?",
                       ("http://127.0.0.1:9301", "old"))
    unit = {"stopped": False, "stop_calls": []}

    def stop_unit(name):
        unit["stop_calls"].append(name)
        unit["stopped"] = True
    monkeypatch.setattr(m, "unit_active", lambda _name: not unit["stopped"])
    monkeypatch.setattr(m, "unit_identity", lambda _name: "exact-unit")
    monkeypatch.setattr(m, "stopped", lambda _row: unit["stopped"])
    monkeypatch.setattr(m, "stop_unit", stop_unit)
    return m, c, unit


def canonical_status(m):
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        return leases.execute("SELECT status FROM browser_profile_leases WHERE lease_id='old'").fetchone()[0]


def test_agent_exit_without_release_stops_browser_on_next_maintain(monkeypatch, tmp_path):
    m, c, unit = live_browser(monkeypatch, tmp_path, exited_process_identity())
    monkeypatch.setattr(m, "lease", lambda *_: pytest.fail("terminal owner must not renew"))
    m.maintain(argparse.Namespace(browser_id=None))
    assert unit["stop_calls"] == ["fixture-unit"]
    assert canonical_status(m) == "released"
    assert c.execute("select state from browsers where lease_id='old'").fetchone()[0] == "stopped"
    # Idempotent: a second pass finds nothing running and stops nothing more.
    m.maintain(argparse.Namespace(browser_id=None))
    assert unit["stop_calls"] == ["fixture-unit"]


def test_live_agent_owner_keeps_its_browser_and_renews(monkeypatch, tmp_path):
    m, c, unit = live_browser(monkeypatch, tmp_path, process_identity(os.getpid()))
    renewals = []
    monkeypatch.setattr(m, "lease", lambda _args, action, *_rest: renewals.append(action) or {"status": "renewed"})
    m.maintain(argparse.Namespace(browser_id=None))
    assert unit["stop_calls"] == [] and renewals == ["renew"]
    assert canonical_status(m) == "active"


def test_historical_ownerless_browser_is_still_never_reclaimed(monkeypatch, tmp_path):
    m, c, unit = live_browser(monkeypatch, tmp_path, None)
    monkeypatch.setattr(m, "lease", lambda *_: pytest.fail("unknown owner is neither renewed nor stopped"))
    m.maintain(argparse.Namespace(browser_id=None))
    assert unit["stop_calls"] == []
    assert canonical_status(m) == "active"


# --- swap-aware admission ------------------------------------------------------------

def admission_for(monkeypatch, tmp_path, ram, swap, pressure):
    m = provisioner(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "meminfo", lambda: (ram, swap))
    monkeypatch.setattr(m, "memory_pressure", lambda: pressure if pressure != "fail" else pytest.fail("not consulted"))
    return m.admission(2048, 512)


HEALTHY = {"some_avg10": 0.0, "full_avg10": 0.0}


def test_reported_swap_exhaustion_with_plentiful_ram_is_admitted(monkeypatch, tmp_path):
    # PC-20260918-222033-c990c35b: ram_available 3893 MiB, swap_free 70 MiB.
    result = admission_for(monkeypatch, tmp_path, 3893, 70, HEALTHY)
    assert result["status"] == "admitted" and result["swap_gate"] == "covered-by-available-ram"
    assert result["memory_pressure"] == HEALTHY
    assert (result["required_ram_available_mib"], result["required_swap_free_mib"]) == (2048, 512)


@pytest.mark.parametrize("ram,swap,pressure,reason", [
    (2000, 4000, "fail", "ram-below-minimum"),
    (3893, 70, {"some_avg10": 25.0, "full_avg10": 0.0}, "swap-below-minimum-memory-pressure"),
    (3893, 70, {"some_avg10": 0.0, "full_avg10": 4.0}, "swap-below-minimum-memory-pressure"),
    (3893, 70, None, "swap-below-minimum-pressure-unknown"),
    (2400, 70, HEALTHY, "swap-below-minimum-ram-cannot-cover-shortfall"),
])
def test_admission_still_rejects_real_shortage_with_reason(monkeypatch, tmp_path, ram, swap, pressure, reason):
    result = admission_for(monkeypatch, tmp_path, ram, swap, pressure)
    assert result["status"] == "rejected" and result["reason"] == reason


def test_admission_with_headroom_is_unchanged(monkeypatch, tmp_path):
    result = admission_for(monkeypatch, tmp_path, 4096, 1024, "fail")
    assert result == {"status": "admitted", "ram_available_mib": 4096, "swap_free_mib": 1024,
                      "required_ram_available_mib": 2048, "required_swap_free_mib": 512}


@pytest.mark.parametrize("text,expected", [
    ("some avg10=1.50 avg60=0.20 avg300=0.00 total=10\nfull avg10=0.25 avg60=0.00 avg300=0.00 total=5\n",
     {"some_avg10": 1.5, "full_avg10": 0.25}),
    ("some avg10=1.50 avg60=0.20 avg300=0.00 total=10\n", None),
    ("garbage\n", None),
])
def test_memory_pressure_parses_psi_or_fails_closed(monkeypatch, tmp_path, text, expected):
    m = provisioner(monkeypatch, tmp_path)
    psi = tmp_path / "memory"
    psi.write_text(text)
    monkeypatch.setattr(m, "MEMORY_PRESSURE", psi)
    assert m.memory_pressure() == expected
    monkeypatch.setattr(m, "MEMORY_PRESSURE", tmp_path / "missing")
    assert m.memory_pressure() is None


@pytest.mark.parametrize("pressure,admitted", [(HEALTHY, True), ({"some_avg10": 40.0, "full_avg10": 9.0}, False)])
def test_start_admits_swap_exhausted_node_only_under_healthy_pressure(monkeypatch, tmp_path, capsys, pressure, admitted):
    m, request = start_fixture(monkeypatch, tmp_path, fake_admission=False)
    request.min_ram_available_mib, request.min_swap_free_mib = 2048, 512
    monkeypatch.setattr(m, "meminfo", lambda: (3893, 70))
    monkeypatch.setattr(m, "memory_pressure", lambda: pressure)
    calls = []
    monkeypatch.setattr(m, "lease", lambda _args, action, *_rest: calls.append(action) or {"status": "locked"})
    with pytest.raises(SystemExit):
        m.start(request)
    result = json.loads(capsys.readouterr().out)
    if admitted:
        assert calls == ["acquire"] and result.get("reason") != "no-capacity"
    else:
        assert calls == [] and result["reason"] == "no-capacity"
        assert result["admission"]["reason"] == "swap-below-minimum-memory-pressure"


# --- run-scoped release keyed on recorded agent/run ---------------------------------

def add_row(m, lease_id, agent, run, unit, state="running"):
    c = m.db()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        lease_id, lease_id + "-browser", "demo", "anon", "legacy-global", agent, run, "fixture",
        unit, "/nonexistent/" + lease_id, "/nonexistent/" + lease_id + ".json", state, 0, 1.0, 1.0, 1.0))
    c.commit()


def release_run(m, capsys, *, apply, agent="agent-a", run="run-1"):
    request = argparse.Namespace(agent_id=agent, run_id=run, disposition="completed",
                                 profile_health="healthy", apply=apply)
    with pytest.raises(SystemExit) as exit_info:
        m.release_run(request)
    return exit_info.value.code, json.loads(capsys.readouterr().out)


@pytest.fixture
def mixed_rows(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    add_row(m, "a1", "agent-a", "run-1", "browser-a1")
    add_row(m, "a2", "agent-a", "run-1", "browser-a2")
    add_row(m, "a3", "agent-a", "run-2", "browser-a3")                 # same agent, other run
    add_row(m, "b1", "agent-b", "run-1", "browser-b1.service")         # other agent, same run label
    add_row(m, "a4", "agent-a", "run-1", "browser-a4", state="stopped")
    fenced = []
    monkeypatch.setattr(m, "fenced_stop_release", lambda c, lease_id, agent_id, **kw:
                        fenced.append((lease_id, agent_id, kw)) or True)
    return m, fenced


def test_release_run_dry_run_selects_exact_run_and_touches_nothing(mixed_rows, capsys):
    m, fenced = mixed_rows
    code, result = release_run(m, capsys, apply=False)
    assert code == 0 and result["mode"] == "dry-run" and fenced == []
    assert [(b["lease_id"], b["unit"], b["result"]) for b in result["browsers"]] == [
        ("a1", "browser-a1.service", "selected"), ("a2", "browser-a2.service", "selected")]
    assert result["kept_running"] == 2 and result["released"] == []


def test_release_run_apply_stops_only_the_exact_recorded_run(mixed_rows, capsys):
    m, fenced = mixed_rows
    code, result = release_run(m, capsys, apply=True)
    assert code == 0 and result["status"] == "ok"
    assert fenced == [("a1", "agent-a", {"disposition": "completed", "health": "healthy"}),
                      ("a2", "agent-a", {"disposition": "completed", "health": "healthy"})]
    assert result["released"] == ["a1-browser", "a2-browser"] and result["kept_running"] == 2


def test_release_run_reports_incomplete_without_skipping_siblings(mixed_rows, monkeypatch, capsys):
    m, fenced = mixed_rows
    monkeypatch.setattr(m, "fenced_stop_release", lambda c, lease_id, agent_id, **kw:
                        fenced.append(lease_id) or lease_id != "a1")
    code, result = release_run(m, capsys, apply=True)
    assert code == 2 and result["status"] == "cleanup-incomplete" and fenced == ["a1", "a2"]
    assert [(b["lease_id"], b["result"]) for b in result["browsers"]] == [
        ("a1", "cleanup-incomplete"), ("a2", "released")]


def test_release_run_real_fence_never_stops_a_kept_unit(monkeypatch, tmp_path, capsys):
    m, c, unit = live_browser(monkeypatch, tmp_path, None)
    add_row(m, "other", "other-agent", "old-run", "fixture-unit.service")  # look-alike name, other owner
    code, result = release_run(m, capsys, apply=True, agent="old-agent", run="old-run")
    assert code == 0 and result["released"] == ["browser-id"] and result["kept_running"] == 1
    assert unit["stop_calls"] == ["fixture-unit"]
    assert canonical_status(m) == "released"
    states = dict(c.execute("select lease_id, state from browsers").fetchall())
    assert states == {"old": "stopped", "other": "running"}


def test_release_run_cli_requires_explicit_terminal_disposition(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["browser_provisioner.py", "release-run", "--agent-id", "a", "--run-id", "r"])
    with pytest.raises(SystemExit) as exit_info:
        m.main()
    assert exit_info.value.code == 2 and "--disposition" in capsys.readouterr().err


def test_service_unit_name_is_canonical_and_idempotent(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    assert m.service_unit_name("browser-x") == m.service_unit_name("browser-x.service") == "browser-x.service"
