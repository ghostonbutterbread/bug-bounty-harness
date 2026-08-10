import argparse
import importlib.util
import os
import sqlite3
import time
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "skills/chromium-test/scripts/browser_provisioner.py"


def load(monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_PROVISIONER_STATE", str(tmp_path / "state" / "manager.sqlite"))
    monkeypatch.setenv("HARNESS_BOUNTY_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    spec = importlib.util.spec_from_file_location("provisioner", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def add(module, root, lease_id, profile, state="stopped", age_days=15):
    profile.mkdir(parents=True, exist_ok=True)
    old = time.time() - age_days * 86400
    c = module.db()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        lease_id, lease_id + "-browser", "demo", "fixture", "agent", "run", "test",
        lease_id + "-unit", str(profile), str(root / (lease_id + ".json")), state, 0,
        old, old, old,
    ))
    c.commit()


def test_sweep_deletes_only_registered_old_profile(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    root = tmp_path / "artifacts"
    profile = root / "demo/web/browser-profiles/fixture"
    add(m, root, "one", profile)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert removed[0]["browser_id"] == "one-browser"
    assert not skipped and not profile.exists()


def test_sweep_refuses_path_outside_managed_root(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    outside = tmp_path / "outside-profile"
    add(m, tmp_path / "artifacts", "two", outside)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and skipped[0]["reason"] == "outside-managed-root"
    assert outside.exists()


def test_sweep_refuses_active_recorded_unit(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    profile = tmp_path / "artifacts/demo/web/browser-profiles/fixture"
    add(m, tmp_path / "artifacts", "three", profile)
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and skipped[0]["reason"] == "unit-active"
    assert profile.exists()


def start_args():
    return argparse.Namespace(program="demo", account="fixture", agent_id="agent", run_id="run", purpose="test", ttl_seconds=60, idle_seconds=60, min_ram_available_mib=1, min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy_cert_mode="none", url=None)


def test_same_owner_running_browser_is_reused(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    c = m.db(); t = time.time()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("l","b","demo","fixture","agent","run","test","u",str(tmp_path/"artifacts/p"),"/tmp/x","running",0,t,t,t)); c.commit()
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    try: m.start(start_args())
    except SystemExit as e: assert e.code == 0


def test_other_owner_lease_denial_starts_no_systemd_unit(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "lease", lambda *a: {"status":"locked"})
    try: m.start(start_args())
    except SystemExit as e: assert e.code == 2


def test_failed_systemd_launch_releases_just_acquired_lease(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path); calls=[]
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], [])); monkeypatch.setattr(m, "admission", lambda *_: {"status":"admitted"})
    def fake_lease(_, action, *rest):
        calls.append(action)
        return {"status":"leased","lease":{"lease_id":"l","account_alias":"fixture"}} if action == "acquire" else {"status":"released"}
    monkeypatch.setattr(m, "lease", fake_lease)
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=1, stderr="systemd denied", stdout=""))
    try: m.start(start_args())
    except SystemExit as e: assert e.code == 2
    assert calls == ["acquire", "release"]
