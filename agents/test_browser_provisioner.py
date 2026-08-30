import argparse
import importlib.util
import os
import sqlite3
import sys
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
    assert not removed and skipped[0]["reason"] == "not-managed-profile"
    assert outside.exists()


def test_sweep_refuses_managed_root_and_profile_parents(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    root = tmp_path / "artifacts"
    for lease_id, path in (("root", root), ("program", root / "demo"), ("parent", root / "demo/web/browser-profiles")):
        add(m, root, lease_id, path)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed
    assert {row["browser_id"] for row in skipped} == {"root-browser", "program-browser", "parent-browser"}
    assert all(row["reason"] == "not-managed-profile" for row in skipped)


def test_sweep_refuses_active_recorded_unit(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    profile = tmp_path / "artifacts/demo/web/browser-profiles/fixture"
    add(m, tmp_path / "artifacts", "three", profile)
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and skipped[0]["reason"] == "unit-active"
    assert profile.exists()


def start_args():
    return argparse.Namespace(program="demo", account="fixture", agent_id="agent", run_id="run", purpose="test", ttl_seconds=60, idle_seconds=60, min_ram_available_mib=1, min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy_cert_mode="none", proxy_server=None, mitm_ca_cert=None, url=None, display_backend=None, kasmvnc_display=None, kasmvnc_web_port=None)


def test_request_forwards_task_proxy_settings_to_start(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    captured = {}
    def fake_run(command, **_):
        captured["command"] = command
        return argparse.Namespace(stdout='{"status":"started"}', returncode=0)
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "now", lambda: 0)
    args = argparse.Namespace(
        program="demo", account="fixture", agent_id="agent", run_id="run", purpose="intercept",
        ttl_seconds=60, idle_seconds=60, wait_seconds=0, min_ram_available_mib=1,
        min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy_cert_mode="import",
        proxy_server="http://127.0.0.1:8081", mitm_ca_cert="/tmp/mitm-ca.pem", url="https://example.test/", display_backend="kasmvnc", kasmvnc_display=20, kasmvnc_web_port=8463,
    )
    try:
        m.request(args)
    except SystemExit as e:
        assert e.code == 0
    assert captured["command"][-12:] == [
        "--proxy-server", "http://127.0.0.1:8081", "--mitm-ca-cert", "/tmp/mitm-ca.pem",
        "--url", "https://example.test/", "--display-backend", "kasmvnc",
        "--kasmvnc-display", "20", "--kasmvnc-web-port", "8463",
    ]


def test_provisioner_marks_its_launcher_invocation_as_internal(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    calls = []

    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(
        m,
        "lease",
        lambda _args, action, *_rest: (
            {"status": "leased", "lease": {"lease_id": "lease", "account_alias": "fixture"}}
            if action == "acquire"
            else {"status": "registered"}
        ),
    )
    monkeypatch.setattr(m, "unit_active", lambda _unit: True)
    monkeypatch.setattr(m.subprocess, "run", lambda command, **_kwargs: calls.append(command) or argparse.Namespace(returncode=0, stdout="", stderr=""))
    launch = tmp_path / "state" / "lease-browser.launch.json"
    monkeypatch.setattr(m.uuid, "uuid4", lambda: "lease-browser")
    monkeypatch.setattr(m.time, "time", lambda: 0)
    monkeypatch.setattr(m.time, "sleep", lambda _seconds: None)
    launch.parent.mkdir(parents=True, exist_ok=True)
    launch.write_text('{"cdp_url": "http://127.0.0.1:9223"}')
    monkeypatch.setattr(m, "now", lambda: 0)

    try:
        m.start(args)
    except SystemExit as exc:
        assert exc.code == 0

    shell = calls[0][-1]
    assert "BROWSER_PROVISIONER_UNIT=browser-lease-browser.service" in shell
    assert "BROWSER_PROVISIONER_LAUNCH" not in shell
    assert "--provisioner-internal" not in shell


def test_provisioner_start_defaults_to_required_proxy_ca_import(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(m, "start", lambda args: captured.setdefault("proxy_cert_mode", args.proxy_cert_mode))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "browser_provisioner.py",
            "start",
            "demo",
            "fixture",
            "--agent-id",
            "agent",
            "--run-id",
            "run",
            "--purpose",
            "test",
        ],
    )

    m.main()

    assert captured["proxy_cert_mode"] == "import"


def test_provisioner_request_defaults_to_required_proxy_ca_import(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(m, "request", lambda args: captured.setdefault("proxy_cert_mode", args.proxy_cert_mode))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "browser_provisioner.py",
            "request",
            "demo",
            "fixture",
            "--agent-id",
            "agent",
            "--run-id",
            "run",
            "--purpose",
            "test",
        ],
    )

    m.main()

    assert captured["proxy_cert_mode"] == "import"


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


def test_capacity_rejection_never_leases_or_starts_a_browser(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "rejected", "swap_free_mib": 0})
    monkeypatch.setattr(m, "lease", lambda *_: calls.append("lease") or {"status": "leased"})
    monkeypatch.setattr(m.subprocess, "run", lambda *_a, **_k: calls.append("systemd"))

    try:
        m.start(start_args())
    except SystemExit as e:
        assert e.code == 2

    assert calls == []


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
