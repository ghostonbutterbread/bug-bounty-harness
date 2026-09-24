import argparse
import importlib.util
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

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
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        lease_id, lease_id + "-browser", "demo", "fixture", "default", "agent", "run", "test",
        lease_id + "-unit", str(profile), str(root / (lease_id + ".json")), state, 0,
        old, old, old,
    ))
    c.commit()


def test_sweep_deletes_only_registered_old_profile(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    root = tmp_path / "artifacts"
    profile = root / "demo/web/browser-profiles/fixture"
    add(m, root, "one", profile)
    (root / 'one.json').write_text(json.dumps({'instance_key': 'explicit'}))
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert removed[0]["browser_id"] == "one-browser"
    assert not skipped and not profile.exists()


def test_sweep_deletes_registered_auth_domain_profile(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    root = tmp_path / "artifacts"
    profile = root / "demo/web/browser-profiles/api.example.test/fixture"
    add(m, root, "domain", profile)
    monkeypatch.setattr(m, "unit_active", lambda _: False)

    removed, skipped = m.sweep_rows(m.db(), 14, True)

    assert removed[0]["browser_id"] == "domain-browser"
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
    (tmp_path / 'artifacts/three.json').write_text(json.dumps({'instance_key': 'explicit'}))
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and skipped[0]["reason"] == "unit-active"
    assert profile.exists()


def start_args():
    return argparse.Namespace(program="demo", account="fixture", auth_domain=None, agent_id="agent", run_id="run", purpose="test", ttl_seconds=60, idle_seconds=60, min_ram_available_mib=1, min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy="none", proxy_ownership="task", proxy_cert_mode="none", proxy_server=None, mitm_ca_cert=None, url=None, display_backend=None, kasmvnc_display=None, kasmvnc_web_port=None)


def test_request_forwards_task_proxy_settings_to_start(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    captured = {}
    def fake_run(command, **_):
        captured["command"] = command
        return argparse.Namespace(stdout='{"status":"started"}', returncode=0)
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "now", lambda: 0)
    args = argparse.Namespace(
        program="demo", account="fixture", auth_domain="api.example.test", agent_id="agent", run_id="run", purpose="intercept",
        ttl_seconds=60, idle_seconds=60, wait_seconds=0, min_ram_available_mib=1,
        min_swap_free_mib=0, memory_high="256M", memory_max="512M", proxy="external", proxy_cert_mode="import",
        proxy_server="http://127.0.0.1:8081", mitm_ca_cert="/tmp/mitm-ca.pem", url="https://example.test/", display_backend="kasmvnc", kasmvnc_display=20, kasmvnc_web_port=8463, recover_profile=True,
    )
    try:
        m.request(args)
    except SystemExit as e:
        assert e.code == 0
    assert captured["command"][captured["command"].index("--auth-domain") : captured["command"].index("--agent-id")] == [
        "--auth-domain", "api.example.test",
    ]
    assert captured["command"][-13:] == [
        "--proxy-server", "http://127.0.0.1:8081", "--mitm-ca-cert", "/tmp/mitm-ca.pem",
        "--url", "https://example.test/", "--display-backend", "kasmvnc",
        "--kasmvnc-display", "20", "--kasmvnc-web-port", "8463", "--recover-profile",
    ]


def test_start_forwards_recover_profile_to_lease_acquire(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.recover_profile = True
    acquire = {}

    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    def fake_lease(_args, action, *rest):
        assert action == "acquire"
        acquire["parts"] = rest
        return {"status": "account-unavailable"}

    monkeypatch.setattr(m, "lease", fake_lease)

    try:
        m.start(args)
    except SystemExit as exc:
        assert exc.code == 2

    assert "--recover-profile" in acquire["parts"]


def test_provisioner_marks_its_launcher_invocation_as_internal(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.driving_mode = "manual"
    args.display_backend = "kasmvnc"
    calls = []

    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(
        m,
        "lease",
        lambda _args, action, *_rest: (
            {"status": "leased", "lease": {"lease_id": "lease", "account_alias": "fixture", "auth_domain": "default", "profile_dir": str(tmp_path / "artifacts/demo/web/browser-profiles/default/fixture")}}
            if action == "acquire"
            else {"status": "registered"}
        ),
    )
    monkeypatch.setattr(m, "unit_active", lambda _unit: False if _unit == "browser-lease-browser" and not calls else True)
    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[0] == "systemd-run":
            launch.write_text('{"cdp_url": "http://127.0.0.1:9223"}')
        return argparse.Namespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
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

    browser_dispatch = calls[0]
    assert "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent" in browser_dispatch
    assert "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent" not in browser_dispatch[-1]
    assert m.sysenv()["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path=/run/user/{os.getuid()}/bus"
    assert browser_dispatch[0] == "systemd-run"
    shell = browser_dispatch[-1]
    assert "BROWSER_PROVISIONER_UNIT=browser-lease-browser.service" in shell
    assert "--driving-mode manual" in shell
    assert "--display-backend kasmvnc" in shell
    assert "BROWSER_PROVISIONER_LAUNCH" not in shell
    assert "--provisioner-internal" not in shell


@pytest.mark.parametrize("appended_domain", [False, True])
def test_start_records_named_fields_across_browser_schema_orders(monkeypatch, tmp_path, capsys, appended_domain):
    m = load(monkeypatch, tmp_path)
    if appended_domain:
        m.STATE.parent.mkdir(parents=True)
        with sqlite3.connect(m.STATE) as c:
            c.execute("""CREATE TABLE browsers (
                lease_id TEXT PRIMARY KEY, browser_id TEXT UNIQUE NOT NULL,
                program TEXT NOT NULL, account TEXT NOT NULL, agent_id TEXT NOT NULL,
                run_id TEXT NOT NULL, purpose TEXT NOT NULL, unit TEXT NOT NULL,
                profile_dir TEXT NOT NULL, launch_file TEXT NOT NULL, state TEXT NOT NULL,
                tab_count INTEGER NOT NULL DEFAULT 0, last_activity REAL NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL)""")
        # Exercise the real db() migration rather than manufacturing its final shape.
        with m.db() as c:
            assert [r[1] for r in c.execute("pragma table_info(browsers)")][-1] == "auth_domain"
            # A previously shifted record is retained verbatim, not repaired or deleted.
            c.execute("""INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                "old", "old-browser", "demo", "fixture", "login.example.test",
                "agent", "run", "test", "browser-old", str(tmp_path / "old-profile"),
                str(tmp_path / "old.json"), "running", 0, 1.0, 1.0, 1.0,
            ))
    args = start_args()
    args.auth_domain = "login.example.test"
    profile = tmp_path / "artifacts/demo/web/browser-profiles/login.example.test/fixture"
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "cleanup_unused", lambda *a: [])
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m, "automatic_instance", lambda *_a, **_k: "")
    monkeypatch.setattr(m, "lease", lambda _args, action, *_rest: (
        {"status": "leased", "lease": {"lease_id": "new", "account_alias": "fixture",
                                      "auth_domain": args.auth_domain, "profile_dir": str(profile)}}
        if action == "acquire" else {"status": "registered"}
    ))
    dispatched = []
    monkeypatch.setattr(m, "unit_active", lambda _unit: bool(dispatched))
    monkeypatch.setattr(m, "start_watcher", lambda _bid: None)
    monkeypatch.setattr(m, "unit_identity", lambda _unit: "invocation")
    launch = m.STATE.parent / "new-browser.launch.json"
    def fake_dispatch(*_args, **_kwargs):
        # The startup reservation must be legible before CDP publication.
        with m.db() as c:
            starting = c.execute("select * from browsers where lease_id='new'").fetchone()
            assert starting["state"] == "starting"
            assert starting["auth_domain"] == args.auth_domain
            assert starting["agent_id"] == args.agent_id
            assert starting["unit"] == "browser-new-browser"
        dispatched.append(True)
        launch.write_text('{"cdp_url": "http://127.0.0.1:9223"}')
        return argparse.Namespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(m.subprocess, "run", fake_dispatch)
    monkeypatch.setattr(m.uuid, "uuid4", lambda: "new-browser")
    launch.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SystemExit) as exit_info:
        m.start(args)
    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "started"
    with m.db() as c:
        c.row_factory = sqlite3.Row
        row = c.execute("select * from browsers where lease_id='new'").fetchone()
        assert {key: row[key] for key in ("lease_id", "browser_id", "program", "account",
                                           "auth_domain", "agent_id", "run_id", "purpose", "unit",
                                           "profile_dir", "launch_file", "state", "tab_count")} == {
            "lease_id": "new", "browser_id": "new-browser", "program": "demo",
            "account": "fixture", "auth_domain": args.auth_domain, "agent_id": "agent",
            "run_id": "run", "purpose": "test", "unit": "browser-new-browser",
            "profile_dir": str(profile), "launch_file": str(launch), "state": "running", "tab_count": 0,
        }
        assert all(isinstance(row[k], (float, int)) for k in ("last_activity", "created", "updated"))
        assert m.selected_browser(c, "demo", "fixture", args.auth_domain, "")["lease_id"] == "new"
        if appended_domain:
            old = c.execute("select * from browsers where lease_id='old'").fetchone()
            assert old["auth_domain"] == "1.0" and old["state"] == str(tmp_path / "old.json")
            assert old["agent_id"] == args.auth_domain


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
    monkeypatch.setattr(m, "matching_proxy", lambda *_: True)
    c = m.db(); t = time.time()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("l","b","demo","fixture","legacy-global","agent","run","test","u",str(tmp_path/"artifacts/p"),"/tmp/x","running",0,t,t,t)); c.commit()
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "healthy", lambda _: True)
    try: m.start(start_args())
    except SystemExit as e: assert e.code == 0


def test_same_owner_reuses_inventory_resolved_auth_domain_without_cli_override(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "matching_proxy", lambda *_: True)
    c = m.db(); t = time.time()
    c.execute("insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("l","b","demo","fixture","login.example.test","agent","run","test","u",str(tmp_path/"artifacts/p"),"/tmp/x","running",0,t,t,t)); c.commit()
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "healthy", lambda _: True)
    monkeypatch.setattr(
        m,
        "lease",
        lambda *_: {"status": "already-owned", "lease": {"lease_id": "l", "account_alias": "fixture", "auth_domain": "login.example.test", "profile_dir": str(tmp_path / "artifacts/p")}},
    )

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


def test_failed_systemd_launch_releases_just_acquired_lease_with_healthy_profile(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path); calls=[]; release_args=[]
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], [])); monkeypatch.setattr(m, "admission", lambda *_: {"status":"admitted"})
    def fake_lease(_, action, *rest):
        calls.append(action)
        if action == "release":
            release_args.extend(rest)
        return {"status":"leased","lease":{"lease_id":"l","account_alias":"fixture","auth_domain":"legacy-global","profile_dir":str(tmp_path / "artifacts/demo/web/browser-profiles/legacy-global/fixture")}} if action == "acquire" else {"status":"released"}
    monkeypatch.setattr(m, "lease", fake_lease)
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=1, stderr="systemd denied", stdout=""))
    try: m.start(start_args())
    except SystemExit as e: assert e.code == 2
    assert calls == ["acquire", "release"]
    assert release_args[release_args.index("--profile-health") + 1] == "healthy"


def proxy_fixture(m, args, root):
    c = m.db()
    directory = root / "task-proxies" / "task-fixture"
    (directory / "mitmproxy").mkdir(parents=True)
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
              (args.agent_id, args.run_id, "demo", "fixture", args.purpose,
               "task-fixture", 8081, "task-mitm-task-fixture", str(directory), "running"))
    c.commit()
    return c


def test_finish_rejects_startup_intent_before_cdp_and_allows_replay_after_release(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    browser = tmp_path / "artifacts/demo/web/browser-profiles/fixture"
    add(m, tmp_path, "first", browser, state="starting")
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    with pytest.raises(SystemExit) as exc:
        m.task_proxy_finish(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "browser-active"
    assert m.proxy_row(c, args)["state"] == "running"
    c.execute("update browsers set state='stopped'")
    c.commit()
    monkeypatch.setattr(m, "stop_unit", lambda _: None)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_k: None)
    with pytest.raises(SystemExit) as exc:
        m.task_proxy_finish(args)
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "finished"
    assert m.proxy_row(c, args) is None
    with pytest.raises(SystemExit) as exc:
        m.task_proxy_finish(args)
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["already_finished"] is True


def test_finish_stop_failure_keeps_reservation_for_retry(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: True)
    monkeypatch.setattr(m, "stop_unit", lambda _: None)
    with pytest.raises(SystemExit) as exc:
        m.task_proxy_finish(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "proxy-stop-failed"
    assert m.proxy_row(c, args)["state"] == "stop-failed"


def test_matching_proxy_rejects_different_trust_and_explicit_none(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"proxy_server": None, "proxy_cert_mode": "none",
                                   "command": ["--no-proxy-server"]}))
    row = {"launch_file": str(receipt)}
    assert m.matching_proxy(m.db(), args, row)
    receipt.write_text(json.dumps({"proxy_server": None, "proxy_cert_mode": "none", "command": []}))
    assert not m.matching_proxy(m.db(), args, row)
    args.proxy = "external"
    args.proxy_server = "http://127.0.0.1:8090"
    args.proxy_cert_mode = "import"
    args.mitm_ca_cert = str(tmp_path / "ca.pem")
    Path(args.mitm_ca_cert).write_text("ca")
    monkeypatch.setattr(m, "endpoint_open", lambda _: True)
    receipt.write_text(json.dumps({"proxy_server": args.proxy_server, "proxy_cert_mode": "import",
                                   "proxy_cert_status": {"status": "trusted", "ca_cert": args.mitm_ca_cert,
                                                         "ca_sha256": m.ca_fingerprint(Path(args.mitm_ca_cert))}}))
    assert m.matching_proxy(m.db(), args, row)
    args.mitm_ca_cert = str(tmp_path / "other.pem")
    assert not m.matching_proxy(m.db(), args, row)


def test_task_mitm_does_not_fallback_to_external_or_ignore(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.proxy = "mitm"
    args.proxy_cert_mode = "auto"
    with pytest.raises(SystemExit) as exc:
        m.proxy_mode(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "invalid-proxy-options"
    args.proxy_cert_mode = "import"
    args.proxy_server = "http://127.0.0.1:8080"
    with pytest.raises(SystemExit) as exc:
        m.proxy_mode(args)
    assert exc.value.code == 2


def test_task_proxy_starts_before_browser_and_reuses_private_lane(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.proxy, args.proxy_cert_mode = "mitm", "import"
    c = m.db()
    commands = []
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "mitm_runtime", lambda: ("/bin/mitmdump", "/bin/python"))
    monkeypatch.setattr(m, "unit_identity", lambda _: "invocation")
    def run(command, **_):
        commands.append(command)
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, "run", run)
    def ready(row):
        Path(m.proxy_metadata(row)["ca_cert"]).write_text("fixture-ca")
        return True
    monkeypatch.setattr(m, "proxy_ready", ready)
    row, created = m.start_proxy(c, args)
    assert created and row["state"] == "running"
    assert commands[0][0] == "systemd-run" and "--listen-port" in commands[0]
    assert "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent" not in commands[0]
    assert Path(row["run_dir"]).stat().st_mode & 0o777 == 0o700
    assert (Path(row["run_dir"]) / "mitmproxy").stat().st_mode & 0o777 == 0o700
    same, created = m.start_proxy(c, args)
    assert not created and same["lane"] == row["lane"] and len(commands) == 1


def test_missing_mitmdump_rolls_back_reservation_without_shared_fallback(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "mitm_runtime", lambda: (_ for _ in ()).throw(RuntimeError("missing")))
    monkeypatch.setattr(m, "stop_unit", lambda _: None)
    with pytest.raises(RuntimeError, match="missing"):
        m.start_proxy(m.db(), args)
    assert m.proxy_row(m.db(), args) is None


def test_failed_browser_rolls_back_only_new_task_ca_after_verified_stop(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    task = m.proxy_row(c, args)
    ca = Path(m.proxy_metadata(task)["ca_cert"])
    ca.write_text("fixture-ca")
    removed = []
    monkeypatch.setattr(m, "remove_matching_ca", lambda profile, ca, **kw: removed.append((profile, ca)))
    monkeypatch.setattr(m, "stop_unit", lambda _: None)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    profile = tmp_path / "profile"
    assert m.rollback_failed_browser_proxy(c, task, True, profile)
    assert removed == [(profile, ca)] and m.proxy_row(c, args) is None

def test_recovery_refuses_live_replay_and_retries_failed_cleanup(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='cleanup-failed'"); c.commit()
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "unit_identity", lambda _: "other")
    monkeypatch.setattr(m, "port_open", lambda _: True)
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 2
    assert m.proxy_row(c, args)["state"] == "cleanup-failed"
    capsys.readouterr()
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_k: None)
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 0
    assert m.proxy_row(c, args) is None

@pytest.mark.parametrize("receipt", [False, True])
def test_recover_interrupted_start_with_both_units_inactive(monkeypatch, tmp_path, capsys, receipt):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting'"); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    if receipt:
        (tmp_path / "first.json").write_text(json.dumps({"pid": 321, "cdp_url": "http://127.0.0.1:9222"}))
        monkeypatch.setattr(m, "process_identity", lambda _: None)
        monkeypatch.setattr(__import__("browser_profile_lease"), "local_cdp_version",
                            lambda _: {"status": "unreachable"})
    stopped_units = []
    monkeypatch.setattr(m, "unit_active", lambda unit: unit == "unrelated-unit")
    monkeypatch.setattr(m, "unit_inactive", lambda unit: unit == "first-unit")
    monkeypatch.setattr(m, "stop_unit", lambda unit: stopped_units.append(unit))
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_k: None)
    monkeypatch.setattr(m, "release_lease", lambda *_a, **_k: pytest.fail("no profile health change"))
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "finished"
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "stopped"
    assert m.proxy_row(c, args) is None
    assert stopped_units == []

def test_recover_refuses_active_interrupted_browser(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting'"); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    stopped_units = []
    monkeypatch.setattr(m, "unit_active", lambda unit: unit == "first-unit")
    monkeypatch.setattr(m, "unit_inactive", lambda _: False)
    monkeypatch.setattr(m, "stop_unit", lambda unit: stopped_units.append(unit))
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "browser-active"
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "starting"
    assert m.proxy_row(c, args)["state"] == "starting"
    assert stopped_units == []

def test_recover_refuses_unverified_inactive_unit(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting'"); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m.subprocess, "run", lambda *_a, **_k: argparse.Namespace(returncode=1, stdout=""))
    monkeypatch.setattr(m, "stop_unit", lambda _: pytest.fail("must not stop a unit"))
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "browser-active"
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "starting"

def test_unit_inactive_requires_explicit_systemd_state(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    def show(state, code=0):
        def run(command, **_kwargs):
            assert command == ["systemctl", "--user", "show", "--property=ActiveState", "--value", "first-unit"]
            return argparse.Namespace(returncode=code, stdout=state + "\n")
        monkeypatch.setattr(m.subprocess, "run", run)
        return m.unit_inactive("first-unit")
    assert show("inactive")
    assert show("failed")
    assert not show("active")
    assert not show("activating")
    assert not show("inactive", 1)

@pytest.mark.parametrize("evidence", ["live-pid", "live-cdp", "unknown-process"])
def test_recover_retains_interrupted_start_when_process_or_cdp_not_proven_stopped(monkeypatch, tmp_path, capsys, evidence):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting'"); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    (tmp_path / "first.json").write_text(json.dumps({"pid": 321, "cdp_url": "http://127.0.0.1:9222"}))
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "stop_unit", lambda _: pytest.fail("must not stop a unit"))
    monkeypatch.setattr(m, "unit_inactive", lambda _: True)
    if evidence == "unknown-process":
        monkeypatch.setattr(m, "process_identity", lambda _: (_ for _ in ()).throw(PermissionError("unknown")))
    else:
        monkeypatch.setattr(m, "process_identity", lambda _: {"pid": 321} if evidence == "live-pid" else None)
    profiles = __import__("browser_profile_lease")
    monkeypatch.setattr(profiles, "local_cdp_version", lambda _: {"status": "ready" if evidence == "live-cdp" else "unreachable"})
    with pytest.raises(SystemExit) as exc: m.task_proxy_recover(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "browser-active"
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "starting"
    assert m.proxy_row(c, args)["state"] == "starting"

def test_reap_interrupted_start_only_after_terminal_owner_and_quiet_flow(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting',updated=?,owner=?",
              (time.time() - 9000, json.dumps({"pid": 123}))); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    monkeypatch.setattr(m, "maintain", lambda _: None)
    monkeypatch.setattr(m, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "unit_inactive", lambda _: True)
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: True)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_k: None)
    with pytest.raises(SystemExit) as exc: m.reap(argparse.Namespace())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["proxy_recovered"] == [["agent", "run"]]
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "stopped"
    assert m.proxy_row(c, args) is None

def test_reap_does_not_reconcile_active_interrupted_browser(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set state='starting',updated=?,owner=?",
              (time.time() - 9000, json.dumps({"pid": 123}))); c.commit()
    add(m, tmp_path, "first", tmp_path / "artifacts/profile", state="starting")
    monkeypatch.setattr(m, "maintain", lambda _: None)
    monkeypatch.setattr(m, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(m, "unit_active", lambda unit: unit == "first-unit")
    monkeypatch.setattr(m, "unit_inactive", lambda _: False)
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: True)
    monkeypatch.setattr(m, "stop_unit", lambda _: pytest.fail("must not stop a unit"))
    with pytest.raises(SystemExit) as exc: m.reap(argparse.Namespace())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["proxy_recovered"] == []
    assert c.execute("select state from browsers where lease_id='first'").fetchone()[0] == "starting"
    assert m.proxy_row(c, args)["state"] == "starting"

def test_matching_proxy_requires_live_external_endpoint_and_same_ca_bytes(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path); args = start_args()
    args.proxy = "external"; args.proxy_cert_mode = "import"
    args.proxy_server = "http://127.0.0.1:8090"
    args.mitm_ca_cert = str(tmp_path / "ca.pem")
    (tmp_path / "ca.pem").write_bytes(b"original")
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"proxy_server": args.proxy_server, "proxy_cert_mode": "import",
        "proxy_cert_status": {"status": "trusted", "ca_cert": args.mitm_ca_cert,
                              "ca_sha256": m.ca_fingerprint(Path(args.mitm_ca_cert))}}))
    monkeypatch.setattr(m, "endpoint_open", lambda address: True)
    assert m.matching_proxy(m.db(), args, {"launch_file": str(receipt)})
    monkeypatch.setattr(m, "endpoint_open", lambda _: False)
    assert not m.matching_proxy(m.db(), args, {"launch_file": str(receipt)})
    monkeypatch.setattr(m, "endpoint_open", lambda _: True)
    (tmp_path / "ca.pem").write_bytes(b"replaced")
    assert not m.matching_proxy(m.db(), args, {"launch_file": str(receipt)})

def test_idle_reaper_needs_terminal_owner_quiet_flow_and_no_clients(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set updated=?,owner=?,invocation=?",
              (time.time() - 9000, json.dumps({"pid": 123}), "owned")); c.commit()
    monkeypatch.setattr(m, "maintain", lambda _: None)
    monkeypatch.setattr(m, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "unit_identity", lambda _: "owned")
    monkeypatch.setattr(m, "owner_state", lambda _: "active")
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: True)
    monkeypatch.setattr(m, "stop_unit", lambda _: None)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    with pytest.raises(SystemExit): m.reap(argparse.Namespace())
    assert m.proxy_row(c, args)
    capsys.readouterr()
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: False)
    with pytest.raises(SystemExit): m.reap(argparse.Namespace())
    assert m.proxy_row(c, args)
    capsys.readouterr()
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: True)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    with pytest.raises(SystemExit) as exc: m.reap(argparse.Namespace())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["proxy_recovered"] == [["agent", "run"]]
    assert m.proxy_row(c, args) is None

def test_task_reuse_rejects_rotated_ca_and_replaced_unit(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path); args = start_args(); args.proxy = "mitm"; args.proxy_cert_mode = "import"
    c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set invocation='original'"); c.commit()
    task = m.proxy_row(c, args)
    ca = Path(m.proxy_metadata(task)["ca_cert"]); ca.write_text("original")
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"proxy_server": m.proxy_metadata(task)["proxy_server"],
        "proxy_cert_mode": "import", "proxy_cert_status": {"status": "trusted", "ca_cert": str(ca),
        "ca_sha256": m.ca_fingerprint(ca)}}))
    monkeypatch.setattr(m, "unit_active", lambda _: True)
    monkeypatch.setattr(m, "unit_identity", lambda _: "original")
    monkeypatch.setattr(m, "port_open", lambda _: True)
    row = {"launch_file": str(receipt)}
    assert m.matching_proxy(c, args, row)
    ca.write_text("rotated")
    assert not m.matching_proxy(c, args, row)
    ca.write_text("original")
    monkeypatch.setattr(m, "unit_identity", lambda _: "replacement")
    assert not m.matching_proxy(c, args, row)

def test_failed_ca_rollback_marks_reservation_recoverable(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    task = m.proxy_row(c, args)
    Path(m.proxy_metadata(task)["ca_cert"]).write_text("ca")
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("busy")))
    assert not m.rollback_failed_browser_proxy(c, task, True, tmp_path / "profile")
    assert m.proxy_row(c, args)["state"] == "cleanup-failed"
