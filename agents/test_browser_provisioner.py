import argparse
import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import subprocess
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


def test_sweep_preserves_unkeyed_named_auth_domain_profile(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    root = tmp_path / "artifacts"
    profile = root / "demo/web/browser-profiles/api.example.test/fixture"
    add(m, root, "domain", profile)
    monkeypatch.setattr(m, "unit_active", lambda _: False)

    removed, skipped = m.sweep_rows(m.db(), 14, True)

    assert not removed and skipped[0]["reason"] == "legacy-auth-retained"
    assert profile.exists()


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


def test_finish_reindex_preserves_lane_and_request_metadata(monkeypatch, tmp_path, capsys):
    if not shutil.which("mitmdump"):
        pytest.skip("real mitmproxy required")
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    for name, path in {
        "HOME": home, "TMPDIR": tmp_path, "XDG_CONFIG_HOME": home / "config",
        "XDG_CACHE_HOME": home / "cache", "XDG_DATA_HOME": home / "data",
        "XDG_STATE_HOME": home / "state", "HARNESS_SHARED_BASE": tmp_path / "shared",
    }.items():
        monkeypatch.setenv(name, str(path))
    m = load(monkeypatch, tmp_path)
    store = home / ".local/share/ghost/proxy-store/proxy_store.sqlite"
    monkeypatch.setattr(m, "DEFAULT_STORE", store)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "unit_identity", lambda _: "fixture-invocation")
    monkeypatch.setattr(m, "proxy_ready", lambda _: True)
    args = start_args()
    with monkeypatch.context() as fake_systemd:
        fake_systemd.setattr(m.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
        row, created = m.start_proxy(m.db(), args)
    assert created
    executable, python = m.mitm_runtime()
    flow = Path(m.proxy_metadata(row)["flow_file"])
    subprocess.run([python, "-c", (
        "import sys; from mitmproxy import http, connection; from mitmproxy.io import FlowWriter; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1234),sockname=('127.0.0.1',8080),timestamp_start=1), connection.Server(address=('example.test',80))); "
        "f.request=http.Request.make('GET','http://example.test/one?key=value'); "
        "out=open(sys.argv[1],'wb'); FlowWriter(out).add(f); out.close()"
    ), str(flow)], check=True, capture_output=True, text=True)
    base = [python, *(["-s"] if executable == "/usr/bin/mitmdump" else []), str(m.PROXY_STORE),
            "--db", str(store), "--json", "index-lane", "--lane", row["lane"],
            "--lane-root", str(flow.parent.parent), "--flow-file", str(flow),
            "--program", "demo", "--task", "test", "--run-id", "run", "--agent-id", "agent",
            "--account-label", "fixture", "--proxy-host", "127.0.0.1", "--proxy-port", str(row["port"]),
            "--proxy-server", m.proxy_metadata(row)["proxy_server"], "--transport", "mixed"]
    first = subprocess.run(base + ["--runtime-host", "first-host", "--browser-profile-id", "first-profile",
                                   "--session-source", "first-source", "--note", "first-note"],
                           check=True, capture_output=True, text=True)
    assert json.loads(first.stdout)["indexed"] == 1
    def metadata():
        with sqlite3.connect(store) as conn:
            lane = conn.execute("select runtime_host,browser_profile_id,session_source,note,request_count from lanes").fetchone()
            request = conn.execute("select runtime_host,browser_profile_id,session_source from requests").fetchone()
            return lane, request
    expected = (("first-host", "first-profile", "first-source", "first-note", 1),
                ("first-host", "first-profile", "first-source"))
    assert metadata() == expected
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args)
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "finished"
    assert metadata() == expected
    # A repeat and a partial explicit update keep omitted values. Empty note is
    # an existing explicit clear; the other attribution flags use truthy values.
    subprocess.run(base, check=True, capture_output=True, text=True)
    assert metadata() == expected
    subprocess.run(base + ["--runtime-host", "second-host", "--note", ""],
                   check=True, capture_output=True, text=True)
    expected = (("second-host", "first-profile", "first-source", "", 1),
                ("second-host", "first-profile", "first-source"))
    assert metadata() == expected

    # Index a new origin and additional real flow: the fresh request inherits
    # existing attribution, while explicit proxy and profile values take effect.
    subprocess.run([python, "-c", (
        "import sys; from mitmproxy import http, connection; from mitmproxy.io import FlowWriter; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1234),sockname=('127.0.0.1',8080),timestamp_start=1), connection.Server(address=('other.test',80))); "
        "f.request=http.Request.make('GET','http://other.test/two'); "
        "out=open(sys.argv[1],'ab'); FlowWriter(out).add(f); out.close()"
    ), str(flow)], check=True, capture_output=True, text=True)
    subprocess.run(base + ["--proxy-host", "other-proxy", "--proxy-port", "9999",
                           "--proxy-server", "http://other-proxy:9999", "--browser-profile-id", "second-profile",
                           "--session-source", "second-source", "--note", "second-note"],
                   check=True, capture_output=True, text=True)
    with sqlite3.connect(store) as conn:
        assert conn.execute("select runtime_host,browser_profile_id,session_source,note,proxy_host,proxy_port,request_count from lanes").fetchone() == (
            "second-host", "second-profile", "second-source", "second-note", "other-proxy", 9999, 2)
        assert conn.execute("select host,runtime_host,browser_profile_id,session_source,proxy_host,proxy_port from requests order by host").fetchall() == [
            ("example.test", "second-host", "second-profile", "second-source", "other-proxy", 9999),
            ("other.test", "second-host", "second-profile", "second-source", "other-proxy", 9999)]
        before = [conn.execute(f"select * from {table} order by rowid").fetchall()
                  for table in ("lanes", "requests", "params", "request_packets")]

    # A malformed trailing flow must roll back the lane and earlier request
    # updates too, rather than leaving attribution half-written.
    with flow.open("ab") as output:
        output.write(b"not a valid mitmproxy flow")
    failed = subprocess.run(base + ["--runtime-host", "should-rollback", "--note", "should-rollback"],
                            capture_output=True, text=True)
    assert failed.returncode != 0
    with sqlite3.connect(store) as conn:
        after = [conn.execute(f"select * from {table} order by rowid").fetchall()
                 for table in ("lanes", "requests", "params", "request_packets")]
    assert after == before


def test_reindex_legacy_lane_does_not_inherit_ambiguous_note(monkeypatch, tmp_path):
    executable = shutil.which("mitmdump")
    if not executable:
        pytest.skip("real mitmproxy required")
    assert executable is not None
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    for name, path in {"HOME": home, "TMPDIR": tmp_path, "XDG_CONFIG_HOME": home / "config",
                       "XDG_CACHE_HOME": home / "cache", "XDG_DATA_HOME": home / "data",
                       "XDG_STATE_HOME": home / "state", "HARNESS_SHARED_BASE": tmp_path / "shared",
                       "HARNESS_BOUNTY_ARTIFACT_ROOT": tmp_path / "artifacts",
                       "BROWSER_PROVISIONER_STATE": tmp_path / "manager.sqlite"}.items():
        monkeypatch.setenv(name, str(path))
    resolved = Path(executable).resolve()
    python = resolved.open("rb").readline().decode().strip()[2:]
    flow = tmp_path / "legacy.mitm"
    subprocess.run([python, "-c", (
        "import sys; from mitmproxy import http, connection; from mitmproxy.io import FlowWriter; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1234),sockname=('127.0.0.1',8080),timestamp_start=1), connection.Server(address=('example.test',80))); "
        "f.request=http.Request.make('GET','http://example.test/legacy'); "
        "out=open(sys.argv[1],'wb'); FlowWriter(out).add(f); out.close()"
    ), str(flow)], check=True, capture_output=True, text=True)
    db = tmp_path / "legacy.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("""create table lanes(lane text primary key, program text, task text, account text,
                     profile_dir text, proxy_server text, flow_file text, raw_dir text,
                     first_indexed_at real, last_indexed_at real, request_count integer default 0, note text)""")
        conn.execute("insert into lanes(lane,first_indexed_at,note) values('legacy',123,'legacy-note')")
    command = [python, *(["-s"] if str(resolved) == "/usr/bin/mitmdump" else []),
               str(SCRIPT.parent / "proxy_store.py"), "--db", str(db), "--json", "index-lane",
               "--lane", "legacy", "--lane-root", str(tmp_path), "--flow-file", str(flow)]
    for _ in range(2):
        subprocess.run(command, check=True, capture_output=True, text=True)
    with sqlite3.connect(db) as conn:
        assert conn.execute("select first_indexed_at,note,runtime_host,browser_profile_id,session_source,request_count from lanes").fetchone() == (
            123, None, None, None, None, 1)
        assert conn.execute("select count(*) from requests").fetchone() == (1,)


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
        proxy_server="http://127.0.0.1:8081", mitm_ca_cert="/tmp/mitm-ca.pem", url="https://example.test/", display_backend="kasmvnc", kasmvnc_display=20, kasmvnc_web_port=8463, recover_profile=True, graphics_backend="external",
    )
    try:
        m.request(args)
    except SystemExit as e:
        assert e.code == 0
    assert captured["command"][captured["command"].index("--auth-domain") : captured["command"].index("--agent-id")] == [
        "--auth-domain", "api.example.test",
    ]
    assert captured["command"][captured["command"].index("--graphics-backend") + 1] == "external"
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


@pytest.mark.parametrize("graphics_backend", ["auto", "external"])
def test_provisioner_marks_its_launcher_invocation_as_internal(monkeypatch, tmp_path, graphics_backend):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setenv("CHROMIUM_TEST_CHROME", "/host/old-vulkan-wrapper")
    args = start_args()
    args.driving_mode = "manual"
    args.display_backend = "kasmvnc"
    args.graphics_backend = graphics_backend
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
    assert ("--graphics-backend external" in shell) == (graphics_backend == "external")
    assert ("--setenv=CHROMIUM_TEST_CHROME=" in browser_dispatch) == (graphics_backend == "auto")
    assert ("--setenv=CHROMIUM_TEST_CHROME=/host/old-vulkan-wrapper" in browser_dispatch) == (graphics_backend == "external")
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
    (tmp_path / "artifacts/p").mkdir(parents=True)
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
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    monkeypatch.setattr(profiles, 'local_filesystem', lambda _: True)
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], [])); monkeypatch.setattr(m, "admission", lambda *_: {"status":"admitted"})
    args = start_args(); args.account = 'anon'
    acquired = {}
    def fake_lease(_, action, *rest):
        assert action == 'acquire'
        acquired.update(profiles.cmd_acquire(argparse.Namespace(
            program='demo', account='anon', auth_domain=None, agent_id='agent',
            run_id='run', purpose='test', ttl_seconds=60, state_dir=str(m.STATE.parent),
            recover_profile=False, manager_id=m.manager_id())))
        return acquired
    monkeypatch.setattr(m, "lease", fake_lease)
    monkeypatch.setattr(m, 'stop_unit', lambda _: None)
    monkeypatch.setattr(m, 'unit_inactive', lambda _: True)
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=1, stderr="systemd denied", stdout=""))
    try: m.start(args)
    except SystemExit as e: assert e.code == 2
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        released = leases.execute('SELECT status,profile_health FROM browser_profile_leases WHERE lease_id=?',
                                  (acquired['lease']['lease_id'],)).fetchone()
        assert tuple(released) == ('released', 'healthy')


@pytest.mark.parametrize('failure', ['exhausted', 'conflict', 'exception'])
def test_proxy_unavailable_releases_acquired_unstarted_lease(monkeypatch, tmp_path, capsys, failure):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    args = start_args()
    args.account, args.proxy, args.proxy_cert_mode = 'anon', 'mitm', 'import'
    acquired = {}
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'DEFAULT_STORE', tmp_path / 'missing-standalone.sqlite')
    monkeypatch.setattr(m, 'port_open', lambda _: True)
    monkeypatch.setattr(m, 'stop_unit', lambda _: pytest.fail('no unit was started'))
    if failure == 'conflict':
        proxy_fixture(m, args, tmp_path)
    elif failure == 'exception':
        def failed_proxy(*_):
            raise RuntimeError('sensitive-proxy-fixture')
        monkeypatch.setattr(m, 'start_proxy', failed_proxy)
    def acquire(_, action, *rest):
        assert action == 'acquire'
        acquired.update(profiles.cmd_acquire(argparse.Namespace(
            program='demo', account='anon', auth_domain=None, agent_id='agent',
            run_id='run', purpose='test', ttl_seconds=60, state_dir=str(m.STATE.parent),
            recover_profile=False, manager_id=m.manager_id())))
        return acquired
    monkeypatch.setattr(m, 'lease', acquire)

    with pytest.raises(SystemExit) as exc:
        m.start(args)

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert json.loads(output.out)['status'] == {
        'exhausted': 'proxy-unavailable', 'conflict': 'proxy-conflict', 'exception': 'proxy-failed'
    }[failure]
    assert output.err == ''
    assert 'sensitive-proxy-fixture' not in output.out
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        row = leases.execute('SELECT status, browser_status, profile_health FROM browser_profile_leases WHERE lease_id=?',
                             (acquired['lease']['lease_id'],)).fetchone()
        assert tuple(row) == ('released', 'stopped', 'healthy')
    assert m.db().execute('SELECT count(*) FROM browsers').fetchone()[0] == 0
    task = m.proxy_row(m.db(), args)
    if failure == 'conflict':
        assert task['lane'] == 'task-fixture' and task['state'] == 'running'
    else:
        assert task is None


def test_request_accepts_only_fixed_cleanup_signal_and_does_not_retry(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.wait_seconds = 60
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    monkeypatch.setattr(m.time, 'sleep', lambda _: pytest.fail('uncertain cleanup must not retry'))
    signal = json.dumps(m.LEASE_RELEASE_UNVERIFIED)
    responses = [
        argparse.Namespace(returncode=2, stdout='{"status":"queued"}', stderr='secret\n' + signal + '\n'),
        argparse.Namespace(returncode=2, stdout='{"status":"proxy-failed"}',
                           stderr=signal[:-1] + ', "secret": "secret-value"}\n'),
    ]
    monkeypatch.setattr(m.subprocess, 'run', lambda *_a, **_k: responses.pop(0))
    with pytest.raises(SystemExit):
        m.request(args)
    first = capsys.readouterr()
    assert json.loads(first.out)['cleanup']['status'] == 'cleanup-incomplete'
    assert first.err == '' and 'secret' not in first.out
    with pytest.raises(SystemExit):
        m.request(args)
    second = capsys.readouterr()
    assert 'cleanup' not in json.loads(second.out)
    assert second.err == '' and 'secret' not in second.out


@pytest.mark.parametrize('child_stdout', ['[]', '"unexpected"', '7', 'false'])
def test_request_rejects_non_object_json_with_cleanup_signal(monkeypatch, tmp_path, capsys, child_stdout):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.wait_seconds = 0
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    response = argparse.Namespace(returncode=7, stdout=child_stdout,
                                  stderr=json.dumps(m.LEASE_RELEASE_UNVERIFIED) + '\nsecret\n')
    monkeypatch.setattr(m.subprocess, 'run', lambda *_a, **_k: response)
    with pytest.raises(SystemExit) as exc:
        m.request(args)
    output = capsys.readouterr()
    assert exc.value.code == 2
    result = json.loads(output.out)
    assert result['status'] == 'launch-failed'
    assert result['cleanup']['status'] == 'cleanup-incomplete'
    assert output.err == '' and 'secret' not in output.out


@pytest.mark.parametrize('failure_kind', ['exit', 'exception', 'exit-without-json', 'exit-with-null-json', 'exit-zero'])
@pytest.mark.parametrize('release_outcome', ['refused', 'error', 'released'])
def test_request_reports_proxy_cleanup_across_real_start_subprocess(
        monkeypatch, tmp_path, capsys, failure_kind, release_outcome):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.account, args.proxy, args.proxy_cert_mode, args.wait_seconds = 'anon', 'mitm', 'import', 0
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    real_run = subprocess.run
    # Exercise request's real subprocess boundary and the actual start function,
    # while injecting only the external admission/proxy/release failure seams.
    fixture = '''
import argparse, importlib.util, sys
script, failure, outcome = sys.argv[1:4]
sys.argv = [script] + sys.argv[4:]
spec = importlib.util.spec_from_file_location("fixture_provisioner", script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
import browser_profile_lease as profiles
m.sweep_rows = lambda *a: ([], [])
m.admission = lambda *a: {"status": "admitted"}
m.port_open = lambda *a: True
m.DEFAULT_STORE = m.STATE.parent / "missing-standalone.sqlite"
def acquire(args, action, *rest):
    assert action == "acquire"
    return profiles.cmd_acquire(argparse.Namespace(
        program=args.program, account=args.account, auth_domain=None, agent_id=args.agent_id,
        run_id=args.run_id, purpose=args.purpose, ttl_seconds=args.ttl_seconds,
        state_dir=str(m.STATE.parent), recover_profile=False, manager_id=m.manager_id()))
m.lease = acquire
def failed_proxy(*args):
    print("sensitive-arbitrary-stderr", end="", file=sys.stderr)
    if failure in ("exit", "exit-zero"):
        m.emit({"status": "proxy-unavailable", "detail": "no task proxy ports"}, 7 if failure == "exit" else 0)
    if failure == "exit-without-json":
        raise SystemExit(7)
    if failure == "exit-with-null-json":
        print("null", flush=True)
        raise SystemExit(7)
    raise RuntimeError("sensitive-proxy-exception")
m.start_proxy = failed_proxy
if outcome != "released":
    def failed_release(*args):
        if outcome == "error":
            raise RuntimeError("sensitive-release-exception")
        return False
    m.release_lease = failed_release
m.main()
'''
    def run_start(cmd, **kwargs):
        assert cmd[1] == str(SCRIPT.resolve()) and cmd[2] == 'start'
        return real_run([cmd[0], '-c', fixture, cmd[1], failure_kind, release_outcome, *cmd[2:]], **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', run_start)

    with pytest.raises(SystemExit) as exc:
        m.request(args)
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert exc.value.code == {'exit': 7, 'exit-zero': 0, 'exception': 2, 'exit-without-json': 2, 'exit-with-null-json': 2}[failure_kind]
    assert result['status'] == {
        'exit': 'proxy-unavailable', 'exit-zero': 'proxy-unavailable', 'exception': 'proxy-failed',
        'exit-without-json': 'launch-failed', 'exit-with-null-json': 'launch-failed',
    }[failure_kind]
    if failure_kind in ('exit', 'exit-zero'):
        assert result['detail'] == 'no task proxy ports'
    if release_outcome == 'released':
        assert 'cleanup' not in result
    else:
        assert result['cleanup'] == {
            'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified',
            'action': 'Inspect the canonical lease for this agent and run; resolve it only after verifying ownership and browser state.',
        }
    if failure_kind not in ('exit-without-json', 'exit-with-null-json'):
        assert result['attempts'] == 1
    assert output.err == ''
    assert 'sensitive-' not in output.out
    with sqlite3.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        rows = leases.execute('SELECT status, browser_status FROM browser_profile_leases').fetchall()
    assert rows == [('released', 'stopped') if release_outcome == 'released' else ('active', 'not-started')]
    assert m.db().execute('SELECT count(*) FROM browsers').fetchone()[0] == 0


@pytest.mark.parametrize('previous_health', ['needs-refresh', 'unknown'])
@pytest.mark.parametrize('failure_kind', ['exit', 'exception'])
def test_proxy_failure_preserves_unrepaired_profile_health(monkeypatch, tmp_path, capsys, previous_health, failure_kind):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    args = start_args()
    args.account, args.proxy, args.proxy_cert_mode = 'anon', 'mitm', 'import'
    args.recover_profile = True
    req = argparse.Namespace(program='demo', account='anon', auth_domain=None,
                             agent_id='agent', run_id='run', purpose='test', ttl_seconds=60,
                             state_dir=str(m.STATE.parent), recover_profile=False,
                             manager_id=m.manager_id())
    previous = profiles.cmd_acquire(req)
    assert previous['status'] == 'leased'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        leases.execute('BEGIN IMMEDIATE')
        row = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?',
                             (previous['lease']['lease_id'],)).fetchone()
        profiles.release_owned_in_transaction(leases, row, disposition='failed', profile_health=previous_health)
        leases.commit()
    assert profiles.cmd_acquire(req)['status'] == 'account-unavailable'
    req.recover_profile = True
    if failure_kind == 'exception':
        def failed_proxy(*_):
            raise RuntimeError('sensitive-proxy-fixture')
        monkeypatch.setattr(m, 'start_proxy', failed_proxy)
    acquired = {}
    def acquire(*_):
        acquired.update(profiles.cmd_acquire(req))
        return acquired
    monkeypatch.setattr(m, 'lease', acquire)
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'DEFAULT_STORE', tmp_path / 'missing-standalone.sqlite')
    monkeypatch.setattr(m, 'port_open', lambda _: True)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert json.loads(output.out)['status'] == ('proxy-unavailable' if failure_kind == 'exit' else 'proxy-failed')
    assert acquired['status'] == 'leased'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        row = leases.execute('SELECT status, profile_health FROM browser_profile_leases WHERE lease_id=?',
                             (acquired['lease']['lease_id'],)).fetchone()
        assert tuple(row) == ('released', previous_health)
    assert 'sensitive-proxy-fixture' not in output.out + output.err
    req.recover_profile = False
    assert profiles.cmd_acquire(req)['status'] == 'account-unavailable'


@pytest.mark.parametrize('failure_kind', ['exit', 'exception'])
def test_proxy_failure_does_not_release_already_owned_lease(monkeypatch, tmp_path, capsys, failure_kind):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    args = start_args()
    args.account, args.proxy, args.proxy_cert_mode = 'anon', 'mitm', 'import'
    req = argparse.Namespace(program='demo', account='anon', auth_domain=None,
                             agent_id='agent', run_id='run', purpose='test', ttl_seconds=60,
                             state_dir=str(m.STATE.parent), recover_profile=False,
                             manager_id=m.manager_id())
    previous = profiles.cmd_acquire(req)
    assert previous['status'] == 'leased'
    if failure_kind == 'exception':
        def failed_proxy(*_):
            raise RuntimeError('sensitive-proxy-fixture')
        monkeypatch.setattr(m, 'start_proxy', failed_proxy)
    reacquired = {}
    def acquire(*_):
        reacquired.update(profiles.cmd_acquire(req))
        return reacquired
    monkeypatch.setattr(m, 'lease', acquire)
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'DEFAULT_STORE', tmp_path / 'missing-standalone.sqlite')
    monkeypatch.setattr(m, 'port_open', lambda _: True)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert json.loads(output.out)['status'] == ('proxy-unavailable' if failure_kind == 'exit' else 'proxy-failed')
    assert output.err == ''
    assert reacquired['status'] == 'already-owned'
    assert reacquired['lease']['lease_id'] == previous['lease']['lease_id']
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        row = leases.execute('SELECT status, browser_status, profile_health FROM browser_profile_leases WHERE lease_id=?',
                             (previous['lease']['lease_id'],)).fetchone()
        assert tuple(row) == ('active', 'not-started', 'unknown')
    assert 'sensitive-proxy-fixture' not in output.out + output.err


@pytest.mark.parametrize('failure_kind', ['exit', 'exception'])
@pytest.mark.parametrize('case', ['wrong-owner', 'wrong-run', 'browser-started', 'release-error', 'interrupt'])
def test_proxy_failure_preserves_uncertain_lease_and_original_error(monkeypatch, tmp_path, capsys, case, failure_kind):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    args = start_args()
    args.account, args.proxy, args.proxy_cert_mode = 'anon', 'mitm', 'import'
    acquired = {}
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'DEFAULT_STORE', tmp_path / 'missing-standalone.sqlite')
    monkeypatch.setattr(m, 'port_open', lambda _: True)
    monkeypatch.setattr(m, 'stop_unit', lambda _: pytest.fail('must not stop a unit'))
    def acquire(_, action, *rest):
        assert action == 'acquire'
        acquired.update(profiles.cmd_acquire(argparse.Namespace(
            program='demo', account='anon', auth_domain=None, agent_id='agent',
            run_id='run', purpose='test', ttl_seconds=60, state_dir=str(m.STATE.parent),
            recover_profile=False, manager_id=m.manager_id())))
        with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
            if case == 'wrong-owner':
                leases.execute("UPDATE browser_profile_leases SET owner_agent_id='other' WHERE lease_id=?",
                               (acquired['lease']['lease_id'],))
            elif case == 'wrong-run':
                leases.execute("UPDATE browser_profile_leases SET owner_run_id='other' WHERE lease_id=?",
                               (acquired['lease']['lease_id'],))
            elif case == 'browser-started':
                leases.execute("UPDATE browser_profile_leases SET browser_status='running' WHERE lease_id=?",
                               (acquired['lease']['lease_id'],))
        return acquired
    monkeypatch.setattr(m, 'lease', acquire)
    if failure_kind == 'exception' and case != 'interrupt':
        def failed_proxy(*_):
            raise RuntimeError('sensitive-proxy-fixture')
        monkeypatch.setattr(m, 'start_proxy', failed_proxy)
    if case == 'release-error':
        def failed_release(*_):
            raise RuntimeError('sensitive-release-fixture')
        monkeypatch.setattr(m, 'release_lease', failed_release)
    elif case == 'interrupt':
        def interrupted(*_):
            raise KeyboardInterrupt()
        monkeypatch.setattr(m, 'start_proxy', interrupted)
        monkeypatch.setattr(m, 'release_lease', lambda *_: pytest.fail('cancellation must propagate'))

    with pytest.raises(KeyboardInterrupt if case == 'interrupt' else SystemExit) as exc:
        m.start(args)
    output = capsys.readouterr()
    if case != 'interrupt':
        assert exc.value.code == 2
        assert json.loads(output.out)['status'] == ('proxy-unavailable' if failure_kind == 'exit' else 'proxy-failed')
        assert json.loads(output.err) == {'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}
        assert 'sensitive-' not in output.out + output.err
    else:
        assert output.out == output.err == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        row = leases.execute('SELECT status FROM browser_profile_leases WHERE lease_id=?',
                             (acquired['lease']['lease_id'],)).fetchone()
        assert row['status'] == 'active'
    assert m.db().execute('SELECT count(*) FROM browsers').fetchone()[0] == 0


@pytest.mark.parametrize("stored,exact,requested,expected", [
    ("demo-name", None, "Demo Name", True),
    ("other-name", None, "Demo Name", False),
    ("demo-name", "Demo Name", "Demo Name", True),
    ("demo-name", "demo-name", "Demo Name", False),
    ("demo-name", "", "Demo Name", False),
])
def test_task_proxy_program_identity_reuse(monkeypatch, tmp_path, capsys, stored, exact, requested, expected):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.program = requested
    args.proxy = "mitm"
    c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set program=?, exact_program=?", (stored, exact))
    c.commit()
    monkeypatch.setattr(m, "proxy_ready", lambda _: True)
    if expected:
        row, created = m.start_proxy(c, args)
        assert row["program"] == stored and not created
    else:
        with pytest.raises(SystemExit) as outcome:
            m.start_proxy(c, args)
        assert outcome.value.code == 2
        assert json.loads(capsys.readouterr().out)["status"] == "proxy-conflict"
    row = m.proxy_row(c, args)
    metadata = m.proxy_metadata(row)
    monkeypatch.setattr(m, "record_info", lambda _: {
        "proxy_server": metadata["proxy_server"], "proxy_cert_mode": "import",
        "proxy_cert_status": {"status": "trusted", "ca_cert": metadata["ca_cert"], "ca_sha256": "fixture"},
    })
    monkeypatch.setattr(m, "ca_fingerprint", lambda _: "fixture")
    assert m.matching_proxy(c, args, {}) is expected
    delattr(args, "program")
    assert m.matching_proxy(c, args, {}) is False


def proxy_fixture(m, args, root):
    c = m.db()
    directory = root / "task-proxies" / "task-fixture"
    (directory / "mitmproxy").mkdir(parents=True)
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
              (args.agent_id, args.run_id, "demo", "fixture", args.purpose,
               "task-fixture", 8081, "task-mitm-task-fixture", str(directory), "running"))
    c.commit()
    return c


@pytest.mark.parametrize("executable,expected", [("/usr/bin/mitmdump", ["/usr/bin/python3", "-s"]),
                                                 ("/opt/venv/bin/mitmdump", ["/usr/bin/python3"])])
def test_finish_indexes_with_matching_user_site_policy(monkeypatch, tmp_path, capsys, executable, expected):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    Path(m.proxy_metadata(m.proxy_row(c, args))["flow_file"]).write_bytes(b"fixture")
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "mitm_runtime", lambda: (executable, "/usr/bin/python3"))
    commands = []
    monkeypatch.setattr(m.subprocess, "run", lambda cmd, **kw: commands.append(cmd) or
                        argparse.Namespace(returncode=0, stdout='{"status":"indexed"}'))
    with pytest.raises(SystemExit) as result:
        m.finish_proxy(args)
    assert result.value.code == 0
    assert commands[0][:len(expected)] == expected
    assert commands[0][len(expected)] == str(m.PROXY_STORE)


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


@pytest.mark.parametrize("header,detail", [
    ("#!/bin/bash\n", "mitmdump shell wrapper unsupported; select a Python entrypoint"),
    ("#!/usr/bin/env python3\n", "mitmdump Python interpreter is unavailable"),
    ("not a shebang\n", "mitmdump Python interpreter is unavailable"),
    ("#!/missing/private-interpreter\n", "mitmdump Python interpreter is unavailable"),
])
def test_mitm_runtime_rejects_non_python_or_malformed_shebang(monkeypatch, tmp_path, header, detail):
    m = load(monkeypatch, tmp_path)
    executable = tmp_path / "mitmdump"
    executable.write_text(header)
    executable.chmod(0o700)
    monkeypatch.setattr(m.shutil, "which", lambda _: str(executable))
    with pytest.raises(RuntimeError) as exc:
        m.mitm_runtime()
    assert str(exc.value) == detail


def test_shell_wrapper_start_reports_guidance_and_releases_own_resources(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    monkeypatch.setattr(profiles, "local_filesystem", lambda _: True)
    monkeypatch.setattr(m, "sweep_rows", lambda *a: ([], []))
    monkeypatch.setattr(m, "admission", lambda *_: {"status": "admitted"})
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    executable = tmp_path / "secret-executable-name"
    executable.write_text("#!/bin/bash\n# secret-wrapper-content\n")
    executable.chmod(0o700)
    monkeypatch.setattr(m.shutil, "which", lambda _: str(executable))
    args = start_args()
    args.account = "anon"
    args.proxy, args.proxy_cert_mode = "mitm", "import"
    acquired = {}
    def acquire(_, action, *rest):
        assert action == "acquire"
        acquired.update(profiles.cmd_acquire(argparse.Namespace(
            program="demo", account="anon", auth_domain=None, agent_id="agent",
            run_id="run", purpose="test", ttl_seconds=60, state_dir=str(m.STATE.parent),
            recover_profile=False, manager_id=m.manager_id())))
        return acquired
    monkeypatch.setattr(m, "lease", acquire)
    c = m.db()
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
              ("other", "other-run", "demo", "anon", "test", "other-lane", 8081,
               "other-unit", str(tmp_path / "other"), "running"))
    c.commit()
    reservation = {}
    runtime = m.mitm_runtime
    def observe_runtime():
        reservation.update(dict(m.proxy_row(c, args)))
        return runtime()
    monkeypatch.setattr(m, "mitm_runtime", observe_runtime)

    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "proxy-failed",
        "detail": "mitmdump shell wrapper unsupported; select a Python entrypoint",
    }
    assert acquired["status"] == "leased" and reservation["lane"] != "other-lane"
    with profiles.connect(m.STATE.parent / "browser_profile_leases.sqlite") as leases:
        released = leases.execute("select status,profile_health from browser_profile_leases where lease_id=?",
                                  (acquired["lease"]["lease_id"],)).fetchone()
        assert tuple(released) == ("released", "healthy")
    assert c.execute("select lane from task_proxies order by lane").fetchall()[0][0] == "other-lane"
    assert c.execute("select count(*) from task_proxies").fetchone()[0] == 1
    assert m.proxy_row(c, args) is None


def test_custom_mitmdump_keeps_user_site(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    home = tmp_path / "custom-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONNOUSERSITE", raising=False)
    site = Path(subprocess.run(["/usr/bin/python3", "-m", "site", "--user-site"],
                               capture_output=True, text=True, check=True, timeout=20).stdout.strip())
    assert site.is_relative_to(home)
    site.mkdir(parents=True)
    (site / "custom_dependency.py").write_text("VALUE = 'custom-user-site'\n")
    interpreter = tmp_path / "custom-interpreter"
    interpreter.symlink_to("/usr/bin/python3")
    executable = tmp_path / "mitmdump"
    executable.write_text(f"#!{interpreter}\nimport custom_dependency\nprint(custom_dependency.VALUE)\n")
    executable.chmod(0o700)
    monkeypatch.setattr(m.shutil, "which", lambda _: str(executable))
    selected, python = m.mitm_runtime()
    result = subprocess.run([selected], capture_output=True, text=True, check=True, timeout=20)
    assert python == str(interpreter) and result.stdout.strip() == "custom-user-site"


def test_system_mitmdump_unit_isolates_only_its_user_site(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    c = m.db()
    commands = []
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "mitm_runtime", lambda: ("/usr/bin/mitmdump", "/usr/bin/python3"))
    monkeypatch.setattr(m, "unit_identity", lambda _: "invocation")
    monkeypatch.setattr(m, "proxy_ready", lambda _: True)
    monkeypatch.setattr(m.subprocess, "run", lambda cmd, **kw: commands.append(cmd) or argparse.Namespace(returncode=0))
    m.start_proxy(c, start_args())
    assert "--setenv=PYTHONNOUSERSITE=1" in commands[0][:commands[0].index("--")]


def test_task_proxy_failed_dispatch_retains_uncertain_reservation(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = m.db()
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "mitm_runtime", lambda: ("/usr/bin/mitmdump", "/usr/bin/python3"))
    commands = []
    monkeypatch.setattr(m.subprocess, "run", lambda cmd, **k: commands.append(cmd) or argparse.Namespace(returncode=1))
    with pytest.raises(m.ProxyStartupError, match="capture or service dispatch is uncertain"):
        m.start_proxy(c, args)
    assert len(commands) == 1 and '--verified-capture-launch' in commands[0]
    row = m.proxy_row(c, args)
    assert row is not None and row['state'] == 'cleanup-failed' and row['capture_identity']
    assert c.execute("select outcome from proxy_attempts where lane=?", (row['lane'],)).fetchone()[0] == 'capture-uncertain'
    assert json.dumps(m.PROXY_CLEANUP_UNVERIFIED) in capsys.readouterr().err.splitlines()


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
    assert "--setenv=PYTHONNOUSERSITE=1" not in commands[0]
    assert "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent" not in commands[0]
    assert Path(row["run_dir"]).stat().st_mode & 0o777 == 0o700
    assert (Path(row["run_dir"]) / "mitmproxy").stat().st_mode & 0o777 == 0o700
    same, created = m.start_proxy(c, args)
    assert not created and same["lane"] == row["lane"] and len(commands) == 1


@pytest.mark.parametrize("occupied, legacy_lease, expected", [
    (set(), False, 8091), ({8091}, False, 8092), (set(), True, 8092),
])
def test_task_proxy_uses_bounded_overflow_when_existing_pool_is_reserved(monkeypatch, tmp_path, occupied, legacy_lease, expected):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "DEFAULT_STORE", tmp_path / "standalone.sqlite")
    c = m.db()
    for offset in range(10):
        c.execute(
            "insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) "
            "values(?,?,?,?,?,?,?,?,?,?)",
            (f"prior-{offset}", f"run-{offset}", "demo", "fixture", "test",
             f"task-prior-{offset}", 8081 + offset, f"task-mitm-prior-{offset}",
             str(tmp_path / f"prior-{offset}"), "running"),
        )
    c.commit()
    if legacy_lease:
        lease_db = m.DEFAULT_STORE
        with sqlite3.connect(lease_db) as standalone:
            standalone.execute("CREATE TABLE proxy_leases(proxy_port INTEGER, status TEXT, expires_at REAL)")
            standalone.execute("INSERT INTO proxy_leases VALUES(8091, 'active', NULL)")
    commands = []
    monkeypatch.setattr(m, "port_open", lambda p: p in occupied)
    monkeypatch.setattr(m, "mitm_runtime", lambda: ("/bin/mitmdump", "/bin/python"))
    monkeypatch.setattr(m, "unit_identity", lambda _: "invocation")
    monkeypatch.setattr(m, "proxy_ready", lambda _: True)
    monkeypatch.setattr(m, "stop_unit", lambda _: pytest.fail("prior unit must not be stopped"))
    def run(command, **_):
        commands.append(command)
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, "run", run)

    row, created = m.start_proxy(c, start_args())

    assert created and row["state"] == "running" and row["port"] == expected
    assert commands[0][commands[0].index("--listen-port") + 1] == str(expected)
    assert c.execute("select count(*) from task_proxies where port between 8081 and 8090").fetchone()[0] == 10


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
    assert json.loads(capsys.readouterr().out)["status"] == "aborted"
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
    result = json.loads(capsys.readouterr().out)
    assert result["proxy_recovered"] == []
    assert result["proxy_blocked"] == {"browser-not-released": 1}
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
    assert json.loads(capsys.readouterr().out)["proxy_blocked"] == {"task-owner-not-terminal": 1}
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: False)
    with pytest.raises(SystemExit): m.reap(argparse.Namespace())
    assert m.proxy_row(c, args)
    assert json.loads(capsys.readouterr().out)["proxy_blocked"] == {"flow-or-replay-not-quiet": 1}
    monkeypatch.setattr(m, "replay_clients_absent", lambda _: True)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    with pytest.raises(SystemExit) as exc: m.reap(argparse.Namespace())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["proxy_recovered"] == [["agent", "run"]]
    assert m.proxy_row(c, args) is None

def test_task_proxy_refuses_owner_pid_reuse_before_reservation(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path)
    args = start_args()
    args.owner_pid = 123
    args._owner_identity = {"pid": 123, "start": "old"}
    monkeypatch.setattr(m, "process_identity", lambda _: {"pid": 123, "start": "new"})
    monkeypatch.setattr(m, "port_open", lambda _: pytest.fail("no port allocation"))
    with pytest.raises(SystemExit) as exc:
        m.start_proxy(m.db(), args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "owner-unavailable"
    assert m.db().execute("select count(*) from task_proxies").fetchone()[0] == 0


def test_reap_reports_unowned_old_proxy_without_stopping_it(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set updated=?,owner=NULL", (time.time() - 9000,)); c.commit()
    monkeypatch.setattr(m, "maintain", lambda _: None)
    monkeypatch.setattr(m, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(m, "stop_unit", lambda _: pytest.fail("no owner proof"))
    with pytest.raises(SystemExit) as exc: m.reap(argparse.Namespace())
    assert exc.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["proxy_blocked"] == {"task-owner-unrecorded": 1}
    assert result["proxy_recovered"] == []
    assert m.proxy_row(c, args)["state"] == "running"

def test_reap_reports_failed_eligible_proxy_finish(monkeypatch, tmp_path, capsys):
    m = load(monkeypatch, tmp_path); args = start_args(); c = proxy_fixture(m, args, tmp_path)
    c.execute("update task_proxies set updated=?,owner=?",
              (time.time() - 9000, json.dumps({"pid": 123}))); c.commit()
    monkeypatch.setattr(m, "maintain", lambda _: None)
    monkeypatch.setattr(m, "cleanup_unused", lambda _: [])
    monkeypatch.setattr(m, "owner_state", lambda _: "terminal")
    monkeypatch.setattr(m, "proxy_quiet", lambda _: True)
    monkeypatch.setattr(m, "finish_proxy", lambda *_a, **_k: m.emit({"status": "proxy-stop-failed", "detail": "private"}, 2))
    with pytest.raises(SystemExit): m.reap(argparse.Namespace())
    result = json.loads(capsys.readouterr().out)
    assert result["proxy_blocked"] == {"proxy-stop-failed": 1}
    assert "private" not in json.dumps(result)
    assert m.proxy_row(c, args)["state"] == "running"

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


def test_system_mitmdump_poisoned_user_site_still_indexes(monkeypatch, tmp_path, capsys):
    if not Path("/usr/bin/mitmdump").is_file():
        pytest.skip("system mitmdump unavailable")
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    home = tmp_path / "poison-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONNOUSERSITE", raising=False)
    site = subprocess.run(["/usr/bin/python3", "-m", "site", "--user-site"],
                          capture_output=True, text=True, check=True, timeout=20).stdout.strip()
    assert Path(site).is_relative_to(home)
    poison = Path(site) / "OpenSSL"
    poison.mkdir(parents=True)
    (poison / "__init__.py").write_text('raise RuntimeError("fixture poisoned user site")\n')
    baseline = subprocess.run(["/usr/bin/python3", "/usr/bin/mitmdump", "--version"],
                              capture_output=True, text=True, timeout=120)
    assert baseline.returncode != 0 and "fixture poisoned user site" in baseline.stderr
    safe = subprocess.run(["/usr/bin/python3", "-s", "/usr/bin/mitmdump", "--version"],
                          capture_output=True, text=True, timeout=120)
    assert safe.returncode == 0, safe.stderr
    flow = Path(m.proxy_metadata(m.proxy_row(c, args))["flow_file"])
    fixture = (
        "from mitmproxy import connection,http,io; import sys; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',12345),"
        "sockname=('127.0.0.1',8081),timestamp_start=1.0),"
        "connection.Server(address=('example.test',443))); "
        "f.request=http.Request.make('GET','https://example.test/check'); "
        "o=open(sys.argv[1],'wb'); io.FlowWriter(o).add(f); o.close()"
    )
    subprocess.run(["/usr/bin/python3", "-s", "-c", fixture, str(flow)], check=True, timeout=120)
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/bin/mitmdump")
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    with pytest.raises(SystemExit) as outcome:
        m.finish_proxy(args)
    assert outcome.value.code == 0, capsys.readouterr().out
    assert m.proxy_row(c, args) is None
    db_path = home / ".local/share/ghost/proxy-store/proxy_store.sqlite"
    with sqlite3.connect(db_path) as index:
        assert index.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1


@pytest.mark.parametrize("recovery", [False, True])
def test_task_proxy_completion_indexes_private_default_and_releases(
    monkeypatch, tmp_path, capsys, recovery,
):
    """Exercise the real index subprocess, not only a mocked finish result."""
    m = load(monkeypatch, tmp_path)
    args = start_args()
    c = proxy_fixture(m, args, tmp_path)
    if recovery:
        c.execute("update task_proxies set state='cleanup-failed'")
        c.commit()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))

    try:
        python = m.mitm_runtime()[1]
    except (RuntimeError, OSError):
        pytest.skip("mitmdump Python unavailable for real-flow fixture")
    flow = Path(m.proxy_metadata(m.proxy_row(c, args))["flow_file"])
    fixture = (
        "from mitmproxy import connection, http, io; import sys; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',12345),"
        "sockname=('127.0.0.1',8081),timestamp_start=1.0), "
        "connection.Server(address=('example.test',443))); "
        "f.request=http.Request.make('GET','https://example.test/check'); "
        "o=open(sys.argv[1],'wb'); io.FlowWriter(o).add(f); o.close()"
    )
    subprocess.run([python, "-c", fixture, str(flow)], check=True)
    monkeypatch.setattr(m, "unit_active", lambda _: False)
    monkeypatch.setattr(m, "port_open", lambda _: False)
    monkeypatch.setattr(m, "remove_matching_ca", lambda *_a, **_k: None)
    with pytest.raises(SystemExit) as outcome:
        (m.task_proxy_recover if recovery else m.task_proxy_finish)(args)
    assert outcome.value.code == 0, capsys.readouterr().out
    assert m.proxy_row(c, args) is None
    db_path = home / ".local/share/ghost/proxy-store/proxy_store.sqlite"
    assert db_path.is_file()
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700
    with sqlite3.connect(db_path) as index:
        assert index.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
