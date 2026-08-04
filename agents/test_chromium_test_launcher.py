from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


def load_launcher_module():
    root = Path(__file__).resolve().parents[1]
    launcher = root / "skills" / "chromium-test" / "scripts" / "chromium_test.py"
    spec = importlib.util.spec_from_file_location("chromium_test_launcher", launcher)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_command_includes_remote_allow_origins(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server=None,
        remote_allow_origins="*",
        url="https://target.example/",
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--remote-debugging-address=127.0.0.1" in command
    assert "--remote-allow-origins=*" in command
    assert command[-1] == "https://target.example/"


def test_build_command_allows_custom_remote_allow_origins(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server=None,
        remote_allow_origins="http://127.0.0.1:9223",
        url=None,
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--remote-allow-origins=http://127.0.0.1:9223" in command
    assert command[-1] == "about:blank"


def test_build_command_proxy_does_not_ignore_cert_by_default(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server="http://127.0.0.1:8081",
        remote_allow_origins="*",
        url=None,
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--proxy-server=http://127.0.0.1:8081" in command
    assert "--ignore-certificate-errors" not in command


def test_build_command_allows_explicit_cert_ignore(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server="http://127.0.0.1:8081",
        remote_allow_origins="*",
        url=None,
        ignore_certificate_errors=True,
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--ignore-certificate-errors" in command


def test_prepare_profile_ca_reports_missing_certutil(monkeypatch, tmp_path):
    module = load_launcher_module()
    monkeypatch.setitem(module.prepare_profile_ca.__globals__, "certutil_path", lambda: None)

    result = module.prepare_profile_ca(tmp_path, tmp_path / "mitmproxy-ca-cert.pem")

    assert result["status"] == "missing-certutil"


def test_auto_cert_mode_falls_back_to_explicit_ignore_when_import_unavailable(
    monkeypatch, tmp_path, capsys
):
    module = load_launcher_module()
    launched = {}

    class FakeProcess:
        pid = 12345

    def fake_popen(command, **kwargs):
        launched["command"] = command
        launched["env"] = kwargs.get("env", {})
        return FakeProcess()

    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "prepare_profile_ca", lambda *args, **kwargs: {"status": "missing-certutil"})
    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--profile-dir",
            str(tmp_path / "profile"),
            "--proxy-server",
            "http://127.0.0.1:8081",
            "--proxy-cert-mode",
            "auto",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["proxy_cert_status"]["status"] == "missing-certutil"
    assert "--ignore-certificate-errors" in launched["command"]


def test_import_cert_mode_fails_closed_when_import_unavailable(monkeypatch, tmp_path):
    module = load_launcher_module()
    popen_called = False

    def fake_popen(*_args, **_kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("Chromium should not launch when required CA import fails")

    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "prepare_profile_ca", lambda *args, **kwargs: {"status": "missing-certutil"})
    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--profile-dir",
            str(tmp_path / "profile"),
            "--proxy-server",
            "http://127.0.0.1:8081",
            "--proxy-cert-mode",
            "import",
        ],
    )

    try:
        module.main()
    except SystemExit as exc:
        assert "Could not import proxy CA" in str(exc)
    else:
        raise AssertionError("Expected SystemExit when required CA import fails")
    assert popen_called is False


def test_ephemeral_profile_dry_run_includes_cleanup_command(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--run-id",
            "run-123",
            "--ephemeral-profile",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["profile_lifetime"] == "ephemeral"
    assert result["profile_dir"].endswith("/demo/web/browser-profiles/runs/run-123")
    assert result["profile_dir"].startswith("/mnt/bounty/")
    assert result["cleanup_command"][1] == "cleanup-profile"
    assert result["cleanup_command"][-2].endswith("/demo/web/browser-profiles/runs/run-123")


def test_launcher_defaults_to_mitm_route_only(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "current_runtime", lambda: "ghostonbread")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    dumped = json.dumps(result)
    assert result["proxy_server"] == "http://hoster:8080"
    assert "--proxy-server=http://hoster:8080" in result["command"]
    assert result["mitm_proxy"]["status"] == "configured"
    assert "mcp_url" not in result
    assert "caido_profile" not in result
    assert "caido" not in dumped.lower()
    assert "mcp" not in dumped.lower()


def test_auth_seed_requires_owner_only_permissions(tmp_path):
    module = load_launcher_module()
    seed = tmp_path / "auth.json"
    seed.write_text(json.dumps({"account_label": "qa-user", "cookie": "secret-cookie"}))
    os.chmod(seed, 0o644)

    try:
        module.auth_seed_metadata(str(seed))
    except SystemExit as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("Expected loose auth seed permissions to be rejected")


def test_auth_seed_metadata_does_not_return_secret_values(tmp_path):
    module = load_launcher_module()
    seed = tmp_path / "auth.json"
    seed.write_text(
        json.dumps(
            {
                "account_label": "qa-user",
                "session_source": "manual-refresh",
                "cookie": "session=secret-cookie",
                "authorization": "Bearer secret-token",
            }
        )
    )
    os.chmod(seed, 0o600)

    result = module.auth_seed_metadata(str(seed))

    dumped = json.dumps(result)
    assert result["status"] == "loaded"
    assert result["safe_metadata"]["account_label"] == "qa-user"
    assert "cookie" in result["secret_fields_present"]
    assert "authorization" in result["secret_fields_present"]
    assert "secret-cookie" not in dumped
    assert "secret-token" not in dumped


def test_auth_seed_dry_run_starts_blank_before_secret_navigation(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    seed = tmp_path / "auth.json"
    seed.write_text(
        json.dumps(
            {
                "account_label": "qa-user",
                "session_source": "smoke",
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie",
                        "domain": "portswigger.net",
                        "path": "/",
                        "secure": True,
                    }
                ],
                "headers": {"Authorization": "Bearer secret-token"},
            }
        )
    )
    os.chmod(seed, 0o600)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--auth-seed-file",
            str(seed),
            "--url",
            "https://portswigger.net/web-security/os-command-injection/lab-simple",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["account"] == "qa-user"
    assert result["session_source"] == "smoke"
    assert result["auth_seed"]["cookie_count"] == 1
    assert result["auth_seed"]["header_names"] == ["Authorization"]
    assert result["auth_application"]["status"] == "dry-run"
    assert result["command"][-1] == "about:blank"
    assert "secret-cookie" not in output
    assert "secret-token" not in output


def test_account_color_resolves_locked_down_auth_seed(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    shared = tmp_path / "shared"
    seed_dir = tmp_path / "secure-auth"
    seed_dir.mkdir()
    seed = seed_dir / "blue.json"
    seed.write_text(
        json.dumps(
            {
                "account_label": "blue-primary",
                "session_source": "manual-refresh",
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie",
                        "domain": "target.example",
                        "path": "/",
                    }
                ],
                "headers": {"Authorization": "Bearer secret-token"},
            }
        )
    )
    os.chmod(seed, 0o600)
    inventory = shared / "demo" / "credentials" / "account_inventory.json"
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        json.dumps(
            {
                "program": "demo",
                "accounts": [
                    {
                        "alias": "blue-primary",
                        "pwnfox_color": "blue",
                        "role": "user",
                        "credential_ref": f"auth-seed:{seed}",
                        "auth_refresh_source": "ryushe-proxy",
                        "auth_refresh_hint": "pwnfox:blue",
                    }
                ],
                "pwnfox_lanes": [{"color": "blue", "account": "blue-primary"}],
            }
        )
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--account",
            "blue",
            "--url",
            "https://target.example/app",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["account"] == "blue-primary"
    assert result["account_resolution"]["status"] == "resolved"
    assert result["account_resolution"]["matched_by"] == "pwnfox_color"
    assert result["account_resolution"]["account_alias"] == "blue-primary"
    assert result["account_resolution"]["credential_ref_type"] == "auth-seed"
    assert result["account_resolution"]["auth_refresh_source"] == "ryushe-proxy"
    assert result["account_resolution"]["auth_refresh_hint"] == "pwnfox:blue"
    assert result["auth_seed"]["status"] == "loaded"
    assert result["auth_seed"]["cookie_count"] == 1
    assert result["command"][-1] == "about:blank"
    assert "secret-cookie" not in output
    assert "secret-token" not in output


def test_missing_account_auth_seed_returns_fallback_plan(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    shared = tmp_path / "shared"
    missing_seed = tmp_path / "secure-auth" / "blue.json"
    inventory = shared / "demo" / "credentials" / "account_inventory.json"
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        json.dumps(
            {
                "program": "demo",
                "accounts": [
                    {
                        "alias": "blue-primary",
                        "pwnfox_color": "blue",
                        "credential_ref": f"auth-seed:{missing_seed}",
                        "auth_refresh_source": "ryushe-proxy",
                        "auth_refresh_hint": "pwnfox:blue",
                    }
                ],
                "pwnfox_lanes": [{"color": "blue", "account": "blue-primary"}],
            }
        )
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--account",
            "blue",
            "--no-auth-auto-refresh",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["auth_seed"]["status"] == "unusable"
    assert result["auth_next_step"]["status"] == "needs-auth"
    assert result["auth_next_step"]["auth_refresh_source"] == "ryushe-proxy"
    assert "try ryushe-proxy" in result["auth_next_step"]["steps"][0]
    assert any("bitwarden fallback" in step for step in result["auth_next_step"]["steps"])
    assert any("agent MITM lane" in step for step in result["auth_next_step"]["steps"])


def test_missing_account_auth_seed_auto_refreshes_with_resolver(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    shared = tmp_path / "shared"
    refreshed_seed = tmp_path / "secure-auth" / "blue.json"
    inventory = shared / "demo" / "credentials" / "account_inventory.json"
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        json.dumps(
            {
                "program": "demo",
                "accounts": [
                    {
                        "alias": "blue-primary",
                        "pwnfox_color": "blue",
                        "auth_refresh_source": "ryushe-proxy",
                        "auth_refresh_hint": "pwnfox:blue",
                    }
                ],
            }
        )
    )

    def fake_run(command, **_kwargs):
        refreshed_seed.parent.mkdir(parents=True)
        refreshed_seed.write_text(json.dumps({"account_label": "blue-primary", "cookies": []}))
        os.chmod(refreshed_seed, 0o600)
        return module.subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "status": "refreshed",
                    "auth_seed": {"path": str(refreshed_seed)},
                    "proxy_provenance": {"request_id": 123, "cookie_count": 0},
                    "host_filter": "example.test",
                }
            ),
            stderr="",
        )

    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--account",
            "blue",
            "--url",
            "https://app.example.test/account",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["account_resolution"]["auth_auto_refresh"]["status"] == "refreshed"
    assert result["auth_seed"]["status"] == "loaded"
    assert result["auth_seed"]["path"] == str(refreshed_seed)


def test_bitwarden_account_ref_returns_bitwarden_fallback_plan(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    shared = tmp_path / "shared"
    inventory = shared / "demo" / "credentials" / "account_inventory.json"
    inventory.parent.mkdir(parents=True)
    inventory.write_text(
        json.dumps(
            {
                "program": "demo",
                "accounts": [
                    {
                        "alias": "cyan-primary",
                        "pwnfox_color": "cyan",
                        "credential_ref": "bitwarden:demo-cyan-primary",
                    }
                ],
            }
        )
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py",
            "demo",
            "smoke",
            "--account",
            "cyan",
            "--dry-run",
            "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["account_resolution"]["credential_ref_type"] == "bitwarden"
    assert result["auth_seed"]["status"] == "none"
    assert result["auth_next_step"]["status"] == "needs-auth"
    assert result["auth_next_step"]["steps"] == [
        "load bitwarden and use the recorded Bitwarden item reference"
    ]


def test_hoster_default_proxy_prefers_synced_hoster_ca(monkeypatch, tmp_path):
    module = load_launcher_module()
    synced_ca = tmp_path / "mitmproxy-ca-cert.pem"
    synced_ca.write_text("fake-ca")
    monkeypatch.setattr(module, "DEFAULT_HOSTER_CA_CERT", synced_ca)

    result = module.resolve_mitm_ca_cert(
        str(module.DEFAULT_CA_CERT),
        "http://hoster:8080",
    )

    assert result == synced_ca


def test_explicit_mitm_ca_is_not_overridden_for_hoster_proxy(monkeypatch, tmp_path):
    module = load_launcher_module()
    synced_ca = tmp_path / "synced-ca.pem"
    explicit_ca = tmp_path / "explicit-ca.pem"
    synced_ca.write_text("synced")
    explicit_ca.write_text("explicit")
    monkeypatch.setattr(module, "DEFAULT_HOSTER_CA_CERT", synced_ca)

    result = module.resolve_mitm_ca_cert(str(explicit_ca), "http://hoster:8080")

    assert result == explicit_ca


def test_hoster_launch_rejects_ssh_service_cgroup(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "current_cgroup_text", lambda: "0::/system.slice/ssh.service/session-42.scope")

    try:
        module.assert_hoster_workload_isolated("hoster")
    except SystemExit as exc:
        assert "hoster-ssh" in str(exc)
    else:
        raise AssertionError("Hoster Chromium launch was allowed from ssh.service")


def test_supervise_browser_waits_for_the_recorded_chromium_process():
    module = load_launcher_module()

    class FakeProcess:
        def wait(self):
            return 7

    assert module.wait_for_browser_if_requested(FakeProcess(), supervise=True) == 7
    assert module.wait_for_browser_if_requested(FakeProcess(), supervise=False) == 0


def load_kasmvnc_session_module():
    root = Path(__file__).resolve().parents[1]
    helper = root / "skills" / "chromium-test" / "scripts" / "kasmvnc_session.py"
    spec = importlib.util.spec_from_file_location("kasmvnc_session", helper)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_kasmvnc_start_uses_dedicated_display_loopback_and_requested_web_port(monkeypatch, tmp_path):
    module = load_kasmvnc_session_module()
    launched = {}

    def fake_popen(command, **kwargs):
        launched["command"] = command
        class FakeProcess:
            def poll(self):
                return None
            def terminate(self):
                return None
        return FakeProcess()

    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(module, "wait_for_web_listener", lambda _port: True)

    result = module.start_session(display=20, web_port=8463, state_dir=tmp_path)

    assert launched["command"] == [
        "vncserver",
        ":20",
        "-geometry",
        "1400x900",
        "-depth",
        "24",
        "-noxstartup",
        "-fg",
        "-interface",
        "127.0.0.1",
        "-websocketPort",
        "8463",
    ]
    assert result["display"] == ":20"
    assert result["web_url"] == "http://127.0.0.1:8463/"
    assert result["listener_host"] == "127.0.0.1"
    assert (tmp_path / "display-20.json").exists()


def test_kasmvnc_status_reports_only_a_live_loopback_web_listener(monkeypatch, tmp_path):
    module = load_kasmvnc_session_module()
    state = tmp_path / "display-20.json"
    state.write_text(json.dumps({"display": 20, "web_port": 8463}))
    monkeypatch.setattr(module, "can_connect_localhost", lambda port: port == 8463)

    result = module.session_status(display=20, state_dir=tmp_path)

    assert result == {
        "display": ":20",
        "listener_host": "127.0.0.1",
        "status": "ready",
        "web_port": 8463,
        "web_url": "http://127.0.0.1:8463/",
    }


def test_kasmvnc_start_reports_a_clean_error_when_vncserver_is_not_installed(monkeypatch, tmp_path):
    module = load_kasmvnc_session_module()

    def missing_vncserver(*_args, **_kwargs):
        raise FileNotFoundError("vncserver")

    monkeypatch.setattr(module.subprocess, "run", missing_vncserver)

    try:
        module.start_session(display=20, web_port=8463, state_dir=tmp_path)
    except module.KasmVNCSessionError as exc:
        assert str(exc) == "vncserver executable was not found"
    else:
        raise AssertionError("Expected a clean KasmVNC startup error")


def test_explicit_kasmvnc_backend_starts_session_and_passes_display_to_chromium(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    launched = {}

    class FakeProcess:
        pid = 12345

    def fake_popen(command, **kwargs):
        launched["command"] = command
        launched["env"] = kwargs["env"]
        return FakeProcess()

    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "prepare_profile_ca", lambda *args, **kwargs: {"status": "trusted"})
    monkeypatch.setattr(module, "start_kasmvnc_session", lambda **kwargs: {
        "display": ":20",
        "listener_host": "127.0.0.1",
        "status": "ready",
        "web_port": 8463,
        "web_url": "http://127.0.0.1:8463/",
    })
    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py", "demo", "manual", "--profile-dir", str(tmp_path / "profile"),
            "--display-backend", "kasmvnc", "--kasmvnc-display", "20", "--kasmvnc-web-port", "8463", "--json",
        ],
    )

    assert module.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert launched["env"]["DISPLAY"] == ":20"
    assert result["display_backend"] == "kasmvnc"
    assert result["kasmvnc"]["web_url"] == "http://127.0.0.1:8463/"
    assert result["cdp_url"] == "http://127.0.0.1:9444"


def test_kasmvnc_is_not_started_when_auth_validation_blocks_browser_launch(monkeypatch, tmp_path, capsys):
    module = load_launcher_module()
    kasmvnc_started = False

    def fake_start(**_kwargs):
        nonlocal kasmvnc_started
        kasmvnc_started = True
        raise AssertionError("KasmVNC should not start before auth validation succeeds")

    missing_seed = tmp_path / "missing-auth.json"
    monkeypatch.setattr(module, "pick_port", lambda requested=None: 9444)
    monkeypatch.setattr(module, "start_kasmvnc_session", fake_start)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "chromium_test.py", "demo", "manual", "--profile-dir", str(tmp_path / "profile"),
            "--auth-seed-file", str(missing_seed), "--display-backend", "kasmvnc", "--json",
        ],
    )

    assert module.main() == 2

    assert kasmvnc_started is False
    assert json.loads(capsys.readouterr().out)["auth_seed"]["status"] == "unusable"
