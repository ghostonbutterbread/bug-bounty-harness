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
    assert result["profile_dir"].endswith("/demo/ghost/chromium-test/profiles/runs/run-123")
    assert result["cleanup_command"][1] == "cleanup-profile"
    assert result["cleanup_command"][-2].endswith("/demo/ghost/chromium-test/profiles/runs/run-123")


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
