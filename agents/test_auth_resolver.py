from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from agents.auth_seed_health import parse_utc


def load_resolver_module():
    root = Path(__file__).resolve().parents[1]
    resolver = root / "skills" / "account-management" / "scripts" / "auth_resolver.py"
    # The resolver imports its sibling inventory_paths module; do not depend on
    # another test file having put the scripts directory on sys.path first.
    if str(resolver.parent) not in sys.path:
        sys.path.insert(0, str(resolver.parent))
    spec = importlib.util.spec_from_file_location("auth_resolver", resolver)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_inventory(shared: Path, program: str, inventory: dict) -> Path:
    path = shared / program / "credentials" / "account_inventory.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inventory))
    return path


def write_route_table(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "default_lane": "agent",
                "runtimes": {
                    "openclaw": {
                        "browser_proxy": "http://hoster:8080",
                        "caido_mcp": "http://hoster:3333/mcp",
                        "lane": "agent",
                        "ryushe_proxy_mode": "hoster-ssh",
                    },
                    "hoster": {
                        "browser_proxy": "http://localhost:8080",
                        "caido_mcp": "http://localhost:3333/mcp",
                        "lane": "agent",
                        "ryushe_proxy_mode": "direct",
                        "ryushe_proxy_mcp": "http://ryushespc:3333/mcp",
                    },
                },
            }
        )
    )


def test_route_openclaw_uses_hoster_ssh(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "openclaw")

    assert module.main(["route", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["runtime"] == "openclaw"
    assert result["ryushe_proxy_mode"] == "hoster-ssh"
    assert result["agent_proxy_server"] == "http://hoster:8080"
    assert result["can_query_ryushe_proxy"] is True


def test_program_auth_check_contract_selects_saved_endpoint_and_method(monkeypatch):
    module = load_resolver_module()
    account = {
        "auth_check": {
            "url": "https://api.example.test/session",
            "method": "POST",
        },
        "auth_check_url": "https://legacy.example.test/me",
    }

    target = module.auth_check_target(account, target_url=None, method_override=None)

    assert target == {"url": "https://api.example.test/session", "method": "POST"}
    assert module.host_filter_from_auth_target(target) == "api.example.test"
    assert module.build_pwnfox_httpql("blue", "api.example.test", request_path="/session") == (
        'req.raw.cont:"X-PwnFox-Color" AND req.raw.cont:"blue" AND '
        'req.host.cont:"api.example.test" AND req.path.cont:"/session"'
    )


def test_resolve_uses_program_auth_check_contract(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    seed = tmp_path / "seeds" / "blue.json"
    seed.parent.mkdir()
    seed.write_text(json.dumps({"headers": {"X-App-Session": "[test]"}}))
    os.chmod(seed, 0o600)
    write_route_table(route_table)
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_seed_ref": f"auth-seed:{seed}",
        "auth_check": {"url": "https://api.example.test/session", "method": "POST"},
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    observed = {}
    def fake_check(url, method, timeout, seed_path):
        observed.update(url=url, method=method, seed_path=seed_path)
        return {"status": "passed", "url": url, "method": method, "status_code": 200}
    monkeypatch.setattr(module, "run_auth_check", fake_check)

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--route-table", str(route_table)]) == 0

    assert observed["url"] == "https://api.example.test/session"
    assert observed["method"] == "POST"
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_shared_base_defaults_to_canonical_web_bounty(monkeypatch):
    module = load_resolver_module()
    monkeypatch.delenv("HARNESS_SHARED_BASE", raising=False)

    assert module.shared_base() == Path.home() / "Shared" / "web_bounty"


def test_route_hoster_uses_direct_ryushe_proxy(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "hoster")

    assert module.main(["route", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["runtime"] == "hoster"
    assert result["ryushe_proxy_mode"] == "direct"
    assert result["ryushe_proxy_endpoint"] == "http://ryushespc:3333/mcp"
    assert result["agent_proxy_server"] == "http://localhost:8080"


def test_retired_inventory_fails_loudly(tmp_path, monkeypatch):
    module = load_resolver_module()
    shared = tmp_path / "legacy"
    write_inventory(shared, "demo", {"status": "retired", "replaced_by": "/shared/bounty_web/demo/credentials/account_inventory.json"})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    try:
        module.load_inventory("demo")
    except SystemExit as exc:
        assert "retired" in str(exc)
        assert "bounty_web" in str(exc)
    else:
        raise AssertionError("retired account inventory was accepted")


def test_resolve_blue_missing_seed_returns_proxy_refresh_plan(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    seed = tmp_path / "seeds" / "blue.json"
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "accounts": [
                {
                    "alias": "blue-primary",
                    "email": "ryushe+blue@example.com",
                    "pwnfox_color": "blue",
                    "auth_seed_ref": f"auth-seed:{seed}",
                    "auth_refresh_source": "ryushe-proxy",
                    "auth_refresh_hint": "pwnfox:blue",
                }
            ],
            "pwnfox_lanes": [{"color": "blue", "account": "blue-primary"}],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "openclaw")

    assert module.main(
        [
            "resolve",
            "--program",
            "demo",
            "--account",
            "blue",
            "--route-table",
            str(route_table),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "needs-proxy-refresh-adapter"
    assert result["account_resolution"]["matched_by"] == "pwnfox_color"
    assert result["auth_seed"]["status"] == "missing"
    assert result["proxy_refresh"]["ryushe_proxy_mode"] == "hoster-ssh"
    assert result["proxy_refresh"]["auth_refresh_hint"] == "pwnfox:blue"
    assert "ryushe+blue@example.com" in json.dumps(result)
    assert "secret" not in json.dumps(result).lower()


def test_resolve_integration_profile_returns_designated_owned_account(tmp_path, monkeypatch):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    write_inventory(
        shared,
        "demo",
        {
            "integration_profile": {"account": "social-hub", "status": "active"},
            "accounts": [{"alias": "social-hub", "lifecycle": "active", "credential_ref": "bitwarden:owned-social-hub"}],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    result = module.resolve_account(module.load_inventory("demo"), "integration-profile", "demo")

    assert result["status"] == "resolved"
    assert result["matched_by"] == "integration_profile"
    assert result["account"]["alias"] == "social-hub"


def test_integration_profile_selector_fails_closed_for_alias_collision_or_inactive_account(tmp_path, monkeypatch):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    write_inventory(shared, "demo", {"accounts": [{"alias": "integration-profile", "lifecycle": "active"}]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    collision = module.resolve_account(module.load_inventory("demo"), "integration-profile", "demo")
    assert collision["status"] == "integration-profile-unavailable"

    write_inventory(
        shared,
        "demo",
        {
            "integration_profile": {"account": "social-hub", "status": "active"},
            "accounts": [
                {"alias": "social-hub", "lifecycle": "active"},
                {"alias": "integration-profile", "lifecycle": "active"},
            ],
        },
    )
    configured_collision = module.resolve_account(module.load_inventory("demo"), "integration-profile", "demo")
    assert configured_collision["status"] == "integration-profile-unavailable"

    write_inventory(
        shared,
        "demo",
        {
            "integration_profile": {"account": "social-hub", "status": "active"},
            "accounts": [{"alias": "social-hub", "lifecycle": "inactive"}],
        },
    )
    inactive = module.resolve_account(module.load_inventory("demo"), "integration-profile", "demo")
    assert inactive["status"] == "integration-profile-unavailable"

    write_inventory(
        shared,
        "demo",
        {
            "integration_profile": {"account": "social-hub", "status": "active"},
            "accounts": [
                {"alias": "social-hub", "lifecycle": "active"},
                {"alias": "SOCIAL-HUB", "lifecycle": "active"},
            ],
        },
    )
    ambiguous = module.resolve_account(module.load_inventory("demo"), "integration-profile", "demo")
    assert ambiguous["status"] == "integration-profile-unavailable"


def test_browser_bound_program_never_queries_ryushe_proxy(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "auth_session_mode": "browser-bound",
            "accounts": [
                {
                    "alias": "blue-primary",
                    "pwnfox_color": "blue",
                    "auth_refresh_source": "ryushe-proxy",
                }
            ],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    def must_not_query(*_args, **_kwargs):
        raise AssertionError("browser-bound session attempted Ryushe-proxy lookup")

    monkeypatch.setattr(module, "query_proxy_seed", must_not_query)
    assert module.main(
        ["resolve", "--program", "demo", "--account", "blue", "--refresh", "--route-table", str(route_table)]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "needs-browser-handoff"
    assert result["auth_session_mode"] == "browser-bound"
    assert result["proxy_refresh"]["status"] == "not-permitted"
    assert result["auth_check"]["status"] == "not-run"


def test_unknown_session_mode_fails_closed_to_browser_handoff(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "auth_session_mode": "unknown",
            "accounts": [{"alias": "blue-primary", "pwnfox_color": "blue", "auth_refresh_source": "ryushe-proxy"}],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    assert module.main(
        ["resolve", "--program", "demo", "--account", "blue", "--refresh", "--route-table", str(route_table)]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "needs-browser-handoff"
    assert result["auth_session_mode"] == "unknown"
    assert result["proxy_refresh"]["status"] == "not-permitted"


def test_resolve_bitwarden_ref_returns_bitwarden_plan(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "accounts": [
                {
                    "alias": "cyan-primary",
                    "email": "ryushe+cyan@example.com",
                    "pwnfox_color": "cyan",
                    "credential_ref": "bitwarden:demo-cyan-primary",
                }
            ],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "hoster")

    assert module.main(
        [
            "resolve",
            "--program",
            "demo",
            "--account",
            "cyan",
            "--route-table",
            str(route_table),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "needs-bitwarden"
    assert result["account"]["credential_ref_type"] == "bitwarden"
    assert result["bitwarden"]["status"] == "available"
    assert result["proxy_refresh"]["status"] == "not-permitted"


def test_resolve_available_seed_without_url_returns_safe_metadata(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    seed = tmp_path / "seeds" / "blue.json"
    seed.parent.mkdir()
    seed.write_text(
        json.dumps(
            {
                "account_label": "blue-primary",
                "session_source": "manual",
                "headers": {"Authorization": "Bearer should-not-print"},
                "cookies": [{"name": "session", "value": "cookie-should-not-print"}],
            }
        )
    )
    os.chmod(seed, 0o600)
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "accounts": [
                {
                    "alias": "blue-primary",
                    "pwnfox_color": "blue",
                    "auth_seed_ref": f"auth-seed:{seed}",
                }
            ],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    assert module.main(
        [
            "resolve",
            "--program",
            "demo",
            "--account",
            "blue",
            "--route-table",
            str(route_table),
        ]
    ) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["auth_seed"]["status"] == "available"
    assert result["auth_seed"]["cookie_count"] == 1
    assert result["auth_seed"]["header_names"] == ["Authorization"]
    assert "should-not-print" not in output


def test_proxy_refresh_fetches_full_request_by_id_after_sanitized_discovery(monkeypatch):
    module = load_resolver_module()
    calls = []

    def response(payload):
        return {"result": {"content": [{"text": json.dumps(payload)}]}}

    def fake_mcp(_endpoint, tool_name, arguments, timeout=12.0):
        calls.append((tool_name, arguments))
        if tool_name == "list_requests":
            return response({"items": [{"id": "42", "request": {"host": "api.example.test"}}]})
        assert tool_name == "get_requests_by_ids"
        assert arguments["ids"] == ["42"]
        return response({"results": [{"id": "42", "item": {"id": "42", "request": {
            "id": "42", "host": "api.example.test", "path": "/me",
            "headers": {"Authorization": "Bearer test-only", "X-PwnFox-Color": "blue"},
        }}}]})

    monkeypatch.setattr(module, "mcp_call", fake_mcp)
    items = module.list_proxy_requests(
        "http://proxy.invalid/mcp", "blue", "api.example.test", "/me", 5, ["authorization"]
    )

    assert items[0]["request"]["headers"]["Authorization"] == "Bearer test-only"
    assert [call[0] for call in calls] == ["list_requests", "get_requests_by_ids"]
    assert calls[0][1]["fields"] == ["id", "request.host", "request.path", "request.method", "request.created_at"]
    assert 'req.raw.cont:"Authorization:"' in calls[0][1]["filter"]


def test_proxy_refresh_rejects_detail_with_mismatched_request_id(monkeypatch):
    module = load_resolver_module()

    def response(payload):
        return {"result": {"content": [{"text": json.dumps(payload)}]}}

    def fake_mcp(_endpoint, tool_name, _arguments, timeout=12.0):
        if tool_name == "list_requests":
            return response({"items": [{"id": "42", "request": {"host": "api.example.test"}}]})
        return response({"results": [{"id": "other", "item": {"id": "other", "request": {
            "headers": {"Authorization": "Bearer wrong-request"},
        }}}]})

    monkeypatch.setattr(module, "mcp_call", fake_mcp)
    assert module.list_proxy_requests("http://proxy.invalid/mcp", "blue", "api.example.test", "/me", 1) == []


def test_seed_from_proxy_items_extracts_cookie_and_auth_headers():
    module = load_resolver_module()
    result = module.seed_from_proxy_items(
        [
            {
                "request": {
                    "id": 123,
                    "url": "https://app.example.test/account",
                    "host": "app.example.test",
                    "path": "/account",
                    "created_at": "2026-06-23T18:00:00Z",
                    "headers": {
                        "Cookie": ["sid=secret-session; theme=light"],
                        "X-PwnFox-Color": ["blue"],
                        "Authorization": ["Bearer secret-token"],
                        "X-Bugcrowd-Username": ["researcher@example.test"],
                        "User-Agent": ["browser"],
                    },
                }
            }
        ],
        {"alias": "blue", "pwnfox_color": "blue"},
        "blue",
        "demo",
    )

    assert result["status"] == "found"
    assert result["seed"]["cookies"][0]["name"] == "sid"
    assert result["seed"]["cookies"][0]["value"] == "secret-session"
    assert result["seed"]["headers"] == {
        "Authorization": "Bearer secret-token",
        "X-Bugcrowd-Username": "researcher@example.test",
        "User-Agent": "browser",
    }
    assert result["provenance"]["cookie_count"] == 2
    assert result["provenance"]["header_names"] == ["Authorization", "User-Agent", "X-Bugcrowd-Username"]


def test_refresh_from_ryushe_proxy_writes_locked_seed_and_updates_inventory(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    write_inventory(
        shared,
        "demo",
        {
            "accounts": [
                {
                    "alias": "blue",
                    "pwnfox_color": "blue",
                    "auth_refresh_source": "ryushe-proxy",
                    "auth_refresh_hint": "pwnfox:blue",
                }
            ],
        },
    )
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "openclaw")

    def fake_query_proxy_seed(route, account, color, program, host_filter, request_path, required_headers, limit):
        assert required_headers == []
        assert request_path is None
        return {
            "status": "found",
            "seed": {
                "account_label": account["alias"],
                "pwnfox_color": color,
                "program": program,
                "session_source": "ryushe-proxy",
                "cookies": [{"name": "sid", "value": "secret-session", "url": "https://app.example.test/"}],
                "headers": {"Authorization": "Bearer secret-token"},
            },
            "provenance": {
                "request_id": 123,
                "host": "app.example.test",
                "path": "/account",
                "cookie_count": 1,
                "header_names": ["Authorization"],
            },
        }

    monkeypatch.setattr(module, "query_proxy_seed", fake_query_proxy_seed)

    assert module.main(
        [
            "refresh-from-ryushe-proxy",
            "--program",
            "demo",
            "--account",
            "blue",
            "--host-filter",
            "example.test",
            "--route-table",
            str(route_table),
        ]
    ) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    seed_path = shared / "demo" / "credentials" / "auth_seeds" / "blue.json"
    inventory = json.loads((shared / "demo" / "credentials" / "account_inventory.json").read_text())
    assert result["status"] == "refreshed"
    assert result["auth_seed"]["path"] == str(seed_path)
    assert result["auth_seed"]["cookie_count"] == 1
    assert result["auth_seed"]["header_names"] == ["Authorization"]
    assert oct(seed_path.stat().st_mode & 0o777) == "0o600"
    assert inventory["accounts"][0]["auth_seed_ref"] == f"auth-seed:{seed_path}"
    assert "secret-session" not in output
    assert "secret-token" not in output


def test_write_auth_seed_is_private_before_writing(monkeypatch, tmp_path):
    seed_path = tmp_path / "credentials" / "seed.json"
    module = load_resolver_module()
    original_dump = module.json.dump

    def check_mode_during_write(value, handle, *args, **kwargs):
        assert stat.S_IMODE(os.fstat(handle.fileno()).st_mode) == 0o600
        return original_dump(value, handle, *args, **kwargs)

    monkeypatch.setattr(module.json, "dump", check_mode_during_write)
    previous = os.umask(0)
    try:
        module.write_auth_seed(seed_path, {"cookies": [{"value": "fixture-only"}]})
    finally:
        os.umask(previous)
    assert stat.S_IMODE(seed_path.stat().st_mode) == 0o600
    assert json.loads(seed_path.read_text())["cookies"][0]["value"] == "fixture-only"


def test_write_auth_seed_refuses_existing_insecure_file_without_mutating_it(tmp_path):
    module = load_resolver_module()
    seed_path = tmp_path / "seed.json"
    seed_path.write_text('{"cookies": []}')
    seed_path.chmod(0o664)
    with pytest.raises(SystemExit, match="verify ownership and contents.*0600"):
        module.write_auth_seed(seed_path, {"cookies": [{"value": "new"}]})
    assert seed_path.read_text() == '{"cookies": []}'
    assert stat.S_IMODE(seed_path.stat().st_mode) == 0o664
    assert list(tmp_path.iterdir()) == [seed_path]


def test_write_auth_seed_refuses_symlink_destination(tmp_path):
    module = load_resolver_module()
    target = tmp_path / "target.json"
    target.write_text("original")
    link = tmp_path / "seed.json"
    link.symlink_to(target)
    with pytest.raises(SystemExit, match="not an owned regular file"):
        module.write_auth_seed(link, {"cookies": []})
    assert link.is_symlink() and target.read_text() == "original"



SYNTHETIC_SECRETS = ("synthetic-cookie-value", "synthetic-bearer-value")


def seed_file(tmp_path: Path, data: dict) -> Path:
    seed = tmp_path / "seeds" / "blue.json"
    seed.parent.mkdir(exist_ok=True)
    seed.write_text(json.dumps(data))
    os.chmod(seed, 0o600)
    return seed


def read_account(shared: Path) -> dict:
    return json.loads((shared / "demo" / "credentials" / "account_inventory.json").read_text())["accounts"][0]


def assert_no_secrets(*texts: str) -> None:
    for text in texts:
        for secret in SYNTHETIC_SECRETS:
            assert secret not in text


def test_refresh_records_captured_at_in_seed_and_unverified_status_in_inventory(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_refresh_source": "ryushe-proxy",
        "auth_seed_status": {"captured_at": "2026-10-22T00:00:00+00:00", "auth_material": "present",
                             "last_verified_at": "2026-10-22T00:00:00+00:00", "last_verified_result": "expired"},
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "openclaw")
    monkeypatch.setattr(module, "query_proxy_seed", lambda *_args: {"status": "found", "seed": {
        "account_label": "blue", "session_source": "ryushe-proxy",
        "cookies": [{"name": "sid", "value": "synthetic-cookie-value"}],
        "headers": {"Authorization": "synthetic-bearer-value", "User-Agent": "browser"},
    }, "provenance": {}})

    assert module.main(["refresh-from-ryushe-proxy", "--program", "demo", "--account", "blue",
                        "--host-filter", "example.test", "--route-table", str(route_table)]) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    seed_path = shared / "demo" / "credentials" / "auth_seeds" / "blue.json"
    captured_at = json.loads(seed_path.read_text())["captured_at"]
    status = read_account(shared)["auth_seed_status"]
    assert parse_utc(captured_at) is not None
    assert status == {"captured_at": captured_at, "auth_material": "present", "replayable_cookie_count": 1,
                      "auth_header_names": ["Authorization"]}
    assert result["auth_seed_usability"]["state"] == "unverified"
    assert result["auth_seed_usability"]["reasons"] == ["never-verified"]
    assert_no_secrets(output, (shared / "demo" / "credentials" / "account_inventory.json").read_text())


def test_refresh_refuses_proxy_seed_without_auth_material_and_keeps_existing_seed(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    existing = seed_file(tmp_path, {"cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_refresh_source": "ryushe-proxy",
        "auth_seed_ref": f"auth-seed:{existing}",
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setenv("GHOST_AGENT_RUNTIME", "openclaw")
    monkeypatch.setattr(module, "query_proxy_seed", lambda *_args: {"status": "found", "seed": {
        "cookies": [], "headers": {"User-Agent": "browser", "Accept": "*/*"},
    }, "provenance": {}})
    before = existing.read_text()

    assert module.main(["refresh-from-ryushe-proxy", "--program", "demo", "--account", "blue",
                        "--host-filter", "example.test", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "no-matching-proxy-auth"
    assert result["proxy_query"]["status"] == "no-replayable-auth-material"
    assert existing.read_text() == before
    assert "auth_seed_status" not in read_account(shared)


def test_resolve_records_failed_liveness_as_stale_without_printing_secrets(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    seed = seed_file(tmp_path, {"captured_at": "2026-10-22T08:00:00Z",
                                "cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_seed_ref": f"auth-seed:{seed}",
        "auth_check": {"url": "https://api.example.test/v1/me?sig=abc", "method": "GET"},
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "run_auth_check", lambda url, method, timeout, seed_path: {
        "status": "failed", "url": url, "method": method, "status_code": 401})

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--route-table", str(route_table)]) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    status = read_account(shared)["auth_seed_status"]
    assert result["status"] != "ready"
    assert result["auth_seed_usability"]["state"] == "stale"
    assert result["auth_seed_status_record"] == {"status": "recorded"}
    assert status["captured_at"] == "2026-10-22T08:00:00Z"
    assert status["last_verified_result"] == "expired"
    assert status["last_verified_reason"] == "http-401"
    assert status["last_verified_check"] == {"method": "GET", "url": "https://api.example.test/v1/me"}
    assert parse_utc(status["last_verified_at"]) is not None
    assert_no_secrets(output, json.dumps(status))


def test_resolve_skips_liveness_for_seed_without_auth_material_and_is_not_ready(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    seed = seed_file(tmp_path, {"cookies": [], "headers": {"User-Agent": "browser"}})
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_seed_ref": f"auth-seed:{seed}",
        "auth_check_url": "https://api.example.test/v1/me",
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    def must_not_check(*_args):
        raise AssertionError("liveness check sent without replayable auth material")

    monkeypatch.setattr(module, "run_auth_check", must_not_check)

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] != "ready"
    assert result["auth_check"] == {"status": "skipped", "reason": "no-replayable-auth-material",
                                    "url": "https://api.example.test/v1/me"}
    assert result["auth_seed"]["auth_material"] == "absent"
    assert result["auth_seed_usability"]["state"] == "unusable"


def test_resolve_old_format_seed_without_check_url_stays_ready_but_unverified(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    seed = seed_file(tmp_path, {"cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    write_inventory(shared, "demo", {"accounts": [{"alias": "blue", "pwnfox_color": "blue",
                                                   "auth_seed_ref": f"auth-seed:{seed}"}]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ready"
    assert result["auth_seed"]["captured_at"] is None
    assert result["auth_seed_usability"] == {"state": "unverified", "reasons": ["never-verified"]}
    assert "auth_seed_status" not in read_account(shared)


def test_resolve_without_check_url_does_not_claim_ready_for_recorded_expired_seed(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    seed = seed_file(tmp_path, {"captured_at": "2026-10-22T08:00:00+00:00",
                                "cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    write_inventory(shared, "demo", {"accounts": [{
        "alias": "blue", "pwnfox_color": "blue", "auth_seed_ref": f"auth-seed:{seed}",
        "auth_seed_status": {"captured_at": "2026-10-22T08:00:00+00:00", "auth_material": "present",
                             "last_verified_at": "2026-11-24T08:00:00+00:00", "last_verified_result": "expired",
                             "last_verified_reason": "http-401"},
    }]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] != "ready"
    assert result["auth_seed_usability"]["state"] == "stale"


class FakeResponse:
    def __init__(self, status, headers):
        import email.message

        self.status = status
        self.headers = email.message.Message()
        for name, value in headers.items():
            self.headers[name] = value

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.mark.parametrize(
    "headers,status,reason",
    [
        ({"Content-Type": "application/json", "CF-Cache-Status": "HIT"}, "inconclusive", "cached-response"),
        ({"Content-Type": "application/json", "Age": "120"}, "inconclusive", "cached-response"),
        ({"Content-Type": "text/html; charset=utf-8"}, "inconclusive", "html-document"),
        ({"Content-Type": "application/json", "CF-Cache-Status": "DYNAMIC"}, "passed", None),
    ],
)
def test_auth_check_200_from_cache_or_html_shell_is_not_live(tmp_path, monkeypatch, headers, status, reason):
    module = load_resolver_module()
    seed = seed_file(tmp_path, {"cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})

    class Opener:
        def open(self, request, timeout):
            return FakeResponse(200, headers)

    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *_args: Opener())

    result = module.run_auth_check("https://api.example.test/v1/me", "GET", 1.0, seed)

    assert result["status"] == status
    assert result.get("reason") == reason



def test_inconclusive_check_keeps_seed_ready_but_unverified_and_records_unknown(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    seed = seed_file(tmp_path, {"captured_at": "2026-11-24T08:00:00+00:00",
                                "cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    write_inventory(shared, "demo", {"accounts": [{"alias": "blue", "pwnfox_color": "blue",
                                                   "auth_seed_ref": f"auth-seed:{seed}"}]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "run_auth_check", lambda url, method, timeout, seed_path: {
        "status": "inconclusive", "reason": "html-document", "url": url, "method": method, "status_code": 200})

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--target-url",
                        "https://app.example.test/", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ready"
    assert result["auth_check"]["discriminator_warning"]
    assert result["auth_seed_usability"]["reasons"] == ["last-check-inconclusive:html-document"]
    assert read_account(shared)["auth_seed_status"]["last_verified_result"] == "unknown"


def test_inconclusive_check_does_not_overwrite_recorded_expiry(tmp_path, monkeypatch, capsys):
    module = load_resolver_module()
    shared = tmp_path / "shared"
    route_table = tmp_path / "proxy_routes.json"
    write_route_table(route_table)
    captured = "2026-10-22T08:00:00+00:00"
    seed = seed_file(tmp_path, {"captured_at": captured,
                                "cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    recorded = {"captured_at": captured, "auth_material": "present", "replayable_cookie_count": 1,
                "auth_header_names": [], "last_verified_at": "2026-11-24T08:00:00+00:00",
                "last_verified_result": "expired", "last_verified_reason": "http-401"}
    write_inventory(shared, "demo", {"accounts": [{"alias": "blue", "pwnfox_color": "blue",
                                                   "auth_seed_ref": f"auth-seed:{seed}",
                                                   "auth_seed_status": recorded}]})
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    monkeypatch.setattr(module, "run_auth_check", lambda url, method, timeout, seed_path: {
        "status": "inconclusive", "reason": "cached-response", "url": url, "method": method, "status_code": 200})

    assert module.main(["resolve", "--program", "demo", "--account", "blue", "--target-url",
                        "https://app.example.test/", "--route-table", str(route_table)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] != "ready"
    assert result["auth_seed_usability"]["state"] == "stale"
    assert "auth_seed_status_record" not in result
    assert read_account(shared)["auth_seed_status"] == recorded



def test_seed_writer_records_utc_captured_at_and_keeps_an_existing_capture_time(tmp_path):
    module = load_resolver_module()
    fresh = tmp_path / "fresh.json"
    rewritten = tmp_path / "rewritten.json"

    module.write_auth_seed(fresh, {"cookies": [{"name": "sid", "value": "synthetic-cookie-value"}]})
    module.write_auth_seed(rewritten, {"captured_at": "2026-10-22T08:00:00+00:00", "cookies": []})

    captured = parse_utc(json.loads(fresh.read_text())["captured_at"])
    assert captured is not None and captured.utcoffset().total_seconds() == 0
    assert json.loads(rewritten.read_text())["captured_at"] == "2026-10-22T08:00:00+00:00"
