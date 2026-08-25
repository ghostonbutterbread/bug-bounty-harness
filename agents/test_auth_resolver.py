from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


def load_resolver_module():
    root = Path(__file__).resolve().parents[1]
    resolver = root / "skills" / "account-management" / "scripts" / "auth_resolver.py"
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
