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
    path.parent.mkdir(parents=True)
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
    assert result["seed"]["headers"] == {"Authorization": "Bearer secret-token"}
    assert result["provenance"]["cookie_count"] == 2
    assert result["provenance"]["header_names"] == ["Authorization"]


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

    def fake_query_proxy_seed(route, account, color, program, host_filter, limit):
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
