#!/usr/bin/env python3
"""Focused regression tests for the persistent Chromium profile lease helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "chromium-test" / "scripts" / "browser_profile_lease.py"


def load_module():
    spec = importlib.util.spec_from_file_location("browser_profile_lease", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_inventory(shared: Path) -> None:
    path = shared / "demo" / "credentials" / "account_inventory.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "program": "demo",
                "accounts": [
                    {
                        "alias": "green-owner",
                        "pwnfox_color": "green",
                        "role": "owner",
                        "tenant_id": "owned-team",
                        "capabilities": ["org-owner", "shared-org:demo-team"],
                        "lifecycle": "active",
                        "browser_lease_enabled": True,
                        "auth_seed_ref": "auth-seed:/private/green.json",
                    },
                    {
                        "alias": "pink-member",
                        "pwnfox_color": "pink",
                        "role": "member",
                        "capabilities": ["org-member", "shared-org:demo-team"],
                        "lifecycle": "active",
                        "browser_lease_enabled": True,
                    },
                    {
                        "alias": "gray-disabled",
                        "pwnfox_color": "gray",
                        "role": "member",
                        "browser_lease_enabled": False,
                    },
                ],
                "resources": [
                    {"type": "organization", "id": "demo-team", "owner": "green-owner"},
                    {"type": "project", "id": "p1", "owner": "green-owner"},
                ],
            }
        )
    )


def args(module, state: Path, command: str, **values):
    parser = module.build_parser()
    argv = ["--state-dir", str(state), command]
    if command == "acquire":
        argv.extend([values.pop("program", "demo"), values.pop("account")])
    elif command == "status":
        argv.append(values.pop("program", "demo"))
        if account := values.pop("account", None):
            argv.extend(["--account", account])
        if tier := values.pop("tier", None):
            argv.extend(["--tier", tier])
    for key, value in values.items():
        flag = "--" + key.replace("_", "-")
        argv.extend([flag, str(value)])
    return parser.parse_args(argv)


def test_color_selector_leases_one_persistent_program_account_profile(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    result = module.cmd_acquire(
        args(module, state, "acquire", account="green", agent_id="agent-a", run_id="run-a", purpose="auth-map")
    )

    assert result["status"] == "leased"
    assert result["account"]["alias"] == "green-owner"
    assert result["account"]["capabilities"] == ["org-owner", "shared-org:demo-team"]
    assert result["account"]["owned_resource_count"] == 2
    assert result["account"]["auth_seed_configured"] is True
    assert "/private/green.json" not in json.dumps(result)
    assert result["lease"]["profile_dir"].endswith("demo/web/browser-profiles/green-owner")
    assert result["lease"]["profile_dir"].startswith("/mnt/bounty/")
    assert result["launch"]["account"] == "green-owner"


def test_shared_base_defaults_to_canonical_web_bounty(monkeypatch):
    module = load_module()
    monkeypatch.delenv("HARNESS_SHARED_BASE", raising=False)

    assert module.shared_base() == Path.home() / "Shared" / "web_bounty"


def test_locked_profile_returns_explicit_safe_alternatives_without_switching(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    first = module.cmd_acquire(
        args(module, state, "acquire", account="green", agent_id="agent-a", run_id="run-a", purpose="auth-map")
    )
    second = module.cmd_acquire(
        args(module, state, "acquire", account="green", agent_id="agent-b", run_id="run-b", purpose="idor")
    )

    assert first["status"] == "leased"
    assert second["status"] == "locked"
    assert second["lease"]["owner_agent_id"] == "agent-a"
    assert [item["alias"] for item in second["available_alternatives"]] == ["pink-member"]
    assert "lease_id" not in second["available_alternatives"][0]


def test_same_owner_renews_and_release_makes_profile_available(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    first = module.cmd_acquire(
        args(module, state, "acquire", account="pink", agent_id="agent-a", run_id="run-a", purpose="role-check")
    )
    again = module.cmd_acquire(
        args(module, state, "acquire", account="pink", agent_id="agent-a", run_id="run-a", purpose="role-check")
    )
    waiting = module.cmd_renew(
        args(module, state, "renew", lease_id=first["lease"]["lease_id"], agent_id="agent-a", work_state="awaiting-input")
    )
    released = module.cmd_release(
        args(module, state, "release", lease_id=first["lease"]["lease_id"], agent_id="agent-a", disposition="completed", profile_health="healthy")
    )
    status = module.cmd_status(args(module, state, "status", account="pink"))

    assert again["status"] == "already-owned"
    assert again["lease"]["lease_id"] == first["lease"]["lease_id"]
    assert waiting["lease"]["work_state"] == "awaiting-input"
    assert released["status"] == "released"
    assert released["lease"]["profile_health"] == "healthy"
    assert status["status"] == "available"
    assert status["last_release"]["profile_health"] == "healthy"


def test_global_tiers_map_owner_to_admin_and_anonymous_needs_no_profile(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    admins = module.cmd_status(args(module, state, "status", tier="admin"))
    anonymous = module.cmd_status(args(module, state, "status", tier="anonymous"))

    assert admins["status"] == "ok"
    assert [row["account"]["alias"] for row in admins["accounts"]] == ["green-owner"]
    assert admins["accounts"][0]["account"]["tier"] == "admin"
    assert anonymous == {
        "status": "anonymous",
        "program": "demo",
        "tier": "anonymous",
        "lease_required": False,
        "next": "use an ephemeral unauthenticated browser or direct request lane; no account profile is allocated",
    }


def test_status_probes_the_registered_loopback_browser_without_returning_cdp(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    acquired = module.cmd_acquire(
        args(module, state, "acquire", account="pink", agent_id="agent-a", run_id="run-a", purpose="role-check")
    )
    with module.connect(state / "browser_profile_leases.sqlite") as conn:
        conn.execute(
            "UPDATE browser_profile_leases SET cdp_url=?, browser_status='not-started' WHERE lease_id=?",
            ("http://127.0.0.1:9222", acquired["lease"]["lease_id"]),
        )
        conn.commit()
    monkeypatch.setattr(module, "local_cdp_version", lambda _: {"status": "ready", "browser": "Chromium", "protocol_version": "1.3"})

    result = module.cmd_status(args(module, state, "status", account="pink"))

    assert result["status"] == "locked"
    assert result["lease"]["browser_status"] == "running"
    assert result["browser_probe"]["status"] == "ready"
    assert "cdp_url" not in json.dumps(result)


def test_disabled_inventory_account_cannot_be_leased_or_suggested(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    result = module.cmd_acquire(
        args(module, state, "acquire", account="gray", agent_id="agent-a", run_id="run-a", purpose="role-check")
    )

    assert result["status"] == "account-unavailable"
    assert result["account"]["browser_lease_enabled"] is False
    assert [item["alias"] for item in result["available_alternatives"]] == ["green-owner", "pink-member"]


def test_unavailable_account_still_reports_its_active_lease(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    acquired = module.cmd_acquire(
        args(module, state, "acquire", account="green", agent_id="agent-a", run_id="run-a", purpose="auth-map")
    )
    inventory_path = shared / "demo" / "credentials" / "account_inventory.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["accounts"][0]["browser_lease_enabled"] = False
    inventory_path.write_text(json.dumps(inventory))

    status = module.cmd_status(args(module, state, "status", account="green"))

    assert status["status"] == "account-unavailable"
    assert status["lease"]["lease_id"] == acquired["lease"]["lease_id"]
    assert status["lease"]["owner_agent_id"] == "agent-a"


def test_register_browser_rejects_non_loopback_cdp(monkeypatch, tmp_path):
    module = load_module()
    shared = tmp_path / "shared"
    state = tmp_path / "state"
    write_inventory(shared)
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))
    lease = module.cmd_acquire(
        args(module, state, "acquire", account="pink", agent_id="agent-a", run_id="run-a", purpose="role-check")
    )

    try:
        module.local_cdp_version("http://hoster:9222")
    except SystemExit as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("non-loopback CDP endpoint was accepted")

    assert lease["status"] == "leased"
