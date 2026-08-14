from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def load_inventory_module():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "account-management" / "scripts" / "account_inventory.py"
    spec = importlib.util.spec_from_file_location("account_inventory", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_linked_login_and_integration_are_non_secret_account_ledger_records(tmp_path, monkeypatch, capsys):
    module = load_inventory_module()
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))

    assert module.main(["add-account", "demo", "--alias", "primary"]) == 0
    assert module.main(
        [
            "link-login", "demo", "--account", "primary", "--provider", "google",
            "--identity", "ryushe+primary@example.com", "--source", "browser",
        ]
    ) == 0
    assert module.main(
        [
            "add-integration", "demo", "--account", "primary", "--provider", "github",
            "--integration-id", "installation-123", "--external-account", "owned-test-org",
            "--capability", "repo:read", "--source", "browser",
        ]
    ) == 0

    inventory = json.loads((tmp_path / "shared" / "demo" / "credentials" / "account_inventory.json").read_text())
    account = inventory["accounts"][0]
    assert inventory["schema_version"] == 5
    assert account["linked_logins"][0]["provider"] == "google"
    assert account["linked_logins"][0]["status"] == "linked"
    assert account["integrations"][0]["external_account"] == "owned-test-org"
    assert account["integrations"][0]["capabilities"] == ["repo:read"]
    assert "token" not in capsys.readouterr().out.lower()


def test_v4_inventory_migrates_with_empty_link_and_integration_lists(tmp_path, monkeypatch):
    module = load_inventory_module()
    shared = tmp_path / "shared"
    path = shared / "demo" / "credentials" / "account_inventory.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": 4, "accounts": [{"alias": "primary"}]}))
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(shared))

    inventory = module.load_inventory("demo")

    assert inventory["schema_version"] == 5
    assert inventory["accounts"][0]["linked_logins"] == []
    assert inventory["accounts"][0]["integrations"] == []


def test_account_and_ledger_upserts_preserve_existing_linked_records(tmp_path, monkeypatch):
    module = load_inventory_module()
    monkeypatch.setenv("HARNESS_SHARED_BASE", str(tmp_path / "shared"))

    assert module.main(["add-account", "demo", "--alias", "primary", "--role", "member"]) == 0
    assert module.main(
        ["link-login", "demo", "--account", "primary", "--provider", "google", "--identity", "owned@example.test"]
    ) == 0
    assert module.main(
        ["add-integration", "demo", "--account", "primary", "--provider", "github", "--integration-id", "install-7", "--capability", "repo:read"]
    ) == 0

    assert module.main(["add-account", "demo", "--alias", "primary", "--role", "owner"]) == 0
    assert module.main(
        ["add-integration", "demo", "--account", "primary", "--provider", "github", "--integration-id", "install-7", "--status", "disconnected"]
    ) == 0

    inventory = module.load_inventory("demo")
    account = inventory["accounts"][0]
    assert account["role"] == "owner"
    assert account["linked_logins"][0]["identity"] == "owned@example.test"
    assert account["integrations"][0]["status"] == "disconnected"
    assert account["integrations"][0]["capabilities"] == ["repo:read"]
