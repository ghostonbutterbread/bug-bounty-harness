#!/usr/bin/env python3
"""Lease one persistent browser profile per program/account without exposing session material.

This script is deliberately a local profile-host coordinator. Run it on the
machine that owns the persistent Chromium profile (normally Hoster). It stores
only non-secret inventory metadata and browser lifecycle metadata; cookies,
tokens, auth seeds, and private headers never enter its database or output.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen


DEFAULT_STATE_DIR = Path("~/.local/state/ghost/browser-profile-leases").expanduser()
DEFAULT_TTL_SECONDS = 30 * 60
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def now() -> float:
    return time.time()


def shared_base() -> Path:
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/bounty_recon")).expanduser()


def slug(value: str) -> str:
    safe = "".join(char.lower() if char.isalnum() or char in "._-" else "-" for char in value.strip())
    safe = safe.strip(".-")
    return safe or "unknown"


def inventory_path(program: str) -> Path:
    return shared_base() / slug(program) / "credentials" / "account_inventory.json"


def profile_dir(program: str, account_alias: str) -> Path:
    return shared_base() / slug(program) / "ghost" / "chromium-test" / "profiles" / slug(account_alias)


def state_db(args: argparse.Namespace) -> Path:
    return Path(args.state_dir).expanduser() / "browser_profile_leases.sqlite"


def connect(db: Path) -> sqlite3.Connection:
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS browser_profile_leases (
            lease_id TEXT PRIMARY KEY,
            program TEXT NOT NULL,
            account_alias TEXT NOT NULL,
            account_color TEXT,
            owner_agent_id TEXT NOT NULL,
            owner_run_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            profile_dir TEXT NOT NULL,
            status TEXT NOT NULL,
            browser_status TEXT NOT NULL DEFAULT 'not-started',
            cdp_url TEXT,
            service_unit TEXT,
            created_at REAL NOT NULL,
            heartbeat_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            released_at REAL,
            UNIQUE(program, account_alias, lease_id)
        );
        CREATE INDEX IF NOT EXISTS idx_browser_profile_leases_active
          ON browser_profile_leases(program, account_alias, status, expires_at);
        """
    )


def load_inventory(program: str) -> dict[str, Any]:
    path = inventory_path(program)
    if not path.exists():
        return {"program": program, "accounts": [], "resources": []}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"account inventory is not valid JSON: {path}") from exc
    if not isinstance(loaded, dict):
        raise SystemExit(f"account inventory must be a JSON object: {path}")
    return loaded


def resolve_account(program: str, selector: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    inventory = load_inventory(program)
    wanted = selector.lower()
    accounts = [entry for entry in inventory.get("accounts", []) if isinstance(entry, dict)]
    for account in accounts:
        if str(account.get("alias", "")).lower() == wanted:
            return account, inventory
    for account in accounts:
        if str(account.get("pwnfox_color", "")).lower() == wanted:
            return account, inventory
    for lane in inventory.get("pwnfox_lanes", []):
        if isinstance(lane, dict) and str(lane.get("color", "")).lower() == wanted:
            alias = str(lane.get("account", "")).lower()
            for account in accounts:
                if str(account.get("alias", "")).lower() == alias:
                    return account, inventory
    return None, inventory


def account_summary(account: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    alias = str(account.get("alias", ""))
    resources = [
        item
        for item in inventory.get("resources", [])
        if isinstance(item, dict) and str(item.get("owner", "")).lower() == alias.lower()
    ]
    capabilities = account.get("capabilities", [])
    if not isinstance(capabilities, list):
        capabilities = []
    return {
        "alias": alias,
        "color": account.get("pwnfox_color"),
        "role": account.get("role"),
        "tenant_id": account.get("tenant_id"),
        "destructible": account.get("destructible", "unknown"),
        "lifecycle": account.get("lifecycle", "active"),
        "browser_lease_enabled": account.get("browser_lease_enabled", True) is not False,
        "capabilities": [str(value) for value in capabilities],
        "auth_seed_configured": bool(account.get("auth_seed_ref") or account.get("credential_ref")),
        "auth_refresh_source": account.get("auth_refresh_source"),
        "owned_resource_types": sorted({str(item.get("type")) for item in resources if item.get("type")}),
        "owned_resource_count": len(resources),
    }


def expire_leases(conn: sqlite3.Connection, timestamp: float) -> None:
    conn.execute(
        """
        UPDATE browser_profile_leases
        SET status = 'expired', browser_status = CASE
              WHEN browser_status = 'running' THEN 'unverified-after-expiry'
              ELSE browser_status END
        WHERE status = 'active' AND expires_at <= ?
        """,
        (timestamp,),
    )


def active_lease(conn: sqlite3.Connection, program: str, alias: str, timestamp: float) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM browser_profile_leases
        WHERE program = ? AND account_alias = ? AND status = 'active' AND expires_at > ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (slug(program), slug(alias), timestamp),
    ).fetchone()


def safe_lease(row: sqlite3.Row | None, *, include_cdp: bool = False) -> dict[str, Any] | None:
    if row is None:
        return None
    payload = {
        "lease_id": row["lease_id"],
        "program": row["program"],
        "account_alias": row["account_alias"],
        "account_color": row["account_color"],
        "owner_agent_id": row["owner_agent_id"],
        "owner_run_id": row["owner_run_id"],
        "purpose": row["purpose"],
        "status": row["status"],
        "browser_status": row["browser_status"],
        "service_unit": row["service_unit"],
        "created_at": row["created_at"],
        "heartbeat_at": row["heartbeat_at"],
        "expires_at": row["expires_at"],
    }
    if include_cdp:
        payload["cdp_url"] = row["cdp_url"]
        payload["profile_dir"] = row["profile_dir"]
    return payload


def account_lease_eligible(account: dict[str, Any]) -> bool:
    """Only explicit inventory state can make an account unavailable for leasing."""
    lifecycle = str(account.get("lifecycle", "active")).lower()
    return account.get("browser_lease_enabled", True) is not False and lifecycle not in {"deleted", "disabled", "suspended"}


def alternatives(conn: sqlite3.Connection, program: str, inventory: dict[str, Any], timestamp: float) -> list[dict[str, Any]]:
    available: list[dict[str, Any]] = []
    for account in inventory.get("accounts", []):
        if not isinstance(account, dict) or not account.get("alias") or not account_lease_eligible(account):
            continue
        lease = active_lease(conn, program, str(account["alias"]), timestamp)
        if lease is None:
            available.append(account_summary(account, inventory))
    return sorted(available, key=lambda row: (str(row.get("color") or ""), row["alias"]))


def cmd_status(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    selector = args.account
    account, inventory = resolve_account(args.program, selector) if selector else (None, load_inventory(args.program))
    with connect(state_db(args)) as conn:
        init_db(conn)
        expire_leases(conn, timestamp)
        conn.commit()
        if selector and account is None:
            return {
                "status": "account-not-found",
                "program": args.program,
                "selector": selector,
                "inventory_path": str(inventory_path(args.program)),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
            }
        if account is not None:
            lease = active_lease(conn, args.program, str(account["alias"]), timestamp)
            browser_probe = None
            if lease is not None:
                lease, browser_probe = probe_lease_browser(conn, lease)
                conn.commit()
            return {
                "status": "locked" if lease else "available",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "lease": safe_lease(lease),
                "browser_probe": browser_probe,
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
            }
        rows = conn.execute(
            """
            SELECT * FROM browser_profile_leases
            WHERE program = ? AND status = 'active' AND expires_at > ?
            ORDER BY account_alias
            """,
            (slug(args.program), timestamp),
        ).fetchall()
        return {
            "status": "ok",
            "program": slug(args.program),
            "active_leases": [safe_lease(row) for row in rows],
            "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
        }


def cmd_acquire(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    account, inventory = resolve_account(args.program, args.account)
    if account is None:
        return {
            "status": "account-not-found",
            "program": args.program,
            "selector": args.account,
            "inventory_path": str(inventory_path(args.program)),
        }
    if not account_lease_eligible(account):
        with connect(state_db(args)) as conn:
            init_db(conn)
            return {
                "status": "account-unavailable",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
                "next": "choose an explicitly eligible account; do not override inventory availability",
            }
    alias = str(account["alias"])
    with connect(state_db(args)) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        expire_leases(conn, timestamp)
        existing = active_lease(conn, args.program, alias, timestamp)
        if existing:
            same_owner = existing["owner_agent_id"] == args.agent_id and existing["owner_run_id"] == args.run_id
            if same_owner:
                expires_at = timestamp + args.ttl_seconds
                conn.execute(
                    "UPDATE browser_profile_leases SET heartbeat_at=?, expires_at=? WHERE lease_id=?",
                    (timestamp, expires_at, existing["lease_id"]),
                )
                conn.commit()
                renewed = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (existing["lease_id"],)).fetchone()
                return {
                    "status": "already-owned",
                    "account": account_summary(account, inventory),
                    "lease": safe_lease(renewed, include_cdp=True),
                    "next": "reuse the recorded browser only from this lease owner; direct replay remains account-scoped",
                }
            conn.commit()
            return {
                "status": "locked",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "lease": safe_lease(existing),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
                "next": "do not attach to or replace this browser; choose an explicitly approved alternative account or wait",
            }
        lease_id = str(uuid.uuid4())
        expires_at = timestamp + args.ttl_seconds
        persistent_profile = profile_dir(args.program, alias)
        conn.execute(
            """
            INSERT INTO browser_profile_leases(
                lease_id, program, account_alias, account_color, owner_agent_id, owner_run_id,
                purpose, profile_dir, status, browser_status, created_at, heartbeat_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'not-started', ?, ?, ?)
            """,
            (
                lease_id,
                slug(args.program),
                slug(alias),
                account.get("pwnfox_color"),
                args.agent_id,
                args.run_id,
                args.purpose,
                str(persistent_profile),
                timestamp,
                timestamp,
                expires_at,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (lease_id,)).fetchone()
    return {
        "status": "leased",
        "account": account_summary(account, inventory),
        "lease": safe_lease(row, include_cdp=True),
        "launch": {
            "required": True,
            "account": alias,
            "profile_mode": "persistent-account-profile",
            "command_hint": "run chromium_test.py with --account set to this resolved account alias; do not pass --ephemeral-profile",
        },
        "next": "register the browser with this lease after Chromium is ready; never substitute another account automatically",
    }


def owned_active_lease(conn: sqlite3.Connection, args: argparse.Namespace, timestamp: float) -> sqlite3.Row | None:
    expire_leases(conn, timestamp)
    row = conn.execute(
        "SELECT * FROM browser_profile_leases WHERE lease_id=? AND status='active' AND expires_at > ?",
        (args.lease_id, timestamp),
    ).fetchone()
    if row is None:
        return None
    if row["owner_agent_id"] != args.agent_id:
        return None
    return row


def cmd_renew(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    with connect(state_db(args)) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = owned_active_lease(conn, args, timestamp)
        if row is None:
            conn.commit()
            return {"status": "not-owner-or-expired", "lease_id": args.lease_id}
        expires_at = timestamp + args.ttl_seconds
        conn.execute(
            "UPDATE browser_profile_leases SET heartbeat_at=?, expires_at=? WHERE lease_id=?",
            (timestamp, expires_at, args.lease_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (args.lease_id,)).fetchone()
    return {"status": "renewed", "lease": safe_lease(updated, include_cdp=True)}


def local_cdp_version(cdp_url: str) -> dict[str, Any]:
    parsed = urlparse(cdp_url)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS or not parsed.port:
        raise SystemExit("CDP URL must be an http:// loopback endpoint with an explicit port")
    endpoint = f"http://{parsed.hostname}:{parsed.port}/json/version"
    try:
        with urlopen(endpoint, timeout=2) as response:  # nosec B310: loopback validated above
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # pragma: no cover - exact urllib errors vary by host
        return {"status": "unreachable", "error": str(exc)}
    return {"status": "ready", "browser": data.get("Browser"), "protocol_version": data.get("Protocol-Version")}


def probe_lease_browser(conn: sqlite3.Connection, row: sqlite3.Row) -> tuple[sqlite3.Row, dict[str, Any] | None]:
    """Refresh browser health from the profile host without exposing CDP to callers."""
    cdp_url = row["cdp_url"]
    if not cdp_url:
        return row, None
    probe = local_cdp_version(cdp_url)
    browser_status = "running" if probe["status"] == "ready" else "unreachable"
    if row["browser_status"] != browser_status:
        conn.execute("UPDATE browser_profile_leases SET browser_status=? WHERE lease_id=?", (browser_status, row["lease_id"]))
        row = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (row["lease_id"],)).fetchone()
    return row, probe


def cmd_register_browser(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    cdp = local_cdp_version(args.cdp_url)
    with connect(state_db(args)) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = owned_active_lease(conn, args, timestamp)
        if row is None:
            conn.commit()
            return {"status": "not-owner-or-expired", "lease_id": args.lease_id}
        browser_status = "running" if cdp["status"] == "ready" else "unreachable"
        conn.execute(
            """
            UPDATE browser_profile_leases
            SET browser_status=?, cdp_url=?, service_unit=?, heartbeat_at=?
            WHERE lease_id=?
            """,
            (browser_status, args.cdp_url, args.service_unit, timestamp, args.lease_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (args.lease_id,)).fetchone()
    return {"status": "registered" if cdp["status"] == "ready" else "registered-unreachable", "lease": safe_lease(updated, include_cdp=True), "cdp": cdp}


def cmd_release(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    with connect(state_db(args)) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (args.lease_id,)).fetchone()
        if row is None or row["owner_agent_id"] != args.agent_id:
            conn.commit()
            return {"status": "not-owner-or-missing", "lease_id": args.lease_id}
        conn.execute(
            "UPDATE browser_profile_leases SET status='released', released_at=?, heartbeat_at=? WHERE lease_id=?",
            (timestamp, timestamp, args.lease_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (args.lease_id,)).fetchone()
    return {"status": "released", "lease": safe_lease(updated, include_cdp=True)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Local state directory on the profile-host machine.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON (default).")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Show whether a program/account browser profile is available or locked.")
    status.add_argument("program")
    status.add_argument("--account", help="Owned account alias or color. Omit for a program overview.")
    status.set_defaults(func=cmd_status)

    acquire = sub.add_parser("acquire", help="Exclusively lease one persistent program/account browser profile.")
    acquire.add_argument("program")
    acquire.add_argument("account", help="Owned account alias or color; never falls back automatically.")
    acquire.add_argument("--agent-id", required=True)
    acquire.add_argument("--run-id", required=True)
    acquire.add_argument("--purpose", required=True)
    acquire.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    acquire.set_defaults(func=cmd_acquire)

    renew = sub.add_parser("renew", help="Renew an owned browser-profile lease heartbeat.")
    renew.add_argument("--lease-id", required=True)
    renew.add_argument("--agent-id", required=True)
    renew.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    renew.set_defaults(func=cmd_renew)

    register = sub.add_parser("register-browser", help="Attach verified local CDP metadata to an owned lease.")
    register.add_argument("--lease-id", required=True)
    register.add_argument("--agent-id", required=True)
    register.add_argument("--cdp-url", required=True)
    register.add_argument("--service-unit")
    register.set_defaults(func=cmd_register_browser)

    release = sub.add_parser("release", help="Release an owned profile lease after browser cleanup or handoff.")
    release.add_argument("--lease-id", required=True)
    release.add_argument("--agent-id", required=True)
    release.set_defaults(func=cmd_release)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"ok", "available", "locked", "leased", "already-owned", "renewed", "registered", "registered-unreachable", "released", "account-not-found", "account-unavailable"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
