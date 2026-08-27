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
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/web_bounty")).expanduser()


def artifact_base() -> Path:
    return Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty")).expanduser()


def slug(value: str) -> str:
    safe = "".join(char.lower() if char.isalnum() or char in "._-" else "-" for char in value.strip())
    safe = safe.strip(".-")
    return safe or "unknown"


def inventory_path(program: str) -> Path:
    return shared_base().joinpath(slug(program), "credentials", "account_inventory.json")


def profile_dir(program: str, account_alias: str) -> Path:
    return artifact_base() / slug(program) / "web" / "browser-profiles" / slug(account_alias)


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
            work_state TEXT NOT NULL DEFAULT 'active',
            profile_health TEXT NOT NULL DEFAULT 'unknown',
            release_disposition TEXT,
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
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(browser_profile_leases)")}
    for name, definition in {
        "work_state": "TEXT NOT NULL DEFAULT 'active'",
        "profile_health": "TEXT NOT NULL DEFAULT 'unknown'",
        "release_disposition": "TEXT",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE browser_profile_leases ADD COLUMN {name} {definition}")


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
    if loaded.get("status") == "retired":
        replacement = loaded.get("replaced_by", "the current canonical registry")
        raise SystemExit(f"account inventory is retired: {path}; use {replacement}")
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


def principal_tier(account: dict[str, Any]) -> str:
    explicit = str(account.get("tier", "")).lower()
    if explicit in {"admin", "user"}:
        return explicit
    role = str(account.get("role", "")).lower()
    return "admin" if role in {"admin", "owner"} else "user" if role in {"user", "member"} else "unknown"


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
        "tier": principal_tier(account),
        "role": account.get("role"),
        "tenant_id": account.get("tenant_id"),
        "organization_access": account.get("organization_access", []),
        "destructible": account.get("destructible", "unknown"),
        "lifecycle": account.get("lifecycle", "active"),
        "browser_lease_enabled": account.get("browser_lease_enabled") is True,
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
        "work_state": row["work_state"],
        "browser_status": row["browser_status"],
        "profile_health": row["profile_health"],
        "release_disposition": row["release_disposition"],
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
    """Lease only accounts explicitly health-cleared in the shared inventory."""
    lifecycle = str(account.get("lifecycle", "unknown")).lower()
    return account.get("browser_lease_enabled") is True and lifecycle == "active"


def last_release(conn: sqlite3.Connection, program: str, alias: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM browser_profile_leases
        WHERE program=? AND account_alias=? AND status='released'
        ORDER BY released_at DESC LIMIT 1
        """,
        (slug(program), slug(alias)),
    ).fetchone()


def profile_available(account: dict[str, Any], release: sqlite3.Row | None) -> bool:
    """A released profile needs an explicit healthy disposition before reuse."""
    return account_lease_eligible(account) and (release is None or release["profile_health"] == "healthy")


def lease_availability(conn: sqlite3.Connection, program: str, account: dict[str, Any], timestamp: float) -> tuple[str, sqlite3.Row | None, sqlite3.Row | None]:
    alias = str(account["alias"])
    lease = active_lease(conn, program, alias, timestamp)
    release = None if lease else last_release(conn, program, alias)
    status = "unavailable" if not account_lease_eligible(account) else "locked" if lease else "available" if profile_available(account, release) else "unavailable"
    return status, lease, release


def alternatives(conn: sqlite3.Connection, program: str, inventory: dict[str, Any], timestamp: float) -> list[dict[str, Any]]:
    available: list[dict[str, Any]] = []
    for account in inventory.get("accounts", []):
        if not isinstance(account, dict) or not account.get("alias"):
            continue
        status, _, _ = lease_availability(conn, program, account, timestamp)
        if status == "available":
            available.append(account_summary(account, inventory))
    return sorted(available, key=lambda row: (str(row.get("color") or ""), row["alias"]))


def color_availability(conn: sqlite3.Connection, program: str, inventory: dict[str, Any], timestamp: float) -> list[dict[str, Any]]:
    """Return non-secret PwnFox lane availability without selecting a substitute."""
    accounts = {
        str(account.get("alias", "")).lower(): account
        for account in inventory.get("accounts", [])
        if isinstance(account, dict) and account.get("alias")
    }
    colors: dict[str, dict[str, Any]] = {}
    for account in accounts.values():
        color = str(account.get("pwnfox_color") or "").lower()
        if color:
            colors[color] = account
    for lane in inventory.get("pwnfox_lanes", []):
        if not isinstance(lane, dict):
            continue
        color = str(lane.get("color") or "").lower()
        account = accounts.get(str(lane.get("account") or "").lower())
        if color and account:
            colors.setdefault(color, account)
    rows: list[dict[str, Any]] = []
    for color, account in colors.items():
        status, lease, _ = lease_availability(conn, program, account, timestamp)
        rows.append(
            {
                "color": color,
                "status": status,
                "alias": account.get("alias"),
                "lease": safe_lease(lease),
            }
        )
    return sorted(rows, key=lambda row: (row["color"], str(row["alias"])))


def cmd_status(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    selector = args.account
    account, inventory = resolve_account(args.program, selector) if selector else (None, load_inventory(args.program))
    with connect(state_db(args)) as conn:
        init_db(conn)
        expire_leases(conn, timestamp)
        conn.commit()
        if args.tier == "anonymous":
            return {
                "status": "anonymous",
                "program": slug(args.program),
                "tier": "anonymous",
                "lease_required": False,
                "next": "use an ephemeral unauthenticated browser or direct request lane; no account profile is allocated",
            }
        if args.tier:
            tier_accounts = []
            for candidate in inventory.get("accounts", []):
                if not isinstance(candidate, dict) or principal_tier(candidate) != args.tier:
                    continue
                candidate_status, lease, _ = lease_availability(conn, args.program, candidate, timestamp)
                tier_accounts.append({
                    "status": candidate_status,
                    "account": account_summary(candidate, inventory),
                    "lease": safe_lease(lease),
                })
            return {
                "status": "ok",
                "program": slug(args.program),
                "tier": args.tier,
                "accounts": tier_accounts,
                "color_availability": color_availability(conn, args.program, inventory, timestamp),
            }
        if args.idor:
            by_alias = {
                str(candidate.get("alias", "")).lower(): candidate
                for candidate in inventory.get("accounts", [])
                if isinstance(candidate, dict)
            }
            primary_aliases = [str(alias).lower() for alias in inventory.get("primary_idor_accounts", []) if isinstance(alias, str)]
            primary_accounts = []
            for alias in primary_aliases:
                candidate = by_alias.get(alias)
                if candidate is None:
                    continue
                candidate_status, lease, _ = lease_availability(conn, args.program, candidate, timestamp)
                primary_accounts.append({
                    "status": candidate_status,
                    "account": account_summary(candidate, inventory),
                    "lease": safe_lease(lease),
                })
            primary_set = set(primary_aliases)
            fallback_accounts = [
                account_summary(candidate, inventory)
                for candidate in inventory.get("accounts", [])
                if isinstance(candidate, dict)
                and str(candidate.get("alias", "")).lower() not in primary_set
                and lease_availability(conn, args.program, candidate, timestamp)[0] == "available"
            ]
            return {
                "status": "ok",
                "program": slug(args.program),
                "primary_idor_accounts": primary_accounts,
                "fallback_accounts": sorted(fallback_accounts, key=lambda row: (str(row.get("color") or ""), row["alias"])),
                "color_availability": color_availability(conn, args.program, inventory, timestamp),
            }
        if selector and account is None:
            return {
                "status": "account-not-found",
                "program": args.program,
                "selector": selector,
                "inventory_path": str(inventory_path(args.program)),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
            }
        if account is not None:
            account_status, lease, last_release = lease_availability(conn, args.program, account, timestamp)
            if account_status == "unavailable":
                return {
                    "status": "account-unavailable",
                    "program": slug(args.program),
                    "account": account_summary(account, inventory),
                    "lease": safe_lease(lease),
                    "last_release": safe_lease(last_release),
                    "browser_probe": None,
                    "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
                    "next": "a current explicit health clearance is required before this profile may be leased",
                }
            browser_probe = None
            if lease is not None:
                lease, browser_probe = probe_lease_browser(conn, lease)
                conn.commit()
            return {
                "status": account_status,
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "lease": safe_lease(lease),
                "last_release": safe_lease(last_release),
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
            "color_availability": color_availability(conn, args.program, inventory, timestamp),
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
        release = last_release(conn, args.program, str(account["alias"]))
        if not profile_available(account, release) and not (args.recover_profile and account_lease_eligible(account)):
            conn.commit()
            return {
                "status": "account-unavailable",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "last_release": safe_lease(release),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp),
                "next": "acquire with --recover-profile only for profile repair, then record a healthy release before leasing it again",
            }
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
                "color_availability": color_availability(conn, args.program, inventory, timestamp),
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
            "command_hint": "request this resolved account through browser_provisioner.py; do not launch chromium_test.py directly",
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
            "UPDATE browser_profile_leases SET heartbeat_at=?, expires_at=?, work_state=? WHERE lease_id=?",
            (timestamp, expires_at, args.work_state, args.lease_id),
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
            """
            UPDATE browser_profile_leases
            SET status='released', released_at=?, heartbeat_at=?, work_state='terminal',
                release_disposition=?, profile_health=?
            WHERE lease_id=?
            """,
            (timestamp, timestamp, args.disposition, args.profile_health, args.lease_id),
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
    status_filter = status.add_mutually_exclusive_group()
    status_filter.add_argument("--tier", choices=("admin", "user", "anonymous"), help="List accounts in a global principal tier; anonymous has no account lease.")
    status_filter.add_argument("--idor", action="store_true", help="List primary IDOR accounts first, their live lease state, then eligible fallback accounts.")
    status.set_defaults(func=cmd_status)

    acquire = sub.add_parser("acquire", help="Exclusively lease one persistent program/account browser profile.")
    acquire.add_argument("program")
    acquire.add_argument("account", help="Owned account alias or color; never falls back automatically.")
    acquire.add_argument("--agent-id", required=True)
    acquire.add_argument("--run-id", required=True)
    acquire.add_argument("--purpose", required=True)
    acquire.add_argument("--recover-profile", action="store_true", help="Lease an unavailable but eligible profile only to repair/re-authenticate it; release healthy before ordinary reuse.")
    acquire.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    acquire.set_defaults(func=cmd_acquire)

    renew = sub.add_parser("renew", help="Renew an owned browser-profile lease heartbeat.")
    renew.add_argument("--lease-id", required=True)
    renew.add_argument("--agent-id", required=True)
    renew.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    renew.add_argument("--work-state", choices=("active", "awaiting-input"), default="active", help="Use awaiting-input while a question/blocker means the work is not terminal.")
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
    release.add_argument("--disposition", required=True, choices=("completed", "handoff", "cancelled"), help="Terminal outcome; use renew --work-state awaiting-input instead while work is pending.")
    release.add_argument("--profile-health", required=True, choices=("healthy", "needs-refresh", "needs-cleanup", "unknown"), help="Non-secret handoff status of the persistent account profile.")
    release.set_defaults(func=cmd_release)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"ok", "available", "locked", "anonymous", "leased", "already-owned", "renewed", "registered", "registered-unreachable", "released", "account-not-found", "account-unavailable"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
