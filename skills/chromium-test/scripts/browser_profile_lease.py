#!/usr/bin/env python3
"""Lease one persistent browser profile per program/auth-domain/account without exposing session material.

This script is deliberately a local profile-host coordinator. Run it on the
machine that owns the persistent Chromium profile (normally Hoster). It stores
only non-secret inventory metadata and browser lifecycle metadata; cookies,
tokens, auth seeds, and private headers never enter its database or output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

ACCOUNT_MANAGEMENT_SCRIPTS = Path(__file__).resolve().parents[2] / "account-management" / "scripts"
if str(ACCOUNT_MANAGEMENT_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(ACCOUNT_MANAGEMENT_SCRIPTS))

from inventory_paths import inventory_path, program_key, shared_base as shared_base


DEFAULT_STATE_DIR = Path("~/.local/state/ghost/browser-profile-leases").expanduser()
DEFAULT_TTL_SECONDS = 30 * 60
DEFAULT_LEGACY_AUTH_DOMAIN = "legacy-global"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
ANONYMOUS_PROFILE_ALIASES = ("anon", "anon1", "anon2")
ANONYMOUS_PROFILE_PATTERN = re.compile(r"anon(?:[1-9][0-9]*)?$")


def now() -> float:
    return time.time()


def artifact_base() -> Path:
    return Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty")).expanduser()


def slug(value: str) -> str:
    safe = "".join(char.lower() if char.isalnum() or char in "._-" else "-" for char in value.strip())
    safe = safe.strip(".-")
    return safe or "unknown"


def profile_dir(program: str, auth_domain: str, account_alias: str) -> Path:
    return artifact_base() / program_key(program) / "web" / "browser-profiles" / slug(auth_domain) / slug(account_alias)


def auth_domain_for(args: argparse.Namespace, account: dict[str, Any] | None = None) -> str:
    explicit = getattr(args, "auth_domain", None)
    if explicit:
        return slug(str(explicit))
    if account and account.get("auth_host_filter"):
        return slug(str(account["auth_host_filter"]))
    return DEFAULT_LEGACY_AUTH_DOMAIN


def anonymous_profile_record(selector: str) -> dict[str, Any] | None:
    """Return a leasable anonymous browser slot without consulting accounts."""
    alias = slug(selector)
    if not ANONYMOUS_PROFILE_PATTERN.fullmatch(alias):
        return None
    return {
        "alias": alias,
        "profile_kind": "anonymous",
        "lifecycle": "active",
        "browser_lease_enabled": True,
    }


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
            auth_domain TEXT,
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
        "auth_domain": "TEXT",
        "manager_id": "TEXT",
        "instance_key": "TEXT NOT NULL DEFAULT ''",
        "instance_selection": "TEXT NOT NULL DEFAULT 'explicit'",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE browser_profile_leases ADD COLUMN {name} {definition}")


def instance_key(args):
    value = getattr(args, "instance_key", None) or ""
    if value and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise ValueError("instance key must be 1-64 lowercase letters, digits, _ or -")
    return value


def instance_profile(program, domain, alias, key=""):
    base = profile_dir(program, domain, alias)
    return (artifact_base() / program_key(program) / "web" / "browser-instances"
            / slug(domain) / slug(alias) / key) if key else base

def physical_profile(path):
    """Identify an existing directory, following symlinks; unknown is never equal."""
    try:
        info = os.stat(path)
        if not stat.S_ISDIR(info.st_mode):
            return None
        return (info.st_dev, info.st_ino)
    except (OSError, ValueError, TypeError):
        return None


def stopped_legacy_profile(conn, args, alias, domain, key):
    """Resolve a stopped manager record against the entire canonical unkeyed history."""
    old_id = getattr(args, 'stopped_legacy_lease_id', None)
    old_path = getattr(args, 'stopped_legacy_profile_dir', None)
    manager = getattr(args, 'manager_id', None)
    if not old_id and not old_path:
        return None, False
    if not old_id or not old_path or not manager or key or getattr(args, 'automatic_instance', False):
        return None, True
    rows = conn.execute(
        "SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? "
        "AND (auth_domain=? OR auth_domain IS NULL) AND instance_key=''",
        (slug(args.program), slug(alias), domain),
    ).fetchall()
    source = next((r for r in rows if r['lease_id'] == old_id), None)
    pre_domain = artifact_base() / program_key(args.program) / 'web' / 'browser-profiles' / slug(alias)
    allowed = (str(pre_domain), str(profile_dir(args.program, domain, alias)))
    identity = physical_profile(old_path)
    if (not source or old_path not in allowed or not identity or source['profile_dir'] != old_path
            or source['auth_domain'] != domain or source['manager_id'] != manager
            or source['owner_agent_id'] != getattr(args, 'stopped_legacy_agent_id', None)
            or source['owner_run_id'] != getattr(args, 'stopped_legacy_run_id', None)
            or source['status'] != 'released' or any(
                physical_profile(r['profile_dir']) != identity or r['auth_domain'] != domain
                or r['manager_id'] != manager for r in rows)):
        return None, True
    return source['profile_dir'], True


def init_resource_policy(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS browser_concurrency_policy (
            program TEXT, account_alias TEXT, auth_domain TEXT, mode TEXT NOT NULL,
            PRIMARY KEY(program, account_alias, auth_domain));
        CREATE TABLE IF NOT EXISTS browser_logout_reports (
            report_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, reported_at REAL NOT NULL,
            reason TEXT NOT NULL);
    """)


def register_legacy_auto(db_path, program, alias, domain, profile, manager_id,
                         lease_id, agent_id, run_id, legacy_running=True):
    """Authorize auto slots beside one exact manager-proven legacy profile."""
    with connect(db_path) as conn:
        init_db(conn)
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("""CREATE TABLE IF NOT EXISTS browser_legacy_auto (
            program TEXT NOT NULL, account_alias TEXT NOT NULL, auth_domain TEXT NOT NULL,
            profile_dir TEXT NOT NULL, manager_id TEXT NOT NULL,
            PRIMARY KEY(program,account_alias,auth_domain))""")
        rows = conn.execute("SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? "
                            "AND (auth_domain=? OR auth_domain IS NULL) AND instance_key=''",
                            (program, alias, domain)).fetchall()
        identity = physical_profile(profile)
        if not rows or not identity or any(physical_profile(r['profile_dir']) != identity or r['auth_domain'] != domain for r in rows):
            return False
        if not any(r['lease_id'] == lease_id and r['owner_agent_id'] == agent_id and
                   r['owner_run_id'] == run_id and r['manager_id'] == manager_id for r in rows):
            return False
        # Under BEGIN IMMEDIATE, no other domain or keyed slot may own this
        # physical profile while we open the legacy parallelism marker.
        if any(physical_profile(r['profile_dir']) in (None, identity) for r in conn.execute(
                "SELECT profile_dir FROM browser_profile_leases WHERE status='active' AND lease_id!=?",
                (lease_id,)).fetchall()):
            return False
        active = [r for r in rows if r['status'] == 'active' and
                  (r['expires_at'] > now() or r['manager_id'] or r['cdp_url'])]
        if (len(active) != (1 if legacy_running else 0) or any(
                r['lease_id'] != lease_id or r['owner_agent_id'] != agent_id or
                r['owner_run_id'] != run_id or r['manager_id'] != manager_id for r in active)):
            return False
        if any(r['status'] == 'active' and
               (r['expires_at'] > now() or r['manager_id'] or r['cdp_url']) and
               r['manager_id'] != manager_id for r in rows):
            return False
        old = conn.execute("SELECT * FROM browser_legacy_auto WHERE program=? AND account_alias=? AND auth_domain=?",
                           (program, alias, domain)).fetchone()
        if old and (physical_profile(old['profile_dir']) != identity or old['manager_id'] != manager_id):
            return False
        conn.execute("INSERT OR IGNORE INTO browser_legacy_auto VALUES(?,?,?,?,?)",
                     (program, alias, domain, profile, manager_id))
        conn.commit()
        return True

def authorize_auto_slot(db_path, program, alias, domain, key, manager_id, agent_id, run_id):
    """Manager issues an opaque, short-lived one-use selection proof."""
    import secrets, hashlib
    token = secrets.token_urlsafe(32)
    with connect(db_path) as conn:
        init_db(conn)
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("""CREATE TABLE IF NOT EXISTS browser_auto_selections (
            token_hash TEXT PRIMARY KEY, program TEXT NOT NULL, account_alias TEXT NOT NULL,
            auth_domain TEXT NOT NULL, instance_key TEXT NOT NULL, manager_id TEXT NOT NULL,
            agent_id TEXT NOT NULL, run_id TEXT NOT NULL, expires_at REAL NOT NULL)""")
        conn.execute('DELETE FROM browser_auto_selections WHERE expires_at<?', (now(),))
        conn.execute('INSERT INTO browser_auto_selections VALUES(?,?,?,?,?,?,?,?,?)',
                     (hashlib.sha256(token.encode()).hexdigest(), program, alias, domain, key,
                      manager_id, agent_id, run_id, now() + 120))
        conn.commit()
    return token


def consume_auto_slot(conn, args, alias, domain, key):
    token = getattr(args, 'selection_proof', None)
    if not token or not getattr(args, 'manager_id', None) or not key.startswith('auto-'):
        return False
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='browser_auto_selections'").fetchone():
        return False
    import hashlib
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = conn.execute('SELECT * FROM browser_auto_selections WHERE token_hash=?', (digest,)).fetchone()
    if not row or any((row[field] != value for field, value in (
            ('program', slug(args.program)), ('account_alias', slug(alias)), ('auth_domain', domain),
            ('instance_key', key), ('manager_id', args.manager_id),
            ('agent_id', args.agent_id), ('run_id', args.run_id)))) or row['expires_at'] < now():
        return False
    conn.execute('DELETE FROM browser_auto_selections WHERE token_hash=?', (digest,))
    return True


def legacy_auto_conflict(conn, row, key, manager_id, automatic=False):
    """An unkeyed lease remains exclusive except for registered auto peers."""
    if row['instance_key'] != '' or not automatic or not key.startswith('auto-') or not manager_id:
        return True
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone():
        return True
    marker = conn.execute("SELECT profile_dir,manager_id FROM browser_legacy_auto WHERE program=? AND account_alias=? AND auth_domain=?",
                          (row['program'], row['account_alias'], row['auth_domain'])).fetchone()
    return not marker or row['profile_dir'] != marker['profile_dir'] or row['manager_id'] != marker['manager_id'] or manager_id != marker['manager_id']

def single_browser_policy(conn, program, alias, domain):
    """One exact resolved account/domain policy, shared by selection and acquire."""
    table = conn.execute("SELECT 1 FROM sqlite_master WHERE name='browser_concurrency_policy'").fetchone()
    policy = conn.execute(
        "SELECT mode FROM browser_concurrency_policy WHERE program=? AND account_alias=? AND auth_domain=?",
        (slug(program), slug(alias), domain),
    ).fetchone() if table else None
    return bool(policy and policy[0] == "single")


def cmd_policy(args):
    account, _ = resolve_account(args.program, args.account)
    if account is None:
        return {"status": "account-not-found"}
    domain = auth_domain_for(args, account)
    with connect(state_db(args)) as conn:
        init_db(conn)
        init_resource_policy(conn)
        conn.execute("INSERT OR REPLACE INTO browser_concurrency_policy VALUES(?,?,?,?)",
                     (slug(args.program), slug(account["alias"]), domain, args.mode))
    return {"status": "policy-set", "mode": args.mode, "auth_domain": domain,
            "effect": "future-acquisitions-only", "automatic_auth_retry": False}


def cmd_report_logout(args):
    with connect(state_db(args)) as conn:
        init_db(conn)
        init_resource_policy(conn)
        row = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=? AND owner_agent_id=?",
                           (args.lease_id, args.agent_id)).fetchone()
        if row is None:
            return {"status": "not-owner-or-missing"}
        report_id = str(uuid.uuid4())
        conn.execute("INSERT INTO browser_logout_reports VALUES(?,?,?,?)",
                     (report_id, args.lease_id, now(), args.reason))
    return {"status": "logout-reported", "report_id": report_id,
            "automatic_auth_retry": False, "policy_changed": False}


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
    anonymous = anonymous_profile_record(selector)
    if anonymous is not None:
        # Anonymous slots are durable browser state, not account fixtures.
        return anonymous, {"program": program, "accounts": [], "resources": []}
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
        "profile_kind": account.get("profile_kind", "account"),
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
        WHERE status = 'active' AND expires_at <= ? AND manager_id IS NULL AND cdp_url IS NULL
        """,
        (timestamp,),
    )


def active_lease(conn: sqlite3.Connection, program: str, alias: str, auth_domain: str, timestamp: float) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM browser_profile_leases
        WHERE program = ? AND account_alias = ? AND status = 'active' AND (expires_at > ? OR manager_id IS NOT NULL OR cdp_url IS NOT NULL)
          AND (auth_domain = ? OR auth_domain IS NULL)
        ORDER BY CASE WHEN auth_domain IS NULL THEN 0 ELSE 1 END, created_at DESC LIMIT 1
        """,
        (slug(program), slug(alias), timestamp, auth_domain),
    ).fetchone()


def safe_lease(row: sqlite3.Row | None, *, include_cdp: bool = False) -> dict[str, Any] | None:
    if row is None:
        return None
    payload = {
        "instance_key": row["instance_key"],
        "lease_id": row["lease_id"],
        "program": row["program"],
        "account_alias": row["account_alias"],
        "account_color": row["account_color"],
        "auth_domain": row["auth_domain"] or DEFAULT_LEGACY_AUTH_DOMAIN,
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
    """Lease health-cleared accounts and inventory-free anonymous slots."""
    lifecycle = str(account.get("lifecycle", "unknown")).lower()
    # `live` is accepted for legacy inventories; writers must continue to use
    # canonical `active`.
    return account.get("browser_lease_enabled") is True and lifecycle in {"active", "live"}


def anonymous_profile_aliases(conn: sqlite3.Connection, program: str) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT account_alias FROM browser_profile_leases WHERE program=?",
        (slug(program),),
    ).fetchall()
    aliases = set(ANONYMOUS_PROFILE_ALIASES)
    aliases.update(row["account_alias"] for row in rows if anonymous_profile_record(row["account_alias"]))
    return sorted(aliases, key=lambda value: (len(value), value))


def anonymous_profile_status(conn: sqlite3.Connection, program: str, timestamp: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for alias in anonymous_profile_aliases(conn, program):
        profile = anonymous_profile_record(alias)
        assert profile is not None
        status, lease, release = lease_availability(conn, program, profile, timestamp, DEFAULT_LEGACY_AUTH_DOMAIN)
        rows.append({
            "alias": alias,
            "profile_kind": "anonymous",
            "status": status,
            "lease": safe_lease(lease),
            "last_release": safe_lease(release),
        })
    return rows


def last_release(conn: sqlite3.Connection, program: str, alias: str, auth_domain: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM browser_profile_leases
        WHERE program=? AND account_alias=? AND auth_domain=? AND status='released'
        ORDER BY released_at DESC LIMIT 1
        """,
        (slug(program), slug(alias), auth_domain),
    ).fetchone()


def profile_available(account: dict[str, Any], release: sqlite3.Row | None) -> bool:
    """A released profile needs an explicit healthy disposition before reuse."""
    return account_lease_eligible(account) and (release is None or release["profile_health"] == "healthy")


def lease_availability(conn: sqlite3.Connection, program: str, account: dict[str, Any], timestamp: float, auth_domain: str | None = None) -> tuple[str, sqlite3.Row | None, sqlite3.Row | None]:
    alias = str(account["alias"])
    auth_domain = auth_domain or DEFAULT_LEGACY_AUTH_DOMAIN
    lease = active_lease(conn, program, alias, auth_domain, timestamp)
    release = None if lease else last_release(conn, program, alias, auth_domain)
    status = "unavailable" if not account_lease_eligible(account) else "locked" if lease else "available" if profile_available(account, release) else "unavailable"
    return status, lease, release


def alternatives(conn: sqlite3.Connection, program: str, inventory: dict[str, Any], timestamp: float, auth_domain: str | None = None) -> list[dict[str, Any]]:
    available: list[dict[str, Any]] = []
    for account in inventory.get("accounts", []):
        if not isinstance(account, dict) or not account.get("alias"):
            continue
        status, _, _ = lease_availability(conn, program, account, timestamp, auth_domain)
        if status == "available":
            available.append(account_summary(account, inventory))
    return sorted(available, key=lambda row: (str(row.get("color") or ""), row["alias"]))


def color_availability(conn: sqlite3.Connection, program: str, inventory: dict[str, Any], timestamp: float, auth_domain: str | None = None) -> list[dict[str, Any]]:
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
        status, lease, _ = lease_availability(conn, program, account, timestamp, auth_domain)
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
    requested_domain = auth_domain_for(args, account)
    with connect(state_db(args)) as conn:
        init_db(conn)
        expire_leases(conn, timestamp)
        conn.commit()
        if args.tier == "anonymous" or args.anonymous:
            return {
                "status": "ok",
                "program": slug(args.program),
                "profile_kind": "anonymous",
                "profiles": anonymous_profile_status(conn, args.program, timestamp),
                "next": "request an exact available anonymous profile through browser_provisioner.py; no account or auth seed is used",
            }
        if args.tier:
            tier_accounts = []
            for candidate in inventory.get("accounts", []):
                if not isinstance(candidate, dict) or principal_tier(candidate) != args.tier:
                    continue
                candidate_status, lease, _ = lease_availability(conn, args.program, candidate, timestamp, auth_domain_for(args, candidate))
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
                "color_availability": color_availability(conn, args.program, inventory, timestamp, requested_domain),
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
                candidate_status, lease, _ = lease_availability(conn, args.program, candidate, timestamp, auth_domain_for(args, candidate))
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
                and lease_availability(conn, args.program, candidate, timestamp, auth_domain_for(args, candidate))[0] == "available"
            ]
            return {
                "status": "ok",
                "program": slug(args.program),
                "primary_idor_accounts": primary_accounts,
                "fallback_accounts": sorted(fallback_accounts, key=lambda row: (str(row.get("color") or ""), row["alias"])),
                "color_availability": color_availability(conn, args.program, inventory, timestamp, requested_domain),
            }
        if selector and account is None:
            return {
                "status": "account-not-found",
                "program": args.program,
                "selector": selector,
                "inventory_path": str(inventory_path(args.program)),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp, requested_domain),
            }
        if account is not None:
            account_status, lease, last_release = lease_availability(conn, args.program, account, timestamp, requested_domain)
            if account_status == "unavailable":
                return {
                    "status": "account-unavailable",
                    "program": slug(args.program),
                    "account": account_summary(account, inventory),
                    "lease": safe_lease(lease),
                    "last_release": safe_lease(last_release),
                    "browser_probe": None,
                    "available_alternatives": alternatives(conn, args.program, inventory, timestamp, requested_domain),
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
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp, requested_domain),
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
            "available_alternatives": alternatives(conn, args.program, inventory, timestamp, requested_domain),
            "color_availability": color_availability(conn, args.program, inventory, timestamp, requested_domain),
        }


def transfer_managed_lease(db_path, old_id, manager_id, agent_id, run_id, purpose, ttl, cdp_url, *, expected=None):
    """Atomic ownership rotation, invoked only after the provisioner's pipe fence."""
    timestamp = now()
    with connect(db_path) as conn:
        init_db(conn)
        conn.execute('BEGIN IMMEDIATE')
        old = conn.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (old_id,)).fetchone()
        if old is None or old['manager_id'] != manager_id or old['status'] != 'active':
            return {'status': 'not-owner-or-expired'}
        if expected and any(old[key] != value for key, value in expected.items()):
            return {'status': 'canonical-identity-mismatch'}
        single = single_browser_policy(conn, old['program'], old['account_alias'], old['auth_domain'])
        conflicts = conn.execute(
            "SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? "
            "AND (auth_domain=? OR auth_domain IS NULL) AND status='active' AND lease_id!=? "
            "AND (expires_at>? OR manager_id IS NOT NULL OR cdp_url IS NOT NULL) "
            "AND (? OR instance_key='' OR ?='' OR instance_key=?)",
            (old['program'], old['account_alias'], old['auth_domain'], old_id, timestamp,
             single, old['instance_key'], old['instance_key']),
        ).fetchall()
        if any(single or legacy_auto_conflict(conn, r, old['instance_key'], manager_id,
                                               old['instance_selection'] == 'automatic') for r in conflicts):
            return {'status': 'locked'}
        values = dict(old)
        values.update(lease_id=str(uuid.uuid4()), owner_agent_id=agent_id, owner_run_id=run_id,
                      purpose=purpose, heartbeat_at=timestamp, created_at=timestamp,
                      expires_at=timestamp+ttl, cdp_url=cdp_url, work_state='active')
        conn.execute("UPDATE browser_profile_leases SET status='released', browser_status='handed-off', cdp_url=NULL, service_unit=NULL, work_state='terminal', release_disposition='handoff', released_at=? WHERE lease_id=?", (timestamp, old_id))
        columns = ','.join(values)
        placeholders = ','.join('?' for _ in values)
        conn.execute(f'INSERT INTO browser_profile_leases ({columns}) VALUES ({placeholders})', tuple(values.values()))
        conn.commit()
        row = conn.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (values['lease_id'],)).fetchone()
        return {'status': 'leased', 'lease': safe_lease(row, include_cdp=True)}


def cmd_acquire(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = now()
    key = instance_key(args)
    if getattr(args, 'task_owned', False):
        if args.program != 'task-owned' or getattr(args, 'auth_domain', None) != 'task' or not re.fullmatch(r'task-[0-9a-f]{24}', args.account):
            return {'status': 'invalid-task-profile'}
        account = {'alias': args.account, 'profile_kind': 'task', 'lifecycle': 'active', 'browser_lease_enabled': True}
        inventory = {'accounts': [], 'resources': []}
    else:
        account, inventory = resolve_account(args.program, args.account)
    if account is None:
        return {
            "status": "account-not-found",
            "program": args.program,
            "selector": args.account,
            "inventory_path": str(inventory_path(args.program)),
        }
    auth_domain = auth_domain_for(args, account)
    if not account_lease_eligible(account):
        with connect(state_db(args)) as conn:
            init_db(conn)
            return {
                "status": "account-unavailable",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp, auth_domain),
                "next": "choose an explicitly eligible account; do not override inventory availability",
            }
    alias = str(account["alias"])
    with connect(state_db(args)) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        expire_leases(conn, timestamp)
        release = conn.execute(
            "SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? AND auth_domain=? AND instance_key=? AND status='released' ORDER BY released_at DESC LIMIT 1",
            (slug(args.program), slug(alias), auth_domain, key),
        ).fetchone()
        if not profile_available(account, release) and not (args.recover_profile and account_lease_eligible(account)):
            conn.commit()
            return {
                "status": "account-unavailable",
                "program": slug(args.program),
                "account": account_summary(account, inventory),
                "last_release": safe_lease(release),
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp, auth_domain),
                "next": "acquire with --recover-profile only for profile repair, then record a healthy release before leasing it again",
            }
        # All admission paths share this SQLite transaction. Legacy profiles
        # remain an account-wide lock; explicit instance keys opt into isolation.
        single = single_browser_policy(conn, args.program, alias, auth_domain)
        conflicts = conn.execute(
            """SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=?
            AND status='active' AND (expires_at>? OR manager_id IS NOT NULL OR cdp_url IS NOT NULL)
            AND (auth_domain=? OR auth_domain IS NULL)
            AND (?='' OR instance_key='' OR instance_key=? OR ?)
            ORDER BY CASE WHEN auth_domain IS NULL THEN 0 ELSE 1 END,
              CASE WHEN ?=0 AND owner_agent_id=? AND owner_run_id=? AND instance_key=? THEN 0 ELSE 1 END,
              created_at DESC""",
            (slug(args.program), slug(alias), timestamp, auth_domain, key, key, single,
             single, args.agent_id, args.run_id, key),
        ).fetchall()
        if getattr(args, 'automatic_instance', False) and not consume_auto_slot(conn, args, alias, auth_domain, key):
            return {'status': 'locked', 'reason': 'manager-selection-required'}
        automatic = bool(getattr(args, 'automatic_instance', False))
        existing = next((r for r in conflicts if single or legacy_auto_conflict(
            conn, r, key, getattr(args, 'manager_id', None), automatic)), None)
        if existing:
            same_owner = existing["owner_agent_id"] == args.agent_id and existing["owner_run_id"] == args.run_id and existing["instance_key"] == key
            if same_owner and existing['manager_id'] != getattr(args, 'manager_id', None):
                return {'status': 'managed-by-provisioner'}
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
                "available_alternatives": alternatives(conn, args.program, inventory, timestamp, auth_domain),
                "color_availability": color_availability(conn, args.program, inventory, timestamp, auth_domain),
                "next": "do not attach to or replace this browser; choose an explicitly approved alternative account or wait",
            }
        inherited_path, requested_inheritance = stopped_legacy_profile(conn, args, alias, auth_domain, key)
        if requested_inheritance and inherited_path is None:
            return {'status': 'locked', 'reason': 'legacy-profile-history-mismatch'}
        lease_id = str(uuid.uuid4())
        expires_at = timestamp + args.ttl_seconds
        persistent_profile = inherited_path or instance_profile(args.program, auth_domain, alias, key)
        conn.execute(
            """
            INSERT INTO browser_profile_leases(
                lease_id, program, account_alias, account_color, auth_domain, owner_agent_id, owner_run_id,
                purpose, profile_dir, status, browser_status, created_at, heartbeat_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'not-started', ?, ?, ?)
            """,
            (
                lease_id,
                slug(args.program),
                slug(alias),
                account.get("pwnfox_color"),
                auth_domain,
                args.agent_id,
                args.run_id,
                args.purpose,
                str(persistent_profile),
                timestamp,
                timestamp,
                expires_at,
            ),
        )
        conn.execute("UPDATE browser_profile_leases SET manager_id=?,instance_key=?,instance_selection=? WHERE lease_id=?",
                     (getattr(args, "manager_id", None), key, 'automatic' if automatic else 'explicit', lease_id))
        conn.commit()
        row = conn.execute("SELECT * FROM browser_profile_leases WHERE lease_id=?", (lease_id,)).fetchone()
    return {
        "status": "leased",
        "account": account_summary(account, inventory),
        "lease": safe_lease(row, include_cdp=True),
        "launch": {
            "required": True,
            "account": alias,
            "profile_mode": "persistent-anonymous-profile" if account.get("profile_kind") == "anonymous" else "persistent-account-profile",
            "command_hint": "request this resolved profile through browser_provisioner.py; do not launch chromium_test.py directly",
        },
        "next": "register the browser with this lease after Chromium is ready; never substitute another account automatically",
    }


def owned_active_lease(conn: sqlite3.Connection, args: argparse.Namespace, timestamp: float) -> sqlite3.Row | None:
    expire_leases(conn, timestamp)
    row = conn.execute(
        "SELECT * FROM browser_profile_leases WHERE lease_id=? AND status='active' AND (expires_at > ? OR manager_id IS NOT NULL)",
        (args.lease_id, timestamp),
    ).fetchone()
    if row is None:
        return None
    if row["owner_agent_id"] != args.agent_id or row["manager_id"] != getattr(args, "manager_id", None):
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
    endpoint = cdp_url.rstrip("/") + "/json/version"
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
        if row is None or row["owner_agent_id"] != args.agent_id or row["status"] != "active" or row["manager_id"] != getattr(args, "manager_id", None):
            conn.commit()
            return {"status": "not-owner-or-missing", "lease_id": args.lease_id}
        conn.execute(
            """
            UPDATE browser_profile_leases
            SET status='released', browser_status=CASE WHEN manager_id IS NOT NULL OR cdp_url IS NULL THEN 'stopped' ELSE 'unverified-after-release' END, cdp_url=NULL, service_unit=NULL, released_at=?, heartbeat_at=?, work_state='terminal',
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

    status = sub.add_parser("status", help="Show whether a program/auth-domain/account browser profile is available or locked.")
    status.add_argument("program")
    status.add_argument("--account", help="Owned account alias or color. Omit for a program overview.")
    status.add_argument("--auth-domain", help="Auth host/domain whose persistent profile is being queried.")
    status_filter = status.add_mutually_exclusive_group()
    status_filter.add_argument("--tier", choices=("admin", "user", "anonymous"), help="List accounts in a global principal tier, or durable anonymous browser slots.")
    status_filter.add_argument("--anonymous", action="store_true", help="List durable anonymous browser slots without consulting account inventory.")
    status_filter.add_argument("--idor", action="store_true", help="List primary IDOR accounts first, their live lease state, then eligible fallback accounts.")
    status.set_defaults(func=cmd_status)

    acquire = sub.add_parser("acquire", help="Exclusively lease one persistent program/auth-domain/account browser profile.")
    acquire.add_argument("program")
    acquire.add_argument("account", help="Owned account alias or color; never falls back automatically.")
    acquire.add_argument("--auth-domain", help="Auth host/domain that scopes this persistent profile lock.")
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
    acquire.add_argument("--task-owned", action="store_true")
    acquire.add_argument("--instance-key")
    acquire.add_argument("--automatic-instance", action="store_true", help=argparse.SUPPRESS)
    acquire.add_argument("--selection-proof-stdin", action="store_true", help=argparse.SUPPRESS)
    acquire.add_argument("--stopped-legacy-lease-id", help=argparse.SUPPRESS)
    acquire.add_argument("--stopped-legacy-profile-dir", help=argparse.SUPPRESS)
    acquire.add_argument("--stopped-legacy-agent-id", help=argparse.SUPPRESS)
    acquire.add_argument("--stopped-legacy-run-id", help=argparse.SUPPRESS)
    policy = sub.add_parser("set-browser-policy", help="Manual concurrency policy; never retries authentication or stops existing browsers.")
    policy.add_argument("program")
    policy.add_argument("account")
    policy.add_argument("--auth-domain", required=True)
    policy.add_argument("--mode", choices=("single", "multiple"), required=True)
    policy.set_defaults(func=cmd_policy)
    report = sub.add_parser("report-logout", help="Record passive caller evidence only; no inference or recovery.")
    report.add_argument("--lease-id", required=True)
    report.add_argument("--agent-id", required=True)
    report.add_argument("--reason", choices=("user-observed", "signed-out-ui", "session-rejected"), required=True)
    report.set_defaults(func=cmd_report_logout)
    for command in (acquire, renew, register, release):
        command.add_argument("--manager-id", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, 'selection_proof_stdin', False):
        args.selection_proof = sys.stdin.readline().strip()
    try:
        instance_key(args)
    except ValueError as exc:
        parser.error(str(exc))
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"policy-set", "logout-reported", "ok", "available", "locked", "anonymous", "leased", "already-owned", "renewed", "registered", "registered-unreachable", "released", "account-not-found", "account-unavailable"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
