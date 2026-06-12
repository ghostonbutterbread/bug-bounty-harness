#!/usr/bin/env python3
"""Non-secret owned account/resource inventory for bug bounty agent handoffs."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
FORBIDDEN_HINTS = (
    "password",
    "passwd",
    "cookie",
    "bearer ",
    "authorization:",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private key",
    "reset link",
    "recovery code",
)

PWNFOX_CONFIG = {
    "header_name": "X-PwnFox-Color",
    "header_value_format": "lowercase color string",
    "caido_httpql_presence_filter": 'req.raw.cont:"X-PwnFox-Color"',
    "caido_httpql_color_filter_template": 'req.raw.cont:"X-PwnFox-Color" AND req.raw.cont:"{color}"',
    "observed_values": [],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def shared_base() -> Path:
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/bounty_recon")).expanduser()


def inventory_path(program: str) -> Path:
    return shared_base() / program / "credentials" / "account_inventory.json"


def blank_inventory(program: str) -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "program": program,
        "created_at": now,
        "updated_at": now,
        "accounts": [],
        "resources": [],
        "pwnfox_lanes": [],
        "proxy_identity": {
            "pwnfox": dict(PWNFOX_CONFIG),
        },
        "notes": [
            "Non-secret owned-account inventory. Do not store passwords, cookies, tokens, reset links, API keys, or private request bodies here."
        ],
    }


def load_inventory(program: str) -> dict[str, Any]:
    path = inventory_path(program)
    if not path.exists():
        return blank_inventory(program)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("program", program)
    data.setdefault("accounts", [])
    data.setdefault("resources", [])
    data.setdefault("pwnfox_lanes", [])
    data.setdefault("proxy_identity", {})
    data["proxy_identity"].setdefault("pwnfox", dict(PWNFOX_CONFIG))
    for key, value in PWNFOX_CONFIG.items():
        data["proxy_identity"]["pwnfox"].setdefault(key, value)
    data.setdefault("notes", [])
    return data


def save_inventory(program: str, data: dict[str, Any]) -> Path:
    path = inventory_path(program)
    path.parent.mkdir(parents=True, exist_ok=True)
    data["program"] = program
    data["schema_version"] = SCHEMA_VERSION
    data["updated_at"] = utc_now()

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        tmp_name = handle.name
    Path(tmp_name).replace(path)
    return path


def reject_secretish(values: dict[str, Any]) -> None:
    for key, value in values.items():
        if value is None:
            continue
        text = str(value).lower()
        if key in {"notes", "source"}:
            # These can contain natural language. Still catch obvious credential blobs.
            pass
        if any(hint in text for hint in FORBIDDEN_HINTS):
            raise SystemExit(f"refusing to store possible secret material in field {key!r}")


def compact_record(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "")}


def upsert(items: list[dict[str, Any]], record: dict[str, Any], keys: tuple[str, ...]) -> str:
    now = utc_now()
    for item in items:
        if all(str(item.get(key, "")) == str(record.get(key, "")) for key in keys):
            item.update(record)
            item["updated_at"] = now
            return "updated"
    record.setdefault("created_at", now)
    record["updated_at"] = now
    items.append(record)
    return "added"


def cmd_init(args: argparse.Namespace) -> int:
    data = load_inventory(args.program)
    path = save_inventory(args.program, data)
    print(path)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_inventory(args.program)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    path = inventory_path(args.program)
    print(f"Path: {path}")
    print(f"Accounts: {len(data.get('accounts', []))}")
    for account in data.get("accounts", []):
        parts = [
            account.get("alias", ""),
            account.get("email") or account.get("username") or "",
            f"user_id={account.get('user_id')}" if account.get("user_id") else "",
            f"role={account.get('role')}" if account.get("role") else "",
            f"pwnfox={account.get('pwnfox_color')}" if account.get("pwnfox_color") else "",
            f"destructible={account.get('destructible')}" if account.get("destructible") else "",
        ]
        print("  - " + " ".join(part for part in parts if part))
    print(f"Resources: {len(data.get('resources', []))}")
    for resource in data.get("resources", []):
        parts = [
            resource.get("type", ""),
            resource.get("id", ""),
            f"name={resource.get('name')}" if resource.get("name") else "",
            f"owner={resource.get('owner')}" if resource.get("owner") else "",
            f"cleanup={resource.get('cleanup_needed')}" if resource.get("cleanup_needed") else "",
        ]
        print("  - " + " ".join(part for part in parts if part))
    print(f"PwnFox lanes: {len(data.get('pwnfox_lanes', []))}")
    pwnfox = data.get("proxy_identity", {}).get("pwnfox", {})
    if pwnfox:
        print(f"PwnFox header: {pwnfox.get('header_name')}")
        print(f"PwnFox presence filter: {pwnfox.get('caido_httpql_presence_filter')}")
    for lane in data.get("pwnfox_lanes", []):
        print(f"  - {lane.get('color')} -> {lane.get('account')}")
    return 0


def cmd_add_account(args: argparse.Namespace) -> int:
    values = compact_record(
        {
            "alias": args.alias,
            "email": args.email,
            "username": args.username,
            "user_id": args.user_id,
            "role": args.role,
            "tenant_id": args.tenant_id,
            "credential_ref": args.credential_ref,
            "auth_seed_ref": args.auth_seed_ref,
            "auth_refresh_source": args.auth_refresh_source,
            "auth_refresh_hint": args.auth_refresh_hint,
            "pwnfox_color": args.pwnfox_color,
            "destructible": args.destructible,
            "source": args.source,
            "notes": args.notes,
        }
    )
    reject_secretish(values)
    data = load_inventory(args.program)
    action = upsert(data["accounts"], values, ("alias",))
    if args.pwnfox_color:
        upsert(
            data["pwnfox_lanes"],
            compact_record({"color": args.pwnfox_color.lower(), "account": args.alias, "source": args.source}),
            ("color",),
        )
    path = save_inventory(args.program, data)
    print(f"{action} account {args.alias} in {path}")
    return 0


def cmd_add_resource(args: argparse.Namespace) -> int:
    values = compact_record(
        {
            "type": args.type,
            "id": args.id,
            "name": args.name,
            "owner": args.owner,
            "url": args.url,
            "pwnfox_color": args.pwnfox_color,
            "run_id": args.run_id,
            "session_id": args.session_id,
            "cleanup_needed": args.cleanup_needed,
            "destructible": args.destructible,
            "source": args.source,
            "notes": args.notes,
        }
    )
    reject_secretish(values)
    data = load_inventory(args.program)
    action = upsert(data["resources"], values, ("type", "id"))
    path = save_inventory(args.program, data)
    print(f"{action} resource {args.type}:{args.id} in {path}")
    return 0


def cmd_link_pwnfox(args: argparse.Namespace) -> int:
    values = compact_record(
        {
            "color": args.color.lower(),
            "account": args.account,
            "source": args.source,
            "notes": args.notes,
        }
    )
    reject_secretish(values)
    data = load_inventory(args.program)
    action = upsert(data["pwnfox_lanes"], values, ("color",))
    observed = data["proxy_identity"]["pwnfox"].setdefault("observed_values", [])
    if args.color.lower() not in observed:
        observed.append(args.color.lower())
        observed.sort()
    path = save_inventory(args.program, data)
    print(f"{action} PwnFox lane {args.color.lower()} in {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create or normalize an inventory file.")
    init.add_argument("program")
    init.set_defaults(func=cmd_init)

    show = sub.add_parser("show", help="Show non-secret inventory summary.")
    show.add_argument("program")
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=cmd_show)

    account = sub.add_parser("add-account", help="Add or update an owned test account record.")
    account.add_argument("program")
    account.add_argument("--alias", required=True)
    account.add_argument("--email")
    account.add_argument("--username")
    account.add_argument("--user-id")
    account.add_argument("--role")
    account.add_argument("--tenant-id")
    account.add_argument("--credential-ref")
    account.add_argument(
        "--auth-seed-ref",
        help="Non-secret pointer to a locked-down auth seed, for example auth-seed:/absolute/path.json.",
    )
    account.add_argument(
        "--auth-refresh-source",
        choices=("none", "ryushe-proxy", "manual", "secret-store"),
        help="Approved fallback source for refreshing stale account auth. Never stores secret values.",
    )
    account.add_argument(
        "--auth-refresh-hint",
        help="Non-secret hint for locating the account in the approved refresh source, such as pwnfox:blue.",
    )
    account.add_argument("--pwnfox-color")
    account.add_argument("--destructible", choices=("yes", "no", "unknown"), default="unknown")
    account.add_argument("--source", default="manual")
    account.add_argument("--notes")
    account.set_defaults(func=cmd_add_account)

    resource = sub.add_parser("add-resource", help="Add or update an owned resource/object record.")
    resource.add_argument("program")
    resource.add_argument("--type", required=True)
    resource.add_argument("--id", required=True)
    resource.add_argument("--name")
    resource.add_argument("--owner")
    resource.add_argument("--url")
    resource.add_argument("--pwnfox-color")
    resource.add_argument("--run-id")
    resource.add_argument("--session-id")
    resource.add_argument("--cleanup-needed", choices=("yes", "no", "unknown"), default="unknown")
    resource.add_argument("--destructible", choices=("yes", "no", "unknown"), default="unknown")
    resource.add_argument("--source", default="manual")
    resource.add_argument("--notes")
    resource.set_defaults(func=cmd_add_resource)

    lane = sub.add_parser("link-pwnfox", help="Map a PwnFox color to an owned account alias.")
    lane.add_argument("program")
    lane.add_argument("--color", required=True)
    lane.add_argument("--account", required=True)
    lane.add_argument("--source", default="manual")
    lane.add_argument("--notes")
    lane.set_defaults(func=cmd_link_pwnfox)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
