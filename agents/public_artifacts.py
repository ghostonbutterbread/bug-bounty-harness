#!/usr/bin/env python3
"""BBH CLI for Bounty Core's owned public-artifact registry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bounty_core import PublicArtifactStore  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Shared storage base override (test/local use)")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="Append a non-secret owned-artifact lifecycle event")
    record.add_argument("--program", required=True)
    record.add_argument("--event", required=True, choices=("created", "updated", "visibility_changed", "cleanup_pending", "deleted", "cleanup_verified"))
    record.add_argument("--producer", default="public-artifacts")
    record.add_argument("--account-ref", required=True, help="Owned account alias or approved non-secret email/username")
    record.add_argument("--artifact-kind", required=True)
    record.add_argument("--url", required=True)
    record.add_argument("--artifact-id")
    record.add_argument("--object-id")
    record.add_argument("--visibility", default="unknown", choices=("private", "unlisted", "community", "public", "unknown"))
    record.add_argument("--purpose")
    record.add_argument("--cleanup-method")
    record.add_argument("--cleanup-verified", action="store_true")
    record.add_argument("--details-json", default="{}")

    current = subparsers.add_parser("current", help="List currently reusable owned artifacts")
    current.add_argument("--program", required=True)
    current.add_argument("--include-cleaned", action="store_true")
    current.add_argument("--limit", type=int, default=100)
    return parser


def _details(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"--details-json must be a JSON object: {error.msg}") from error
    if not isinstance(parsed, dict):
        raise ValueError("--details-json must be a JSON object")
    return parsed


def _store(args: argparse.Namespace) -> PublicArtifactStore:
    return PublicArtifactStore(args.program, family=args.family, lane=args.lane, root_override=args.root)


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.command == "record":
        return store.record(
            event=args.event,
            producer=args.producer,
            account_ref=args.account_ref,
            artifact_kind=args.artifact_kind,
            url=args.url,
            artifact_id=args.artifact_id,
            object_id=args.object_id,
            visibility=args.visibility,
            purpose=args.purpose,
            cleanup_method=args.cleanup_method,
            cleanup_verified=args.cleanup_verified,
            details=_details(args.details_json),
        )
    if args.command == "current":
        artifacts = store.current(include_cleaned=args.include_cleaned, limit=args.limit)
        return {"artifacts": artifacts, "returned_count": len(artifacts)}
    raise ValueError(f"unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args), sort_keys=True))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
