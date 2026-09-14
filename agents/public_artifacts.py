#!/usr/bin/env python3
"""BBH CLI for Bounty Core's owned public-artifact registry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


    current = subparsers.add_parser("current", help="List currently reusable owned artifacts")
    current.add_argument("--program", required=True)
    current.add_argument("--include-cleaned", action="store_true")
    current.add_argument("--limit", type=int, default=100)
    return parser


def _store(args: argparse.Namespace) -> PublicArtifactStore:
    return PublicArtifactStore(args.program, family=args.family, lane=args.lane, root_override=args.root)


def _validate_canonical_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--url must be an absolute http(s) artifact URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--url must be a canonical URL without credentials, query parameters, or a fragment")


def _latest_artifact(store: PublicArtifactStore, artifact_id: str | None) -> dict[str, Any] | None:
    if not artifact_id:
        return None
    return next((row for row in store.current(include_cleaned=True, limit=10_000) if row["artifact_id"] == artifact_id), None)


def _validate_cleanup_event(store: PublicArtifactStore, args: argparse.Namespace) -> None:
    if args.event not in {"cleanup_pending", "deleted", "cleanup_verified"}:
        return
    if not args.artifact_id:
        raise ValueError("artifact_id is required for lifecycle events after creation")
    if args.visibility != "private":
        raise ValueError(f"{args.event} requires --visibility private; make the artifact private before cleanup")
    latest = _latest_artifact(store, args.artifact_id)
    if args.event == "cleanup_pending":
        return
    required_prior = "cleanup_pending" if args.event == "deleted" else "deleted"
    if latest is None or latest["event"] != required_prior:
        raise ValueError(f"{args.event} requires a prior {required_prior} event for the same artifact")


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.command == "record":
        _validate_canonical_url(args.url)
        _validate_cleanup_event(store, args)
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
            details={},
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
