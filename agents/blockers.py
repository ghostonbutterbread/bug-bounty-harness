#!/usr/bin/env python3
"""BBH CLI for Bounty Core's prerequisite-aware Blocker Store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bounty_core import BlockerStore  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Shared storage base override (test/local use)")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="Append one redacted blocker lifecycle event")
    record.add_argument("--program", required=True)
    record.add_argument("--producer", required=True)
    record.add_argument("--subject", required=True, help="Exact route, operation, or flow being gated")
    record.add_argument("--test-scope", required=True, help="For example access-control:horizontal:campaign")
    record.add_argument("--blocker-key", required=True, help="Stable dedupe key for this prerequisite")
    record.add_argument("--blocker-type", required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--state", choices=("open", "resolved", "superseded"), default="open")
    record.add_argument("--unblock-condition")
    record.add_argument("--account-ref", action="append", default=[])
    record.add_argument("--capability")
    record.add_argument("--fixture")
    record.add_argument("--attempt-ref")
    record.add_argument("--artifact-ref")
    record.add_argument("--details-json", default="{}")

    query = subparsers.add_parser("query", help="Read bounded blocker evidence or a coverage gate")
    query.add_argument("--program", required=True)
    query.add_argument("--intent", choices=("events", "active", "coverage"), default="events")
    query.add_argument("--subject")
    query.add_argument("--test-scope")
    query.add_argument("--blocker-key")
    query.add_argument("--limit", type=int, default=100)
    return parser


def _details(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"--details-json must be a JSON object: {error.msg}") from error
    if not isinstance(parsed, dict):
        raise ValueError("--details-json must be a JSON object")
    return parsed


def _store(args: argparse.Namespace) -> BlockerStore:
    return BlockerStore(args.program, family=args.family, lane=args.lane, root_override=args.root)


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.command == "record":
        return store.record(
            producer=args.producer, subject=args.subject, test_scope=args.test_scope,
            blocker_key=args.blocker_key, blocker_type=args.blocker_type, reason=args.reason,
            state=args.state, unblock_condition=args.unblock_condition, account_refs=args.account_ref,
            capability=args.capability, fixture=args.fixture, attempt_ref=args.attempt_ref,
            artifact_ref=args.artifact_ref, details=_details(args.details_json),
        )
    if args.intent == "coverage":
        if not args.subject or not args.test_scope:
            raise ValueError("--subject and --test-scope are required for coverage intent")
        return store.coverage_gate(subject=args.subject, test_scope=args.test_scope)
    if args.intent == "active":
        return {"events": store.active(subject=args.subject, test_scope=args.test_scope, limit=args.limit)}
    where = {key: value for key, value in {
        "subject": args.subject, "test_scope": args.test_scope, "blocker_key": args.blocker_key,
    }.items() if value is not None}
    return {"events": store.query(where=where, limit=args.limit)}


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args), sort_keys=True))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
