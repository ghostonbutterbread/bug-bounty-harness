#!/usr/bin/env python3
"""BBH CLI for known external blockers and end-of-run blocker briefs."""

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

    record = subparsers.add_parser("record", help="Record an external blocker the agent cannot solve")
    record.add_argument("--program", required=True)
    record.add_argument("--producer", required=True)
    record.add_argument("--run-id", required=True)
    record.add_argument("--subject", required=True, help="Exact route, operation, or flow being gated")
    record.add_argument("--test-scope", required=True)
    record.add_argument("--blocker-key", required=True, help="Stable prerequisite key")
    record.add_argument("--blocker-type", required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--state", choices=("open", "resolved", "superseded"), default="open")
    record.add_argument("--unblock-condition", help="External action that wakes an open blocker; omit for resolved/superseded events")
    record.add_argument("--account-ref", action="append", default=[])
    record.add_argument("--capability")
    record.add_argument("--fixture")
    record.add_argument("--attempt-ref")
    record.add_argument("--artifact-ref")
    record.add_argument("--details-json", default="{}")

    check = subparsers.add_parser("check", help="Check for known open blockers before spending effort")
    check.add_argument("--program", required=True)
    check.add_argument("--subject", required=True)
    check.add_argument("--test-scope", required=True)
    check.add_argument("--blocker-key")

    brief = subparsers.add_parser("brief", help="Return open blockers from one completed run")
    brief.add_argument("--program", required=True)
    brief.add_argument("--run-id", required=True)
    brief.add_argument("--limit", type=int, default=100)

    query = subparsers.add_parser("query", help="Diagnostic blocker read; not required for ordinary testing")
    query.add_argument("--program", required=True)
    query.add_argument("--intent", choices=("events", "active"), default="events")
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


def _brief_item(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in (
        "blocker_id", "blocker_key", "blocker_type", "subject", "test_scope", "reason",
        "unblock_condition", "account_refs", "capability", "fixture", "attempt_ref", "artifact_ref",
    )}


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.command == "record":
        return store.record(
            producer=args.producer, run_id=args.run_id, subject=args.subject, test_scope=args.test_scope,
            blocker_key=args.blocker_key, blocker_type=args.blocker_type, reason=args.reason, state=args.state,
            unblock_condition=args.unblock_condition, account_refs=args.account_ref, capability=args.capability,
            fixture=args.fixture, attempt_ref=args.attempt_ref, artifact_ref=args.artifact_ref,
            details=_details(args.details_json),
        )
    if args.command == "check":
        blockers = store.active(subject=args.subject, test_scope=args.test_scope, limit=100)
        if args.blocker_key:
            blockers = [row for row in blockers if row["blocker_key"] == args.blocker_key]
        return {
            "known_blocker": bool(blockers),
            "blockers": [_brief_item(row) for row in blockers],
            "next_action": (
                "Do not repeat setup or exploratory work for these blockers; continue only if the agent can perform the stated unblock condition."
                if blockers else "No known external blocker matches this scope. Continue normal work; record one only if the agent cannot perform the unblock."
            ),
        }
    if args.command == "brief":
        result = store.brief(run_id=args.run_id, limit=args.limit)
        blockers = [_brief_item(row) for row in result.pop("open_blockers")]
        result["open_blockers"] = blockers
        result["what_happened"] = (
            "The run completed with no externally blocked work."
            if not blockers else f"The run completed with {len(blockers)} external blocker(s) left open."
        )
        result["next_to_push"] = [row["unblock_condition"] for row in blockers]
        return result
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
