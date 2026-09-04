#!/usr/bin/env python3
"""BBH CLI for Bounty Core's lane-scoped Error Store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bounty_core import ErrorStore  # noqa: E402


VALID_QUERY_INTENTS = ("events", "dedupe")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Shared storage base override (test/local use)")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="Append one redacted observed error event")
    record.add_argument("--program", required=True)
    record.add_argument("--producer", required=True)
    record.add_argument("--subject", required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--layer", required=True)
    record.add_argument("--channel", required=True)
    record.add_argument("--status-or-event", required=True)
    record.add_argument("--fingerprint", required=True)
    record.add_argument("--trigger-family", required=True)
    record.add_argument("--novelty-basis", help="Required for edge events; state the controlled differential or disclosure")
    record.add_argument("--input-location")
    record.add_argument("--actor-context", default="unknown")
    record.add_argument("--reproducibility", default="observed-once")
    record.add_argument("--attempt-ref")
    record.add_argument("--artifact-ref")
    record.add_argument("--details-json", default="{}")

    query = subparsers.add_parser("query", help="Read bounded redacted error evidence")
    query.add_argument("--program", required=True)
    query.add_argument("--intent", choices=VALID_QUERY_INTENTS, default="events")
    query.add_argument("--fingerprint")
    query.add_argument("--subject")
    query.add_argument("--layer")
    query.add_argument("--channel")
    query.add_argument("--limit", type=int, default=100)
    return parser


def _store(args: argparse.Namespace) -> ErrorStore:
    return ErrorStore(args.program, family=args.family, lane=args.lane, root_override=args.root)


def _details(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"--details-json must be a JSON object: {error.msg}") from error
    if not isinstance(parsed, dict):
        raise ValueError("--details-json must be a JSON object")
    return parsed


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.command == "record":
        details = _details(args.details_json)
        if args.layer.lower() == "edge":
            novelty_basis = str(args.novelty_basis or "").strip()
            if not novelty_basis:
                raise ValueError("--novelty-basis is required for edge events; record routine branded/WAF responses as WAF telemetry")
            details["novelty_basis"] = novelty_basis
        return store.record(
            producer=args.producer,
            subject=args.subject,
            reason=args.reason,
            layer=args.layer,
            channel=args.channel,
            status_or_event=args.status_or_event,
            fingerprint=args.fingerprint,
            trigger_family=args.trigger_family,
            input_location=args.input_location,
            actor_context=args.actor_context,
            reproducibility=args.reproducibility,
            attempt_ref=args.attempt_ref,
            artifact_ref=args.artifact_ref,
            details=details,
        )
    if args.command == "query":
        where = {key: value for key, value in {
            "fingerprint": args.fingerprint,
            "subject": args.subject,
            "layer": args.layer,
            "channel": args.channel,
        }.items() if value is not None}
        events = store.query(where=where, limit=args.limit)
        result: dict[str, Any] = {"intent": args.intent, "events": events, "returned_count": len(events)}
        if args.intent == "dedupe":
            result["fingerprints"] = store.fingerprint_summary(where=where, limit=args.limit)
        return result
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
