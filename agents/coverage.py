#!/usr/bin/env python3
"""Dedicated CLI for mapped live-surface/class coverage."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.coverage_evidence import verify_references
from agents.surface_coverage import SurfaceCoverageStore

DEFAULT_AGENT = os.environ.get("ME_AGENT") or "codex"


def _surface_store(args: argparse.Namespace) -> SurfaceCoverageStore:
    return SurfaceCoverageStore(args.program, family=args.family, lane=args.lane,
                                root_override=getattr(args, "root_override", None))


def _xss_canary_inventory(records: list[dict], source_ref: str) -> list[dict]:
    """Project planned mapper inputs, never its canaries or scan verdicts."""
    if not source_ref:
        raise ValueError("--source-ref is required for XSS canary sources")
    rows = []
    for line_number, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValueError(f"XSS source line {line_number}: expected object")
        url = str(record.get("url") or "")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"XSS source line {line_number}: expected HTTP(S) URL without credentials")
        method = str(record.get("method") or "").upper()
        vector = str(record.get("vector") or "")
        field = str(record.get("field") or "")
        if not method or not vector or not field or not record.get("source_id"):
            raise ValueError(f"XSS source line {line_number}: incomplete mapper source")
        rows.append({"kind": "route", "host": parsed.netloc.lower(),
                     "surface_key": f"{method} {parsed.path or '/'}",
                     "input_key": f"{vector}:{field}", "consumer": "",
                     "class_names": ["xss"], "source_ref": f"{source_ref}:{record['source_id']}",
                     "run_id": record.get("run_id"), "fingerprint": ""})
    return rows


def cmd_surface_discover(args: argparse.Namespace) -> int:
    """Register mapped surfaces; no attempt or finding implies review state."""
    store = _surface_store(args)
    if args.input_jsonl and args.xss_canary_sources:
        raise ValueError("select only one inventory input")
    if args.input_jsonl or args.xss_canary_sources:
        input_path = args.input_jsonl or args.xss_canary_sources
        rows = []
        with Path(input_path).open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("expected JSON object")
                    rows.append(row)
                except ValueError as exc:
                    raise ValueError(f"inventory line {line_number}: {exc}") from exc
        if args.xss_canary_sources:
            rows = _xss_canary_inventory(rows, args.source_ref)
    else:
        rows = [{"kind": args.kind, "host": args.host, "surface_key": args.surface_key,
                 "input_key": args.input_key, "consumer": args.consumer,
                 "class_names": [args.class_name] if args.class_name else [],
                 "source_ref": args.source_ref, "run_id": args.run_id,
                 "fingerprint": args.fingerprint}]
    surface_ids = store.discover_many(rows)
    print(json.dumps({"discovered": len(surface_ids), "surface_ids": surface_ids,
                      "coverage_path": str(store.path)}, indent=2))
    return 0


def cmd_surface_assess(args: argparse.Namespace) -> int:
    store = _surface_store(args)
    result = store.assess(args.surface_id, class_name=args.class_name, status=args.status,
                          expected_fingerprint=args.expected_fingerprint,
                          evidence_refs=args.evidence_ref, reason=args.reason,
                          pressure=args.pressure, boundary=args.boundary,
                          axes=args.axis, reopen_when=args.reopen_when,
                          agent=args.agent,
                          run_id=args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    print(json.dumps({**result, "coverage_path": str(store.path)}, indent=2))
    return 0


def cmd_surface_brief(args: argparse.Namespace) -> int:
    print(json.dumps(_surface_store(args).brief(class_name=args.class_name,
                                                host=args.host, limit=args.limit,
                                                offset=args.offset), indent=2))
    return 0


def cmd_surface_history(args: argparse.Namespace) -> int:
    events = _surface_store(args).history(args.surface_id, class_name=args.class_name,
                                          limit=args.limit)
    print(json.dumps({"surface_id": args.surface_id, "class_name": args.class_name,
                      "events": events}, indent=2))
    return 0


def cmd_surface_verify(args: argparse.Namespace) -> int:
    events = _surface_store(args).history(args.surface_id, class_name=args.class_name, limit=1)
    if not events:
        raise ValueError("no assessment history for this surface/class")
    references = verify_references(args.program, family=args.family, lane=args.lane,
                                   root_override=args.root_override,
                                   refs=events[-1]["evidence_refs"])
    print(json.dumps({"surface_id": args.surface_id, "class_name": args.class_name,
                      "references": references}, indent=2))
    return 0


def register_commands(subparsers: argparse._SubParsersAction, *, legacy: bool = False) -> None:
    """Expose one parser/handler contract under dedicated or compatibility names."""
    prefix = "surface-" if legacy else ""

    def common(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--program", required=True)
        parser.add_argument("--family", default="binaries", help="Storage family, e.g. binaries or web_bounty.")
        parser.add_argument("--lane", default="apk", help="Storage lane, e.g. apk, exe, mac, web, api.")
        parser.add_argument("--root", dest="root_override", help="Explicit local canonical root override.")

    discover = subparsers.add_parser(prefix + "discover", help="Register mapped live surfaces and relevant class questions")
    common(discover)
    discover.add_argument("--input-jsonl", help="Inventory rows with class_names; no review status is inferred")
    discover.add_argument("--xss-canary-sources", help="Import planned XSS canary mapper sources.jsonl as no_assessment inputs; pair with --source-ref")
    for name in ("kind", "host", "surface-key", "input-key", "consumer", "class-name", "source-ref", "run-id", "fingerprint"):
        discover.add_argument("--" + name)
    discover.set_defaults(func=cmd_surface_discover)

    assess = subparsers.add_parser(prefix + "assess", help="Record an evidence-backed review of one surface/class")
    common(assess)
    assess.add_argument("--surface-id", required=True)
    assess.add_argument("--class-name", required=True)
    assess.add_argument("--status", required=True, choices=("in_progress", "blocked", "bounded_review", "exhausted"),
                        help="Review status; exhausted is a deprecated input alias for bounded_review")
    assess.add_argument("--expected-fingerprint", required=True,
                        help="Fingerprint shown by brief (legacy surface-brief) for the version actually reviewed; use '' only for unversioned inventory")
    assess.add_argument("--evidence-ref", action="append", default=[], help="Opaque Attempt or MapStore reference; repeatable")
    assess.add_argument("--reason", required=True)
    assess.add_argument("--pressure", default="", help="Optional class-specific state, e.g. XSS warm")
    assess.add_argument("--boundary", default="", help="Exact scoped conclusion, required for bounded_review")
    assess.add_argument("--axis", action="append", default=[], help="Tested dimension, required for bounded_review; repeatable")
    assess.add_argument("--reopen-when", default="", help="Required for blocked")
    assess.add_argument("--agent", default=DEFAULT_AGENT)
    assess.add_argument("--run-id", help="Assessment run identity; defaults to UTC timestamp")
    assess.set_defaults(func=cmd_surface_assess)

    brief = subparsers.add_parser(prefix + "brief", help="Bounded mapped-versus-tested class coverage")
    common(brief)
    brief.add_argument("--class-name")
    brief.add_argument("--host")
    brief.add_argument("--limit", type=int, default=50)
    brief.add_argument("--offset", type=int, default=0, help="Page offset; follow next_offset until null")
    brief.set_defaults(func=cmd_surface_brief)

    history = subparsers.add_parser(prefix + "history", help="Bounded assessment history for one mapped surface/class")
    common(history)
    history.add_argument("--surface-id", required=True)
    history.add_argument("--class-name", required=True)
    history.add_argument("--limit", type=int, default=50)
    history.set_defaults(func=cmd_surface_history)

    if not legacy:
        verify = subparsers.add_parser("verify", help="Read-only audit of current assessment evidence pointers")
        common(verify)
        verify.add_argument("--surface-id", required=True)
        verify.add_argument("--class-name", required=True)
        verify.set_defaults(func=cmd_surface_verify)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mapped live-surface coverage coordination")
    register_commands(parser.add_subparsers(dest="command"))
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return 1
    try:
        return int(args.func(args) or 0)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
