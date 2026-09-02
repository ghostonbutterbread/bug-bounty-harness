#!/usr/bin/env python3
"""Create, search, and lifecycle-update public MapStore lead projections."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.map_store import MapStore

VALID_LEAD_STATUSES = {"active", "candidate", "needs_recheck", "stale", "archived", "failed"}


def build_lead_body(*, observed_basis: str, candidate_chain: str, exact_unknown: str,
                    next_discriminator: str, blocker: str, wake_condition: str,
                    evidence_refs: list[str]) -> str:
    return "\n".join((
        "Lead:",
        f"- Observed basis: {observed_basis}",
        f"- Candidate chain: {candidate_chain}",
        f"- Exact unknown: {exact_unknown}",
        f"- Blocker: {blocker or 'none'}",
        f"- Next discriminator: {next_discriminator}",
        f"- Wake condition: {wake_condition or 'none'}",
        f"- Evidence: {', '.join(evidence_refs) or 'none'}",
    )) + "\n"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="command", required=True)
    def common(s: argparse.ArgumentParser) -> None:
        s.add_argument("--program", required=True); s.add_argument("--family", default="web_bounty")
        s.add_argument("--lane", default="web"); s.add_argument("--root", default=None)
    create = subs.add_parser("create", help="Create an evidence-backed public lead")
    common(create); create.add_argument("--class", dest="vuln_class", required=True); create.add_argument("--surface", required=True)
    create.add_argument("--title", required=True); create.add_argument("--url", default=""); create.add_argument("--scope", default="url")
    create.add_argument("--observed-basis", required=True); create.add_argument("--candidate-chain", required=True)
    create.add_argument("--exact-unknown", required=True); create.add_argument("--next-discriminator", required=True)
    create.add_argument("--blocker", default=""); create.add_argument("--wake-condition", default="")
    create.add_argument("--evidence-ref", action="append", required=True); create.add_argument("--tag", action="append", default=[])
    create.add_argument("--agent", default="ghost"); create.add_argument("--run-id", default=None); create.add_argument("--status", default="candidate")
    search = subs.add_parser("search", help="Search public leads")
    common(search); search.add_argument("--class", dest="vuln_class", default=""); search.add_argument("--status", default="active,candidate,needs_recheck")
    status = subs.add_parser("update-status", help="Update a lead lifecycle status")
    common(status); status.add_argument("--path", required=True); status.add_argument("--status", required=True); status.add_argument("--reason", required=True); status.add_argument("--agent", default="ghost")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = MapStore(args.program, family=args.family, lane=args.lane, root=args.root, create=True)
    store.init()
    if args.command == "create":
        tags = ["lead", args.vuln_class, *args.tag]
        path = store.write(url=args.url, surface=args.surface,
            body=build_lead_body(observed_basis=args.observed_basis, candidate_chain=args.candidate_chain,
                exact_unknown=args.exact_unknown, next_discriminator=args.next_discriminator,
                blocker=args.blocker, wake_condition=args.wake_condition, evidence_refs=args.evidence_ref),
            scope=args.scope, tags=tags, agent=args.agent, run_id=args.run_id, title=args.title, status=args.status)
        print(path.relative_to(store.maps_root).as_posix()); return 0
    if args.command == "search":
        tags = ["lead"] + ([args.vuln_class] if args.vuln_class else [])
        for lead in store.query(tags=tags, statuses=args.status.split(",")):
            print(f"{lead['status']}\t{lead.get('surface','')}\t{lead.get('title','')}\t{lead['path']}")
        return 0
    if args.status not in VALID_LEAD_STATUSES:
        raise ValueError(f"invalid lead status: {args.status}; use one of {sorted(VALID_LEAD_STATUSES)}")
    entry = next((item for item in store.query(include_archived=True) if item.get("path") == args.path), None)
    if entry is None or "lead" not in entry.get("tags", []):
        raise ValueError("update-status requires a MapStore lead path")
    updated = store.update_status(path=args.path, status=args.status, reason=args.reason, agent=args.agent)
    print(updated["path"]); return 0


if __name__ == "__main__":
    raise SystemExit(main())
