#!/usr/bin/env python3
"""BBH CLI for the private-first, heartbeat-backed hypothesis ledger."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from bounty_core.hypothesis_ledger import DEFAULT_TTL_SECONDS, UNRESOLVED_STATUSES, HypothesisLedger  # noqa: E402
from agents.map_store import MapStore  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Shared storage base override (test/local use)")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def program_command(name: str) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name)
        command.add_argument("program")
        command.add_argument("--agent-id", required=True)
        command.add_argument("--run-id", required=True)
        return command

    create = program_command("create")
    create.add_argument("--title", required=True)
    create.add_argument("--surface", required=True)
    create.add_argument("--url")
    create.add_argument("--tag", action="append", default=[])
    create.add_argument("--parent-id")
    create.add_argument("--lead-id", help="Opaque public Lead ID for explicit follow-up context")
    create.add_argument("--expected-chain")
    create.add_argument("--next-discriminator")
    create.add_argument("--evidence-ref", action="append", default=[])

    heartbeat = program_command("heartbeat")
    _ = heartbeat

    listing = program_command("list")
    listing.add_argument("--url")
    listing.add_argument("--surface")
    listing.add_argument("--tag", action="append", default=[])
    listing.add_argument("--status", action="append")

    release = program_command("release")
    release.add_argument("hypothesis_id")

    followup = program_command("lead-followup")
    followup.add_argument("--lead-id", required=True)

    peer_surface_review = program_command("peer-surface-review")
    peer_surface_review.add_argument("--surface", required=True)
    peer_surface_review.add_argument("--url", required=True)
    peer_surface_review.add_argument("--review-intent", required=True)
    peer_surface_review.add_argument("--tag", action="append", default=[])
    peer_surface_review.add_argument("--status", action="append")
    peer_surface_review.add_argument("--limit", type=int, default=25)
    peer_surface_review.add_argument("--cursor")

    operator_app_review = program_command("operator-app-review")
    operator_app_review.add_argument("--operator-request-id", required=True)
    operator_app_review.add_argument("--operator-intent", required=True)
    operator_app_review.add_argument("--status", action="append")
    operator_app_review.add_argument("--limit", type=int, default=50)
    operator_app_review.add_argument("--cursor")

    continuation = program_command("continuation")
    continuation.add_argument("--surface")

    transition = program_command("transition")
    transition.add_argument("hypothesis_id")
    transition.add_argument("--status", required=True, choices=sorted(UNRESOLVED_STATUSES))

    reclaim = program_command("reclaim")
    reclaim.add_argument("hypothesis_id")

    delegate = program_command("delegate")
    delegate.add_argument("hypothesis_id")
    delegate.add_argument("--child-agent-id", required=True)
    delegate.add_argument("--child-run-id", required=True)

    complete = program_command("complete")
    complete.add_argument("hypothesis_id")
    complete.add_argument("--status", default="completed", choices=["completed", "disproved", "retired", "combined"])
    return parser


def _ledger(args: argparse.Namespace) -> HypothesisLedger:
    return HypothesisLedger(
        args.program,
        family=args.family,
        lane=args.lane,
        root_override=args.root,
        ttl_seconds=args.ttl_seconds,
    )


def _public_lead(args: argparse.Namespace, lead_id: str) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Resolve one exact public MapStore lead card for a deliberate follow-up."""
    store = MapStore(args.program, family=args.family, lane=args.lane, root=args.root, create=False)
    lead = next(
        (
            entry
            for entry in store.query(include_archived=True)
            if "lead" in entry.get("tags", [])
            and (
                entry.get("path") == lead_id
                or str(store.maps_root / entry.get("path", "")) == lead_id
            )
        ),
        None,
    )
    if lead is None:
        raise ValueError("lead-followup requires an exact public MapStore lead ID/path")
    canonical_relative_id = str(lead["path"])
    canonical_absolute_id = str(store.maps_root / canonical_relative_id)
    return lead, tuple(dict.fromkeys((canonical_relative_id, canonical_absolute_id)))


def run(args: argparse.Namespace) -> dict[str, Any]:
    ledger = _ledger(args)
    if args.command == "create":
        return ledger.create(
            agent_id=args.agent_id, run_id=args.run_id, title=args.title, surface=args.surface,
            url=args.url, tags=args.tag, parent_id=args.parent_id, lead_id=args.lead_id,
            expected_chain=args.expected_chain, next_discriminator=args.next_discriminator, evidence_refs=args.evidence_ref,
        )
    if args.command == "heartbeat":
        return ledger.heartbeat(agent_id=args.agent_id, run_id=args.run_id)
    if args.command == "list":
        return {"hypotheses": ledger.list_visible(
            agent_id=args.agent_id, run_id=args.run_id, url=args.url, surface=args.surface,
            tags=args.tag, statuses=args.status,
        )}
    if args.command == "release":
        return ledger.release(args.hypothesis_id, agent_id=args.agent_id, run_id=args.run_id)
    if args.command == "lead-followup":
        lead, lead_ids = _public_lead(args, args.lead_id)
        hypotheses_by_id: dict[str, dict[str, Any]] = {}
        for candidate_lead_id in lead_ids:
            for hypothesis in ledger.lead_followup(
                agent_id=args.agent_id, run_id=args.run_id, lead_id=candidate_lead_id,
            ):
                hypotheses_by_id.setdefault(hypothesis["id"], hypothesis)
        ordered_hypotheses = sorted(
            hypotheses_by_id.values(),
            key=lambda hypothesis: (hypothesis["created_at"], hypothesis["id"]),
        )
        return {"lead": lead, "hypotheses": ordered_hypotheses}
    if args.command == "peer-surface-review":
        return ledger.review_current_surface(
            viewer_agent_id=args.agent_id,
            viewer_run_id=args.run_id,
            surface=args.surface,
            url=args.url,
            review_intent=args.review_intent,
            tags=args.tag,
            statuses=args.status,
            limit=args.limit,
            cursor=args.cursor,
        )
    if args.command == "operator-app-review":
        return ledger.operator_app_review(
            actor_agent_id=args.agent_id,
            actor_run_id=args.run_id,
            operator_request_id=args.operator_request_id,
            operator_intent=args.operator_intent,
            statuses=args.status,
            limit=args.limit,
            cursor=args.cursor,
        )
    if args.command == "continuation":
        return ledger.continuation_state(agent_id=args.agent_id, run_id=args.run_id, surface=args.surface)
    if args.command == "transition":
        return ledger.transition(args.hypothesis_id, agent_id=args.agent_id, run_id=args.run_id, status=args.status)
    if args.command == "reclaim":
        return ledger.reclaim(args.hypothesis_id, agent_id=args.agent_id, run_id=args.run_id)
    if args.command == "delegate":
        return ledger.delegate(
            args.hypothesis_id,
            agent_id=args.agent_id,
            run_id=args.run_id,
            child_agent_id=args.child_agent_id,
            child_run_id=args.child_run_id,
        )
    if args.command == "complete":
        return ledger.complete(args.hypothesis_id, agent_id=args.agent_id, run_id=args.run_id, status=args.status)
    raise ValueError(f"unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    print(json.dumps(run(args), sort_keys=True))


if __name__ == "__main__":
    main()
