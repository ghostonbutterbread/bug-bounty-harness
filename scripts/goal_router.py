#!/usr/bin/env python3
"""Create explicit, policy-neutral routing briefs for `/goal` bug-bounty runs.

This utility does not contact targets, choose payloads, or launch agents. It
classifies an explicitly requested goal and writes the small routing state that
an orchestrator or agent can use to select existing BBH skills and artifacts.

Examples:
    bbh scripts/goal_router.py plan --program example --objective "Find a new vulnerability"
    bbh scripts/goal_router.py init --program example --objective "Assess XSS in preview" \
        --class xss --url https://app.example/preview --run-dir /tmp/example-goal
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.surface_coverage import SurfaceCoverageStore, _plain


MODES = {
    "broad-program",
    "focused-surface",
    "technology-review",
    "continuation",
    "revalidation",
}
REVALIDATION_WORDS = ("retest", "revalidate", "revalidation", "repass", "old issue", "old lead", "previously tested")
CONTINUATION_WORDS = ("continue", "resume", "warm lead", "hot lead", "roadblock", "stuck")
TECHNOLOGY_WORDS = (
    "technology",
    "implementation",
    "library",
    "framework",
    "dompurify",
    "sanitizer",
    "parser",
    "render path",
    "source code",
    "javascript",
)
CLASS_SKILLS = {
    "access-control": "access-control",
    "ai": "ai-tester",
    "ai-security": "ai-tester",
    "auth": "ato",
    "csrf": "csrf",
    "dom-xss": "dom-xss",
    "idor": "idor",
    "lfi": "lfi",
    "race": "race",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "sqli": "sqli",
    "xss": "xss",
}
BASE_SKILLS = ["bug-goals", "general-security-testing-policy", "live-testing-policy", "coverage"]
RETRIEVAL_CAPABILITIES = [
    "map-store-target-facts",
    "research-map",
    "preview-mcp",
    "official-docs-and-source",
    "independent-web-research",
]


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalized(text: str | None) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def classify_goal(*, objective: str, url: str | None = None, vulnerability_class: str | None = None) -> str:
    """Classify only an explicit `/goal`; normal agent work never calls this."""
    text = normalized(" ".join((objective, url or "", vulnerability_class or "")))
    if contains_any(text, REVALIDATION_WORDS):
        return "revalidation"
    if contains_any(text, CONTINUATION_WORDS):
        return "continuation"
    if contains_any(text, TECHNOLOGY_WORDS) and not vulnerability_class:
        return "technology-review"
    if url or vulnerability_class:
        return "focused-surface"
    return "broad-program"


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def mode_skills(mode: str, vulnerability_class: str | None) -> list[str]:
    if mode == "broad-program":
        skills = BASE_SKILLS + [
            "hunter-loop",
            "hunt-orchestration-policy",
            "recon",
            "live-map",
            "hunter-memory",
            "hypothesis-expansion-policy",
        ]
    elif mode == "focused-surface":
        skills = BASE_SKILLS + ["live-map", "hunter-memory", "hypothesis-expansion-policy"]
    elif mode == "technology-review":
        skills = BASE_SKILLS + ["js", "live-map", "hypothesis-expansion-policy"]
    elif mode == "continuation":
        skills = BASE_SKILLS + ["hunter-memory", "map-store", "hypothesis-expansion-policy"]
    elif mode == "revalidation":
        skills = BASE_SKILLS + ["map-store", "hunter-memory"]
    else:
        raise ValueError(f"unknown goal mode: {mode}")
    class_skill = CLASS_SKILLS.get(normalized(vulnerability_class))
    return unique(skills + ([class_skill] if class_skill else []))


def build_plan(*, program: str, objective: str, url: str | None = None, vulnerability_class: str | None = None) -> dict[str, Any]:
    if not program.strip():
        raise ValueError("program is required")
    if not objective.strip():
        raise ValueError("objective is required")
    mode = classify_goal(objective=objective, url=url, vulnerability_class=vulnerability_class)
    artifact_kind = "hunter-loop" if mode == "broad-program" else "attempts"
    if mode == "continuation":
        artifact_kind = "hunter-memory"
    if mode == "revalidation":
        artifact_kind = "revalidation"
    return {
        "program": program.strip(),
        "objective": objective.strip(),
        "url": url.strip() if url else None,
        "vulnerability_class": normalized(vulnerability_class) or None,
        "mode": mode,
        "skills": mode_skills(mode, vulnerability_class),
        "capabilities": RETRIEVAL_CAPABILITIES,
        "run_artifact_kind": artifact_kind,
        "historical_material": "primary" if mode == "revalidation" else "targeted-after-fresh-observation",
        "opening_contract": opening_contract(mode),
        "completion_contract": completion_contract(mode),
        "checkpoint_contract": (
            "At a goal pivot and before a negative stop, read the class/lane Coverage brief "
            "and source-attributed surface inventory; choose deepen, explore, map, unblock, "
            "or bounded-stop with named residuals. The parent owns this decision in solo "
            "and coordinated runs. A bounded stop is not goal completion."
        ),
        "research_contract": [
            "Use target observation and internal surface synthesis before broad retrieval when sufficient evidence exists.",
            "MapStore is available but must not be queried until a concrete current surface and decision question exist.",
            "MapStore then answers target-specific facts, tested state, coverage, and durable constraints for that question.",
            "ResearchMap, Preview MCP, official source material, and independent web research provide cited mechanisms or technology understanding, not target facts.",
            "Before closing a plausible line with no next discriminator, use the research escalation appropriate to the observed technology or mechanism.",
        ],
    }


def opening_contract(mode: str) -> list[str]:
    contracts = {
        "broad-program": [
            "Verify scope and account context.",
            "Perform enough cold recon/live mapping to name meaningful current surfaces and collect fresh observations.",
            "Select one surface plus lens before specialist depth.",
            "Use Hunter Loop as the parent hunt cadence and Hunt Orchestration as an optional coordination overlay.",
            "A strong current signal may be pursued immediately and as deeply as justified; incomplete mapping is not a reason to interrupt it.",
        ],
        "focused-surface": [
            "Verify scope and map the named surface's normal workflow.",
            "Identify input, transformations, consumers, and impact boundary.",
            "Use class methodology only after the current context is understood.",
        ],
        "technology-review": [
            "Identify the exact implementation, version, configuration, and call sites.",
            "Compare source/runtime behavior with the relevant browser, server, or framework consumer.",
            "Turn implementation understanding into bounded hypotheses.",
        ],
        "continuation": [
            "Read the active Hunter Memory/attempt context and restate the missing chain edge.",
            "Preserve warm/hot continuity and choose a distinct next discriminator.",
        ],
        "revalidation": [
            "Read prior evidence and current scope/policy before replaying.",
            "Establish a fresh baseline and record changes as current evidence.",
        ],
    }
    return contracts[mode]


def completion_contract(mode: str) -> list[str]:
    if mode != "broad-program":
        return []
    return [
        "Before a broad negative or exhaustion conclusion, ask: is there more to map?",
        "Reconcile unvisited or unexercised normal UI/browser behavior, relevant client or JavaScript capabilities, authorized task-MITM feature traffic, available role/auth states, and material consumer families.",
        "Record unavailable UI, missing access, failed auth recovery, or absent authorized task-MITM traffic as coverage gaps, not evidence of exhaustion.",
        "This reconciliation does not reopen a locally exhausted lane without a new wake condition or interrupt a warm/hot chain.",
    ]


def initialize_run(plan: dict[str, Any], run_dir: Path) -> Path:
    """Write routing state only; durable app facts belong in existing stores."""
    run_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "created_at": iso_now(),
        **plan,
        "current_surface": None,
        "current_lens": None,
        "fresh_observations": [],
        "active_hypotheses": [],
        "retrieval_decision": "unselected",
        "retrieval_reason": None,
        "next_discriminator": None,
        "pressure": "cold",
        "checkpoints": [],
    }
    path = run_dir / "goal-state.json"
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def record_checkpoint(
    run_dir: Path, *, family: str, lane: str, decision: str, reason: str,
    next_step: str, root: Path | None = None, vulnerability_class: str | None = None,
    host: str | None = None, remaining: list[str] | None = None,
    inventory_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Record a goal-parent decision from existing coverage, never a verdict about a target."""
    state_path = run_dir / "goal-state.json"
    if not state_path.is_file():
        raise ValueError("initialize an explicit goal run before checkpointing")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if decision not in {"deepen", "explore", "map", "unblock", "bounded-stop"}:
        raise ValueError("decision must be deepen, explore, map, unblock, or bounded-stop")
    goal_class = state.get("vulnerability_class")
    class_name = normalized(vulnerability_class) or goal_class
    if goal_class and class_name != goal_class:
        raise ValueError("checkpoint class must match the focused goal class")
    if decision == "bounded-stop" and host:
        raise ValueError("bounded-stop must not hide other hosts behind a host filter")
    if decision == "bounded-stop" and not goal_class and class_name:
        raise ValueError("broad goal bounded-stop must not hide other classes behind a class filter")
    reason = _plain(reason, "reason", required=True)
    next_step = _plain(next_step, "next_step", required=True)
    remaining = [_plain(item, "remaining", required=True) for item in (remaining or [])]
    inventory_refs = [_plain(item, "inventory_ref", required=True) for item in (inventory_refs or [])]
    if decision == "bounded-stop" and not (remaining or inventory_refs):
        raise ValueError("bounded-stop requires remaining unknowns or a checked inventory reference")
    store = SurfaceCoverageStore(state["program"], family=family, lane=lane, root_override=root)
    brief = store.brief(class_name=class_name, host=host, limit=10)
    unfiltered = store.brief(limit=1) if class_name or host else brief
    open_count = sum(brief["counts"].get(status, 0) for status in
                     ("no_assessment", "in_progress", "blocked", "stale"))
    if decision == "bounded-stop" and (open_count or not brief["total"]) and not remaining:
        raise ValueError("bounded-stop requires remaining unknowns for open or missing Coverage")
    items = [
        {key: row[key] for key in ("surface_id", "class_name", "status", "host", "kind", "surface_key",
                                   "input_key", "consumer", "source_ref", "reason", "reopen_when")}
        for row in brief["items"]
    ]
    receipt = {
        "recorded_at": iso_now(), "program": state["program"], "family": family,
        "lane": lane, "class_name": class_name, "host": host,
        "inventory_state": ("missing" if not store.path.exists() else
                            "empty" if not unfiltered["total"] and not unfiltered["unclassified_surfaces"] else
                            "no_matching_questions" if not brief["total"] else "mapped"),
        "coverage": {"counts": brief["counts"], "total": brief["total"],
                     "items": items, "next_offset": brief["next_offset"],
                     "unclassified_surfaces": brief["unclassified_surfaces"],
                     "unfiltered_total": unfiltered["total"]},
        "inventory_refs": inventory_refs, "decision": decision, "reason": reason,
        "next_step": next_step, "remaining": remaining,
        "goal_outcome": "paused_bounded" if decision == "bounded-stop" else "in_progress",
        "eligible_goal_complete": False,
    }
    # One atomic run-state file owns the checkpoint history; Coverage owns target truth.
    state["last_checkpoint"] = receipt
    state.setdefault("checkpoints", []).append(receipt)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=run_dir,
                                         prefix=".goal-state-", delete=False) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(state, indent=2, sort_keys=True) + "\n")
        os.replace(temp_path, state_path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return receipt


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("plan", "Print a goal-routing plan"), ("init", "Create a small goal-run routing state")):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("--program", required=True)
        command.add_argument("--objective", required=True)
        command.add_argument("--url")
        command.add_argument("--class", dest="vulnerability_class")
        if name == "init":
            command.add_argument("--run-dir", type=Path, required=True)
    checkpoint = subcommands.add_parser("checkpoint", help="Record a goal-parent Coverage continuation decision")
    checkpoint.add_argument("--run-dir", type=Path, required=True)
    checkpoint.add_argument("--family", required=True)
    checkpoint.add_argument("--lane", required=True)
    checkpoint.add_argument("--root", type=Path, help="Explicit local storage root, for isolated fixtures")
    checkpoint.add_argument("--class", dest="vulnerability_class")
    checkpoint.add_argument("--host")
    checkpoint.add_argument("--decision", required=True,
                            choices=("deepen", "explore", "map", "unblock", "bounded-stop"))
    checkpoint.add_argument("--reason", required=True)
    checkpoint.add_argument("--next-step", required=True)
    checkpoint.add_argument("--remaining", action="append", default=[])
    checkpoint.add_argument("--inventory-ref", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "checkpoint":
        print(json.dumps(record_checkpoint(
            args.run_dir.expanduser().resolve(), family=args.family, lane=args.lane,
            root=args.root, vulnerability_class=args.vulnerability_class, host=args.host,
            decision=args.decision, reason=args.reason, next_step=args.next_step,
            remaining=args.remaining, inventory_refs=args.inventory_ref,
        ), indent=2, sort_keys=True))
        return 0
    plan = build_plan(
        program=args.program,
        objective=args.objective,
        url=args.url,
        vulnerability_class=args.vulnerability_class,
    )
    if args.command == "init":
        path = initialize_run(plan, args.run_dir.expanduser().resolve())
        print(path)
    else:
        print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
