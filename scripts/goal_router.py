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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
BASE_SKILLS = ["bug-goals", "general-security-testing-policy", "live-testing-policy"]
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
        skills = BASE_SKILLS + ["hunter-loop", "recon", "live-map", "hunter-memory", "hypothesis-expansion-policy"]
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
            "Perform a cold recon/live-map pass and collect fresh observations.",
            "Select one surface plus lens before specialist depth.",
            "Use Hunter Loop as the parent orchestration model.",
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
    }
    path = run_dir / "goal-state.json"
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
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
