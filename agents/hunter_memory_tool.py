#!/usr/bin/env python3
"""Standalone Bug Bounty Harness helper for Hunter Memory Loop workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.hunter_memory_adapter import (  # noqa: E402
    HunterMemoryRef,
    _clean_field,
    _clean_list,
    _ensure_core_importable,
    build_hunter_memory_ref,
    harvest_hunter_memory_from_log,
)


ALLOWED_CLAIM_STATUSES = (
    "planned",
    "in_progress",
    "tested_no_signal",
    "interesting_signal",
    "blocked",
    "confirmed",
    "needs_followup",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create and update Hunter Memory Loop records from BBH mapping or hunting workflows."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Create a hunter-memory run/agent scaffold and print the agent prompt.")
    start.add_argument("program")
    start.add_argument("--vulnerability", default="general")
    start.add_argument("--surface", required=True)
    start.add_argument("--goal", required=True)
    start.add_argument("--target")
    start.add_argument("--agent-id", default="manual-hunter")
    start.add_argument("--provider", default="codex")
    start.add_argument("--root", help="Override Hunter Memory storage root. Defaults to ~/Shared/bounty_recon.")
    start.add_argument("--prompt-out", help="Write the generated agent prompt to this file.")
    start.add_argument("--json", action="store_true", help="Print machine-readable paths and prompt.")

    attempt = sub.add_parser("attempt", help="Append one durable attempt/learning row to an agent memory dir.")
    attempt.add_argument("--agent-dir", required=True)
    attempt.add_argument("--goal", required=True)
    attempt.add_argument("--action", required=True)
    attempt.add_argument("--result", required=True)
    attempt.add_argument("--observation", default="")
    attempt.add_argument("--interpretation", default="")
    attempt.add_argument("--learning", default="")
    attempt.add_argument("--next-action", default="")
    attempt.add_argument("--evidence-ref", action="append", default=[])

    claim = sub.add_parser("claim", help="Append one reusable claim to a hunter-memory run.")
    claim.add_argument("--run-path", required=True)
    claim.add_argument("--agent-id", required=True)
    claim.add_argument("--claim", required=True)
    claim.add_argument("--status", choices=ALLOWED_CLAIM_STATUSES, default="in_progress")
    claim.add_argument("--confidence", choices=("low", "medium", "high"), default="medium")

    harvest = sub.add_parser("harvest", help="Harvest fenced hunter-memory JSONL blocks from an agent log.")
    harvest.add_argument("--run-path", required=True)
    harvest.add_argument("--agent-id", required=True)
    harvest.add_argument("--log", required=True)
    harvest.add_argument("--agent-dir", help="Override agent memory dir. Defaults to <run-path>/agents/<agent-id>.")

    context = sub.add_parser("context", help="Print the memory surface directory for a program/vuln/surface.")
    context.add_argument("program")
    context.add_argument("--vulnerability", required=True)
    context.add_argument("--surface", required=True)
    context.add_argument("--root", help="Override Hunter Memory storage root. Defaults to ~/Shared/bounty_recon.")

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "start":
        return _cmd_start(args)
    if args.command == "attempt":
        return _cmd_attempt(args)
    if args.command == "claim":
        return _cmd_claim(args)
    if args.command == "harvest":
        return _cmd_harvest(args)
    if args.command == "context":
        return _cmd_context(args)
    return 1


def _cmd_start(args: argparse.Namespace) -> int:
    ref = build_hunter_memory_ref(
        program=args.program,
        agent_key=args.agent_id,
        vulnerability=args.vulnerability,
        surface=args.surface,
        goal=args.goal,
        target=args.target,
        provider=args.provider,
        root=args.root,
    )
    if not ref.enabled:
        print(f"hunter-memory unavailable: {ref.unavailable_reason}", file=sys.stderr)
        return 1

    if args.prompt_out:
        prompt_path = Path(args.prompt_out).expanduser()
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(ref.prompt + "\n", encoding="utf-8")

    payload = {
        "enabled": ref.enabled,
        "run_path": str(ref.run_path),
        "agent_path": str(ref.agent_path),
        "agent_key": ref.agent_key,
        "prompt": ref.prompt,
        "prompt_path": str(Path(args.prompt_out).expanduser()) if args.prompt_out else None,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Run: {ref.run_path}")
    print(f"Agent: {ref.agent_path}")
    if args.prompt_out:
        print(f"Prompt: {payload['prompt_path']}")
    else:
        print()
        print(ref.prompt)
    return 0


def _cmd_attempt(args: argparse.Namespace) -> int:
    _ensure_core_importable()
    from hunter_memory.cli import _agent_from_path

    agent = _agent_from_path(Path(args.agent_dir))
    agent.append_attempt(
        goal=_clean_field(args.goal),
        action=_clean_field(args.action),
        result=_clean_field(args.result),
        observation=_clean_field(args.observation),
        interpretation=_clean_field(args.interpretation),
        learning=_clean_field(args.learning),
        next_action=_clean_field(args.next_action),
        evidence_refs=_clean_list(args.evidence_ref),
    )
    print(agent.path / "attempts.jsonl")
    return 0


def _cmd_claim(args: argparse.Namespace) -> int:
    _ensure_core_importable()
    from hunter_memory.cli import _run_from_path

    run = _run_from_path(Path(args.run_path), "codex")
    run.append_claim(
        agent_id=_clean_field(args.agent_id),
        claim=_clean_field(args.claim),
        status=_clean_field(args.status),
        confidence=_clean_field(args.confidence),
    )
    print(run.path / "claims.jsonl")
    return 0


def _cmd_harvest(args: argparse.Namespace) -> int:
    run_path = Path(args.run_path).expanduser()
    agent_path = Path(args.agent_dir).expanduser() if args.agent_dir else run_path / "agents" / _slugify(args.agent_id)
    ref = HunterMemoryRef(
        enabled=True,
        run_path=run_path,
        agent_path=agent_path,
        agent_key=args.agent_id,
        prompt="",
    )
    result = harvest_hunter_memory_from_log(Path(args.log).expanduser(), ref)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result.get("errors") else 1


def _cmd_context(args: argparse.Namespace) -> int:
    root = Path(args.root or "~/Shared/bounty_recon").expanduser()
    surface = root / _slugify(args.program) / "hunter_memory" / _slugify(args.vulnerability) / _slugify(args.surface)
    print(surface)
    return 0


def _slugify(value: Any) -> str:
    _ensure_core_importable()
    from hunter_memory.paths import slugify

    return slugify(str(value or ""))


if __name__ == "__main__":
    raise SystemExit(main())
