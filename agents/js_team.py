#!/usr/bin/env python3
"""Staged JavaScript Team wrapper for offline /js deep campaigns.

The lower-level js_offline_campaign adapter builds the offline target,
brainstorm spec, MapStore candidate files, and zero_day_team command. This
wrapper adds the operator-facing staged plan: mapper/anomaly first, then an
explicitly selected follow-up category wave.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents import js_offline_campaign as campaign


PLANNER_LANES = ("general-map", "anomaly-hunter")


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _split_lane_args(values: Sequence[str] | None) -> list[str]:
    lanes: list[str] = []
    for raw in values or []:
        lanes.extend(part.strip() for part in str(raw).split(",") if part.strip())
    return _stable_unique(lanes)


def _lane_keys(granularity: str) -> list[str]:
    return [lane.key for lane in campaign.lanes_for_granularity(granularity)]


def _follow_up_candidates(granularity: str) -> list[str]:
    return [key for key in _lane_keys(granularity) if key not in PLANNER_LANES]


def _validate_follow_up_lanes(selected: list[str], granularity: str) -> None:
    known = set(_follow_up_candidates(granularity))
    unknown = [key for key in selected if key not in known]
    if unknown:
        expected = ", ".join(sorted(known))
        raise SystemExit(f"unknown follow-up lane(s): {', '.join(unknown)}. Expected one of: {expected}")


def _auto_follow_up_lanes(mode: str, metadata_rows: list[dict], granularity: str) -> list[str]:
    probe_mode = "look" if mode in {"deep", "full"} else mode
    lanes = campaign.selected_lanes(probe_mode, metadata_rows, granularity=granularity)
    return [lane.key for lane in lanes if lane.key not in PLANNER_LANES]


def _hypothesis_ids_by_lane(manifest: dict) -> dict[str, str]:
    return {
        str(lane.get("key")): f"H{index:03d}"
        for index, lane in enumerate(manifest.get("lanes") or [], start=1)
        if isinstance(lane, dict) and lane.get("key")
    }


def _command_for_hypothesis(manifest: dict, hypothesis_id: str) -> list[str]:
    command = [str(part) for part in manifest.get("zero_day_command") or []]
    if not command:
        raise SystemExit("zero_day_command missing from prepared campaign manifest")
    if "--brainstorm-hypothesis" in command:
        index = command.index("--brainstorm-hypothesis")
        if index + 1 < len(command):
            command[index + 1] = hypothesis_id
            return command
        raise SystemExit("invalid zero_day_command contains dangling --brainstorm-hypothesis")
    insert_at = len(command)
    if command and command[-1] == "--parallel":
        insert_at -= 1
    return [*command[:insert_at], "--brainstorm-hypothesis", hypothesis_id, *command[insert_at:]]


def _stage_commands(manifest: dict, lane_keys: list[str]) -> list[dict]:
    ids_by_lane = _hypothesis_ids_by_lane(manifest)
    commands: list[dict] = []
    for lane_key in lane_keys:
        hypothesis_id = ids_by_lane.get(lane_key)
        if not hypothesis_id:
            continue
        command = _command_for_hypothesis(manifest, hypothesis_id)
        commands.append(
            {
                "lane": lane_key,
                "hypothesis_id": hypothesis_id,
                "command": command,
                "command_text": campaign.shell_join(command),
            }
        )
    return commands


def _prepare_args(args: argparse.Namespace, campaign_root: Path | None) -> argparse.Namespace:
    return argparse.Namespace(
        js_run_root=args.js_run_root,
        campaign_root=str(campaign_root) if campaign_root else args.campaign_root,
        program=args.program,
        mode=args.mode,
        force=args.force,
        no_parallel=args.no_parallel,
        granularity=args.granularity,
        scheduler=args.scheduler,
        agent_wave_size=args.agent_wave_size,
        no_category_master_mode=args.no_category_master_mode,
    )


def build_staged_plan(args: argparse.Namespace) -> dict:
    js_run_root = Path(args.js_run_root).expanduser().resolve(strict=False)
    campaign_root = (
        Path(args.campaign_root).expanduser().resolve(strict=False)
        if args.campaign_root
        else js_run_root / "offline_campaign"
    )
    prepare_args = _prepare_args(args, campaign_root)
    manifest = campaign.prepare_campaign(prepare_args)
    metadata_rows = campaign.read_jsonl(js_run_root / "metadata.jsonl")

    requested_follow_ups = _split_lane_args(args.follow_up_lane)
    if requested_follow_ups:
        follow_up_lanes = requested_follow_ups
    elif args.auto_follow_up_from_signals:
        follow_up_lanes = _auto_follow_up_lanes(args.mode, metadata_rows, args.granularity)
    else:
        follow_up_lanes = []
    _validate_follow_up_lanes(follow_up_lanes, args.granularity)

    planner_lanes = [key for key in PLANNER_LANES if key in _lane_keys(args.granularity)]
    available_follow_ups = _follow_up_candidates(args.granularity)
    plan = {
        "schema": "js-team-staged-plan.v1",
        "program": manifest["program"],
        "mode": args.mode,
        "agent_granularity": args.granularity,
        "execution_mode": "offline",
        "live_requests_allowed": False,
        "campaign_root": manifest["campaign_root"],
        "campaign_manifest": str(Path(manifest["campaign_root"]) / "manifest.json"),
        "brainstorm_spec": manifest["brainstorm_spec"],
        "mapstore_candidates": manifest["mapstore_candidates"],
        "stage_order": ["planner", "follow-up"],
        "stages": {
            "planner": {
                "description": "Run js-general-map and js-anomaly-hunter first.",
                "lanes": planner_lanes,
                "commands": _stage_commands(manifest, planner_lanes),
            },
            "follow-up": {
                "description": "Run only selected category/lens lanes after reading mapper/anomaly output.",
                "lanes": follow_up_lanes,
                "available_lanes": available_follow_ups,
                "selection_mode": (
                    "explicit"
                    if requested_follow_ups
                    else "auto-signals"
                    if args.auto_follow_up_from_signals
                    else "waiting-for-mapper-output"
                ),
                "commands": _stage_commands(manifest, follow_up_lanes),
            },
        },
        "notes": [
            "Deep planning is staged: do not run every category before mapper/anomaly output is reviewed.",
            "Use --follow-up-lane after reading stage 1 output, or --auto-follow-up-from-signals for deterministic metadata-triggered lanes.",
            "All commands remain offline and use --brainstorm-hypothesis to target one generated hypothesis at a time.",
        ],
    }
    write_plan = not getattr(args, "dry_run", False) or bool(args.write_plan)
    if write_plan:
        plan_path = campaign_root / "js_team_plan.json"
        campaign.write_json(plan_path, plan)
        plan["plan_path"] = str(plan_path)
    return plan


def _execute_stage(plan: dict, stage: str) -> int:
    stage_names = ["planner", "follow-up"] if stage == "all" else [stage]
    for stage_name in stage_names:
        commands = list((plan.get("stages") or {}).get(stage_name, {}).get("commands") or [])
        if not commands:
            print(f"[js-team] no commands for stage {stage_name}")
            continue
        for item in commands:
            command = [str(part) for part in item.get("command") or []]
            print(f"[js-team] running {stage_name}:{item.get('lane')} {item.get('hypothesis_id')}")
            rc = subprocess.call(command, cwd=campaign.REPO_ROOT)
            if rc != 0:
                return rc
    return 0


def command_dry_run(args: argparse.Namespace) -> int:
    args.dry_run = True
    temporary_root: Path | None = None
    if not args.campaign_root and not args.write_plan:
        temporary_root = Path(tempfile.mkdtemp(prefix="js-team-dry-run-"))
        args.campaign_root = str(temporary_root)
        args.force = True
    try:
        plan = build_staged_plan(args)
        if temporary_root is not None:
            plan["campaign_root"] = "(temporary; removed after dry run)"
            plan["campaign_manifest"] = "(temporary; removed after dry run)"
            plan["brainstorm_spec"] = "(temporary; removed after dry run)"
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    finally:
        if temporary_root is not None:
            shutil.rmtree(temporary_root, ignore_errors=True)


def command_run(args: argparse.Namespace) -> int:
    args.dry_run = False
    if args.execute and args.stage == "all":
        raise SystemExit(
            "--execute --stage all is disabled: execute planner and follow-up stages separately "
            "so mapper/anomaly output is reviewed before category follow-up."
        )
    plan = build_staged_plan(args)
    if not args.execute:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    return _execute_stage(plan, args.stage)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--js-run-root", required=True, help="Existing js_analyzer.py inventory run root")
    parser.add_argument("--campaign-root", help="Output campaign root. Defaults to <js-run-root>/offline_campaign")
    parser.add_argument("--program", help="Program override if manifest lacks program")
    parser.add_argument("--mode", choices=sorted(campaign.MODE_LANES), default="deep")
    parser.add_argument(
        "--granularity",
        choices=("category", "lens"),
        default="category",
        help="Agent shape: category uses broad mapper-led lanes; lens uses the old narrow matrix.",
    )
    parser.add_argument(
        "--follow-up-lane",
        action="append",
        default=[],
        help="Follow-up lane key to include after planner output. Repeatable or comma-separated.",
    )
    parser.add_argument(
        "--auto-follow-up-from-signals",
        action="store_true",
        help="Select deterministic follow-up lanes from cheap inventory metadata signals.",
    )
    parser.add_argument(
        "--scheduler",
        choices=("off", "legacy", "policy-aware"),
        default="policy-aware",
        help="zero_day_team scheduler mode for generated commands.",
    )
    parser.add_argument("--agent-wave-size", default="all", help="Generated zero_day_team --agent-wave-size value.")
    parser.add_argument(
        "--no-category-master-mode",
        action="store_true",
        help="Do not include zero_day_team --category-master-mode in generated commands.",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing campaign root")
    parser.add_argument("--no-parallel", action="store_true", help="Do not include --parallel in generated commands")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run staged offline JavaScript Team campaigns")
    sub = parser.add_subparsers(dest="command", required=True)

    dry_run = sub.add_parser("dry-run", help="Preview the staged /js deep plan without executing agents")
    _add_common_args(dry_run)
    dry_run.add_argument("--write-plan", action="store_true", help="Write js_team_plan.json during dry-run")
    dry_run.set_defaults(func=command_dry_run)

    run = sub.add_parser("run", help="Prepare the staged plan and optionally execute one stage")
    _add_common_args(run)
    run.add_argument("--stage", choices=("planner", "follow-up", "all"), default="planner")
    run.add_argument("--execute", action="store_true", help="Actually run the selected stage commands")
    run.set_defaults(func=command_run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
