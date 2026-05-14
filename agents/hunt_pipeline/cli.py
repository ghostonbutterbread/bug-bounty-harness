from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if _PROJECT_ROOT.as_posix() not in (Path(item).as_posix() for item in sys.path if item):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.hunt_pipeline.dry_run import build_dry_run_plan
from agents.hunt_pipeline.preflight_report import write_runtime_preflight_report
from agents.hunt_pipeline.run_state import (
    clear_pause,
    request_pause,
    request_stop,
    resolve_pipeline_plan_path,
    run_state_path_for_plan,
    summarize_run,
)
from agents.hunt_pipeline.runtime import execute_next_wave

COMMANDS = {"plan", "status", "run", "resume", "pause", "stop"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan and control bounded AppMap hunt-pipeline runs.")
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    plan_parser = subparsers.add_parser("plan", help="write pipeline_plan.json and scheduler decision JSONLs")
    _add_plan_args(plan_parser)
    plan_parser.add_argument("--dry-run", action="store_true", help="compatibility alias; planning is always dry-run safe")
    plan_parser.set_defaults(func=_cmd_plan)

    status_parser = subparsers.add_parser("status", help="summarize a pipeline plan or output directory")
    _add_state_locator_args(status_parser)
    status_parser.add_argument("--max-agents", type=_non_negative_int)
    status_parser.add_argument("--concurrent-agents", type=_positive_int)
    status_parser.add_argument("--format", choices=("json", "text"), default="json", help="output format; default: json")
    status_parser.add_argument(
        "--write-preflight-report",
        action="store_true",
        help="write runtime_preflight_report.json beside the plan without invoking runtime adapters",
    )
    status_parser.add_argument("--preflight-report-path", help="optional path for --write-preflight-report")
    status_parser.set_defaults(func=_cmd_status)

    run_parser = subparsers.add_parser("run", help="execute the next wave through the dry-run-safe runtime adapter")
    _add_runtime_args(run_parser, allow_plan_inputs=True)
    run_parser.set_defaults(func=_cmd_run)

    resume_parser = subparsers.add_parser("resume", help="continue from durable selected/deferred state")
    _add_runtime_args(resume_parser, allow_plan_inputs=False)
    resume_parser.set_defaults(func=_cmd_resume)

    pause_parser = subparsers.add_parser("pause", help="request that no new waves start")
    _add_state_locator_args(pause_parser)
    pause_parser.set_defaults(func=_cmd_pause)

    stop_parser = subparsers.add_parser("stop", help="stop future waves from starting")
    _add_state_locator_args(stop_parser)
    stop_parser.add_argument("--kill-active", action="store_true", help="accepted for compatibility; force killing is not implemented")
    stop_parser.set_defaults(func=_cmd_stop)
    return parser


def main(argv: list[str] | None = None) -> int:
    normalized = _normalize_legacy_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(normalized)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)


def _cmd_plan(args: argparse.Namespace) -> int:
    artifact, plan_path = _build_plan_from_args(args)
    print(json.dumps({"pipeline_plan": str(Path(plan_path)), "hypotheses": len(artifact.hypotheses)}, sort_keys=True))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args)
    summary = summarize_run(plan_path, max_agents=args.max_agents, concurrent_agents=args.concurrent_agents)
    if args.write_preflight_report:
        report, report_path = write_runtime_preflight_report(
            plan_path,
            output_path=args.preflight_report_path,
        )
        summary["runtime_preflight_report"] = report
        summary["runtime_preflight_report_path"] = str(report_path)
    if args.format == "text":
        print(_format_status_text(summary))
    else:
        print(json.dumps(summary, sort_keys=True))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    if args.pipeline_plan or (not args.program and args.output_dir):
        plan_path = _plan_path_from_args(args)
    else:
        if not args.program or not args.target_path:
            raise SystemExit("run requires either --pipeline-plan/--output-dir or program target_path")
        _, plan_path = _build_plan_from_args(args)
    return _execute_and_print(args, plan_path)


def _cmd_resume(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args)
    if args.execute_live:
        return _execute_and_print(args, plan_path)
    clear_pause(plan_path)
    return _execute_and_print(args, plan_path)


def _cmd_pause(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args)
    state = request_pause(plan_path)
    print(json.dumps({"pipeline_plan": str(plan_path), "run_state": str(run_state_path_for_plan(plan_path)), "pause_requested": state["pause_requested"]}, sort_keys=True))
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args)
    state = request_stop(plan_path)
    payload = {
        "pipeline_plan": str(plan_path),
        "run_state": str(run_state_path_for_plan(plan_path)),
        "stopped": state["stopped"],
        "kill_active_requested": bool(args.kill_active),
        "kill_active_implemented": False,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def _execute_and_print(args: argparse.Namespace, plan_path: Path) -> int:
    if args.execute_live:
        result = execute_next_wave(
            plan_path,
            max_agents=args.max_agents,
            concurrent_agents=args.concurrent_agents,
            execute_live=True,
        )
        print(json.dumps(result, sort_keys=True))
        return 2
    result = execute_next_wave(
        plan_path,
        max_agents=args.max_agents,
        concurrent_agents=args.concurrent_agents,
        execute_live=False,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _build_plan_from_args(args: argparse.Namespace):
    return build_dry_run_plan(
        program=args.program,
        target_path=args.target_path,
        target_kind=args.target_kind,
        ruleset_id=args.ruleset,
        appmap_run=args.appmap_run,
        output_dir=args.output_dir,
        run_id=args.run_id,
        max_hypotheses=args.max_hypotheses,
        max_agents=args.max_agents,
        concurrent_agents=args.concurrent_agents,
        write_hypotheses=bool(getattr(args, "write_hypotheses", False)),
    )


def _plan_path_from_args(args: argparse.Namespace) -> Path:
    locator = getattr(args, "path", None)
    pipeline_plan = getattr(args, "pipeline_plan", None)
    output_dir = getattr(args, "output_dir", None)
    if locator:
        path = Path(locator).expanduser().resolve(strict=False)
        if path.is_dir():
            output_dir = path
        else:
            pipeline_plan = path
    return resolve_pipeline_plan_path(output_dir=output_dir, pipeline_plan=pipeline_plan)


def _add_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("program")
    parser.add_argument("target_path")
    parser.add_argument("--target-kind", default="auto")
    parser.add_argument("--ruleset", default="auto")
    parser.add_argument("--from-appmap-run", dest="appmap_run")
    parser.add_argument("--output-dir", default="hunt_pipeline_out")
    parser.add_argument("--run-id", default="pipeline-dry-run")
    parser.add_argument("--max-hypotheses", type=int)
    parser.add_argument("--concurrent-agents", type=_positive_int)
    parser.add_argument("--max-agents", type=_non_negative_int)
    parser.add_argument("--write-hypotheses", action="store_true", help="write hypotheses.jsonl beside pipeline_plan.json")


def _add_state_locator_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", help="pipeline_plan.json path or output directory")
    parser.add_argument("--pipeline-plan")
    parser.add_argument("--output-dir")


def _add_runtime_args(parser: argparse.ArgumentParser, *, allow_plan_inputs: bool) -> None:
    if allow_plan_inputs:
        parser.add_argument("program", nargs="?")
        parser.add_argument("target_path", nargs="?")
        parser.add_argument("--target-kind", default="auto")
        parser.add_argument("--ruleset", default="auto")
        parser.add_argument("--from-appmap-run", dest="appmap_run")
        parser.add_argument("--run-id", default="pipeline-dry-run")
        parser.add_argument("--max-hypotheses", type=int)
        parser.add_argument("--pipeline-plan")
        parser.add_argument("--output-dir", default="hunt_pipeline_out")
        parser.add_argument("--write-hypotheses", action="store_true", help="write hypotheses.jsonl when planning from inputs")
    else:
        _add_state_locator_args(parser)
    parser.add_argument("--concurrent-agents", type=_positive_int)
    parser.add_argument("--max-agents", type=_non_negative_int)
    parser.add_argument("--execute-live", action="store_true", help="explicit live-execution gate; currently rejected")


def _normalize_legacy_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] in {"-h", "--help"}:
        return argv
    if argv[0] in COMMANDS:
        return argv
    normalized = [item for item in argv if item != "--dry-run"]
    return ["plan", *normalized]


def _format_status_text(summary: dict[str, object]) -> str:
    contract = summary.get("runtime_handoff_contract") if isinstance(summary.get("runtime_handoff_contract"), dict) else {}
    protocol = summary.get("runtime_promotion_protocol") if isinstance(summary.get("runtime_promotion_protocol"), dict) else {}
    report = summary.get("runtime_preflight_report") if isinstance(summary.get("runtime_preflight_report"), dict) else {}
    static_handoffs = report.get("static_team_handoffs") if isinstance(report.get("static_team_handoffs"), dict) else {}
    dynamic_queue = report.get("dynamic_validation_queue") if isinstance(report.get("dynamic_validation_queue"), dict) else {}
    return (
        f"pipeline_plan={summary.get('pipeline_plan')} "
        f"run_state={summary.get('run_state')} "
        f"total={summary.get('total')} "
        f"completed={summary.get('completed')} "
        f"unrun={summary.get('unrun')} "
        f"next_wave={summary.get('next_wave_count')} "
        f"pause_requested={str(bool(summary.get('pause_requested'))).lower()} "
        f"stopped_requested={str(bool(summary.get('stopped_requested'))).lower()} "
        f"runtime_contract_status={contract.get('status')} "
        f"promotion_allowed={str(bool(contract.get('promotion_allowed'))).lower()} "
        f"promotion_protocol_status={protocol.get('status')} "
        f"promotion_enabled={str(bool(protocol.get('promotion_enabled'))).lower()} "
        f"preflight_status={report.get('status')} "
        f"failed_required_gates={contract.get('failed_required_gate_count', len(report.get('failed_required_gates', [])))} "
        f"static_team_handoffs={static_handoffs.get('state')} "
        f"dynamic_validation_queue={dynamic_queue.get('state')}"
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
