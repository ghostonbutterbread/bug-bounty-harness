from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if _PROJECT_ROOT.as_posix() not in (Path(item).as_posix() for item in sys.path if item):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.hunt_pipeline.dry_run import build_dry_run_plan
from agents.hunt_pipeline.operator_approval_schema import write_runtime_operator_approval_schema
from agents.hunt_pipeline.preflight_report import write_runtime_preflight_report
from agents.hunt_pipeline.promotion_readiness import write_runtime_promotion_readiness_checklist
from agents.hunt_pipeline.promotion_request_packet import write_runtime_promotion_request_packet
from agents.hunt_pipeline.run_state import (
    clear_pause,
    discover_durable_runs,
    load_pipeline_plan,
    load_run_state,
    request_pause,
    request_stop,
    resolve_durable_run_plan,
    resolve_pipeline_plan_path,
    run_state_path_for_plan,
    summarize_run,
    validate_run_id,
)
from agents.hunt_pipeline.promotion_decision import evaluate_runtime_promotion_decision
from agents.hunt_pipeline.runtime import execute_next_wave

COMMANDS = {"plan", "status", "runs", "list-runs", "run", "resume", "live", "live-test", "pause", "stop"}
DEFAULT_RUN_HYPOTHESES = 10
DEFAULT_OUTPUT_ROOT = Path("hunt_pipeline_out")
DEFAULT_RECENT_RUN_LIMIT = 10


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan and control bounded AppMap hunt-pipeline runs. "
            "Run and resume execute source-only dynamic agents by default unless --dry-run is used. "
            "Live-testing/VM execution still requires a valid runtime promotion decision, an approved runtime environment, "
            "and a valid runtime action policy."
        )
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    plan_parser = subparsers.add_parser("plan", help="write pipeline_plan.json and scheduler decision JSONLs")
    _add_plan_args(plan_parser)
    plan_parser.add_argument("--dry-run", action="store_true", help="compatibility alias; planning is always dry-run safe")
    plan_parser.set_defaults(func=_cmd_plan)

    status_parser = subparsers.add_parser("status", help="summarize a pipeline plan or output directory")
    _add_state_locator_args(status_parser)
    _add_run_hypotheses_args(status_parser)
    status_parser.add_argument("--concurrent-agents", type=_positive_int)
    status_parser.add_argument("--format", choices=("json", "text"), default="json", help="output format; default: json")
    status_parser.add_argument(
        "--write-preflight-report",
        action="store_true",
        help="write runtime_preflight_report.json beside the plan without invoking runtime adapters",
    )
    status_parser.add_argument("--preflight-report-path", help="optional path for --write-preflight-report")
    status_parser.add_argument(
        "--write-readiness-checklist",
        action="store_true",
        help="write runtime_promotion_readiness.json beside the plan without enabling live execution",
    )
    status_parser.add_argument("--readiness-checklist-path", help="optional path for --write-readiness-checklist")
    status_parser.add_argument(
        "--write-operator-approval-schema",
        action="store_true",
        help="write runtime_operator_approval_schema.json beside the plan without enabling live execution",
    )
    status_parser.add_argument("--operator-approval-schema-path", help="optional path for --write-operator-approval-schema")
    status_parser.add_argument(
        "--write-promotion-request-packet",
        action="store_true",
        help="write runtime_promotion_request_packet.json beside the plan for human review only",
    )
    status_parser.add_argument("--promotion-request-packet-path", help="optional path for --write-promotion-request-packet")
    status_parser.set_defaults(func=_cmd_status)

    runs_parser = subparsers.add_parser(
        "runs",
        aliases=["list-runs"],
        help="list recent durable hunt-pipeline runs under the base output root",
    )
    _add_runs_args(runs_parser)
    runs_parser.set_defaults(func=_cmd_runs)

    run_parser = subparsers.add_parser(
        "run",
        help=(
            "plan if needed, then execute the next source-only dynamic-agent wave by default; "
            "use --dry-run to simulate only"
        ),
        description=(
            "Plan if needed, then execute the next source-only dynamic-agent wave by default. "
            "Live-testing/VM execution still requires a valid runtime promotion decision, an approved runtime environment, "
            "and a valid runtime action policy. Use --dry-run to simulate only."
        ),
    )
    _add_runtime_args(run_parser, allow_plan_inputs=True)
    run_parser.set_defaults(func=_cmd_run)

    resume_parser = subparsers.add_parser(
        "resume",
        help=(
            "continue from durable selected/deferred state through source-only dynamic-agent execution by default; "
            "use --dry-run to simulate only"
        ),
        description=(
            "Continue from durable selected/deferred state through source-only dynamic-agent execution by default. "
            "Live-testing/VM execution still requires a valid runtime promotion decision, an approved runtime environment, "
            "and a valid runtime action policy. Use --dry-run to simulate only."
        ),
    )
    _add_runtime_args(resume_parser, allow_plan_inputs=False)
    resume_parser.set_defaults(func=_cmd_resume)

    live_parser = subparsers.add_parser(
        "live",
        aliases=["live-test"],
        help=(
            "execute the next selected wave with live-testing mode enabled from an existing plan/output path; "
            "requires promotion decision, approved environment, and valid action policy"
        ),
    )
    _add_state_locator_args(live_parser)
    live_parser.add_argument("--concurrent-agents", type=_positive_int)
    _add_run_hypotheses_args(live_parser)
    live_parser.add_argument("--no-ledger", action="store_true", help="skip live BaseTeam ledger/review/persistence writes")
    live_parser.set_defaults(func=_cmd_live)

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
    print(
        json.dumps(
            {"run_id": artifact.run_id, "pipeline_plan": str(Path(plan_path)), "hypotheses": len(artifact.hypotheses)},
            sort_keys=True,
        )
    )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args)
    run_cap = _run_hypotheses_cap(args)
    summary = summarize_run(plan_path, max_agents=run_cap, concurrent_agents=args.concurrent_agents)
    if args.write_preflight_report:
        report, report_path = write_runtime_preflight_report(
            plan_path,
            output_path=args.preflight_report_path,
        )
        summary["runtime_preflight_report"] = report
        summary["runtime_preflight_report_path"] = str(report_path)
    if args.write_readiness_checklist:
        checklist, checklist_path = write_runtime_promotion_readiness_checklist(
            plan_path,
            output_path=args.readiness_checklist_path,
            status_summary=summary,
        )
        summary["runtime_promotion_readiness"] = checklist
        summary["runtime_promotion_readiness_path"] = str(checklist_path)
    if args.write_operator_approval_schema:
        schema, schema_path = write_runtime_operator_approval_schema(
            plan_path,
            output_path=args.operator_approval_schema_path,
        )
        summary["runtime_operator_approval_schema"] = schema
        summary["runtime_operator_approval_schema_path"] = str(schema_path)
    if args.write_promotion_request_packet:
        packet, packet_path = write_runtime_promotion_request_packet(
            plan_path,
            output_path=args.promotion_request_packet_path,
            status_summary=summary,
        )
        summary["runtime_promotion_request_packet"] = packet
        summary["runtime_promotion_request_packet_path"] = str(packet_path)
    if args.format == "text":
        print(_format_status_text(summary))
    else:
        print(json.dumps(summary, sort_keys=True))
    return 0


def _cmd_runs(args: argparse.Namespace) -> int:
    rows = discover_durable_runs(_runs_base_output_root(args), limit=args.limit)
    payload = {
        "base_output_root": str(_runs_base_output_root(args)),
        "count": len(rows),
        "runs": rows,
    }
    if args.format == "text":
        print(_format_runs_text(rows))
    else:
        print(json.dumps(payload, sort_keys=True))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    if _run_uses_existing_plan(args):
        plan_path = _plan_path_from_args(args)
    else:
        if not args.program or not args.target_path:
            raise SystemExit("run requires --pipeline-plan, --output-dir, --run-id, or program target_path")
        _, plan_path = _build_plan_from_args(args)
    return _execute_and_print(args, plan_path)


def _cmd_resume(args: argparse.Namespace) -> int:
    plan_path = _plan_path_from_args(args, allow_latest_durable=True)
    live_testing_enabled = _live_testing_enabled_for_args(args, plan_path)
    if not _execute_live_requested(args) or not live_testing_enabled:
        clear_pause(plan_path)
    else:
        plan = load_pipeline_plan(plan_path)
        if evaluate_runtime_promotion_decision(plan, plan_path=plan_path).get("promoted") is True:
            clear_pause(plan_path)
    return _execute_and_print(args, plan_path)


def _cmd_live(args: argparse.Namespace) -> int:
    return _execute_and_print_live(args, _plan_path_from_args(args))


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
    live_testing_enabled = _live_testing_enabled_for_args(args, plan_path)
    if _execute_live_requested(args):
        return _execute_and_print_live(args, plan_path, live_testing_enabled=live_testing_enabled)
    run_cap = _run_hypotheses_cap(args)
    result = execute_next_wave(
        plan_path,
        max_agents=run_cap,
        concurrent_agents=args.concurrent_agents,
        execute_live=False,
        live_testing_enabled=live_testing_enabled,
        no_ledger=bool(getattr(args, "no_ledger", False)),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _execute_and_print_live(
    args: argparse.Namespace,
    plan_path: Path,
    *,
    live_testing_enabled: bool = True,
) -> int:
    run_cap = _run_hypotheses_cap(args)
    result = execute_next_wave(
        plan_path,
        max_agents=run_cap,
        concurrent_agents=args.concurrent_agents,
        execute_live=True,
        live_testing_enabled=live_testing_enabled,
        no_ledger=bool(getattr(args, "no_ledger", False)),
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 2


def _build_plan_from_args(args: argparse.Namespace):
    run_id = _plan_run_id(args)
    output_dir = _output_dir_for_plan(args, run_id=run_id)
    return build_dry_run_plan(
        program=args.program,
        target_path=args.target_path,
        target_kind=args.target_kind,
        ruleset_id=args.ruleset,
        appmap_run=args.appmap_run,
        output_dir=output_dir,
        run_id=run_id,
        max_hypotheses=args.max_hypotheses,
        max_agents=_run_hypotheses_cap(args),
        concurrent_agents=args.concurrent_agents,
        write_hypotheses=_write_hypotheses_enabled(args),
        tmp_output=bool(getattr(args, "tmp", False)),
    )


def _plan_path_from_args(args: argparse.Namespace, *, allow_latest_durable: bool = False) -> Path:
    try:
        locator = getattr(args, "path", None)
        pipeline_plan = getattr(args, "pipeline_plan", None)
        output_dir = getattr(args, "output_dir", None)
        if locator:
            path = Path(locator).expanduser().resolve(strict=False)
            if path.is_dir():
                output_dir = path
            else:
                pipeline_plan = path
        if pipeline_plan is not None:
            return resolve_pipeline_plan_path(pipeline_plan=pipeline_plan)
        run_id = getattr(args, "run_id", None)
        if run_id:
            return resolve_durable_run_plan(_runs_base_output_root(args), run_id=run_id)
        if output_dir is not None:
            return resolve_pipeline_plan_path(output_dir=output_dir)
        if allow_latest_durable:
            return resolve_durable_run_plan(DEFAULT_OUTPUT_ROOT, most_recent=True)
        return resolve_pipeline_plan_path(output_dir=output_dir, pipeline_plan=pipeline_plan)
    except (FileNotFoundError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def _add_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("program")
    parser.add_argument("target_path")
    parser.add_argument("--target-kind", default="auto")
    parser.add_argument("--ruleset", default="auto")
    parser.add_argument("--from-appmap-run", dest="appmap_run")
    parser.add_argument(
        "--output-dir",
        help="explicit run output directory; defaults to hunt_pipeline_out/<generated-run-id> for durable runs",
    )
    parser.add_argument("--tmp", action="store_true", help="write plan artifacts to an isolated temporary directory under /tmp")
    parser.add_argument("--run-id", help="durable run id override; defaults to a generated timestamp-like id")
    parser.add_argument("--max-hypotheses", type=int)
    parser.add_argument("--concurrent-agents", type=_positive_int)
    _add_run_hypotheses_args(parser)
    _add_hypotheses_write_args(parser)


def _add_state_locator_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", help="pipeline_plan.json path or output directory")
    parser.add_argument("--pipeline-plan")
    parser.add_argument("--output-dir", help="existing run output directory, or base output root when used with --run-id")
    parser.add_argument("--run-id", help="durable run id to resolve under --output-dir or the default base output root")


def _add_runtime_args(parser: argparse.ArgumentParser, *, allow_plan_inputs: bool) -> None:
    if allow_plan_inputs:
        parser.add_argument("program", nargs="?")
        parser.add_argument("target_path", nargs="?")
        parser.add_argument("--target-kind", default="auto")
        parser.add_argument("--ruleset", default="auto")
        parser.add_argument("--from-appmap-run", dest="appmap_run")
        parser.add_argument(
            "--run-id",
            help=(
                "for new plans, override the generated durable run id; "
                "without planning inputs, resolve an existing durable run under the base output root"
            ),
        )
        parser.add_argument("--max-hypotheses", type=int)
        parser.add_argument("--pipeline-plan")
        parser.add_argument(
            "--output-dir",
            help=(
                "for new plans, use this exact output directory; "
                "without planning inputs, treat it as an existing run directory"
            ),
        )
        parser.add_argument("--tmp", action="store_true", help="write plan artifacts to an isolated temporary directory under /tmp")
        _add_hypotheses_write_args(parser)
    else:
        _add_state_locator_args(parser)
    parser.add_argument("--concurrent-agents", type=_positive_int)
    _add_run_hypotheses_args(parser)
    parser.add_argument("--no-ledger", action="store_true", help="skip live BaseTeam ledger/review/persistence writes")
    parser.add_argument("--dry-run", action="store_true", help="simulate execution with the dry-run BaseTeam adapter")
    parser.add_argument(
        "--live-testing",
        "--live",
        dest="live_testing",
        action="store_true",
        help=(
            "enable live-testing/VM mode metadata for this run; source-only agent spawning is allowed by default, "
            "but live-testing still requires promotion unless --dry-run is used"
        ),
    )
    parser.add_argument(
        "--execute-live",
        dest="execute_live_compat",
        action="store_true",
        help=argparse.SUPPRESS,
    )


def _normalize_legacy_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] in {"-h", "--help"}:
        return argv
    if argv[0] in COMMANDS:
        return argv
    normalized = [item for item in argv if item != "--dry-run"]
    return ["plan", *normalized]


def _execute_live_requested(args: argparse.Namespace) -> bool:
    return not bool(getattr(args, "dry_run", False))


def _add_run_hypotheses_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run-hypotheses",
        type=_run_hypotheses_value,
        metavar="N|all|max",
        help=(
            f"cap runnable hypotheses/agents for this plan or wave; default: {DEFAULT_RUN_HYPOTHESES}; "
            "use all/max for no cap"
        ),
    )
    parser.add_argument(
        "--max-agents",
        type=_non_negative_int,
        help="compatibility alias for --run-hypotheses N",
    )


def _add_hypotheses_write_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--write-hypotheses",
        dest="write_hypotheses",
        action="store_true",
        default=None,
        help="compatibility flag; hypotheses.jsonl is written by default",
    )
    parser.add_argument(
        "--no-write-hypotheses",
        dest="write_hypotheses",
        action="store_false",
        help="do not write hypotheses.jsonl beside pipeline_plan.json",
    )


def _run_hypotheses_cap(args: argparse.Namespace) -> int | None:
    value = getattr(args, "run_hypotheses", None)
    if value in {"all", "max"}:
        return None
    if value is not None:
        return int(value)
    max_agents = getattr(args, "max_agents", None)
    if max_agents is not None:
        return int(max_agents)
    return DEFAULT_RUN_HYPOTHESES


def _write_hypotheses_enabled(args: argparse.Namespace) -> bool:
    value = getattr(args, "write_hypotheses", None)
    return True if value is None else bool(value)


def _output_dir_for_plan(args: argparse.Namespace, *, run_id: str) -> str | Path:
    if bool(getattr(args, "tmp", False)):
        return Path(tempfile.mkdtemp(prefix="hunt_pipeline_", dir="/tmp"))
    if getattr(args, "output_dir", None):
        return args.output_dir
    return DEFAULT_OUTPUT_ROOT / run_id


def _add_runs_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", help="base output root to scan; defaults to hunt_pipeline_out")
    parser.add_argument("--limit", type=_positive_int, default=DEFAULT_RECENT_RUN_LIMIT)
    parser.add_argument("--format", choices=("json", "text"), default="json", help="output format; default: json")


def _run_uses_existing_plan(args: argparse.Namespace) -> bool:
    if getattr(args, "program", None) or getattr(args, "target_path", None):
        return False
    return any(
        (
            getattr(args, "pipeline_plan", None),
            getattr(args, "output_dir", None),
            getattr(args, "run_id", None),
        )
    )


def _plan_run_id(args: argparse.Namespace) -> str:
    supplied = getattr(args, "run_id", None)
    if supplied:
        return validate_run_id(supplied)
    return _default_run_id()


def _runs_base_output_root(args: argparse.Namespace) -> Path:
    root = getattr(args, "output_dir", None) or DEFAULT_OUTPUT_ROOT
    return Path(root).expanduser().resolve(strict=False)


def _default_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"hunt-{stamp}-{uuid.uuid4().hex[:6]}"


def _live_testing_enabled_for_args(args: argparse.Namespace, plan_path: Path) -> bool:
    if bool(getattr(args, "live_testing", False)) or bool(getattr(args, "execute_live_compat", False)):
        return True
    if getattr(args, "command", None) in {"live", "live-test"}:
        return True
    state = load_run_state(run_state_path_for_plan(plan_path))
    config = state.get("run_config") if isinstance(state.get("run_config"), dict) else {}
    return bool(config.get("live_testing_enabled", False))


def _format_status_text(summary: dict[str, object]) -> str:
    contract = summary.get("runtime_handoff_contract") if isinstance(summary.get("runtime_handoff_contract"), dict) else {}
    protocol = summary.get("runtime_promotion_protocol") if isinstance(summary.get("runtime_promotion_protocol"), dict) else {}
    report = summary.get("runtime_preflight_report") if isinstance(summary.get("runtime_preflight_report"), dict) else {}
    readiness = (
        summary.get("runtime_promotion_readiness")
        if isinstance(summary.get("runtime_promotion_readiness"), dict)
        else {}
    )
    approval_schema = (
        summary.get("runtime_operator_approval_schema")
        if isinstance(summary.get("runtime_operator_approval_schema"), dict)
        else {}
    )
    environment_approval = (
        summary.get("runtime_environment_approval")
        if isinstance(summary.get("runtime_environment_approval"), dict)
        else {}
    )
    action_policy = (
        summary.get("runtime_action_policy")
        if isinstance(summary.get("runtime_action_policy"), dict)
        else {}
    )
    request_packet = (
        summary.get("runtime_promotion_request_packet")
        if isinstance(summary.get("runtime_promotion_request_packet"), dict)
        else {}
    )
    promotion_decision = (
        summary.get("runtime_promotion_decision")
        if isinstance(summary.get("runtime_promotion_decision"), dict)
        else {}
    )
    execution = summary.get("runtime_execution") if isinstance(summary.get("runtime_execution"), dict) else {}
    run_config = summary.get("run_config") if isinstance(summary.get("run_config"), dict) else {}
    static_handoffs = report.get("static_team_handoffs") if isinstance(report.get("static_team_handoffs"), dict) else {}
    dynamic_queue = report.get("dynamic_validation_queue") if isinstance(report.get("dynamic_validation_queue"), dict) else {}
    live_testing = report.get("live_testing_playbook") if isinstance(report.get("live_testing_playbook"), dict) else {}
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
        f"readiness_status={readiness.get('status')} "
        f"readiness_promoted={str(bool(readiness.get('promoted'))).lower()} "
        f"live_execution_ready={str(bool(readiness.get('live_execution_ready'))).lower()} "
        f"operator_approval_status={approval_schema.get('status')} "
        f"operator_approval_promoted={str(bool(approval_schema.get('promoted'))).lower()} "
        f"environment_approval_status={environment_approval.get('status')} "
        f"environment_approval_approved={str(bool(environment_approval.get('approved'))).lower()} "
        f"action_policy_status={action_policy.get('status')} "
        f"action_policy_valid={str(bool(action_policy.get('valid'))).lower()} "
        f"live_testing_enabled={str(bool(run_config.get('live_testing_enabled'))).lower()} "
        f"request_packet_status={request_packet.get('status')} "
        f"request_packet_action={request_packet.get('requested_action')} "
        f"request_packet_promoted={str(bool(request_packet.get('promoted'))).lower()} "
        f"promotion_decision_status={promotion_decision.get('status')} "
        f"promotion_decision_promoted={str(bool(promotion_decision.get('promoted'))).lower()} "
        f"live_requirements=promotion_decision+environment_approval+action_policy "
        f"execution_mode={execution.get('mode')} "
        f"default_execution_mode={execution.get('default_mode')} "
        f"preflight_status={report.get('status')} "
        f"failed_required_gates={contract.get('failed_required_gate_count', len(report.get('failed_required_gates', [])))} "
        f"static_team_handoffs={static_handoffs.get('state')} "
        f"dynamic_validation_queue={dynamic_queue.get('state')} "
        f"live_testing={live_testing.get('state')}"
    )


def _format_runs_text(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "no durable hunt-pipeline runs found"
    return "\n".join(
        (
            f"run_id={row.get('run_id') or '-'} "
            f"program={row.get('program') or '-'} "
            f"target_kind={row.get('target_kind') or '-'} "
            f"selected={row.get('selected')} "
            f"completed={row.get('completed')} "
            f"unrun={row.get('unrun')} "
            f"next_wave={row.get('next_wave')} "
            f"updated_at={row.get('updated_at') or '-'} "
            f"path={row.get('path')}"
        )
        for row in rows
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


def _run_hypotheses_value(value: str) -> int | str:
    normalized = str(value).strip().lower()
    if normalized in {"all", "max"}:
        return normalized
    return _non_negative_int(normalized)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
