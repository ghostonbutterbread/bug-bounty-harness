#!/usr/bin/env python3
"""CLI for the dynamic validation harness MVP."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.storage_resolver import resolve_family_lane, resolve_storage

from agents.dynamic_validation.execution import action_requires_transport, execute_action
from agents.dynamic_validation.models import EvidenceRecord, ValidationAction, ValidationVerdict
from agents.dynamic_validation.playbooks import CanvaElectronPlaybook, ElectronBasePlaybook
from agents.dynamic_validation.policy import PolicyGate
from agents.dynamic_validation.queue import ScopedTaskQueue
from agents.dynamic_validation.report_ingest import ingest_execute_action_task, ingest_report_task, ingest_scout_task
from agents.dynamic_validation.report_layout import legacy_status_first_dirs
from agents.dynamic_validation.reporting import live_validation_lock_root, write_live_validation_artifacts
from agents.dynamic_validation.transports import CDPTransportError, ElectronCDPTransport

DEFAULT_QUEUE = ScopedTaskQueue()
SCOUT_PRIVATE_WORKFLOW_AI_ACTIONS = frozenset(
    {
        "private_workflow_create",
        "canva_ai_private_chat",
    }
)


def _playbook_for(name: str, target: str):
    selected = (name or "").strip().lower()
    normalized_target = target.strip().lower()
    if selected == "canva-electron" or (not selected and normalized_target == "canva"):
        return CanvaElectronPlaybook()
    return ElectronBasePlaybook()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dynamic validation harness MVP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Show live-validation status")
    status_parser.add_argument("--target", required=True)
    status_parser.add_argument("--lane", required=True)
    status_parser.add_argument("--family")
    status_parser.add_argument("--root")

    validate_parser = subparsers.add_parser("validate-report", help="Dry-run validate a finding report")
    validate_parser.add_argument("--target", required=True)
    validate_parser.add_argument("--lane", required=True)
    validate_parser.add_argument("--family")
    validate_parser.add_argument("--root")
    validate_parser.add_argument("--fid")
    validate_parser.add_argument("--report-path")
    validate_parser.add_argument("--cdp")
    validate_parser.add_argument("--account", default="default")
    validate_parser.add_argument("--vm", default="default")
    validate_parser.add_argument("--playbook", default="")
    validate_parser.add_argument("--dry-run", action="store_true", default=True)

    scout_parser = subparsers.add_parser("scout", help="Rehearse live validation without a report or ledger mutation")
    scout_parser.add_argument("--target", required=True)
    scout_parser.add_argument("--lane", required=True)
    scout_parser.add_argument("--family")
    scout_parser.add_argument("--root")
    scout_parser.add_argument("--cdp")
    scout_parser.add_argument("--account", default="default")
    scout_parser.add_argument("--vm", default="default")
    scout_parser.add_argument("--playbook", default="")
    scout_parser.add_argument("--allow-private-workflow-ai", action="store_true")

    execute_parser = subparsers.add_parser("execute-action", help="Execute one bounded live validation action")
    execute_parser.add_argument("--target", required=True)
    execute_parser.add_argument("--lane", required=True)
    execute_parser.add_argument("--family")
    execute_parser.add_argument("--root")
    execute_parser.add_argument("--fid")
    execute_parser.add_argument("--report-path")
    execute_parser.add_argument("--cdp")
    execute_parser.add_argument("--account", default="default")
    execute_parser.add_argument("--vm", default="default")
    execute_parser.add_argument("--playbook", default="")
    execute_parser.add_argument("--action-kind", required=True)
    execute_parser.add_argument("--description", required=True)
    execute_parser.add_argument("--target-ref")
    execute_parser.add_argument("--metadata-json")
    return parser


def _all_actions_allowed(decisions) -> bool:
    return all(decision.decision == "allow" for decision in decisions)


def _build_verdict(
    task,
    *,
    state: str = "blocked",
    playbook_name: str,
    decisions,
    summary: str,
    evidence: list[EvidenceRecord] | None = None,
    error: str | None = None,
    metadata: dict | None = None,
    dry_run: bool | None = None,
) -> ValidationVerdict:
    verdict_metadata = {
        "playbook": playbook_name,
        "mutation_status": "todo",
        "task": task.to_dict(),
    }
    if metadata:
        verdict_metadata.update(metadata)
    if error:
        verdict_metadata["error"] = error
    return ValidationVerdict(
        state=state,
        summary=summary,
        run_id=task.run_id,
        fid=task.fid,
        report_path=task.report_path,
        dry_run=task.dry_run if dry_run is None else dry_run,
        evidence=list(evidence or ()),
        policy_decisions=decisions,
        metadata=verdict_metadata,
    )


def _policy_gate_for(args: argparse.Namespace) -> PolicyGate:
    operator_approved_actions: set[str] = set()
    if getattr(args, "allow_private_workflow_ai", False):
        operator_approved_actions.update(SCOUT_PRIVATE_WORKFLOW_AI_ACTIONS)
    return PolicyGate(operator_approved_actions=operator_approved_actions)


def _scout_operator_approved_actions(args: argparse.Namespace) -> list[str]:
    approved_actions: list[str] = []
    if getattr(args, "allow_private_workflow_ai", False):
        approved_actions.extend(sorted(SCOUT_PRIVATE_WORKFLOW_AI_ACTIONS))
    return approved_actions


def _metadata_json_for(args: argparse.Namespace) -> dict:
    raw = str(getattr(args, "metadata_json", "") or "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"metadata-json must be valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("metadata-json must decode to a JSON object")
    return payload


def _render_scout_action_plan(task, decisions) -> str:
    action_lines = []
    for index, decision in enumerate(decisions, start=1):
        action = decision.action
        description = action.description if action is not None else decision.action_kind
        target = f" ({action.target})" if action is not None and action.target else ""
        action_lines.append(
            f"{index}. `{decision.action_kind}`{target}: {description} -> `{decision.decision}` ({decision.reason})"
        )

    return "\n".join(
        [
            "# Live Agent Scout Plan",
            "",
            f"Run ID: `{task.run_id}`",
            f"Target: `{task.target}`",
            f"Mode: `{task.metadata.get('mode', 'unknown')}`",
            "",
            "## Safe rehearsal scope",
            "",
            "- Collect CDP version, target-list, snapshot, and bounded local test-account evidence.",
            "- Local test-user actions are allowed when private/non-disruptive: IPC, templates, private docs, store apps, and Canva AI.",
            "- Do not publish, share publicly, comment, invite, message, contact support, buy, delete, or change team/billing/account state.",
            "",
            "## Allowed bounded private interactions for a future live agent",
            "",
            "- Live IPC calls tied to the report hypothesis and scoped to the isolated VM/test account.",
            "- Private workflow/document creation, template usage, and free store-app install/use in an isolated account/workspace.",
            "- Private Canva AI chat in a non-sharing, non-publishing path.",
            "",
            "## Stop conditions",
            "",
            "- Stop if the UI flow would publish, share, invite, comment, message, or expose content publicly.",
            "- Stop if the UI reaches billing, purchase, team-admin, account-settings, deletion, or bulk-creation surfaces.",
            "- Stop if the app requests wider privileges, mass traffic, or any action outside the single-object private scope.",
            "- Stop if CDP context looks unexpected, unstable, or points away from the intended private target.",
            "",
            "## Planned actions and policy decisions",
            "",
            *action_lines,
            "",
        ]
    )


def _status(args: argparse.Namespace) -> int:
    family, lane = resolve_family_lane(family=args.family, lane=args.lane, hunt_type="source")
    storage = resolve_storage(
        args.target,
        family=family,
        lane=lane,
        root_override=args.root,
        create=False,
    )
    live_root = storage.reports_root / "live_validation"
    payload = {
        "target": args.target,
        "family": family,
        "lane": lane,
        "reports_root": str(storage.reports_root),
        "live_runs": sorted(
            path.name for path in live_root.iterdir() if not path.name.startswith(".")
        ) if live_root.is_dir() else [],
        "legacy_status_first_dirs": [path.name for path in legacy_status_first_dirs(storage.reports_root)],
        "queue": DEFAULT_QUEUE.status(),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _validate_report(args: argparse.Namespace) -> int:
    if not args.fid and not args.report_path:
        raise SystemExit("validate-report requires --fid or --report-path")

    family, lane = resolve_family_lane(family=args.family, lane=args.lane, hunt_type="source")
    storage = resolve_storage(
        args.target,
        family=family,
        lane=lane,
        root_override=args.root,
        create=False,
    )
    playbook = _playbook_for(args.playbook, args.target)
    task = ingest_report_task(
        args.target,
        fid=args.fid,
        report_path=args.report_path,
        family=family,
        lane=lane,
        root_override=args.root,
        cdp_url=args.cdp,
        account=args.account,
        vm=args.vm,
        playbook=playbook.name,
        dry_run=True,
    )
    task.actions = playbook.plan(task)
    decisions = _policy_gate_for(args).evaluate_actions(task.actions)
    with DEFAULT_QUEUE.acquire(task, lock_root=live_validation_lock_root(storage)):
        if not _all_actions_allowed(decisions):
            verdict = _build_verdict(
                task,
                playbook_name=playbook.name,
                decisions=decisions,
                summary="Dry run blocked by dynamic validation policy before preflight.",
            )
        else:
            try:
                transport = ElectronCDPTransport(task.cdp_url) if task.cdp_url else None
                evidence = playbook.collect_preflight(task, transport)
                verdict = _build_verdict(
                    task,
                    state="planned",
                    playbook_name=playbook.name,
                    decisions=decisions,
                    summary="Dry run only; no mutating live validation steps were executed.",
                    evidence=evidence,
                )
            except CDPTransportError as exc:
                verdict = _build_verdict(
                    task,
                    playbook_name=playbook.name,
                    decisions=decisions,
                    summary="Dry run blocked by CDP preflight error.",
                    evidence=[
                        EvidenceRecord(
                            kind="error",
                            name="cdp_error.json",
                            data={"message": str(exc), "cdp_url": task.cdp_url or ""},
                            note="Read-only preflight failed before any live validation step ran.",
                        )
                    ],
                    error=str(exc),
                )
        artifact_root = write_live_validation_artifacts(storage, task, verdict)

    payload = {
        "status": "ok",
        "target": args.target,
        "fid": task.fid,
        "run_id": task.run_id,
        "artifact_root": str(artifact_root),
        "playbook": playbook.name,
        "dry_run": True,
        "verdict_state": verdict.state,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _scout(args: argparse.Namespace) -> int:
    family, lane = resolve_family_lane(family=args.family, lane=args.lane, hunt_type="source")
    storage = resolve_storage(
        args.target,
        family=family,
        lane=lane,
        root_override=args.root,
        create=True,
    )
    playbook = _playbook_for(args.playbook, args.target)
    task = ingest_scout_task(
        args.target,
        family=family,
        lane=lane,
        root_override=args.root,
        cdp_url=args.cdp,
        account=args.account,
        vm=args.vm,
        playbook=playbook.name,
        dry_run=True,
    )
    task.actions = playbook.plan(task)
    approved_actions = _scout_operator_approved_actions(args)
    decisions = _policy_gate_for(args).evaluate_actions(task.actions)
    evidence = [
        EvidenceRecord(
            kind="plan",
            name="action_plan.md",
            data=_render_scout_action_plan(task, decisions),
            note="Scout rehearsal plan and stop conditions",
        ),
        EvidenceRecord(
            kind="policy",
            name="policy_decisions.json",
            data=[decision.to_dict() for decision in decisions],
            note="Policy decisions for the scout rehearsal plan",
        ),
    ]
    summary = "Scout rehearsal recorded without executing live UI actions."
    state = "planned"

    with DEFAULT_QUEUE.acquire(task, lock_root=live_validation_lock_root(storage)):
        try:
            transport = ElectronCDPTransport(task.cdp_url) if task.cdp_url else None
            evidence = evidence + playbook.collect_preflight(task, transport)
        except CDPTransportError as exc:
            evidence.append(
                EvidenceRecord(
                    kind="error",
                    name="cdp_error.json",
                    data={"message": str(exc), "cdp_url": task.cdp_url or ""},
                    note="Read-only scout preflight failed before any live UI action ran.",
                )
            )
            summary = "Scout rehearsal recorded, but CDP preflight evidence collection failed."
            state = "blocked"

        verdict = _build_verdict(
            task,
            state=state,
            playbook_name=playbook.name,
            decisions=decisions,
            summary=summary,
            evidence=evidence,
            metadata={
                "mode": "scout",
                "report_source": "none",
                "operator_approved_actions": approved_actions,
            },
        )
        artifact_root = write_live_validation_artifacts(storage, task, verdict)

    payload = {
        "status": "ok",
        "target": args.target,
        "fid": task.fid,
        "run_id": task.run_id,
        "artifact_root": str(artifact_root),
        "playbook": playbook.name,
        "dry_run": True,
        "verdict_state": verdict.state,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _execute_action(args: argparse.Namespace) -> int:
    family, lane = resolve_family_lane(family=args.family, lane=args.lane, hunt_type="source")
    storage = resolve_storage(
        args.target,
        family=family,
        lane=lane,
        root_override=args.root,
        create=True,
    )
    task = ingest_execute_action_task(
        args.target,
        fid=args.fid,
        report_path=args.report_path,
        family=family,
        lane=lane,
        root_override=args.root,
        cdp_url=args.cdp,
        account=args.account,
        vm=args.vm,
        playbook=args.playbook or _playbook_for(args.playbook, args.target).name,
        dry_run=False,
    )
    action = ValidationAction(
        kind=args.action_kind,
        description=args.description,
        target=(args.target_ref or "").strip() or None,
        metadata=_metadata_json_for(args),
    )
    task.actions = [action]
    decisions = _policy_gate_for(args).evaluate_actions(task.actions)
    evidence = [
        EvidenceRecord(
            kind="action",
            name="action.json",
            data=action.to_dict(),
            note="Requested one-step validation action payload.",
        ),
        EvidenceRecord(
            kind="policy",
            name="policy_decisions.json",
            data=[decision.to_dict() for decision in decisions],
            note="Policy decision for the execute-action run.",
        ),
    ]

    with DEFAULT_QUEUE.acquire(task, lock_root=live_validation_lock_root(storage)):
        decision = decisions[0]
        if decision.decision != "allow":
            verdict = _build_verdict(
                task,
                playbook_name=task.playbook,
                decisions=decisions,
                summary="Execute-action request was blocked by dynamic validation policy before transport.",
                evidence=evidence,
                metadata={
                    "mode": "execute-action",
                    "action": action.to_dict(),
                },
                dry_run=False,
            )
        else:
            try:
                transport = None
                if action_requires_transport(action):
                    if not task.cdp_url:
                        raise CDPTransportError(f"{action.kind} requires --cdp")
                    transport = ElectronCDPTransport(task.cdp_url)
                state, summary, action_evidence, action_metadata = execute_action(action, transport=transport)
                verdict = _build_verdict(
                    task,
                    state=state,
                    playbook_name=task.playbook,
                    decisions=decisions,
                    summary=summary,
                    evidence=evidence + action_evidence,
                    metadata={
                        "mode": "execute-action",
                        "action": action.to_dict(),
                        **action_metadata,
                    },
                    dry_run=False,
                )
            except CDPTransportError as exc:
                verdict = _build_verdict(
                    task,
                    playbook_name=task.playbook,
                    decisions=decisions,
                    summary="Execute-action request was blocked by a CDP transport error.",
                    evidence=evidence
                    + [
                        EvidenceRecord(
                            kind="error",
                            name="cdp_error.json",
                            data={"message": str(exc), "cdp_url": task.cdp_url or ""},
                            note="The bounded action stopped after a CDP transport or target-selection error.",
                        )
                    ],
                    error=str(exc),
                    metadata={
                        "mode": "execute-action",
                        "action": action.to_dict(),
                    },
                    dry_run=False,
                )
        artifact_root = write_live_validation_artifacts(storage, task, verdict)

    payload = {
        "status": "ok",
        "target": args.target,
        "fid": task.fid,
        "run_id": task.run_id,
        "artifact_root": str(artifact_root),
        "playbook": task.playbook,
        "dry_run": False,
        "verdict_state": verdict.state,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        return _status(args)
    if args.command == "validate-report":
        return _validate_report(args)
    if args.command == "scout":
        return _scout(args)
    if args.command == "execute-action":
        return _execute_action(args)
    raise SystemExit(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
