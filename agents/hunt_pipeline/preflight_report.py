from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from agents.hunt_pipeline.live_testing import summarize_live_testing_playbook
from agents.hunt_pipeline.runtime_action_policy import evaluate_runtime_action_policy
from agents.hunt_pipeline.runtime_environment_approval import evaluate_runtime_environment_approval
from agents.hunt_pipeline.runtime_contract import (
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    failed_required_gates,
)

REPORT_SCHEMA_VERSION = 1
REPORT_FILENAME = "runtime_preflight_report.json"


def build_runtime_preflight_report(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a non-live promotion preflight summary from pipeline_plan.json."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    payload = dict(plan or _load_plan(resolved_plan_path))
    contract = evaluate_runtime_handoff_contract(payload)
    protocol = evaluate_runtime_promotion_protocol(payload)
    failed_gates = failed_required_gates(contract)
    static_handoffs = _summarize_static_team_handoffs(payload)
    dynamic_queue = _summarize_dynamic_validation_queue(payload)
    live_testing = summarize_live_testing_playbook(payload)
    environment_approval = evaluate_runtime_environment_approval(payload, plan_path=resolved_plan_path)
    action_policy = evaluate_runtime_action_policy(payload, plan_path=resolved_plan_path)
    blockers = _blockers_before_future_promotion(
        failed_gates=failed_gates,
        protocol=protocol,
        plan=payload,
        live_testing=live_testing,
        environment_approval=environment_approval,
        action_policy=action_policy,
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "blocked",
        "pipeline_plan": str(resolved_plan_path),
        "promotion_enabled": False,
        "runtime_handoff_contract": {
            "status": str(contract.get("status") or "unknown"),
            "promotion_allowed": False,
            "failed_required_gate_count": len(failed_gates),
        },
        "failed_required_gates": failed_gates,
        "runtime_promotion_protocol": {
            "status": str(protocol.get("status") or "unknown"),
            "promotion_enabled": False,
            "stored_promotion_enabled": bool(protocol.get("stored_promotion_enabled", False)),
            "valid": bool(protocol.get("valid") is True),
            "details": str(protocol.get("details") or ""),
        },
        "runtime_environment_approval": environment_approval,
        "runtime_action_policy": action_policy,
        "static_team_handoffs": static_handoffs,
        "dynamic_validation_queue": dynamic_queue,
        "live_testing_playbook": live_testing,
        "blockers_before_future_promotion": blockers,
    }


def write_runtime_preflight_report(
    plan_path: str | Path,
    *,
    output_path: str | Path | None = None,
    plan: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    """Write the preflight report artifact without invoking runtime adapters."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    report = build_runtime_preflight_report(resolved_plan_path, plan=plan)
    destination = (
        Path(output_path).expanduser().resolve(strict=False)
        if output_path is not None
        else resolved_plan_path.parent / REPORT_FILENAME
    )
    _atomic_write_text(destination, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report, destination


def _summarize_static_team_handoffs(plan: Mapping[str, Any]) -> dict[str, Any]:
    handoffs = plan.get("static_team_handoffs") if isinstance(plan.get("static_team_handoffs"), Mapping) else {}
    planned_raw = handoffs.get("planned")
    planned_shape_valid = isinstance(planned_raw, list | tuple)
    planned = [item for item in (planned_raw if planned_shape_valid else ()) if isinstance(item, Mapping)]
    statuses = [str(item.get("invocation_status") or "").strip() for item in planned]
    enabled = bool(handoffs.get("enabled") is True)
    invocation_enabled = bool(handoffs.get("invocation_enabled") is True)
    planned_only = (
        planned_shape_valid
        and not enabled
        and not invocation_enabled
        and all(status == "planned-only" for status in statuses)
    )
    blockers: list[str] = []
    if enabled:
        blockers.append("static_team_handoffs.enabled must remain false")
    if invocation_enabled:
        blockers.append("static_team_handoffs.invocation_enabled must remain false")
    if not planned_shape_valid:
        blockers.append("static_team_handoffs.planned must be a list")
    if any(status != "planned-only" for status in statuses):
        blockers.append("every static_team_handoffs.planned item must have invocation_status=planned-only")
    return {
        "state": "planned-only" if planned_only else "blocking",
        "enabled": enabled,
        "invocation_enabled": invocation_enabled,
        "planned_count": len(planned),
        "planned_teams": [str(item.get("team") or "").strip() for item in planned if str(item.get("team") or "").strip()],
        "invocation_statuses": statuses,
        "blockers": blockers,
    }


def _summarize_dynamic_validation_queue(plan: Mapping[str, Any]) -> dict[str, Any]:
    queue = plan.get("dynamic_validation_queue") if isinstance(plan.get("dynamic_validation_queue"), Mapping) else {}
    queued_raw = queue.get("queued")
    queued_shape_valid = isinstance(queued_raw, list | tuple)
    queued = list(queued_raw if queued_shape_valid else ())
    enabled = bool(queue.get("enabled") is True)
    disabled = queued_shape_valid and not enabled and len(queued) == 0
    blockers: list[str] = []
    if enabled:
        blockers.append("dynamic_validation_queue.enabled must remain false")
    if not queued_shape_valid:
        blockers.append("dynamic_validation_queue.queued must be a list")
    if queued:
        blockers.append("dynamic_validation_queue.queued must be empty")
    return {
        "state": "disabled" if disabled else "blocking",
        "enabled": enabled,
        "queued_count": len(queued),
        "blockers": blockers,
    }


def _blockers_before_future_promotion(
    *,
    failed_gates: list[dict[str, Any]],
    protocol: Mapping[str, Any],
    plan: Mapping[str, Any],
    live_testing: Mapping[str, Any],
    environment_approval: Mapping[str, Any],
    action_policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = [
        {
            "source": "runtime_handoff_contract.required_gate",
            "id": str(gate.get("gate_id") or ""),
            "details": str(gate.get("details") or ""),
        }
        for gate in failed_gates
    ]
    stored_protocol = plan.get("runtime_promotion_protocol")
    if isinstance(stored_protocol, Mapping):
        approvals, approvals_valid = _mapping_sequence(stored_protocol.get("required_approvals"))
        if not approvals_valid:
            blockers.append(
                {
                    "source": "runtime_promotion_protocol.required_approvals",
                    "id": "required_approvals",
                    "details": "required_approvals must be a list of objects",
                }
            )
        for approval in approvals:
            if approval.get("required") is not True:
                continue
            blockers.append(
                {
                    "source": "runtime_promotion_protocol.required_approval",
                    "id": str(approval.get("approval") or ""),
                    "details": _approval_details(approval),
                }
            )
        future_steps, future_steps_valid = _mapping_sequence(stored_protocol.get("future_promotion_steps"))
        if not future_steps_valid:
            blockers.append(
                {
                    "source": "runtime_promotion_protocol.future_promotion_steps",
                    "id": "future_promotion_steps",
                    "details": "future_promotion_steps must be a list of objects",
                }
            )
        for step in future_steps:
            status = str(step.get("status") or "").strip()
            if status == "complete":
                continue
            blockers.append(
                {
                    "source": "runtime_promotion_protocol.future_promotion_step",
                    "id": str(step.get("step") or ""),
                    "status": status or "unknown",
                    "details": _requires_details(step.get("requires")),
                }
            )
    elif protocol.get("status") == "missing":
        blockers.append(
            {
                "source": "runtime_promotion_protocol",
                "id": "runtime_promotion_protocol",
                "details": str(protocol.get("details") or "runtime_promotion_protocol is missing"),
            }
        )
    if str(live_testing.get("state") or "") != "planned-only":
        for detail in live_testing.get("blockers", ()):
            blockers.append(
                {
                    "source": "live_testing_playbook",
                    "id": "live_testing_playbook",
                    "details": str(detail or "live_testing_playbook is malformed"),
                }
            )
    if bool(environment_approval.get("valid") is not True):
        blockers.append(
            {
                "source": "runtime_environment_approval",
                "id": "runtime_environment_approval",
                "details": str(environment_approval.get("details") or "runtime_environment_approval is not valid"),
            }
        )
    elif bool(environment_approval.get("approved") is not True):
        blockers.append(
            {
                "source": "runtime_environment_approval",
                "id": "runtime_environment_approval_approval_required",
                "details": str(
                    environment_approval.get("details")
                    or "runtime_environment_approval must be approved for live execution"
                ),
            }
        )
    if bool(action_policy.get("valid") is not True):
        blockers.append(
            {
                "source": "runtime_action_policy",
                "id": "runtime_action_policy",
                "details": str(action_policy.get("details") or "runtime_action_policy is not valid"),
            }
        )
    return blockers


def _approval_details(approval: Mapping[str, Any]) -> str:
    owner = str(approval.get("owner") or "").strip()
    evidence = str(approval.get("evidence") or "").strip()
    parts = []
    if owner:
        parts.append(f"owner={owner}")
    if evidence:
        parts.append(f"evidence={evidence}")
    return "; ".join(parts)


def _requires_details(value: Any) -> str:
    if isinstance(value, list | tuple):
        requirements = [str(item).strip() for item in value if str(item).strip()]
        if requirements:
            return "requires=" + ", ".join(requirements)
    return "requires not specified"


def _mapping_sequence(value: Any) -> tuple[list[Mapping[str, Any]], bool]:
    if value is None:
        return [], False
    if not isinstance(value, list | tuple):
        return [], False
    mappings = [item for item in value if isinstance(item, Mapping)]
    return mappings, len(mappings) == len(value)


def _load_plan(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"pipeline plan must be a JSON object: {path}")
    return payload


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(path)
