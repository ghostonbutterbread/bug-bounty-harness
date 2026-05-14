from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report
from agents.hunt_pipeline.runtime_action_policy import evaluate_runtime_action_policy
from agents.hunt_pipeline.runtime_contract import (
    PROMOTION_READINESS_SCHEMA_VERSION,
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    evaluate_runtime_promotion_readiness,
    failed_required_gates,
)
from agents.hunt_pipeline.runtime_environment_approval import evaluate_runtime_environment_approval

READINESS_FILENAME = "runtime_promotion_readiness.json"


@dataclass(frozen=True, slots=True)
class RuntimePromotionReadinessChecklist:
    schema_version: int
    status: str
    promoted: bool
    promotion_enabled: bool
    live_execution_ready: bool
    pipeline_plan: str
    explicit_status: dict[str, Any]
    required_approvals: tuple[dict[str, Any], ...]
    blockers: tuple[dict[str, Any], ...]
    gates: dict[str, Any]
    preflight_states: dict[str, Any]
    runtime_environment_approval: dict[str, Any]
    runtime_action_policy: dict[str, Any]
    runtime_promotion_protocol: dict[str, Any]
    run_status: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_runtime_promotion_readiness_checklist(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any] | None = None,
    status_summary: Mapping[str, Any] | None = None,
) -> RuntimePromotionReadinessChecklist:
    """Build a typed, non-live readiness packet without invoking runtime adapters."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    payload = dict(plan or _load_plan(resolved_plan_path))
    contract = evaluate_runtime_handoff_contract(payload)
    protocol = evaluate_runtime_promotion_protocol(payload)
    stored_readiness = evaluate_runtime_promotion_readiness(payload)
    preflight = build_runtime_preflight_report(resolved_plan_path, plan=payload)
    environment_approval = evaluate_runtime_environment_approval(payload, plan_path=resolved_plan_path)
    action_policy = evaluate_runtime_action_policy(payload, plan_path=resolved_plan_path)
    failed_gates = failed_required_gates(contract)
    approvals = _required_approvals(payload)
    blockers = _dedupe_blockers(
        [
            *_gate_blockers(failed_gates),
            *_preflight_blockers(preflight),
            *_protocol_blockers(protocol),
            *_stored_readiness_blockers(stored_readiness),
            *_environment_approval_blockers(environment_approval),
            *_action_policy_blockers(action_policy),
            *_approval_blockers(approvals),
        ]
    )
    return RuntimePromotionReadinessChecklist(
        schema_version=PROMOTION_READINESS_SCHEMA_VERSION,
        status="not_ready",
        promoted=False,
        promotion_enabled=False,
        live_execution_ready=False,
        pipeline_plan=str(resolved_plan_path),
        explicit_status={
            "ready": False,
            "promoted": False,
            "not_promoted_reason": "live execution is intentionally unavailable in this non-live slice",
        },
        required_approvals=tuple(approvals),
        blockers=tuple(blockers),
        gates={
            "status": str(contract.get("status") or "unknown"),
            "promotion_allowed": False,
            "failed_required_gate_count": len(failed_gates),
            "failed_required_gates": failed_gates,
        },
        preflight_states={
            "status": str(preflight.get("status") or "unknown"),
            "promotion_enabled": False,
            "runtime_environment_approval": preflight.get("runtime_environment_approval") or {},
            "runtime_action_policy": preflight.get("runtime_action_policy") or {},
            "static_team_handoffs": preflight.get("static_team_handoffs") or {},
            "dynamic_validation_queue": preflight.get("dynamic_validation_queue") or {},
            "live_testing_playbook": preflight.get("live_testing_playbook") or {},
        },
        runtime_environment_approval={
            "status": str(environment_approval.get("status") or "unknown"),
            "valid": bool(environment_approval.get("valid") is True),
            "approved": bool(environment_approval.get("approved") is True),
            "details": str(environment_approval.get("details") or ""),
        },
        runtime_action_policy={
            "status": str(action_policy.get("status") or "unknown"),
            "valid": bool(action_policy.get("valid") is True),
            "active": bool(action_policy.get("active") is True),
            "default_classification": str(action_policy.get("default_classification") or ""),
            "details": str(action_policy.get("details") or ""),
        },
        runtime_promotion_protocol={
            "status": str(protocol.get("status") or "unknown"),
            "valid": bool(protocol.get("valid") is True),
            "promotion_enabled": False,
            "stored_promotion_enabled": bool(protocol.get("stored_promotion_enabled", False)),
            "details": str(protocol.get("details") or ""),
        },
        run_status=_run_status_snapshot(status_summary),
        notes=(
            "This checklist is an approval packet only; it does not promote or execute agents.",
            "Missing, malformed, or claimed-enabled readiness data keeps --execute-live blocked.",
            "Adapters, static teams, dynamic validation, and ledger writes remain out of scope.",
        ),
    )


def write_runtime_promotion_readiness_checklist(
    plan_path: str | Path,
    *,
    output_path: str | Path | None = None,
    plan: Mapping[str, Any] | None = None,
    status_summary: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    """Write the readiness packet without changing run state or invoking adapters."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    checklist = build_runtime_promotion_readiness_checklist(
        resolved_plan_path,
        plan=plan,
        status_summary=status_summary,
    ).to_dict()
    destination = (
        Path(output_path).expanduser().resolve(strict=False)
        if output_path is not None
        else resolved_plan_path.parent / READINESS_FILENAME
    )
    _atomic_write_text(destination, json.dumps(checklist, indent=2, sort_keys=True) + "\n")
    return checklist, destination


def non_live_readiness_stub() -> dict[str, Any]:
    return {
        "schema_version": PROMOTION_READINESS_SCHEMA_VERSION,
        "status": "not_ready",
        "promoted": False,
        "promotion_enabled": False,
        "live_execution_ready": False,
        "required_approvals": [
            {
                "approval": "operator_live_execution_approval",
                "owner": "human-operator",
                "required": True,
                "status": "required_unapproved",
            }
        ],
        "blockers": [
            {
                "source": "runtime_handoff_contract.required_gate",
                "id": "explicit_contract_promotion",
                "details": "contract has not been explicitly promoted for live execution",
            }
        ],
        "gates": {"status": "blocked", "promotion_allowed": False},
        "preflight_states": {"status": "blocked", "promotion_enabled": False},
    }


def _required_approvals(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    protocol = plan.get("runtime_promotion_protocol") if isinstance(plan.get("runtime_promotion_protocol"), Mapping) else {}
    raw = protocol.get("required_approvals") if isinstance(protocol, Mapping) else None
    if not isinstance(raw, list | tuple):
        return []
    approvals: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        approval = dict(item)
        approval["status"] = "required_unapproved" if approval.get("required") is True else "optional_unapproved"
        approvals.append(approval)
    return approvals


def _gate_blockers(failed_gates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "source": "runtime_handoff_contract.required_gate",
            "id": str(gate.get("gate_id") or ""),
            "details": str(gate.get("details") or ""),
        }
        for gate in failed_gates
    ]


def _preflight_blockers(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = preflight.get("blockers_before_future_promotion")
    if not isinstance(raw, list | tuple):
        return []
    return [dict(item) for item in raw if isinstance(item, Mapping)]


def _protocol_blockers(protocol: Mapping[str, Any]) -> list[dict[str, Any]]:
    if protocol.get("valid") is True and protocol.get("stored_promotion_enabled") is not True:
        return []
    return [
        {
            "source": "runtime_promotion_protocol",
            "id": "runtime_promotion_protocol",
            "details": str(protocol.get("details") or "runtime_promotion_protocol is not valid"),
        }
    ]


def _stored_readiness_blockers(readiness: Mapping[str, Any]) -> list[dict[str, Any]]:
    if readiness.get("valid") is True:
        return []
    return [
        {
            "source": "runtime_promotion_readiness",
            "id": "runtime_promotion_readiness",
            "details": str(readiness.get("details") or "runtime_promotion_readiness is not valid"),
        }
    ]


def _approval_blockers(approvals: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    if not approvals:
        return [
            {
                "source": "runtime_promotion_protocol.required_approvals",
                "id": "required_approvals",
                "details": "required approvals are missing or malformed",
            }
        ]
    for approval in approvals:
        if approval.get("required") is not True:
            continue
        blockers.append(
            {
                "source": "runtime_promotion_protocol.required_approval",
                "id": str(approval.get("approval") or ""),
                "details": f"status={approval.get('status', 'required_unapproved')}",
            }
        )
    return blockers


def _environment_approval_blockers(environment_approval: Mapping[str, Any]) -> list[dict[str, Any]]:
    if environment_approval.get("valid") is not True:
        return [
            {
                "source": "runtime_environment_approval",
                "id": "runtime_environment_approval",
                "details": str(environment_approval.get("details") or "runtime_environment_approval is not valid"),
            }
        ]
    if environment_approval.get("approved") is True:
        return []
    return [
        {
            "source": "runtime_environment_approval",
            "id": "runtime_environment_approval_approval_required",
            "details": str(
                environment_approval.get("details")
                or "runtime_environment_approval must be approved for live execution"
            ),
        }
    ]


def _action_policy_blockers(action_policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    if action_policy.get("valid") is True:
        return []
    return [
        {
            "source": "runtime_action_policy",
            "id": "runtime_action_policy",
            "details": str(action_policy.get("details") or "runtime_action_policy is not valid"),
        }
    ]


def _run_status_snapshot(status_summary: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(status_summary, Mapping):
        return {}
    keys = (
        "total",
        "selected",
        "completed",
        "running",
        "failed",
        "deferred",
        "skipped",
        "unrun",
        "next_wave_count",
        "pause_requested",
        "stopped_requested",
    )
    return {key: status_summary[key] for key in keys if key in status_summary}


def _dedupe_blockers(blockers: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in blockers:
        source = str(item.get("source") or "")
        blocker_id = str(item.get("id") or "")
        details = str(item.get("details") or "")
        key = (source, blocker_id, details)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(item))
    return deduped


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
