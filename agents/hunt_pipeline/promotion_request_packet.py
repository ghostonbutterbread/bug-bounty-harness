from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.hunt_pipeline.operator_approval_schema import (
    build_runtime_operator_approval_schema,
    evaluate_runtime_operator_approval_schema,
)
from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report
from agents.hunt_pipeline.promotion_readiness import build_runtime_promotion_readiness_checklist
from agents.hunt_pipeline.runtime_contract import (
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    failed_required_gates,
)

REQUEST_PACKET_SCHEMA_VERSION = 1
REQUEST_PACKET_FILENAME = "runtime_promotion_request_packet.json"


@dataclass(frozen=True, slots=True)
class RuntimePromotionRequestPacket:
    schema_version: int
    status: str
    requested_action: str
    promoted: bool
    promotion_enabled: bool
    pipeline_plan: str
    explicit_status: dict[str, Any]
    evidence_paths: dict[str, str]
    evidence_sections: dict[str, Any]
    blocker_summary: tuple[dict[str, Any], ...]
    missing_approvals: tuple[str, ...]
    next_review_steps: tuple[dict[str, Any], ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_runtime_promotion_request_packet(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any] | None = None,
    status_summary: Mapping[str, Any] | None = None,
) -> RuntimePromotionRequestPacket:
    """Build a human-review-only promotion request packet without runtime side effects."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    payload = dict(plan or _load_plan(resolved_plan_path))
    contract = evaluate_runtime_handoff_contract(payload)
    protocol = evaluate_runtime_promotion_protocol(payload)
    preflight = build_runtime_preflight_report(resolved_plan_path, plan=payload)
    readiness = build_runtime_promotion_readiness_checklist(
        resolved_plan_path,
        plan=payload,
        status_summary=status_summary,
    ).to_dict()
    stored_approval_schema = evaluate_runtime_operator_approval_schema(payload)
    approval_schema = build_runtime_operator_approval_schema(resolved_plan_path, plan=payload).to_dict()
    missing_approvals = tuple(
        str(item)
        for item in (
            stored_approval_schema.get("missing_approval_ids")
            or approval_schema.get("missing_approval_ids")
            or ()
        )
        if str(item).strip()
    )
    blockers = tuple(
        _dedupe_blockers(
            [
                *_gate_blockers(failed_required_gates(contract)),
                *_blockers_from(preflight, "blockers_before_future_promotion"),
                *_blockers_from(readiness, "blockers"),
                *_blockers_from(approval_schema, "blockers"),
                *_missing_approval_blockers(missing_approvals),
                {
                    "source": "runtime_promotion_request_packet",
                    "id": "review_only",
                    "details": "request packet is a draft for human review and cannot promote runtime execution",
                },
            ]
        )
    )
    return RuntimePromotionRequestPacket(
        schema_version=REQUEST_PACKET_SCHEMA_VERSION,
        status="blocked" if blockers or missing_approvals else "draft",
        requested_action="review_only",
        promoted=False,
        promotion_enabled=False,
        pipeline_plan=str(resolved_plan_path),
        explicit_status={
            "promoted": False,
            "promotion_enabled": False,
            "not_promoted": True,
            "review_only": True,
            "not_promoted_reason": "runtime promotion request packets are evidence bundles only",
        },
        evidence_paths=_default_evidence_paths(resolved_plan_path),
        evidence_sections={
            "runtime_handoff_contract": {
                "status": str(contract.get("status") or "unknown"),
                "promotion_allowed": False,
                "failed_required_gate_count": len(failed_required_gates(contract)),
                "failed_required_gates": failed_required_gates(contract),
            },
            "runtime_promotion_protocol": {
                "status": str(protocol.get("status") or "unknown"),
                "valid": bool(protocol.get("valid") is True),
                "promotion_enabled": False,
                "stored_promotion_enabled": bool(protocol.get("stored_promotion_enabled", False)),
                "details": str(protocol.get("details") or ""),
            },
            "runtime_preflight_report": {
                "status": str(preflight.get("status") or "unknown"),
                "promotion_enabled": False,
                "static_team_handoffs": preflight.get("static_team_handoffs") or {},
                "dynamic_validation_queue": preflight.get("dynamic_validation_queue") or {},
            },
            "runtime_promotion_readiness": {
                "status": str(readiness.get("status") or "unknown"),
                "promotion_enabled": False,
                "promoted": False,
                "live_execution_ready": False,
                "blocker_count": len(readiness.get("blockers") or ()),
            },
            "runtime_operator_approval_schema": {
                "status": str(stored_approval_schema.get("status") or "unknown"),
                "valid": bool(stored_approval_schema.get("valid") is True),
                "promotion_enabled": False,
                "promoted": False,
                "missing_approval_ids": tuple(missing_approvals),
                "claimed_approved_ids": tuple(stored_approval_schema.get("claimed_approved_ids") or ()),
            },
        },
        blocker_summary=blockers,
        missing_approvals=missing_approvals,
        next_review_steps=_next_review_steps(missing_approvals),
        notes=(
            "This packet is for human review only; requested_action must remain review_only.",
            "promotion_enabled=false and promoted=false are required in this non-live slice.",
            "Missing, malformed, or claimed-promoted request packets cannot bypass runtime_handoff_contract.",
        ),
    )


def evaluate_runtime_promotion_request_packet(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return a conservative summary of a stored request packet artifact."""

    packet = _stored_request_packet(plan)
    if not isinstance(packet, Mapping):
        return {
            "schema_version": 0,
            "status": "missing",
            "requested_action": "missing",
            "promotion_enabled": False,
            "promoted": False,
            "valid": False,
            "details": "runtime_promotion_request_packet is missing",
        }
    schema_version = _schema_version(packet.get("schema_version"))
    status = str(packet.get("status") or "").strip()
    requested_action = str(packet.get("requested_action") or "").strip()
    stored_promotion_enabled = bool(packet.get("promotion_enabled") is True)
    stored_promoted = bool(packet.get("promoted") is True)
    top_level_flags_valid = isinstance(packet.get("promotion_enabled"), bool) and isinstance(
        packet.get("promoted"), bool
    )
    explicit_status = packet.get("explicit_status")
    explicit_status_valid = isinstance(explicit_status, Mapping) and all(
        isinstance(explicit_status.get(key), bool)
        for key in ("promoted", "promotion_enabled", "not_promoted", "review_only")
    )
    explicit_claim = (
        _nested_true(explicit_status, "promoted")
        or _nested_true(explicit_status, "promotion_enabled")
        or _nested_true(explicit_status, "not_promoted") is False
        or _nested_true(explicit_status, "review_only") is False
    )
    evidence_paths_valid = isinstance(packet.get("evidence_paths"), Mapping) and _has_required_keys(
        packet.get("evidence_paths"),
        _required_evidence_keys(),
    )
    evidence_sections_valid = isinstance(packet.get("evidence_sections"), Mapping) and _has_required_keys(
        packet.get("evidence_sections"),
        _required_evidence_keys(),
    )
    blockers_valid = isinstance(packet.get("blocker_summary"), list | tuple) and all(
        isinstance(item, Mapping) for item in packet.get("blocker_summary", ())
    )
    missing_approvals_valid = isinstance(packet.get("missing_approvals"), list | tuple) and all(
        isinstance(item, str) for item in packet.get("missing_approvals", ())
    )
    next_steps_valid = isinstance(packet.get("next_review_steps"), list | tuple) and all(
        isinstance(item, Mapping) for item in packet.get("next_review_steps", ())
    )
    valid = (
        schema_version >= REQUEST_PACKET_SCHEMA_VERSION
        and status in {"draft", "blocked"}
        and requested_action == "review_only"
        and top_level_flags_valid
        and stored_promotion_enabled is False
        and stored_promoted is False
        and explicit_status_valid
        and explicit_claim is False
        and evidence_paths_valid
        and evidence_sections_valid
        and blockers_valid
        and missing_approvals_valid
        and next_steps_valid
    )
    if valid:
        details = "runtime_promotion_request_packet is review-only and explicitly not promoted"
    elif stored_promotion_enabled or stored_promoted or explicit_claim:
        details = "runtime_promotion_request_packet cannot claim promotion in this slice"
    elif not top_level_flags_valid or not explicit_status_valid:
        details = "runtime_promotion_request_packet promotion flags must be JSON booleans"
    else:
        details = "runtime_promotion_request_packet is missing required review-only structure"
    return {
        "schema_version": schema_version,
        "status": status or "malformed",
        "requested_action": requested_action or "malformed",
        "promotion_enabled": False,
        "stored_promotion_enabled": stored_promotion_enabled,
        "promoted": False,
        "stored_promoted": stored_promoted,
        "valid": valid,
        "details": details,
        "missing_approvals": tuple(
            str(item) for item in packet.get("missing_approvals", ()) if isinstance(item, str)
        )
        if isinstance(packet.get("missing_approvals"), list | tuple)
        else (),
    }


def write_runtime_promotion_request_packet(
    plan_path: str | Path,
    *,
    output_path: str | Path | None = None,
    plan: Mapping[str, Any] | None = None,
    status_summary: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    """Write the request packet artifact without changing run state or invoking adapters."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    packet = build_runtime_promotion_request_packet(
        resolved_plan_path,
        plan=plan,
        status_summary=status_summary,
    ).to_dict()
    destination = (
        Path(output_path).expanduser().resolve(strict=False)
        if output_path is not None
        else resolved_plan_path.parent / REQUEST_PACKET_FILENAME
    )
    _atomic_write_text(destination, json.dumps(packet, indent=2, sort_keys=True) + "\n")
    return packet, destination


def _default_evidence_paths(plan_path: Path) -> dict[str, str]:
    return {
        "runtime_handoff_contract": f"{plan_path}#runtime_handoff_contract",
        "runtime_promotion_protocol": f"{plan_path}#runtime_promotion_protocol",
        "runtime_preflight_report": str(plan_path.parent / "runtime_preflight_report.json"),
        "runtime_promotion_readiness": str(plan_path.parent / "runtime_promotion_readiness.json"),
        "runtime_operator_approval_schema": str(plan_path.parent / "runtime_operator_approval_schema.json"),
    }


def _required_evidence_keys() -> tuple[str, ...]:
    return (
        "runtime_handoff_contract",
        "runtime_promotion_protocol",
        "runtime_preflight_report",
        "runtime_promotion_readiness",
        "runtime_operator_approval_schema",
    )


def _gate_blockers(failed_gates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "source": "runtime_handoff_contract.required_gate",
            "id": str(gate.get("gate_id") or ""),
            "details": str(gate.get("details") or ""),
        }
        for gate in failed_gates
    ]


def _blockers_from(artifact: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    raw = artifact.get(key)
    if not isinstance(raw, list | tuple):
        return []
    return [dict(item) for item in raw if isinstance(item, Mapping)]


def _missing_approval_blockers(missing: Sequence[str]) -> list[dict[str, Any]]:
    return [
        {
            "source": "runtime_promotion_request_packet.missing_approval",
            "id": approval_id,
            "details": "approval remains missing; packet stays review-only",
        }
        for approval_id in missing
    ]


def _next_review_steps(missing_approvals: Sequence[str]) -> tuple[dict[str, Any], ...]:
    return (
        {
            "step": "review_evidence_bundle",
            "status": "pending",
            "details": "review evidence_paths and evidence_sections; do not execute runtime adapters",
        },
        {
            "step": "resolve_missing_approvals",
            "status": "blocked" if missing_approvals else "pending",
            "details": ", ".join(missing_approvals) if missing_approvals else "no missing approvals claimed by packet",
        },
        {
            "step": "open_future_promotion_slice",
            "status": "future",
            "details": "runtime_handoff_contract must be changed in a separate reviewed slice before live execution",
        },
    )


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


def _stored_request_packet(plan: Mapping[str, Any]) -> Any:
    return plan.get("runtime_promotion_request_packet")


def _schema_version(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _has_required_keys(value: Any, required: Sequence[str]) -> bool:
    return isinstance(value, Mapping) and all(key in value for key in required)


def _nested_true(mapping: Any, key: str) -> bool:
    return isinstance(mapping, Mapping) and mapping.get(key) is True


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
