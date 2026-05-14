from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report
from agents.hunt_pipeline.runtime_contract import (
    evaluate_runtime_promotion_protocol,
    evaluate_runtime_promotion_readiness,
)

APPROVAL_SCHEMA_VERSION = 1
APPROVAL_SCHEMA_FILENAME = "runtime_operator_approval_schema.json"
APPROVAL_RECORD_FIELDS = ("approval_id", "approver", "timestamp", "scope", "evidence", "decision")
APPROVAL_DECISIONS = {"missing", "pending", "approved", "rejected", "blocked"}


@dataclass(frozen=True, slots=True)
class RuntimeOperatorApprovalSchema:
    schema_version: int
    status: str
    promoted: bool
    promotion_enabled: bool
    pipeline_plan: str
    explicit_status: dict[str, Any]
    required_approval_ids: tuple[str, ...]
    approval_record_fields: tuple[str, ...]
    approval_records: tuple[dict[str, Any], ...]
    missing_approval_ids: tuple[str, ...]
    blockers: tuple[dict[str, Any], ...]
    runtime_promotion_protocol: dict[str, Any]
    runtime_promotion_readiness: dict[str, Any]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_runtime_operator_approval_schema(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any] | None = None,
) -> RuntimeOperatorApprovalSchema:
    """Build a non-live approval-record schema for a future promotion request."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    payload = dict(plan or _load_plan(resolved_plan_path))
    protocol = evaluate_runtime_promotion_protocol(payload)
    readiness = evaluate_runtime_promotion_readiness(payload)
    preflight = build_runtime_preflight_report(resolved_plan_path, plan=payload)
    required_ids = tuple(_required_approval_ids(payload))
    records = tuple(_placeholder_record(approval_id, payload) for approval_id in required_ids)
    missing = tuple(required_ids)
    blockers = tuple(
        _dedupe_blockers(
            [
                *_preflight_blockers(preflight),
                *_missing_approval_blockers(missing),
                {
                    "source": "runtime_operator_approval_schema",
                    "id": "not_promoted",
                    "details": "approval records are draft-only and cannot promote runtime execution",
                },
            ]
        )
    )
    return RuntimeOperatorApprovalSchema(
        schema_version=APPROVAL_SCHEMA_VERSION,
        status="blocked",
        promoted=False,
        promotion_enabled=False,
        pipeline_plan=str(resolved_plan_path),
        explicit_status={
            "promoted": False,
            "promotion_enabled": False,
            "not_promoted": True,
            "not_promoted_reason": "operator approval records are not a live promotion mechanism in this slice",
        },
        required_approval_ids=required_ids,
        approval_record_fields=APPROVAL_RECORD_FIELDS,
        approval_records=records,
        missing_approval_ids=missing,
        blockers=blockers,
        runtime_promotion_protocol={
            "status": str(protocol.get("status") or "unknown"),
            "valid": bool(protocol.get("valid") is True),
            "promotion_enabled": False,
            "stored_promotion_enabled": bool(protocol.get("stored_promotion_enabled", False)),
            "details": str(protocol.get("details") or ""),
        },
        runtime_promotion_readiness={
            "status": str(readiness.get("status") or "unknown"),
            "valid": bool(readiness.get("valid") is True),
            "promotion_enabled": False,
            "stored_promotion_enabled": bool(readiness.get("stored_promotion_enabled", False)),
            "promoted": False,
            "stored_promoted": bool(readiness.get("stored_promoted", False)),
            "live_execution_ready": False,
            "stored_live_execution_ready": bool(readiness.get("stored_live_execution_ready", False)),
            "details": str(readiness.get("details") or ""),
        },
        notes=(
            "This schema records future operator approvals only; it does not promote runtime execution.",
            "status must remain draft or blocked and promotion_enabled must remain false.",
            "Approved-looking records are evidence only and cannot bypass runtime_handoff_contract.",
        ),
    )


def evaluate_runtime_operator_approval_schema(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return a conservative summary of a stored operator approval schema artifact."""

    artifact = _stored_approval_schema(plan)
    if not isinstance(artifact, Mapping):
        return {
            "schema_version": 0,
            "status": "missing",
            "promotion_enabled": False,
            "promoted": False,
            "valid": False,
            "details": "runtime_operator_approval_schema is missing",
            "required_approval_ids": tuple(_required_approval_ids(plan)),
            "missing_approval_ids": tuple(_required_approval_ids(plan)),
            "claimed_approved_ids": (),
        }
    schema_version = _schema_version(artifact.get("schema_version"))
    status = str(artifact.get("status") or "").strip()
    stored_promotion_enabled = bool(artifact.get("promotion_enabled") is True)
    stored_promoted = bool(artifact.get("promoted") is True)
    top_level_flags_valid = isinstance(artifact.get("promotion_enabled"), bool) and isinstance(
        artifact.get("promoted"), bool
    )
    explicit_status = artifact.get("explicit_status")
    explicit_status_valid = isinstance(explicit_status, Mapping) and all(
        isinstance(explicit_status.get(key), bool)
        for key in ("promoted", "promotion_enabled", "not_promoted")
    )
    explicit_claim = (
        _nested_true(explicit_status, "promoted")
        or _nested_true(explicit_status, "promotion_enabled")
        or _nested_true(explicit_status, "not_promoted") is False
    )
    required_ids = tuple(_required_approval_ids(plan))
    stored_required_ids, required_ids_shape_valid = _string_sequence(artifact.get("required_approval_ids"))
    fields, fields_shape_valid = _string_sequence(artifact.get("approval_record_fields"))
    records, records_shape_valid = _mapping_sequence(artifact.get("approval_records"))
    record_shape_valid = records_shape_valid and all(_approval_record_valid(record) for record in records)
    record_ids = tuple(str(record.get("approval_id") or "").strip() for record in records if isinstance(record, Mapping))
    claimed_approved_ids = tuple(
        record_id
        for record_id, record in zip(record_ids, records, strict=False)
        if str(record.get("decision") or "").strip() == "approved"
    )
    decisions_by_id = {
        str(record.get("approval_id") or "").strip(): str(record.get("decision") or "").strip()
        for record in records
        if isinstance(record, Mapping)
    }
    missing_ids = tuple(
        approval_id for approval_id in required_ids if decisions_by_id.get(approval_id) != "approved"
    )
    required_ids_valid = required_ids_shape_valid and set(required_ids).issubset(set(stored_required_ids))
    fields_valid = fields_shape_valid and set(APPROVAL_RECORD_FIELDS).issubset(set(fields))
    blockers_shape_valid = isinstance(artifact.get("blockers"), list | tuple)
    valid = (
        schema_version >= APPROVAL_SCHEMA_VERSION
        and status in {"draft", "blocked"}
        and top_level_flags_valid
        and stored_promotion_enabled is False
        and stored_promoted is False
        and explicit_status_valid
        and explicit_claim is False
        and required_ids_valid
        and fields_valid
        and record_shape_valid
        and blockers_shape_valid
    )
    if valid:
        details = "runtime_operator_approval_schema is non-live and explicitly not promoted"
    elif stored_promotion_enabled or stored_promoted or explicit_claim:
        details = "runtime_operator_approval_schema cannot claim promotion in this slice"
    elif not top_level_flags_valid or not explicit_status_valid:
        details = "runtime_operator_approval_schema promotion flags must be JSON booleans"
    elif not record_shape_valid or not required_ids_shape_valid or not fields_shape_valid:
        details = "runtime_operator_approval_schema has malformed approval record structure"
    else:
        details = "runtime_operator_approval_schema is missing required draft-only structure"
    return {
        "schema_version": schema_version,
        "status": status or "malformed",
        "promotion_enabled": False,
        "stored_promotion_enabled": stored_promotion_enabled,
        "promoted": False,
        "stored_promoted": stored_promoted,
        "valid": valid,
        "details": details,
        "required_approval_ids": required_ids,
        "stored_required_approval_ids": stored_required_ids,
        "missing_approval_ids": missing_ids,
        "claimed_approved_ids": claimed_approved_ids,
    }


def write_runtime_operator_approval_schema(
    plan_path: str | Path,
    *,
    output_path: str | Path | None = None,
    plan: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    """Write the approval schema artifact without invoking adapters or changing run state."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    schema = build_runtime_operator_approval_schema(resolved_plan_path, plan=plan).to_dict()
    destination = (
        Path(output_path).expanduser().resolve(strict=False)
        if output_path is not None
        else resolved_plan_path.parent / APPROVAL_SCHEMA_FILENAME
    )
    _atomic_write_text(destination, json.dumps(schema, indent=2, sort_keys=True) + "\n")
    return schema, destination


def _required_approval_ids(plan: Mapping[str, Any]) -> list[str]:
    ids: list[str] = []
    for source_name in ("runtime_promotion_protocol", "runtime_promotion_readiness"):
        source = plan.get(source_name) if isinstance(plan.get(source_name), Mapping) else {}
        raw = source.get("required_approvals") if isinstance(source, Mapping) else None
        if not isinstance(raw, list | tuple):
            continue
        for item in raw:
            if not isinstance(item, Mapping) or item.get("required") is not True:
                continue
            approval_id = str(item.get("approval") or item.get("approval_id") or "").strip()
            if approval_id and approval_id not in ids:
                ids.append(approval_id)
    return ids


def _placeholder_record(approval_id: str, plan: Mapping[str, Any]) -> dict[str, Any]:
    source = _approval_source(approval_id, plan)
    return {
        "approval_id": approval_id,
        "approver": "",
        "timestamp": "",
        "scope": source.get("scope", "future runtime promotion request"),
        "evidence": source.get("evidence", ""),
        "decision": "missing",
    }


def _approval_source(approval_id: str, plan: Mapping[str, Any]) -> dict[str, str]:
    for source_name in ("runtime_promotion_protocol", "runtime_promotion_readiness"):
        source = plan.get(source_name) if isinstance(plan.get(source_name), Mapping) else {}
        raw = source.get("required_approvals") if isinstance(source, Mapping) else None
        if not isinstance(raw, list | tuple):
            continue
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            item_id = str(item.get("approval") or item.get("approval_id") or "").strip()
            if item_id != approval_id:
                continue
            owner = str(item.get("owner") or "").strip()
            evidence = str(item.get("evidence") or "").strip()
            scope = f"{source_name}:{owner}" if owner else source_name
            return {"scope": scope, "evidence": evidence}
    return {}


def _preflight_blockers(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = preflight.get("blockers_before_future_promotion")
    if not isinstance(raw, list | tuple):
        return []
    return [dict(item) for item in raw if isinstance(item, Mapping)]


def _missing_approval_blockers(missing: Sequence[str]) -> list[dict[str, Any]]:
    return [
        {
            "source": "runtime_operator_approval_schema.required_approval",
            "id": approval_id,
            "details": "approval record is missing or unapproved",
        }
        for approval_id in missing
    ]


def _approval_record_valid(record: Mapping[str, Any]) -> bool:
    if not set(APPROVAL_RECORD_FIELDS).issubset(record.keys()):
        return False
    decision = str(record.get("decision") or "").strip()
    return (
        isinstance(record.get("approval_id"), str)
        and bool(record.get("approval_id").strip())
        and isinstance(record.get("approver"), str)
        and isinstance(record.get("timestamp"), str)
        and isinstance(record.get("scope"), str)
        and isinstance(record.get("evidence"), str)
        and decision in APPROVAL_DECISIONS
    )


def _stored_approval_schema(plan: Mapping[str, Any]) -> Any:
    artifact = plan.get("runtime_operator_approval_schema")
    if artifact is None:
        artifact = plan.get("runtime_promotion_approval_schema")
    return artifact


def _schema_version(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _string_sequence(value: Any) -> tuple[tuple[str, ...], bool]:
    if value is None or not isinstance(value, list | tuple):
        return (), False
    strings = tuple(str(item).strip() for item in value if isinstance(item, str) and str(item).strip())
    return strings, len(strings) == len(value)


def _mapping_sequence(value: Any) -> tuple[tuple[Mapping[str, Any], ...], bool]:
    if value is None or not isinstance(value, list | tuple):
        return (), False
    mappings = tuple(item for item in value if isinstance(item, Mapping))
    return mappings, len(mappings) == len(value)


def _nested_true(mapping: Any, key: str) -> bool:
    return isinstance(mapping, Mapping) and mapping.get(key) is True


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
