from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from agents.hunt_pipeline.live_testing import summarize_live_testing_playbook
from agents.hunt_pipeline.runtime_action_policy import evaluate_runtime_action_policy
from agents.hunt_pipeline.runtime_environment_approval import evaluate_runtime_environment_approval

DECISION_SCHEMA_VERSION = 1
DECISION_FILENAME = "runtime_promotion_decision.json"


def evaluate_runtime_promotion_decision(
    plan: Mapping[str, Any],
    *,
    plan_path: str | Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate the only artifact allowed to promote hunt-pipeline live execution."""

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    decision, source, load_error = _load_decision(plan, resolved_plan_path)
    if load_error:
        return _blocked("malformed", source=source, details=load_error)
    if not isinstance(decision, Mapping):
        status = "missing" if source == "missing" else "malformed"
        details = (
            "runtime promotion decision record is missing"
            if status == "missing"
            else "runtime promotion decision record must be a JSON object"
        )
        return _blocked(status, source=source, details=details)

    schema_version = _schema_version(decision.get("schema_version"))
    status = str(decision.get("status") or "").strip()
    decision_type = str(decision.get("decision") or "").strip()
    execution_mode = str(decision.get("execution_mode") or "").strip()
    promoted_flag = bool(decision.get("promotion_enabled") is True or decision.get("promoted") is True)
    approved_by = str(decision.get("approved_by") or "").strip()
    approved_at = _parse_timestamp(decision.get("approved_at"))
    expires_at = _parse_timestamp(decision.get("expires_at"))
    scope = decision.get("scope")
    controls = decision.get("controls")

    shape_errors: list[str] = []
    if schema_version < DECISION_SCHEMA_VERSION:
        shape_errors.append("schema_version is missing or unsupported")
    if status != "approved":
        shape_errors.append("status must be approved")
    if decision_type != "promote-runtime":
        shape_errors.append("decision must be promote-runtime")
    if execution_mode != "live":
        shape_errors.append("execution_mode must be live")
    if decision.get("promotion_enabled") is not True:
        shape_errors.append("promotion_enabled must be true")
    if not approved_by:
        shape_errors.append("approved_by is required")
    if approved_at is None:
        shape_errors.append("approved_at must be an ISO timestamp")
    if expires_at is None:
        shape_errors.append("expires_at must be an ISO timestamp")
    if not isinstance(scope, Mapping):
        shape_errors.append("scope must be an object")
    if not isinstance(controls, Mapping):
        shape_errors.append("controls must be an object")

    if shape_errors:
        status_value = "claimed" if promoted_flag or status == "promoted" else "malformed"
        return _blocked(
            status_value,
            source=source,
            schema_version=schema_version,
            details="; ".join(shape_errors),
            stored_promotion_enabled=promoted_flag,
        )

    assert isinstance(scope, Mapping)
    assert isinstance(controls, Mapping)
    scope_errors = _scope_errors(scope, plan=plan, plan_path=resolved_plan_path)
    if scope_errors:
        return _blocked(
            "wrong_scope",
            source=source,
            schema_version=schema_version,
            details="; ".join(scope_errors),
            stored_promotion_enabled=promoted_flag,
        )

    current_time = now or datetime.now(UTC)
    if expires_at is not None and expires_at <= current_time:
        return _blocked(
            "expired",
            source=source,
            schema_version=schema_version,
            details="runtime promotion decision record has expired",
            stored_promotion_enabled=promoted_flag,
            expires_at=_timestamp_text(decision.get("expires_at")),
        )

    live_testing = summarize_live_testing_playbook(plan)
    environment_approval = evaluate_runtime_environment_approval(plan, plan_path=resolved_plan_path, now=current_time)
    if environment_approval.get("valid") is not True:
        return _blocked(
            str(environment_approval.get("status") or "malformed"),
            source=source,
            schema_version=schema_version,
            details=str(environment_approval.get("details") or "runtime_environment_approval is not valid"),
            stored_promotion_enabled=promoted_flag,
            expires_at=_timestamp_text(decision.get("expires_at")),
        )
    if environment_approval.get("approved") is not True:
        return _blocked(
            "approval_required",
            source=source,
            schema_version=schema_version,
            details=str(
                environment_approval.get("details")
                or "runtime_environment_approval must be approved for live execution"
            ),
            stored_promotion_enabled=promoted_flag,
            expires_at=_timestamp_text(decision.get("expires_at")),
        )

    action_policy = evaluate_runtime_action_policy(plan, plan_path=resolved_plan_path, now=current_time)
    if action_policy.get("valid") is not True:
        return _blocked(
            str(action_policy.get("status") or "malformed"),
            source=source,
            schema_version=schema_version,
            details=str(action_policy.get("details") or "runtime_action_policy is not valid"),
            stored_promotion_enabled=promoted_flag,
            expires_at=_timestamp_text(decision.get("expires_at")),
        )

    control_errors = [*_control_errors(controls), *_live_testing_errors(live_testing)]
    if control_errors:
        return _blocked(
            "claimed",
            source=source,
            schema_version=schema_version,
            details="; ".join(control_errors),
            stored_promotion_enabled=promoted_flag,
        )

    return {
        "schema_version": schema_version,
        "status": "promoted",
        "valid": True,
        "promoted": True,
        "promotion_allowed": True,
        "execution_mode": "live",
        "decision_source": source,
        "decision_id": str(decision.get("decision_id") or "").strip(),
        "approved_by": approved_by,
        "approved_at": _timestamp_text(decision.get("approved_at")),
        "expires_at": _timestamp_text(decision.get("expires_at")),
        "scope": dict(scope),
        "controls": dict(controls),
        "runtime_environment_approval": dict(environment_approval),
        "runtime_action_policy": dict(action_policy),
        "details": "runtime promotion decision record is valid for this plan",
    }


def runtime_execution_mode(
    plan: Mapping[str, Any],
    *,
    plan_path: str | Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    decision = evaluate_runtime_promotion_decision(plan, plan_path=plan_path)
    if dry_run:
        return {
            "mode": "dry-run",
            "default_mode": "live" if decision.get("promoted") is True else "blocked",
            "dry_run": True,
            "live": False,
            "promotion_required": False,
            "runtime_promotion_decision": decision,
        }
    if decision.get("promoted") is True:
        return {
            "mode": "live",
            "default_mode": "live",
            "dry_run": False,
            "live": True,
            "promotion_required": False,
            "runtime_promotion_decision": decision,
        }
    return {
        "mode": "blocked",
        "default_mode": "blocked",
        "dry_run": False,
        "live": False,
        "promotion_required": True,
        "runtime_promotion_decision": decision,
    }


def _load_decision(plan: Mapping[str, Any], plan_path: Path) -> tuple[Any, str, str]:
    inline = plan.get("runtime_promotion_decision")
    if inline is not None:
        return inline, "pipeline_plan.runtime_promotion_decision", ""
    sidecar = plan_path.parent / DECISION_FILENAME
    if not sidecar.exists():
        return None, "missing", ""
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(sidecar), f"{type(exc).__name__}: {exc}"
    return payload, str(sidecar), ""


def _scope_errors(scope: Mapping[str, Any], *, plan: Mapping[str, Any], plan_path: Path) -> list[str]:
    errors: list[str] = []
    expected_plan = str(plan_path)
    expected_program = str(plan.get("program") or "").strip()
    expected_target = str(Path(str(plan.get("target_path") or "")).expanduser().resolve(strict=False))
    appmap_source = plan.get("appmap_source") if isinstance(plan.get("appmap_source"), Mapping) else {}
    expected_appmap = str(Path(str(appmap_source.get("run_root") or "")).expanduser().resolve(strict=False))

    if str(scope.get("pipeline_plan") or "").strip() != expected_plan:
        errors.append("scope.pipeline_plan does not match this plan")
    if str(scope.get("program") or "").strip() != expected_program:
        errors.append("scope.program does not match this plan")
    if str(Path(str(scope.get("target_path") or "")).expanduser().resolve(strict=False)) != expected_target:
        errors.append("scope.target_path does not match this plan")
    if "appmap_run" in scope and str(Path(str(scope.get("appmap_run") or "")).expanduser().resolve(strict=False)) != expected_appmap:
        errors.append("scope.appmap_run does not match this plan")
    return errors


def _control_errors(controls: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if controls.get("bounded_live_execution") is not True:
        errors.append("controls.bounded_live_execution must be true")
    if controls.get("use_base_team_primitives") is not True:
        errors.append("controls.use_base_team_primitives must be true")
    if controls.get("scope_and_wave_controls") is not True:
        errors.append("controls.scope_and_wave_controls must be true")
    if controls.get("live_testing_playbook_reviewed") is not True:
        errors.append("controls.live_testing_playbook_reviewed must be true")
    return errors


def _live_testing_errors(live_testing: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if live_testing.get("state") != "planned-only":
        blockers = live_testing.get("blockers")
        if isinstance(blockers, list | tuple) and blockers:
            errors.extend(str(item) for item in blockers)
        else:
            errors.append("live_testing_playbook must be planned-only and valid")
    if live_testing.get("execution_enabled") is True:
        errors.append("live_testing_playbook.execution_enabled must remain false")
    return errors


def _blocked(
    status: str,
    *,
    source: str,
    details: str,
    schema_version: int = 0,
    stored_promotion_enabled: bool = False,
    expires_at: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "status": status,
        "valid": False,
        "promoted": False,
        "promotion_allowed": False,
        "execution_mode": "blocked",
        "decision_source": source,
        "stored_promotion_enabled": stored_promotion_enabled,
        "expires_at": expires_at,
        "details": details,
    }


def _schema_version(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _timestamp_text(value: Any) -> str:
    return str(value or "").strip()
