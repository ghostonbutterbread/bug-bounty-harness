from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

ENVIRONMENT_APPROVAL_SCHEMA_VERSION = 1
RUN_INTENT = "hunt-pipeline-live-testing"
DEFAULT_ALLOWED_SURFACES = (
    "ghidra-mcp",
    "mcp",
    "cdp",
    "ssh-local",
    "target-local-process",
    "localhost-tunnel-binding",
)


@dataclass(frozen=True, slots=True)
class RuntimeEnvironmentApproval:
    schema_version: int
    status: str
    environment_id: str
    environment_type: str
    scope: dict[str, Any]
    route_policy: dict[str, Any]
    surface_policy: dict[str, Any]
    environment_characteristics: dict[str, Any]
    approval_owner: str
    approved_at: str
    expires_at: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_runtime_environment_approval(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any],
) -> RuntimeEnvironmentApproval:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    return RuntimeEnvironmentApproval(
        schema_version=ENVIRONMENT_APPROVAL_SCHEMA_VERSION,
        status="approval_required",
        environment_id="",
        environment_type="",
        scope=_expected_scope(plan, resolved_plan_path),
        route_policy={
            "approved_route_roots": [],
            "denied_route_patterns": [
                {"kind": "cidr", "route": "169.254.169.254/32", "reason": "block metadata service access"},
                {"kind": "cidr", "route": "10.0.0.0/8", "reason": "block arbitrary LAN access unless explicitly approved"},
                {"kind": "cidr", "route": "172.16.0.0/12", "reason": "block arbitrary LAN access unless explicitly approved"},
                {"kind": "cidr", "route": "192.168.0.0/16", "reason": "block arbitrary LAN access unless explicitly approved"},
                {"kind": "pattern", "route": "*", "reason": "block unmanaged external hosts unless explicitly approved"},
            ],
            "denied_routes_override_allowed_routes": True,
        },
        surface_policy={
            "default_decision": "allow_in_environment",
            "allowed_by_default": list(DEFAULT_ALLOWED_SURFACES),
            "denied_surfaces": [],
        },
        environment_characteristics={
            "disposable_expected": True,
            "snapshot_backed_expected": True,
        },
        approval_owner="",
        approved_at="",
        expires_at="",
        notes=(
            "Approve one VM/tunnel environment for the run rather than whitelisting individual in-VM tools.",
            "Once approved, in-environment CDP, Ghidra MCP, MCP, SSH-local, localhost tunnel binds, and target-local processes are allowed unless explicitly denied.",
        ),
    )


def evaluate_runtime_environment_approval(
    plan: Mapping[str, Any],
    *,
    plan_path: str | Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    artifact = plan.get("runtime_environment_approval")
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    if not isinstance(artifact, Mapping):
        return {
            "schema_version": 0,
            "status": "missing",
            "valid": False,
            "approved": False,
            "environment_id": "",
            "environment_type": "",
            "scope_matches": False,
            "approved_route_root_count": 0,
            "denied_route_count": 0,
            "allowed_surface_defaults": [],
            "details": "runtime_environment_approval is missing",
        }

    schema_version = _schema_version(artifact.get("schema_version"))
    status = str(artifact.get("status") or "").strip()
    environment_id = str(artifact.get("environment_id") or "").strip()
    environment_type = str(artifact.get("environment_type") or "").strip()
    scope = artifact.get("scope")
    route_policy = artifact.get("route_policy")
    surface_policy = artifact.get("surface_policy")
    approval_owner = str(artifact.get("approval_owner") or "").strip()
    approved_at = _parse_timestamp(artifact.get("approved_at"))
    expires_at = _parse_timestamp(artifact.get("expires_at"))

    route_roots, route_roots_valid = _mapping_sequence(
        route_policy.get("approved_route_roots") if isinstance(route_policy, Mapping) else None
    )
    denied_routes, denied_routes_valid = _mapping_sequence(
        route_policy.get("denied_route_patterns") if isinstance(route_policy, Mapping) else None
    )
    allowed_surfaces = _string_sequence(
        surface_policy.get("allowed_by_default") if isinstance(surface_policy, Mapping) else None
    )
    denied_surfaces_valid = isinstance(
        surface_policy.get("denied_surfaces") if isinstance(surface_policy, Mapping) else None,
        list | tuple,
    )

    structure_errors: list[str] = []
    if schema_version < ENVIRONMENT_APPROVAL_SCHEMA_VERSION:
        structure_errors.append("schema_version is missing or unsupported")
    if status not in {"approval_required", "approved"}:
        structure_errors.append("status must be approval_required or approved")
    if not isinstance(scope, Mapping):
        structure_errors.append("scope must be an object")
    if not isinstance(route_policy, Mapping):
        structure_errors.append("route_policy must be an object")
    if not isinstance(surface_policy, Mapping):
        structure_errors.append("surface_policy must be an object")
    if not route_roots_valid:
        structure_errors.append("route_policy.approved_route_roots must be a list of objects")
    if not denied_routes_valid or not denied_routes:
        structure_errors.append("route_policy.denied_route_patterns must be a non-empty list of objects")
    if not isinstance(route_policy, Mapping) or route_policy.get("denied_routes_override_allowed_routes") is not True:
        structure_errors.append("route_policy.denied_routes_override_allowed_routes must be true")
    if not isinstance(surface_policy, Mapping) or str(surface_policy.get("default_decision") or "").strip() != "allow_in_environment":
        structure_errors.append("surface_policy.default_decision must be allow_in_environment")
    missing_surfaces = [surface for surface in DEFAULT_ALLOWED_SURFACES if surface not in allowed_surfaces]
    if missing_surfaces:
        structure_errors.append("surface_policy.allowed_by_default is missing required in-environment defaults")
    if not denied_surfaces_valid:
        structure_errors.append("surface_policy.denied_surfaces must be a list")

    if structure_errors:
        return _result(
            schema_version=schema_version,
            status="malformed",
            valid=False,
            approved=False,
            environment_id=environment_id,
            environment_type=environment_type,
            scope_matches=False,
            approved_route_root_count=len(route_roots),
            denied_route_count=len(denied_routes),
            allowed_surface_defaults=allowed_surfaces,
            details="; ".join(structure_errors),
        )

    assert isinstance(scope, Mapping)
    scope_errors = _scope_errors(scope, plan=plan, plan_path=resolved_plan_path)
    if scope_errors:
        return _result(
            schema_version=schema_version,
            status="wrong_scope",
            valid=False,
            approved=False,
            environment_id=environment_id,
            environment_type=environment_type,
            scope_matches=False,
            approved_route_root_count=len(route_roots),
            denied_route_count=len(denied_routes),
            allowed_surface_defaults=allowed_surfaces,
            details="; ".join(scope_errors),
        )

    if status == "approval_required":
        return _result(
            schema_version=schema_version,
            status=status,
            valid=True,
            approved=False,
            environment_id=environment_id,
            environment_type=environment_type,
            scope_matches=True,
            approved_route_root_count=len(route_roots),
            denied_route_count=len(denied_routes),
            allowed_surface_defaults=allowed_surfaces,
            details="runtime_environment_approval is well-formed but not yet approved for this run",
        )

    approval_errors: list[str] = []
    if not environment_id:
        approval_errors.append("environment_id is required once status=approved")
    if not environment_type:
        approval_errors.append("environment_type is required once status=approved")
    if not route_roots:
        approval_errors.append("approved_route_roots must be non-empty once status=approved")
    if not approval_owner:
        approval_errors.append("approval_owner is required once status=approved")
    if approved_at is None:
        approval_errors.append("approved_at must be an ISO timestamp once status=approved")
    if expires_at is None:
        approval_errors.append("expires_at must be an ISO timestamp once status=approved")
    if approval_errors:
        return _result(
            schema_version=schema_version,
            status="malformed",
            valid=False,
            approved=False,
            environment_id=environment_id,
            environment_type=environment_type,
            scope_matches=True,
            approved_route_root_count=len(route_roots),
            denied_route_count=len(denied_routes),
            allowed_surface_defaults=allowed_surfaces,
            details="; ".join(approval_errors),
        )

    current_time = now or datetime.now(UTC)
    if expires_at is not None and expires_at <= current_time:
        return _result(
            schema_version=schema_version,
            status="expired",
            valid=False,
            approved=False,
            environment_id=environment_id,
            environment_type=environment_type,
            scope_matches=True,
            approved_route_root_count=len(route_roots),
            denied_route_count=len(denied_routes),
            allowed_surface_defaults=allowed_surfaces,
            details="runtime_environment_approval has expired",
            expires_at=_timestamp_text(artifact.get("expires_at")),
        )

    return _result(
        schema_version=schema_version,
        status="approved",
        valid=True,
        approved=True,
        environment_id=environment_id,
        environment_type=environment_type,
        scope_matches=True,
        approved_route_root_count=len(route_roots),
        denied_route_count=len(denied_routes),
        allowed_surface_defaults=allowed_surfaces,
        details="runtime_environment_approval is approved for this plan and target/run intent",
        approval_owner=approval_owner,
        approved_at=_timestamp_text(artifact.get("approved_at")),
        expires_at=_timestamp_text(artifact.get("expires_at")),
    )


def _expected_scope(plan: Mapping[str, Any], plan_path: Path) -> dict[str, Any]:
    appmap_source = plan.get("appmap_source") if isinstance(plan.get("appmap_source"), Mapping) else {}
    return {
        "pipeline_plan": str(plan_path),
        "program": str(plan.get("program") or "").strip(),
        "target_path": str(Path(str(plan.get("target_path") or "")).expanduser().resolve(strict=False)),
        "target_kind": str(plan.get("target_kind") or "").strip(),
        "ruleset_id": str((plan.get("selected_rulesets") or {}).get("id") or "").strip()
        if isinstance(plan.get("selected_rulesets"), Mapping)
        else "",
        "appmap_run": str(Path(str(appmap_source.get("run_root") or "")).expanduser().resolve(strict=False)),
        "run_intent": RUN_INTENT,
    }


def _scope_errors(scope: Mapping[str, Any], *, plan: Mapping[str, Any], plan_path: Path) -> list[str]:
    expected = _expected_scope(plan, plan_path)
    errors: list[str] = []
    for key, expected_value in expected.items():
        actual = str(scope.get(key) or "").strip()
        if actual != expected_value:
            errors.append(f"scope.{key} does not match this plan")
    return errors


def _result(
    *,
    schema_version: int,
    status: str,
    valid: bool,
    approved: bool,
    environment_id: str,
    environment_type: str,
    scope_matches: bool,
    approved_route_root_count: int,
    denied_route_count: int,
    allowed_surface_defaults: list[str],
    details: str,
    approval_owner: str = "",
    approved_at: str = "",
    expires_at: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "status": status,
        "valid": valid,
        "approved": approved,
        "environment_id": environment_id,
        "environment_type": environment_type,
        "scope_matches": scope_matches,
        "approved_route_root_count": approved_route_root_count,
        "denied_route_count": denied_route_count,
        "allowed_surface_defaults": allowed_surface_defaults,
        "approval_owner": approval_owner,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "details": details,
    }


def _mapping_sequence(value: Any) -> tuple[list[Mapping[str, Any]], bool]:
    if not isinstance(value, list | tuple):
        return [], False
    mappings = [item for item in value if isinstance(item, Mapping)]
    return mappings, len(mappings) == len(value)


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


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
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _timestamp_text(value: Any) -> str:
    return str(value or "").strip()
