from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from agents.hunt_pipeline.runtime_environment_approval import RUN_INTENT

RUNTIME_ACTION_POLICY_SCHEMA_VERSION = 1
RISKY_DEFAULT_ACTION_TAGS = {
    "account_create",
    "bulk_creation",
    "bulk_update",
    "channel_create",
    "comment",
    "community_create",
    "coupon",
    "credit",
    "dm",
    "email",
    "follow",
    "gift_card",
    "guild_create",
    "invite",
    "message",
    "notification",
    "payment",
    "post",
    "public_upload",
    "publish",
    "purchase",
    "rating",
    "reaction",
    "refund",
    "review",
    "scrape",
    "server_create",
    "shared_state_change",
    "sms",
    "social_action",
    "subscription",
    "vendor_visible_persist",
    "webhook",
    "workspace_create",
}


@dataclass(frozen=True, slots=True)
class RuntimeActionPolicy:
    schema_version: int
    status: str
    policy_id: str
    default_classification: str
    scope: dict[str, Any]
    issued_at: str
    expires_at: str
    classifications: dict[str, Any]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_runtime_action_policy(
    plan_path: str | Path,
    *,
    plan: Mapping[str, Any],
) -> RuntimeActionPolicy:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    return RuntimeActionPolicy(
        schema_version=RUNTIME_ACTION_POLICY_SCHEMA_VERSION,
        status="active",
        policy_id="private-by-default-v1",
        default_classification="approval_required",
        scope=_expected_scope(plan, resolved_plan_path),
        issued_at="1970-01-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        classifications={
            "allowed_private": {
                "description": (
                    "Scoped testing actions allowed by default when they are private, reversible, local, "
                    "sandboxed, low-risk, or read-only."
                ),
                "action_tags": [
                    "static_analysis",
                    "debugger_inspection",
                    "read_only_ui_mapping",
                    "vm_local_interaction",
                    "scoped_browser_testing",
                    "scoped_api_replay",
                    "authenticated_session_use",
                    "caido_session_header_use",
                    "current_session_update",
                    "bounded_race_test",
                    "owned_account_message",
                    "owned_account_invite",
                    "owned_resource_share",
                    "private_draft",
                    "self_settings_change",
                    "evidence_capture",
                    "stop_before_confirmation",
                    "sandbox_test_endpoint",
                ],
                "examples": [
                    "Inspect code, flows, and debugger state without changing shared state.",
                    "Use approved owned/test accounts to browse, replay requests, compare behavior, and validate vulnerabilities inside scope.",
                    "Use explicitly approved Caido-held Authorization/Cookie values in memory to update the current scoped browser session, such as mySession, without printing or storing the raw values.",
                    "Race test owned resources with a total burst budget of 35 requests or less for one hypothesis.",
                    "Send invites or messages only between validated owned test accounts or clearly owned private workspaces/resources.",
                    "Share resources only when the resource, sender, recipients, and workspace are all validated as owned/approved for the test.",
                    "Use private drafts or self-only settings that can be reverted.",
                    "Stop at the final confirmation step of risky flows without submitting them.",
                ],
            },
            "approval_required": {
                "description": "Potentially valid tests that could affect people, money, shared state, or vendor-visible systems and need exact approval for the action, target, account, and environment.",
                "action_tags": sorted(RISKY_DEFAULT_ACTION_TAGS),
                "examples": [
                    "Payments, purchases, subscriptions, refunds, credits, coupons, or checkout submission.",
                    "Public posts, publishing, comments, reactions, invites, messages, notifications, emails, or social actions.",
                    "Shared guild/community/workspace creation, bulk changes, public uploads, or vendor/customer-visible persistence.",
                ],
            },
            "blocked": {
                "description": "Damaging or out-of-scope behavior that should not occur in normal promoted runs.",
                "action_tags": [
                    "bypass_vm_guard",
                    "credential_harvesting",
                    "destructive_change",
                    "exfiltration",
                    "irreversible_financial_change",
                    "lateral_movement",
                    "malware_like_behavior",
                    "privilege_escalation_out_of_scope",
                    "spam_like_behavior",
                    "tenant_escape",
                ],
                "examples": [
                    "Do not bypass route restrictions, approval gates, or leave the approved VM/tunnel boundary.",
                    "Do not perform destructive, spam-like, or irreversible financial/account state changes.",
                    "Do not harvest, print, persist, or exfiltrate credentials, cookies, bearer tokens, or auth headers; in-memory use of explicitly approved Caido session headers for the current scoped browser session is not credential harvesting.",
                ],
            },
        },
        notes=(
            "Core posture: scoped testing is allowed; damaging behavior is explicit.",
            "Unknown or uncertain live actions must downgrade to approval_required.",
            "Public, payment, vendor/customer-visible, or non-owned messaging/invite state changes are never allowed_private by default.",
            "Using Caido-held Authorization/Cookie values to update the current scoped browser session is allowed only when explicitly instructed and must not disclose, log, persist, or reuse the raw values outside that run.",
            "Race testing is allowed only for owned accounts/resources and only up to 35 total requests per hypothesis unless explicitly approved otherwise.",
        ),
    )


def evaluate_runtime_action_policy(
    plan: Mapping[str, Any],
    *,
    plan_path: str | Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    artifact = plan.get("runtime_action_policy")
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    if not isinstance(artifact, Mapping):
        return {
            "schema_version": 0,
            "status": "missing",
            "valid": False,
            "active": False,
            "policy_id": "",
            "scope_matches": False,
            "default_classification": "",
            "allowed_private_count": 0,
            "approval_required_count": 0,
            "blocked_count": 0,
            "risky_default_tags": [],
            "details": "runtime_action_policy is missing",
        }

    schema_version = _schema_version(artifact.get("schema_version"))
    status = str(artifact.get("status") or "").strip()
    policy_id = str(artifact.get("policy_id") or "").strip()
    default_classification = str(artifact.get("default_classification") or "").strip()
    scope = artifact.get("scope")
    issued_at = _parse_timestamp(artifact.get("issued_at"))
    expires_at = _parse_timestamp(artifact.get("expires_at"))
    classifications = artifact.get("classifications")

    structure_errors: list[str] = []
    if schema_version < RUNTIME_ACTION_POLICY_SCHEMA_VERSION:
        structure_errors.append("schema_version is missing or unsupported")
    if status != "active":
        structure_errors.append("status must be active")
    if not policy_id:
        structure_errors.append("policy_id is required")
    if default_classification != "approval_required":
        structure_errors.append("default_classification must be approval_required")
    if not isinstance(scope, Mapping):
        structure_errors.append("scope must be an object")
    if issued_at is None:
        structure_errors.append("issued_at must be an ISO timestamp")
    if expires_at is None:
        structure_errors.append("expires_at must be an ISO timestamp")
    if not isinstance(classifications, Mapping):
        structure_errors.append("classifications must be an object")

    allowed_private_tags, allowed_private_valid = _classification_tags(classifications, "allowed_private")
    approval_required_tags, approval_required_valid = _classification_tags(classifications, "approval_required")
    blocked_tags, blocked_valid = _classification_tags(classifications, "blocked")
    if not allowed_private_valid:
        structure_errors.append("classifications.allowed_private.action_tags must be a non-empty list")
    if not approval_required_valid:
        structure_errors.append("classifications.approval_required.action_tags must be a non-empty list")
    if not blocked_valid:
        structure_errors.append("classifications.blocked.action_tags must be a non-empty list")

    if structure_errors:
        return _result(
            schema_version=schema_version,
            status="malformed",
            valid=False,
            active=False,
            policy_id=policy_id,
            scope_matches=False,
            default_classification=default_classification,
            allowed_private_count=len(allowed_private_tags),
            approval_required_count=len(approval_required_tags),
            blocked_count=len(blocked_tags),
            risky_default_tags=[],
            details="; ".join(structure_errors),
        )

    assert isinstance(scope, Mapping)
    scope_errors = _scope_errors(scope, plan=plan, plan_path=resolved_plan_path)
    if scope_errors:
        return _result(
            schema_version=schema_version,
            status="wrong_scope",
            valid=False,
            active=False,
            policy_id=policy_id,
            scope_matches=False,
            default_classification=default_classification,
            allowed_private_count=len(allowed_private_tags),
            approval_required_count=len(approval_required_tags),
            blocked_count=len(blocked_tags),
            risky_default_tags=[],
            details="; ".join(scope_errors),
        )

    current_time = now or datetime.now(UTC)
    if expires_at is not None and expires_at <= current_time:
        return _result(
            schema_version=schema_version,
            status="expired",
            valid=False,
            active=False,
            policy_id=policy_id,
            scope_matches=True,
            default_classification=default_classification,
            allowed_private_count=len(allowed_private_tags),
            approval_required_count=len(approval_required_tags),
            blocked_count=len(blocked_tags),
            risky_default_tags=[],
            details="runtime_action_policy has expired",
            expires_at=_timestamp_text(artifact.get("expires_at")),
        )

    risky_default_tags = sorted(set(allowed_private_tags) & RISKY_DEFAULT_ACTION_TAGS)
    if risky_default_tags:
        return _result(
            schema_version=schema_version,
            status="risky_default",
            valid=False,
            active=False,
            policy_id=policy_id,
            scope_matches=True,
            default_classification=default_classification,
            allowed_private_count=len(allowed_private_tags),
            approval_required_count=len(approval_required_tags),
            blocked_count=len(blocked_tags),
            risky_default_tags=risky_default_tags,
            details="runtime_action_policy allows risky public/payment/message actions by default",
            expires_at=_timestamp_text(artifact.get("expires_at")),
        )

    return _result(
        schema_version=schema_version,
        status="active",
        valid=True,
        active=True,
        policy_id=policy_id,
        scope_matches=True,
        default_classification=default_classification,
        allowed_private_count=len(allowed_private_tags),
        approval_required_count=len(approval_required_tags),
        blocked_count=len(blocked_tags),
        risky_default_tags=[],
        details="runtime_action_policy is active, scoped to this plan, and private-by-default",
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


def _classification_tags(classifications: Any, key: str) -> tuple[list[str], bool]:
    if not isinstance(classifications, Mapping):
        return [], False
    classification = classifications.get(key)
    if not isinstance(classification, Mapping):
        return [], False
    raw = classification.get("action_tags")
    if not isinstance(raw, list | tuple):
        return [], False
    values = [str(item).strip() for item in raw if str(item).strip()]
    return values, len(values) == len(raw) and bool(values)


def _result(
    *,
    schema_version: int,
    status: str,
    valid: bool,
    active: bool,
    policy_id: str,
    scope_matches: bool,
    default_classification: str,
    allowed_private_count: int,
    approval_required_count: int,
    blocked_count: int,
    risky_default_tags: list[str],
    details: str,
    expires_at: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "status": status,
        "valid": valid,
        "active": active,
        "policy_id": policy_id,
        "scope_matches": scope_matches,
        "default_classification": default_classification,
        "allowed_private_count": allowed_private_count,
        "approval_required_count": approval_required_count,
        "blocked_count": blocked_count,
        "risky_default_tags": risky_default_tags,
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
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _timestamp_text(value: Any) -> str:
    return str(value or "").strip()
