from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

LIVE_TESTING_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class LiveTestingPlaybook:
    schema_version: int
    status: str
    enabled: bool
    execution_enabled: bool
    operator_approval_required: bool
    target_kind: str
    ruleset_id: str
    goal: str
    environment_requirements: dict[str, Any]
    attachment_surfaces: tuple[dict[str, Any], ...]
    coordination: dict[str, Any]
    evidence_capture: dict[str, Any]
    scope_guardrails: dict[str, Any]
    non_goals: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_live_testing_playbook(
    *,
    target_kind: str,
    ruleset_id: str,
) -> LiveTestingPlaybook:
    normalized_target_kind = str(target_kind or "").strip() or "unknown"
    return LiveTestingPlaybook(
        schema_version=LIVE_TESTING_SCHEMA_VERSION,
        status="planned-only",
        enabled=False,
        execution_enabled=False,
        operator_approval_required=True,
        target_kind=normalized_target_kind,
        ruleset_id=str(ruleset_id or "").strip() or "unknown",
        goal=(
            "Document approved live-testing connection, attachment, lock, and evidence rules "
            "without launching targets, tunnels, browsers, Ghidra, MCP, SSH sessions, or live agents."
        ),
        environment_requirements={
            "approved_environments": [
                {
                    "kind": "vm",
                    "state": "approved-only",
                    "requirements": [
                        "Use an operator-approved disposable or snapshot-backed VM.",
                        "Keep target binaries, tooling, and credentials scoped to that VM.",
                    ],
                },
                {
                    "kind": "tunnel",
                    "state": "approved-only",
                    "requirements": [
                        "Use only operator-approved tunnel endpoints, hostnames, and exposure windows.",
                        "Record endpoint ownership, purpose, and teardown evidence before use.",
                    ],
                },
            ],
            "startup_policy": {
                "default_mode": "attach-to-existing",
                "pipeline_target_launch_enabled": False,
                "allowed_modes_after_promotion": [
                    {
                        "mode": "operator-started-target",
                        "notes": "Prefer attaching to an operator-started target process or browser session.",
                    },
                    {
                        "mode": "agent-started-target",
                        "notes": "Requires explicit promotion review and approved startup commands per target.",
                    },
                ],
            },
        },
        attachment_surfaces=tuple(_attachment_surfaces(normalized_target_kind)),
        coordination={
            "turn_taking": "single-active-holder-per-resource",
            "lock_resources": [
                "vm-instance",
                "tunnel-endpoint",
                "target-session",
                "cdp-debug-port",
                "ghidra-project",
                "mcp-session",
                "ssh-host",
            ],
            "rules": [
                "One live actor at a time may hold a given attached resource.",
                "Acquire environment and attachment locks before connecting or starting the target.",
                "Release locks and capture teardown notes before another actor takes the turn.",
                "Static teams remain metadata-only; no static-team invocation is allowed from this playbook.",
            ],
        },
        evidence_capture={
            "required_session_metadata": [
                "operator approval reference",
                "environment identifier",
                "target build or binary hash",
                "attachment surface",
                "start and end timestamps",
            ],
            "required_artifacts": [
                "connection transcript or attach parameters",
                "screenshots or terminal captures for the exercised step",
                "observed request/response or debugger evidence",
                "cleanup or teardown notes",
            ],
            "redaction_rules": [
                "Avoid storing secrets, tokens, or unrelated customer data in artifacts.",
                "Prefer minimally sufficient evidence over full raw environment dumps.",
            ],
            "storage_constraints": [
                "This slice is descriptive only and does not write live evidence automatically.",
                "Any future evidence storage must stay inside the existing promoted runtime/report path.",
            ],
        },
        scope_guardrails={
            "required_checks": [
                "Confirm the target, host, and environment are explicitly in scope before attaching.",
                "Confirm the planned connection method is approved for this target and time window.",
                "Confirm the requested action is bounded to one hypothesis or one debugging step at a time.",
            ],
            "forbidden_actions": [
                "Do not widen scope to new hosts, tenants, credentials, or environments.",
                "Do not create ad-hoc public exposure, reverse tunnels, or unmanaged listeners.",
                "Do not run destructive persistence, lateral movement, or unrelated automation.",
                "Do not launch live validation, browsers, Ghidra, MCP clients, SSH sessions, or target programs from this slice.",
            ],
            "approval_boundaries": [
                "Operator approval is required before any target startup or live attachment.",
                "Human review is required before evidence leaves the approved runtime/report path.",
            ],
        },
        non_goals=(
            "This playbook does not launch or attach to any live target.",
            "This playbook does not enable tunnels, browsers, Ghidra, MCP, SSH, or live agents.",
            "This playbook does not write to ledgers outside the existing promoted runtime path.",
        ),
        notes=(
            "Use attach-first workflows where possible so startup commands remain operator-auditable.",
            "Prefer the smallest attachment surface that can validate the current hypothesis.",
        ),
    )


def summarize_live_testing_playbook(plan: Mapping[str, Any]) -> dict[str, Any]:
    playbook = plan.get("live_testing_playbook")
    if not isinstance(playbook, Mapping):
        return {
            "state": "blocking",
            "enabled": False,
            "execution_enabled": False,
            "target_kind": "",
            "ruleset_id": "",
            "attachment_surfaces": [],
            "lock_resources": [],
            "blockers": ["live_testing_playbook must be a JSON object"],
        }

    environment_requirements = (
        playbook.get("environment_requirements")
        if isinstance(playbook.get("environment_requirements"), Mapping)
        else {}
    )
    startup_policy = (
        environment_requirements.get("startup_policy")
        if isinstance(environment_requirements.get("startup_policy"), Mapping)
        else {}
    )
    approved_environments, approved_envs_valid = _string_mapping_sequence(
        environment_requirements.get("approved_environments")
    )
    attachment_surfaces, attachment_valid = _string_mapping_sequence(playbook.get("attachment_surfaces"))
    coordination = playbook.get("coordination") if isinstance(playbook.get("coordination"), Mapping) else {}
    evidence_capture = playbook.get("evidence_capture") if isinstance(playbook.get("evidence_capture"), Mapping) else {}
    scope_guardrails = playbook.get("scope_guardrails") if isinstance(playbook.get("scope_guardrails"), Mapping) else {}
    blockers: list[str] = []

    schema_version = _schema_version(playbook.get("schema_version"))
    status = str(playbook.get("status") or "").strip()
    enabled = bool(playbook.get("enabled") is True)
    execution_enabled = bool(playbook.get("execution_enabled") is True)

    if schema_version < LIVE_TESTING_SCHEMA_VERSION:
        blockers.append("live_testing_playbook.schema_version is missing or unsupported")
    if status != "planned-only":
        blockers.append("live_testing_playbook.status must be planned-only")
    if enabled:
        blockers.append("live_testing_playbook.enabled must remain false")
    if execution_enabled:
        blockers.append("live_testing_playbook.execution_enabled must remain false")
    if not approved_envs_valid or not approved_environments:
        blockers.append("live_testing_playbook.environment_requirements.approved_environments must be a non-empty list")
    if not startup_policy or startup_policy.get("pipeline_target_launch_enabled") is not False:
        blockers.append("live_testing_playbook.environment_requirements.startup_policy must disable pipeline target launch")
    if not attachment_valid or not attachment_surfaces:
        blockers.append("live_testing_playbook.attachment_surfaces must be a non-empty list")

    lock_resources = _string_sequence(coordination.get("lock_resources"))
    if not coordination:
        blockers.append("live_testing_playbook.coordination must be an object")
    elif not lock_resources:
        blockers.append("live_testing_playbook.coordination.lock_resources must be a non-empty list")

    required_artifacts = _string_sequence(evidence_capture.get("required_artifacts"))
    if not evidence_capture:
        blockers.append("live_testing_playbook.evidence_capture must be an object")
    elif not required_artifacts:
        blockers.append("live_testing_playbook.evidence_capture.required_artifacts must be a non-empty list")

    forbidden_actions = _string_sequence(scope_guardrails.get("forbidden_actions"))
    if not scope_guardrails:
        blockers.append("live_testing_playbook.scope_guardrails must be an object")
    elif not forbidden_actions:
        blockers.append("live_testing_playbook.scope_guardrails.forbidden_actions must be a non-empty list")

    return {
        "state": "planned-only" if not blockers else "blocking",
        "enabled": enabled,
        "execution_enabled": execution_enabled,
        "target_kind": str(playbook.get("target_kind") or "").strip(),
        "ruleset_id": str(playbook.get("ruleset_id") or "").strip(),
        "attachment_surfaces": [
            str(item.get("surface") or "").strip()
            for item in attachment_surfaces
            if str(item.get("surface") or "").strip()
        ],
        "lock_resources": lock_resources,
        "blockers": blockers,
    }


def _attachment_surfaces(target_kind: str) -> list[dict[str, Any]]:
    target = target_kind.lower()
    cdp_recommended = target in {"electron", "electron-exe", "app_asar", "browser", "browser-extension"}
    ghidra_recommended = target in {"desktop", "native-desktop", "electron", "electron-exe", "app_asar"}
    return [
        {
            "surface": "cdp",
            "state": "planned-only",
            "recommended_for_target": cdp_recommended,
            "attach_mode": "attach-to-existing-debug-endpoint",
            "locks": ["vm-instance", "target-session", "cdp-debug-port"],
            "evidence": ["debug endpoint metadata", "DOM or console capture", "network trace excerpt"],
        },
        {
            "surface": "ghidra",
            "state": "planned-only",
            "recommended_for_target": ghidra_recommended,
            "attach_mode": "open-approved-project-or-binary",
            "locks": ["vm-instance", "ghidra-project"],
            "evidence": ["function or sink location", "analysis note", "screenshot or export snippet"],
        },
        {
            "surface": "mcp",
            "state": "planned-only",
            "recommended_for_target": True,
            "attach_mode": "attach-to-approved-existing-mcp-server",
            "locks": ["vm-instance", "mcp-session"],
            "evidence": ["server identifier", "tool transcript", "captured result excerpt"],
        },
        {
            "surface": "ssh",
            "state": "planned-only",
            "recommended_for_target": True,
            "attach_mode": "connect-to-approved-existing-host",
            "locks": ["vm-instance", "ssh-host"],
            "evidence": ["host identifier", "command transcript", "cleanup note"],
        },
    ]


def _schema_version(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _string_mapping_sequence(value: Any) -> tuple[list[Mapping[str, Any]], bool]:
    if not isinstance(value, list | tuple):
        return [], False
    mappings = [item for item in value if isinstance(item, Mapping)]
    return mappings, len(mappings) == len(value)


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
