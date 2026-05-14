from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from agents.base_team import AgentSpec as BaseTeamAgentSpec
from agents.dynamic_agent_builder import AgentSpec as DynamicBuilderAgentSpec
from agents.hunt_pipeline.models import HypothesisAgentPacket

ADAPTER_SCHEMA_VERSION = 1


def packet_to_base_team_agent_spec(
    packet: HypothesisAgentPacket,
    *,
    program: str,
    snapshot_id: str,
    created_at: str | None = None,
) -> BaseTeamAgentSpec:
    """Convert a hunt-pipeline packet into BaseTeam's passive AgentSpec shape."""

    created = created_at or _timestamp_iso()
    return BaseTeamAgentSpec(
        key=packet.key,
        vuln_class=packet.surface_family,
        surface=packet.surface_family,
        prompt_template=_prompt_template(packet),
        focus_globs=list(packet.focus_files),
        code_patterns=_code_patterns(packet),
        program=str(program).strip(),
        created_at=created,
        snapshot_id=str(snapshot_id).strip(),
        metadata=_trace_metadata(packet),
    )


def selected_decision_to_base_team_agent_spec(
    decision: Mapping[str, Any],
    packets_by_id: Mapping[str, HypothesisAgentPacket | Mapping[str, Any]],
    *,
    program: str,
    snapshot_id: str,
    created_at: str | None = None,
) -> BaseTeamAgentSpec:
    """Convert a scheduler decision plus packet evidence into a passive BaseTeam AgentSpec."""

    packet = _packet_for_decision(decision, packets_by_id)
    spec = packet_to_base_team_agent_spec(packet, program=program, snapshot_id=snapshot_id, created_at=created_at)
    decision_hypothesis_ids = _decision_hypothesis_ids(decision)
    agent_key = str(decision.get("agent_key") or packet.key).strip()
    spec.key = agent_key
    spec.metadata = {
        **spec.metadata,
        "scheduler_decision": copy.deepcopy(dict(decision)),
        "selected_agent_key": agent_key,
        "selected_hypothesis_ids": decision_hypothesis_ids or [packet.id],
        "runtime_handoff": {
            **spec.metadata.get("runtime_handoff", {}),
            "decision_to_agent_spec": True,
        },
    }
    return spec


def selected_decisions_to_base_team_agent_specs(
    decisions: Sequence[Mapping[str, Any]],
    packets: Sequence[HypothesisAgentPacket | Mapping[str, Any]],
    *,
    program: str,
    snapshot_id: str,
    created_at: str | None = None,
) -> list[BaseTeamAgentSpec]:
    packets_by_id = {_coerce_packet(packet).id: _coerce_packet(packet) for packet in packets}
    return [
        selected_decision_to_base_team_agent_spec(
            decision,
            packets_by_id,
            program=program,
            snapshot_id=snapshot_id,
            created_at=created_at,
        )
        for decision in decisions
    ]


def packet_to_dynamic_agent_builder_agent_spec(
    packet: HypothesisAgentPacket,
    *,
    version: str | None = None,
    created_at: str | None = None,
) -> DynamicBuilderAgentSpec:
    """Convert a packet into the legacy dynamic_agent_builder AgentSpec shape."""

    return DynamicBuilderAgentSpec(
        key=packet.key,
        name=packet.title,
        description=_description(packet),
        surface_type=packet.surface_family,
        vuln_class=packet.surface_family,
        patterns=_code_patterns(packet),
        focus_files_glob=list(packet.focus_files),
        ignore_files_glob=[],
        agent_prompt_template=_prompt_template(packet),
        parent_keys=["hunt-pipeline", packet.ruleset_id, packet.id],
        created_by="hunt_pipeline",
        version=str(version or packet.ruleset_id).strip(),
        created_at=created_at or _timestamp_iso(),
    )


def packet_from_dict(payload: Mapping[str, Any]) -> HypothesisAgentPacket:
    return HypothesisAgentPacket(
        id=str(payload.get("id") or "").strip(),
        key=str(payload.get("key") or "").strip(),
        title=str(payload.get("title") or "").strip(),
        role=str(payload.get("role") or "entry").strip(),  # type: ignore[arg-type]
        surface_family=str(payload.get("surface_family") or "").strip(),
        priority=str(payload.get("priority") or "").strip(),
        target_kind=str(payload.get("target_kind") or "").strip(),
        ruleset_id=str(payload.get("ruleset_id") or "").strip(),
        source_evidence=tuple(item for item in payload.get("source_evidence") or () if isinstance(item, dict)),
        secondary_families=tuple(str(item) for item in payload.get("secondary_families") or ()),
        evidence_requirements=tuple(str(item) for item in payload.get("evidence_requirements") or ()),
        chain_requirements=tuple(str(item) for item in payload.get("chain_requirements") or ()),
        focus_files=tuple(str(item) for item in payload.get("focus_files") or ()),
        tags=tuple(str(item) for item in payload.get("tags") or ()),
        reasons=tuple(str(item) for item in payload.get("reasons") or ()),
        scheduler_metadata=dict(payload.get("scheduler_metadata") or {})
        if isinstance(payload.get("scheduler_metadata"), dict)
        else {},
    )


def runtime_adapter_availability() -> dict[str, Any]:
    return {
        "base_team_agent_spec": True,
        "dynamic_agent_builder_agent_spec": True,
        "conversion_only": True,
        "spawn_enabled": False,
        "ledger_writes_enabled": False,
        "notes": [
            "hunt-pipeline packets can be converted into passive AgentSpec shapes",
            "scheduler decisions can be converted into passive BaseTeam AgentSpec shapes",
            "runtime execution, agent spawning, and ledger writes remain disabled in this slice",
        ],
    }


def runtime_handoff_boundary() -> dict[str, Any]:
    """Document the current non-live handoff contract in dry-run artifacts."""

    return {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "status": "explicit-non-live-boundary",
        "allowed_actions": [
            "build HypothesisAgentPacket records from normalized AppMap artifacts",
            "plan scheduler selected/deferred/skipped decisions",
            "convert packets into passive BaseTeam AgentSpec objects",
            "convert selected scheduler decisions into passive BaseTeam AgentSpec objects",
            "convert packets into legacy dynamic_agent_builder AgentSpec objects",
            "write dry-run plan artifacts for human inspection",
        ],
        "prohibited_actions": [
            "spawn BaseTeam/zero_day_team/apk_team/electron_team agents",
            "write findings ledgers or coverage state",
            "enqueue dynamic validation",
            "mutate vendor/customer/live target data",
            "treat legacy candidates as neutral truth",
        ],
        "required_before_live_execution": [
            "operator approval of the runtime handoff contract",
            "reviewed mapping from scheduler decisions to selected runtime profiles",
            "explicit ledger/review/coverage owner path",
            "tests proving disabled dry-run flags cannot spawn agents",
        ],
        "adapter_outputs": {
            "base_team_agent_spec": "passive conversion only",
            "dynamic_agent_builder_agent_spec": "legacy compatibility conversion only",
        },
    }


def _trace_metadata(packet: HypothesisAgentPacket) -> dict[str, Any]:
    return {
        "adapter": "agents.hunt_pipeline.runtime_adapter",
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "runtime_handoff": {
            "conversion_only": True,
            "spawn_enabled": False,
            "ledger_writes_enabled": False,
        },
        "hypothesis_id": packet.id,
        "hypothesis_key": packet.key,
        "hypothesis_title": packet.title,
        "hypothesis_role": packet.role,
        "surface_family": packet.surface_family,
        "secondary_families": list(packet.secondary_families),
        "priority": packet.priority,
        "target_kind": packet.target_kind,
        "ruleset_id": packet.ruleset_id,
        "source_evidence": [copy.deepcopy(item) for item in packet.source_evidence],
        "evidence_requirements": list(packet.evidence_requirements),
        "chain_requirements": list(packet.chain_requirements),
        "focus_files": list(packet.focus_files),
        "tags": list(packet.tags),
        "reasons": list(packet.reasons),
        "scheduler_metadata": copy.deepcopy(packet.scheduler_metadata),
        "packet": asdict(packet),
    }


def _packet_for_decision(
    decision: Mapping[str, Any],
    packets_by_id: Mapping[str, HypothesisAgentPacket | Mapping[str, Any]],
) -> HypothesisAgentPacket:
    for hypothesis_id in _decision_hypothesis_ids(decision):
        if hypothesis_id in packets_by_id:
            return _coerce_packet(packets_by_id[hypothesis_id])
    raise KeyError(f"no hypothesis packet found for decision agent {decision.get('agent_key')!r}")


def _decision_hypothesis_ids(decision: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    hypothesis_id = str(decision.get("hypothesis_id") or "").strip()
    if hypothesis_id:
        values.append(hypothesis_id)
    for item in decision.get("member_hypothesis_ids") or ():
        cleaned = str(item).strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return values


def _coerce_packet(packet: HypothesisAgentPacket | Mapping[str, Any]) -> HypothesisAgentPacket:
    if isinstance(packet, HypothesisAgentPacket):
        return packet
    return packet_from_dict(packet)


def _prompt_template(packet: HypothesisAgentPacket) -> str:
    evidence_requirements = _bullet_list(packet.evidence_requirements)
    chain_requirements = _bullet_list(packet.chain_requirements)
    source_evidence = _source_evidence_lines(packet)
    reasons = _bullet_list(packet.reasons)
    tags = _bullet_list(packet.tags)
    return (
        "You are a hunt-pipeline handoff agent for {program}.\n\n"
        "Target path: {target_path}\n"
        "Agent key: {agent_key}\n"
        f"Hypothesis ID: {_format_safe(packet.id)}\n"
        f"Hypothesis title: {_format_safe(packet.title)}\n"
        f"Role: {_format_safe(packet.role)}\n"
        f"Priority: {_format_safe(packet.priority)}\n"
        f"Target kind: {_format_safe(packet.target_kind)}\n"
        f"Ruleset: {_format_safe(packet.ruleset_id)}\n\n"
        "Surface: {surface}\n"
        "Vulnerability class: {vuln_class}\n\n"
        "Focus files:\n"
        "{focus_globs}\n\n"
        "Code and evidence patterns:\n"
        "{code_patterns}\n\n"
        f"Evidence requirements:\n{evidence_requirements}\n\n"
        f"Chain requirements:\n{chain_requirements}\n\n"
        f"Source evidence:\n{source_evidence}\n\n"
        f"Why this agent exists:\n{reasons}\n\n"
        f"Tags:\n{tags}\n\n"
        "Use the shared workspace paths when recording local notes during manual analysis:\n"
        "- Shared brain: {shared_brain_dir}\n"
        "- Notes root: {notes_root}\n"
        "- Traces root: {traces_dir}\n\n"
        "Hunting policy:\n"
        "{hunting_policy_snippet}"
    )


def _description(packet: HypothesisAgentPacket) -> str:
    return (
        f"{packet.title} "
        f"(role={packet.role}, priority={packet.priority}, surface_family={packet.surface_family})"
    )


def _format_safe(value: Any) -> str:
    return str(value).replace("{", "{{").replace("}", "}}")


def _code_patterns(packet: HypothesisAgentPacket) -> list[str]:
    patterns: list[str] = []
    for value in (
        *packet.evidence_requirements,
        *packet.chain_requirements,
        *packet.tags,
        *packet.secondary_families,
    ):
        cleaned = str(value).strip()
        if cleaned and cleaned not in patterns:
            patterns.append(cleaned)
    return patterns


def _bullet_list(values: tuple[str, ...]) -> str:
    lines = [str(item).strip() for item in values if str(item).strip()]
    return "\n".join(f"- {_format_safe(item)}" for item in lines) or "- None provided"


def _source_evidence_lines(packet: HypothesisAgentPacket) -> str:
    lines: list[str] = []
    for item in packet.source_evidence:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("id") or item.get("candidate_id") or item.get("source_id") or "").strip()
        kind = str(item.get("kind") or item.get("type") or "").strip()
        file_path = str(item.get("file") or item.get("path") or "").strip()
        parts = [part for part in (evidence_id, kind, file_path) if part]
        if parts:
            lines.append("- " + _format_safe(" | ".join(parts)))
    return "\n".join(lines) or "- None provided"


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
