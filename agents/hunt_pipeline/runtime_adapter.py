from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

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
        parent_keys=[],
        created_by="hunt_pipeline",
        version=str(version or packet.ruleset_id).strip(),
        created_at=created_at or _timestamp_iso(),
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
            "runtime execution, agent spawning, and ledger writes remain disabled in this slice",
        ],
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
        f"Hypothesis ID: {packet.id}\n"
        f"Hypothesis title: {packet.title}\n"
        f"Role: {packet.role}\n"
        f"Priority: {packet.priority}\n"
        f"Target kind: {packet.target_kind}\n"
        f"Ruleset: {packet.ruleset_id}\n\n"
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
    return "\n".join(f"- {item}" for item in lines) or "- None provided"


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
            lines.append("- " + " | ".join(parts))
    return "\n".join(lines) or "- None provided"


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
