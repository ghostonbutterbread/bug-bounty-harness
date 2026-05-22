from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from agents.base_team import AgentSpec as BaseTeamAgentSpec
from agents.dynamic_agent_builder import AgentSpec as DynamicBuilderAgentSpec
from agents.hunt_pipeline.category_pack_planner import pack_verdict_options, plan_category_packs
from agents.hunt_pipeline.models import CategoryPack, CategoryPackPlan, HypothesisAgentPacket

ADAPTER_SCHEMA_VERSION = 1
ADAPTER_NAME = "agents.hunt_pipeline.runtime_adapter"

_STATUS_SCORES = {
    "selected": 300,
    "candidate": 200,
    "deferred": 100,
    "skipped": 0,
}
_PRIORITY_SCORES = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
}
_ROLE_SCORES = {
    "entry": 50,
    "amplifier": 40,
    "chain": 30,
    "hardening": 20,
    "notes_only": 10,
}


@dataclass(slots=True)
class _GroupedPacketSet:
    source_key: str
    surface_key: str
    family_key: str
    packets: list[HypothesisAgentPacket] = field(default_factory=list)
    member_ids: set[str] = field(default_factory=set)
    member_signatures: set[tuple[Any, ...]] = field(default_factory=set)
    selected_ids: set[str] = field(default_factory=set)
    deferred_ids: set[str] = field(default_factory=set)
    skipped_ids: set[str] = field(default_factory=set)
    decision_agent_keys: list[str] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    adjacent_packets: list[HypothesisAgentPacket] = field(default_factory=list)
    first_index: int = 0

    def add_packet(
        self,
        packet: HypothesisAgentPacket,
        *,
        index: int,
        selected_ids: set[str],
        deferred_ids: set[str],
        skipped_ids: set[str],
    ) -> None:
        signature = _packet_signature(packet)
        if signature in self.member_signatures:
            return
        self.member_signatures.add(signature)
        self.packets.append(packet)
        self.member_ids.add(packet.id)
        if len(self.packets) == 1:
            self.first_index = index
        if packet.id in selected_ids:
            self.selected_ids.add(packet.id)
        if packet.id in deferred_ids:
            self.deferred_ids.add(packet.id)
        if packet.id in skipped_ids:
            self.skipped_ids.add(packet.id)

    def add_decision(self, decision: Mapping[str, Any]) -> None:
        record = copy.deepcopy(dict(decision))
        agent_key = str(record.get("agent_key") or "").strip()
        if agent_key and agent_key not in self.decision_agent_keys:
            self.decision_agent_keys.append(agent_key)
        if record not in self.decisions:
            self.decisions.append(record)

    @property
    def status(self) -> str:
        if self.selected_ids:
            return "selected"
        if self.deferred_ids:
            return "deferred"
        if self.skipped_ids:
            return "skipped"
        return "candidate"

    @property
    def ranking_score(self) -> int:
        packet_scores = [
            _PRIORITY_SCORES.get(packet.priority, 0) + _ROLE_SCORES.get(packet.role, 0)
            for packet in self.packets
        ]
        return _STATUS_SCORES[self.status] + max(packet_scores or [0]) + min(len(self.member_ids), 9)

    @property
    def primary_packet(self) -> HypothesisAgentPacket:
        return sorted(
            self.packets,
            key=lambda item: (
                -_PRIORITY_SCORES.get(item.priority, 0),
                -_ROLE_SCORES.get(item.role, 0),
                item.id,
            ),
        )[0]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source_key, self.surface_key, self.family_key)


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


def category_pack_to_base_team_agent_spec(
    pack: CategoryPack,
    packets_by_id: Mapping[str, HypothesisAgentPacket | Mapping[str, Any]],
    *,
    program: str,
    snapshot_id: str,
    created_at: str | None = None,
) -> BaseTeamAgentSpec:
    packet_map = {packet_id: _coerce_packet(packet) for packet_id, packet in packets_by_id.items()}
    missing_hypothesis_ids = [hypothesis_id for hypothesis_id in pack.hypothesis_ids if hypothesis_id not in packet_map]
    if missing_hypothesis_ids:
        raise KeyError(
            f"category pack {pack.pack_id!r} references unresolved hypothesis ids: "
            f"{', '.join(missing_hypothesis_ids)}"
        )
    members = [packet_map[hypothesis_id] for hypothesis_id in pack.hypothesis_ids]
    created = created_at or _timestamp_iso()
    focus_globs = list(pack.source_files) or list(dict.fromkeys(item for packet in members for item in packet.focus_files))
    metadata = {
        "adapter": ADAPTER_NAME,
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "runtime_handoff": {
            "conversion_only": True,
            "spawn_enabled": False,
            "ledger_writes_enabled": False,
        },
        "category_pack": pack.to_dict(),
        "category_pack_id": pack.pack_id,
        "category_pack_hypothesis_ids": list(pack.hypothesis_ids),
        "category_pack_evidence_ids": list(pack.evidence_ids),
        "source_files": list(pack.source_files),
        "selected_hypothesis_ids": list(pack.hypothesis_ids),
        "surface_family": pack.surface_family,
        "source_path_kind": "pipeline-category-pack",
    }
    return BaseTeamAgentSpec(
        key=pack.pack_id,
        vuln_class=pack.vuln_class,
        surface=pack.surface_family,
        prompt_template=_category_pack_prompt(pack, members),
        focus_globs=focus_globs,
        code_patterns=_group_code_patterns_from_packets(members),
        program=str(program).strip(),
        created_at=created,
        snapshot_id=str(snapshot_id).strip(),
        metadata=metadata,
    )


def category_packs_to_base_team_agent_specs(
    plan: CategoryPackPlan,
    packets_by_id: Mapping[str, HypothesisAgentPacket | Mapping[str, Any]],
    *,
    program: str,
    snapshot_id: str,
    created_at: str | None = None,
) -> list[BaseTeamAgentSpec]:
    return [
        category_pack_to_base_team_agent_spec(
            pack,
            packets_by_id,
            program=program,
            snapshot_id=snapshot_id,
            created_at=created_at,
        )
        for pack in plan.packs
    ]


def grouped_decisions_to_base_team_agent_specs(
    decisions: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    packets: Sequence[HypothesisAgentPacket | Mapping[str, Any]],
    *,
    program: str,
    snapshot_id: str,
    max_agents: int | None = None,
    created_at: str | None = None,
    include_candidate_packets: bool = True,
) -> tuple[list[BaseTeamAgentSpec], dict[str, Any]]:
    """Collapse packet-backed scheduler decisions into ranked BaseTeam AgentSpecs."""

    packet_list = [_coerce_packet(packet) for packet in packets]
    decision_rows = _flatten_scheduler_decisions(decisions)
    selected_ids, deferred_ids, skipped_ids = _decision_status_sets(decision_rows)
    decided_ids = selected_ids | deferred_ids | skipped_ids
    grouped_packets = (
        packet_list
        if include_candidate_packets or not decided_ids
        else [packet for packet in packet_list if packet.id in decided_ids]
    )
    grouped = _collapse_packets(
        grouped_packets,
        selected_ids=selected_ids,
        deferred_ids=deferred_ids,
        skipped_ids=skipped_ids,
    )
    _attach_decisions(grouped, decision_rows)
    _attach_adjacent_packets(grouped, packet_list)

    ranked = sorted(grouped, key=lambda item: (-item.ranking_score, item.first_index, item.key))
    eligible = [group for group in ranked if _group_is_eligible(group, selected_ids, deferred_ids, skipped_ids)]
    selected_keys = {group.key for group in eligible[: max(0, int(max_agents))]} if max_agents is not None else {
        group.key for group in eligible
    }

    selected_groups: list[_GroupedPacketSet] = []
    deferred_groups: list[_GroupedPacketSet] = []
    skipped_groups: list[_GroupedPacketSet] = []
    for group in ranked:
        if group.key in selected_keys:
            selected_groups.append(group)
            continue
        if group.status == "skipped":
            skipped_groups.append(group)
            continue
        deferred_groups.append(group)

    created = created_at or _timestamp_iso()
    specs = [
        _group_to_base_team_agent_spec(
            group,
            program=program,
            snapshot_id=snapshot_id,
            created_at=created,
        )
        for group in selected_groups
    ]
    metrics = {
        "input_hypotheses": len(packet_list),
        "input_decisions": len(decision_rows),
        "collapsed_groups": len(grouped),
        "selected_groups": len(selected_groups),
        "deferred_groups": len(deferred_groups),
        "skipped_groups": len(skipped_groups),
        "agent_specs_created": len(specs),
        "source_coverage": _source_coverage(ranked),
        "top_source_coverage": _source_coverage(ranked)[:3],
        "hypothesis_counts": {
            "selected": len(selected_ids),
            "deferred": len(deferred_ids),
            "skipped": len(skipped_ids),
            "candidate": len([packet for packet in packet_list if packet.id not in decided_ids]),
        },
    }
    return specs, metrics


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
        entry_status=str(payload.get("entry_status") or "unknown").strip(),
        attacker_influence_score=_safe_float(payload.get("attacker_influence_score")),
        context_privilege_score=_safe_float(payload.get("context_privilege_score")),
        incremental_impact_score=_safe_float(payload.get("incremental_impact_score")),
        entry_reportability_score=_safe_float(payload.get("entry_reportability_score")),
        chain_unlock_score=_safe_float(payload.get("chain_unlock_score")),
        ingestion_path=str(payload.get("ingestion_path") or "unknown").strip(),
        required_entry_primitives=tuple(str(item) for item in payload.get("required_entry_primitives") or ()),
        context_tags=tuple(str(item) for item in payload.get("context_tags") or ()),
        unlocked_amplifiers=tuple(str(item) for item in payload.get("unlocked_amplifiers") or ()),
        reportability=str(payload.get("reportability") or "unknown").strip(),
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


def _flatten_scheduler_decisions(decisions: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> list[dict[str, Any]]:
    if isinstance(decisions, Mapping):
        rows: list[dict[str, Any]] = []
        for status, values in (
            ("selected", decisions.get("selected") or ()),
            ("deferred", decisions.get("deferred") or ()),
            ("skipped", decisions.get("skipped") or ()),
        ):
            for item in values:
                if not isinstance(item, Mapping):
                    continue
                record = copy.deepcopy(dict(item))
                record.setdefault("scheduler_status", status)
                rows.append(record)
        return rows
    return [copy.deepcopy(dict(item)) for item in decisions if isinstance(item, Mapping)]


def _decision_status_sets(decisions: Sequence[Mapping[str, Any]]) -> tuple[set[str], set[str], set[str]]:
    selected: set[str] = set()
    deferred: set[str] = set()
    skipped: set[str] = set()
    for decision in decisions:
        status = _decision_status(decision)
        target = {"selected": selected, "deferred": deferred, "skipped": skipped}.get(status)
        if target is None:
            continue
        target.update(_decision_hypothesis_ids(decision))
    return selected, deferred, skipped


def _decision_status(decision: Mapping[str, Any]) -> str:
    explicit = str(decision.get("scheduler_status") or decision.get("status") or "").strip().lower()
    if explicit in {"selected", "deferred", "skipped"}:
        return explicit
    raw_decision = str(decision.get("decision") or "").strip().lower()
    if raw_decision in {"spawn", "selected", "run"}:
        return "selected"
    if raw_decision in {"defer", "deferred"}:
        return "deferred"
    if raw_decision in {"skip", "skipped"}:
        return "skipped"
    return "candidate"


def _collapse_packets(
    packets: Sequence[HypothesisAgentPacket],
    *,
    selected_ids: set[str],
    deferred_ids: set[str],
    skipped_ids: set[str],
) -> list[_GroupedPacketSet]:
    grouped: dict[tuple[str, str, str], _GroupedPacketSet] = {}
    for index, packet in enumerate(packets):
        source_key = _source_key(packet)
        surface_key = _surface_key(packet)
        family_key = str(packet.surface_family or surface_key or "hunt-family").strip() or "hunt-family"
        key = (source_key, surface_key, family_key)
        group = grouped.get(key)
        if group is None:
            group = _GroupedPacketSet(source_key=source_key, surface_key=surface_key, family_key=family_key)
            grouped[key] = group
        group.add_packet(
            packet,
            index=index,
            selected_ids=selected_ids,
            deferred_ids=deferred_ids,
            skipped_ids=skipped_ids,
        )
    return list(grouped.values())


def _attach_decisions(groups: Sequence[_GroupedPacketSet], decisions: Sequence[Mapping[str, Any]]) -> None:
    by_hypothesis_id: dict[str, list[Mapping[str, Any]]] = {}
    for decision in decisions:
        for hypothesis_id in _decision_hypothesis_ids(decision):
            by_hypothesis_id.setdefault(hypothesis_id, []).append(decision)
    for group in groups:
        for hypothesis_id in sorted(group.member_ids):
            for decision in by_hypothesis_id.get(hypothesis_id, ()):
                group.add_decision(decision)


def _attach_adjacent_packets(
    groups: Sequence[_GroupedPacketSet],
    packets: Sequence[HypothesisAgentPacket] | None = None,
) -> None:
    by_source: dict[str, list[HypothesisAgentPacket]] = {}
    if packets is None:
        for group in groups:
            by_source.setdefault(_source_identity(group.source_key), []).extend(group.packets)
    else:
        for packet in packets:
            by_source.setdefault(_source_identity(_source_key(packet)), []).append(packet)

    for group in groups:
        seen = set(group.member_ids)
        adjacent: list[HypothesisAgentPacket] = []
        for packet in by_source.get(_source_identity(group.source_key), []):
            if packet.id in seen:
                continue
            seen.add(packet.id)
            adjacent.append(packet)
        group.adjacent_packets = adjacent


def _group_is_eligible(
    group: _GroupedPacketSet,
    selected_ids: set[str],
    deferred_ids: set[str],
    skipped_ids: set[str],
) -> bool:
    if group.status == "skipped":
        return False
    if group.status == "selected":
        return True
    if selected_ids or deferred_ids or skipped_ids:
        return _group_has_worthy_ambiguous_signal(group)
    return True


def _group_has_worthy_ambiguous_signal(group: _GroupedPacketSet) -> bool:
    for packet in group.packets:
        if packet.priority in {"critical", "high"}:
            return True
        if packet.role in {"entry", "amplifier", "chain"} and packet.source_evidence:
            return True
        if packet.chain_requirements or packet.evidence_requirements:
            return True
    return False


def _group_to_base_team_agent_spec(
    group: _GroupedPacketSet,
    *,
    program: str,
    snapshot_id: str,
    created_at: str,
) -> BaseTeamAgentSpec:
    primary = group.primary_packet
    source_files = _source_files(group)
    focus_globs = source_files or list(dict.fromkeys(primary.focus_files))
    category_pack_plan = plan_category_packs(group.packets)
    category_packs = [pack.to_dict() for pack in category_pack_plan.packs]
    metadata = {
        "adapter": ADAPTER_NAME,
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "runtime_handoff": {
            "conversion_only": True,
            "spawn_enabled": False,
            "ledger_writes_enabled": False,
        },
        "hypothesis_id": primary.id,
        "hypothesis_key": primary.key,
        "hypothesis_title": primary.title,
        "surface_family": primary.surface_family,
        "source_group": {
            "source": group.source_key,
            "surface": group.surface_key,
            "family": group.family_key,
            "status": group.status,
            "hypothesis_ids": sorted(group.member_ids),
            "decision_agent_keys": list(group.decision_agent_keys),
        },
        "selected_agent_key": group.decision_agent_keys[0] if group.decision_agent_keys else _group_key(group),
        "selected_hypothesis_ids": sorted(group.member_ids),
        "scheduler_decision": copy.deepcopy(group.decisions[0]) if group.decisions else {},
        "scheduler_decisions": copy.deepcopy(group.decisions),
        "grouped_evidence": _grouped_evidence(group),
        "category_pack_plan": category_pack_plan.to_dict(),
        "category_packs": category_packs,
        "category_pack_ids": [pack["pack_id"] for pack in category_packs],
        "source_files": source_files,
        "adjacent_hypothesis_ids": [packet.id for packet in group.adjacent_packets],
        "source_path_kind": "pipeline-hypothesis-plan",
    }
    if len(category_packs) == 1:
        metadata["category_pack"] = category_packs[0]
    return BaseTeamAgentSpec(
        key=group.decision_agent_keys[0] if len(group.member_ids) == 1 and group.decision_agent_keys else _group_key(group),
        vuln_class=group.family_key,
        surface=group.surface_key,
        prompt_template=_group_prompt(group),
        focus_globs=focus_globs,
        code_patterns=_group_code_patterns(group),
        program=str(program).strip(),
        created_at=created_at,
        snapshot_id=str(snapshot_id).strip(),
        metadata=metadata,
    )


def _group_prompt(group: _GroupedPacketSet) -> str:
    primary = group.primary_packet
    category_pack_plan = plan_category_packs(group.packets)
    member_lines = []
    for packet in sorted(group.packets, key=lambda item: item.id):
        member_lines.append(
            f"- {_format_safe(packet.id)} | role={_format_safe(packet.role)} | "
            f"priority={_format_safe(packet.priority)} | {_format_safe(packet.title)}"
        )
    reason_lines = _deduped_lines(packet.reasons for packet in group.packets) or ["- None provided"]
    evidence_lines = _grouped_evidence_lines(group) or ["- None provided"]
    source_files = [f"- {_format_safe(path)}" for path in _source_files(group)] or ["- None provided"]
    adjacent_lines = _adjacent_hypothesis_lines(group) or ["- None provided"]
    return (
        f'You are a hunt-pipeline grouped handoff agent for "{_format_safe(group.family_key)}".\n\n'
        "Program: {program}\n"
        "BaseTeam storage team_type: {team_type}\n"
        "Family/lane: {family}/{lane}\n"
        "Target path: {target_path}\n"
        "Snapshot id: {snapshot_id}\n"
        "Shared brain index: {shared_brain_index}\n"
        "Append-only findings file: {findings_path}\n"
        "Ledger path: {ledger_path}\n"
        "Reports root: {reports_root}\n"
        "Notes root: {notes_root}\n"
        "Traces root: {traces_dir}\n\n"
        f'Grouped family: {_format_safe(group.family_key)}\n'
        f'Grouped surface: {_format_safe(group.surface_key)}\n'
        f'Grouped source: {_format_safe(group.source_key)}\n'
        f'Primary hypothesis: {_format_safe(primary.title)}\n\n'
        "Grouped member hypotheses:\n"
        + "\n".join(member_lines)
        + "\n\nGrouped evidence:\n"
        + "\n".join(evidence_lines)
        + "\n\nSource files for this group:\n"
        + "\n".join(source_files)
        + "\n\nAdjacent source-backed hypotheses not assigned to this exact group:\n"
        + "\n".join(adjacent_lines)
        + "\n\nWhy this group was selected:\n"
        + "\n".join(reason_lines)
        + "\n\nFocus globs:\n{focus_globs}\n\n"
        "Relevant code patterns:\n{code_patterns}\n\n"
        "Category-pack planning:\n"
        + _category_pack_prompt_section(category_pack_plan, group.packets)
        + "\n\n"
        "Rules:\n"
        "- This group is a starting point, not a hard gate. If adjacent source-backed branches look strong, pursue them and document how they branch from this evidence cluster.\n"
        "- Stay anchored to grouped evidence, source files, and the target's trust boundaries before widening scope.\n"
        "- Treat stale or ambiguous branches as hypotheses until code evidence proves reachability.\n"
        "- This agent evaluates multiple hypotheses. Emit a per-hypothesis verdict for every listed hypothesis before closing the task.\n"
        "- Optional specialist follow-up requests are allowed only when static evidence justifies them.\n"
        "- If there is no real issue, print exactly: {{}}\n"
        "- When you find an issue, append a single-line JSON object to {findings_path} and print the same JSON line to stdout.\n"
        "- Use keys: agent, category, class_name, type, file, line, description, severity, context, source, trust_boundary, flow_path, sink, exploitability.\n\n"
        + _phased_output_schema_prompt()
        + "\n\n"
        "Hunting policy:\n"
        "{hunting_policy_snippet}"
    )


def _trace_metadata(packet: HypothesisAgentPacket) -> dict[str, Any]:
    return {
        "adapter": ADAPTER_NAME,
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
        "entry_status": packet.entry_status,
        "attacker_influence_score": packet.attacker_influence_score,
        "context_privilege_score": packet.context_privilege_score,
        "incremental_impact_score": packet.incremental_impact_score,
        "entry_reportability_score": packet.entry_reportability_score,
        "chain_unlock_score": packet.chain_unlock_score,
        "ingestion_path": packet.ingestion_path,
        "required_entry_primitives": list(packet.required_entry_primitives),
        "context_tags": list(packet.context_tags),
        "unlocked_amplifiers": list(packet.unlocked_amplifiers),
        "reportability": packet.reportability,
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
        "{hunting_policy_snippet}\n\n"
        + _phased_output_schema_prompt()
    )


def _phased_output_schema_prompt() -> str:
    return (
        "Required phased-testing output fields for every non-empty finding JSON:\n"
        "- finding_role: entry|amplifier|chain|hardening\n"
        "- entry_status: proven|plausible|missing|not_required\n"
        "- ingestion_path: shared design|file import|collaboration sync|deeplink|uploaded media|link preview|external URL|unknown\n"
        "- unlocked_context: renderer/window/WebView/native context reached by the entry\n"
        "- chain_handles: list of focused follow-up handles, e.g. HostRpc.DownloadService or canva-recording://read\n"
        "- required_entry_primitives: list such as renderer_xss, webview_js, malicious_file_import, deeplink_control, auth_callback_control\n"
        "- unlocked_amplifiers: list of matching amplifier families or sinks\n"
        "- reportability: submit|validate_entry|hold_for_chain|notes_only\n"
        "- payout_confidence: high|medium|low\n"
        "If the issue requires a prior renderer/WebView/native execution bug and does not prove standalone critical impact, "
        "set finding_role=amplifier, entry_status=missing, reportability=hold_for_chain."
    )


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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


def _group_key(group: _GroupedPacketSet) -> str:
    primary = group.primary_packet
    source = _slug(group.source_key.split("|", 1)[0] if "|" in group.source_key else group.source_key)
    family = _slug(group.family_key)
    surface = _slug(group.surface_key)
    suffix = _slug(primary.id or primary.key)
    return f"hunt-hypothesis-{family}-{surface}-{source}-{suffix}".strip("-")


def _group_code_patterns(group: _GroupedPacketSet) -> list[str]:
    return _group_code_patterns_from_packets(group.packets)


def _group_code_patterns_from_packets(packets: Sequence[HypothesisAgentPacket]) -> list[str]:
    values: list[str] = []
    for packet in packets:
        for item in (*packet.evidence_requirements, *packet.chain_requirements, *packet.tags, *packet.secondary_families):
            cleaned = str(item).strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return values


def _grouped_evidence(group: _GroupedPacketSet) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for packet in group.packets:
        for item in packet.source_evidence:
            key = (
                str(item.get("id") or item.get("candidate_id") or item.get("source_id") or "").strip(),
                str(item.get("kind") or item.get("type") or "").strip(),
                str(item.get("file") or item.get("path") or "").strip(),
            )
            if key in seen:
                continue
            seen.add(key)
            evidence.append(json.loads(json.dumps(item)))
    return evidence


def _grouped_evidence_lines(group: _GroupedPacketSet) -> list[str]:
    lines: list[str] = []
    for item in _grouped_evidence(group):
        evidence_id = str(item.get("id") or item.get("candidate_id") or item.get("source_id") or "").strip()
        kind = str(item.get("kind") or item.get("type") or "").strip()
        file_path = str(item.get("file") or item.get("path") or "").strip()
        parts = [part for part in (evidence_id, kind, file_path) if part]
        if parts:
            lines.append("- " + _format_safe(" | ".join(parts)))
    return lines


def _adjacent_hypothesis_lines(group: _GroupedPacketSet) -> list[str]:
    lines: list[str] = []
    for packet in sorted(group.adjacent_packets, key=lambda item: item.id):
        lines.append(
            f"- {_format_safe(packet.id)} | family={_format_safe(packet.surface_family)} | "
            f"role={_format_safe(packet.role)} | priority={_format_safe(packet.priority)} | {_format_safe(packet.title)}"
        )
    return lines


def _source_files(group: _GroupedPacketSet) -> list[str]:
    values: list[str] = []
    for packet in group.packets:
        for item in packet.focus_files:
            cleaned = str(item).strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
        for evidence in packet.source_evidence:
            cleaned = str(evidence.get("file") or evidence.get("path") or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return values


def _source_coverage(groups: Sequence[_GroupedPacketSet]) -> list[dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = {}
    for group in groups:
        item = coverage.setdefault(group.source_key, {"source": group.source_key, "groups": 0, "hypotheses": 0})
        item["groups"] += 1
        item["hypotheses"] += len(group.member_ids)
    return sorted(coverage.values(), key=lambda item: (-int(item["groups"]), -int(item["hypotheses"]), item["source"]))


def _category_pack_prompt(
    pack: CategoryPack,
    packets: Sequence[HypothesisAgentPacket],
) -> str:
    member_lines = []
    for packet in sorted(packets, key=lambda item: item.id):
        member_lines.append(
            f"- {_format_safe(packet.id)} | role={_format_safe(packet.role)} | "
            f"priority={_format_safe(packet.priority)} | {_format_safe(packet.title)}"
        )
    evidence_lines = [f"- {_format_safe(item)}" for item in pack.evidence_ids] or ["- None provided"]
    source_files = [f"- {_format_safe(item)}" for item in pack.source_files] or ["- None provided"]
    route_keys = [f"- {_format_safe(item)}" for item in pack.route_or_endpoint_keys] or ["- None provided"]
    sink_types = [f"- {_format_safe(item)}" for item in pack.sink_types] or ["- None provided"]
    entry_paths = [f"- {_format_safe(item)}" for item in pack.entry_paths] or ["- None provided"]
    expected_outputs = [f"- {_format_safe(item)}" for item in pack.expected_outputs] or ["- None provided"]
    verdicts = [f"- {_format_safe(item)}" for item in pack_verdict_options()]
    policy_id = _format_safe(pack.policy_id or "None")
    guardrail = _category_pack_guardrail(pack)
    bounded_context = _category_pack_bounded_context_section(pack, packets)
    specialist_schema = _category_pack_specialist_request_schema(pack)
    return (
        f'You are a hunt-pipeline category-pack agent for "{_format_safe(pack.vuln_class)}".\n\n'
        "Program: {program}\n"
        "BaseTeam storage team_type: {team_type}\n"
        "Family/lane: {family}/{lane}\n"
        "Target path: {target_path}\n"
        "Snapshot id: {snapshot_id}\n"
        "Shared brain index: {shared_brain_index}\n"
        "Append-only findings file: {findings_path}\n"
        "Ledger path: {ledger_path}\n"
        "Reports root: {reports_root}\n"
        "Notes root: {notes_root}\n"
        "Traces root: {traces_dir}\n\n"
        f"Category pack id: {_format_safe(pack.pack_id)}\n"
        f"Vulnerability class: {_format_safe(pack.vuln_class)}\n"
        f"Subclass: {_format_safe(pack.subclass)}\n"
        f"Surface family: {_format_safe(pack.surface_family)}\n"
        f"Context cluster: {_format_safe(pack.context_cluster_id)}\n"
        f"Policy id: {policy_id}\n"
        f"Specialist follow-up allowed: {_format_safe(str(pack.specialist_followup_allowed).lower())}\n\n"
        "Hypotheses in this pack:\n"
        + "\n".join(member_lines)
        + "\n\nEvidence ids:\n"
        + "\n".join(evidence_lines)
        + "\n\nSource files:\n"
        + "\n".join(source_files)
        + "\n\nRoute or endpoint keys:\n"
        + "\n".join(route_keys)
        + "\n\nSink types:\n"
        + "\n".join(sink_types)
        + "\n\nEntry paths:\n"
        + "\n".join(entry_paths)
        + "\n\nExpected outputs:\n"
        + "\n".join(expected_outputs)
        + "\n\nBounded context section:\n"
        + bounded_context
        + "\n\nPer-hypothesis verdicts are required for every listed hypothesis.\n"
        "Allowed verdict values:\n"
        + "\n".join(verdicts)
        + "\n\nSpecialist request schema:\n"
        + specialist_schema
        + "\n\nOptional specialist follow-up requests must be evidence-based and scoped to concrete hypothesis ids.\n"
        + guardrail
        + "\nFocus globs:\n{focus_globs}\n\n"
        "Relevant code patterns:\n{code_patterns}\n\n"
        "Hunting policy:\n"
        "{hunting_policy_snippet}"
    )


def _category_pack_prompt_section(
    plan: CategoryPackPlan,
    packets: Sequence[HypothesisAgentPacket],
) -> str:
    packet_map = {packet.id: packet for packet in packets}
    sections: list[str] = []
    for pack in plan.packs:
        sections.append(
            f"- Pack {_format_safe(pack.pack_id)} | class={_format_safe(pack.vuln_class)} | "
            f"subclass={_format_safe(pack.subclass)} | context={_format_safe(pack.context_cluster_id)} | "
            f"hypotheses={_format_safe(', '.join(pack.hypothesis_ids))}"
        )
        if pack.evidence_ids:
            sections.append(f"  Evidence ids: {_format_safe(', '.join(pack.evidence_ids))}")
        if pack.route_or_endpoint_keys:
            sections.append(f"  Route keys: {_format_safe(', '.join(pack.route_or_endpoint_keys))}")
        if pack.sink_types:
            sections.append(f"  Sink types: {_format_safe(', '.join(pack.sink_types))}")
        if pack.entry_paths:
            sections.append(f"  Entry paths: {_format_safe(', '.join(pack.entry_paths))}")
        sections.append("  Bounded context: use listed source files/routes/sinks/entry paths first; avoid broad repo scans unless needed to resolve these hypotheses.")
        if pack.specialist_followup_allowed:
            sections.append("  Specialist follow-up requests are allowed when static evidence supports them.")
            sections.append("  Specialist request schema: request_type, parent_pack_id, reason, recommended_agent, hypothesis_ids, required_context, estimated_value, safety_gate.")
        guardrail = _category_pack_guardrail(pack)
        if guardrail:
            sections.append(f"  {_format_safe(guardrail.strip())}")
        for hypothesis_id in pack.hypothesis_ids:
            packet = packet_map.get(hypothesis_id)
            if packet is None:
                continue
            sections.append(
                f"  - {_format_safe(packet.id)} => {_format_safe(packet.title)} "
                f"(role={_format_safe(packet.role)}, priority={_format_safe(packet.priority)})"
            )
    verdict_lines = ", ".join(pack_verdict_options())
    sections.append(f"- Per-hypothesis verdict values: {_format_safe(verdict_lines)}")
    sections.append("- Optional specialist follow-up requests must cite hypothesis ids and concrete static evidence.")
    return "\n".join(sections) or "- None provided"


def _category_pack_bounded_context_section(
    pack: CategoryPack,
    packets: Sequence[HypothesisAgentPacket],
) -> str:
    hypothesis_ids = ", ".join(_format_safe(item) for item in pack.hypothesis_ids) or "None"
    evidence_ids = ", ".join(_format_safe(item) for item in pack.evidence_ids) or "None"
    source_files = ", ".join(_format_safe(item) for item in pack.source_files) or "None"
    route_keys = ", ".join(_format_safe(item) for item in pack.route_or_endpoint_keys) or "None"
    entry_paths = ", ".join(_format_safe(item) for item in pack.entry_paths) or "None"
    packet_files = ", ".join(
        _format_safe(item)
        for item in dict.fromkeys(file_path for packet in packets for file_path in packet.focus_files)
    ) or "None"
    return (
        f"- Pack identity: {_format_safe(pack.pack_id)}\n"
        f"- Hypothesis ids in scope: {hypothesis_ids}\n"
        f"- Evidence ids in scope: {evidence_ids}\n"
        f"- Primary source files: {source_files}\n"
        f"- Packet focus files: {packet_files}\n"
        f"- Route/endpoint keys: {route_keys}\n"
        f"- Entry paths: {entry_paths}\n"
        "- Context budget rule: build one local map for this source/route cluster; prefer capped line windows, symbol/module extraction, and rg/head/sed limits over broad full-repo or full-bundle dumps."
    )


def _category_pack_specialist_request_schema(pack: CategoryPack) -> str:
    allowed = "true" if pack.specialist_followup_allowed else "false"
    return (
        "Write specialist_requests.jsonl only when specialist_followup_allowed is true and static evidence justifies extra spend. "
        f"specialist_followup_allowed={allowed}. JSONL object fields: "
        "request_type='specialist_followup', parent_pack_id, reason, recommended_agent, hypothesis_ids, "
        "required_context, estimated_value, safety_gate. Each request must cite concrete hypothesis_ids from this pack and the minimal required_context."
    )


def _category_pack_guardrail(pack: CategoryPack) -> str:
    if pack.vuln_class != "ipc":
        return ""
    return (
        "\nIPC/HostRpc bridge-only or dangerous-method evidence is amplifier-only and non-reportable "
        "unless attacker-controlled renderer, deeplink, file, or import entry-path evidence exists.\n"
    )


def _packet_signature(packet: HypothesisAgentPacket) -> tuple[Any, ...]:
    source = tuple(
        (
            str(item.get("id") or item.get("candidate_id") or item.get("source_id") or "").strip(),
            str(item.get("kind") or item.get("type") or "").strip(),
            str(item.get("file") or item.get("path") or "").strip(),
        )
        for item in packet.source_evidence
        if isinstance(item, Mapping)
    )
    return (
        packet.id,
        packet.key,
        packet.title,
        packet.role,
        packet.priority,
        packet.surface_family,
        source,
    )


def _source_key(packet: HypothesisAgentPacket) -> str:
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        evidence_id = str(item.get("id") or item.get("candidate_id") or item.get("source_id") or "").strip()
        file_path = str(item.get("file") or item.get("path") or "").strip()
        if evidence_id and file_path:
            return f"{evidence_id}|{file_path}"
        if file_path:
            return file_path
        if evidence_id:
            return evidence_id
    for item in packet.focus_files:
        cleaned = str(item).strip()
        if cleaned:
            return cleaned
    return packet.key or packet.id or "unknown-source"


def _source_identity(source_key: str) -> str:
    return str(source_key).split("|", 1)[0].strip() or str(source_key)


def _surface_key(packet: HypothesisAgentPacket) -> str:
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        cleaned = str(item.get("kind") or item.get("type") or "").strip()
        if cleaned:
            return cleaned
    return packet.surface_family or "hunt-surface"


def _deduped_lines(groups: Sequence[Sequence[str] | tuple[str, ...]]) -> list[str]:
    values: list[str] = []
    for group in groups:
        for item in group:
            cleaned = str(item).strip()
            if cleaned and cleaned not in values:
                values.append(f"- {_format_safe(cleaned)}")
    return values


def _slug(value: str) -> str:
    cleaned = []
    for character in str(value or "").strip().lower():
        cleaned.append(character if character.isalnum() else "-")
    slug = "".join(cleaned).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "hunt-hypothesis"


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
