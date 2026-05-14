from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.base_team import AgentSpec
from agents.hunt_pipeline.models import HypothesisAgentPacket
from agents.hunt_pipeline.runtime_adapter import packet_from_dict

ADAPTER_NAME = "agents.electron_hypothesis_adapter"

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


@dataclass(frozen=True, slots=True)
class LoadedHypothesisPlan:
    packets: tuple[HypothesisAgentPacket, ...]
    selected_ids: frozenset[str] = frozenset()
    deferred_ids: frozenset[str] = frozenset()
    skipped_ids: frozenset[str] = frozenset()
    program: str | None = None
    target_path: str | None = None
    source_path: str = ""


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
    adjacent_packets: list[HypothesisAgentPacket] = field(default_factory=list)
    first_index: int = 0

    def add(
        self,
        packet: HypothesisAgentPacket,
        *,
        index: int,
        selected_ids: frozenset[str],
        deferred_ids: frozenset[str],
        skipped_ids: frozenset[str],
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


def load_hypothesis_plan(
    *,
    hypotheses_path: str | Path | None = None,
    pipeline_plan_path: str | Path | None = None,
) -> LoadedHypothesisPlan:
    if bool(hypotheses_path) == bool(pipeline_plan_path):
        raise ValueError("exactly one of hypotheses_path or pipeline_plan_path is required")

    path = Path(hypotheses_path or pipeline_plan_path or "").expanduser().resolve(strict=False)
    payload = _load_payload(path)
    if isinstance(payload, list):
        packets = tuple(packet_from_dict(item) for item in payload if isinstance(item, Mapping))
        return LoadedHypothesisPlan(packets=packets, source_path=str(path))
    if not isinstance(payload, Mapping):
        raise ValueError(f"hypothesis input must decode to a JSON object, JSON array, or JSONL rows: {path}")

    packet_rows = payload.get("hypotheses")
    if packet_rows is None:
        packet_rows = [payload]
    packets = tuple(packet_from_dict(item) for item in packet_rows if isinstance(item, Mapping))
    selected_ids, deferred_ids, skipped_ids = _decision_status_sets(payload.get("scheduler_plan"))
    return LoadedHypothesisPlan(
        packets=packets,
        selected_ids=selected_ids,
        deferred_ids=deferred_ids,
        skipped_ids=skipped_ids,
        program=_optional_text(payload.get("program")),
        target_path=_optional_text(payload.get("target_path")),
        source_path=str(path),
    )


def build_electron_hypothesis_specs(
    packets: Sequence[HypothesisAgentPacket],
    *,
    program: str,
    snapshot_id: str,
    max_agents: int,
    selected_ids: frozenset[str] = frozenset(),
    deferred_ids: frozenset[str] = frozenset(),
    skipped_ids: frozenset[str] = frozenset(),
    created_at: str | None = None,
) -> tuple[list[AgentSpec], dict[str, Any]]:
    grouped = _collapse_packets(
        packets,
        selected_ids=selected_ids,
        deferred_ids=deferred_ids,
        skipped_ids=skipped_ids,
    )
    created = created_at or _timestamp_iso()
    ranked = sorted(
        grouped,
        key=lambda item: (-item.ranking_score, item.first_index, item.key),
    )

    selected_groups: list[_GroupedPacketSet] = []
    deferred_groups: list[_GroupedPacketSet] = []
    skipped_groups: list[_GroupedPacketSet] = []

    _attach_adjacent_packets(ranked)

    eligible = [group for group in ranked if _group_is_eligible(group, selected_ids, deferred_ids, skipped_ids)]
    selected_keys = {group.key for group in eligible[: max(0, int(max_agents))]}
    for group in ranked:
        if group.key in selected_keys:
            selected_groups.append(group)
            continue
        if group.status == "skipped":
            skipped_groups.append(group)
            continue
        deferred_groups.append(group)

    specs = [
        _group_to_agent_spec(
            group,
            program=program,
            snapshot_id=snapshot_id,
            created_at=created,
        )
        for group in selected_groups
    ]
    metrics = {
        "input_hypotheses": len(list(packets)),
        "collapsed_groups": len(grouped),
        "selected_groups": len(selected_groups),
        "deferred_groups": len(deferred_groups),
        "skipped_groups": len(skipped_groups),
        "agent_specs_created": len(specs),
        "top_source_coverage": _top_source_coverage(ranked),
        "source_path": None,
    }
    return specs, metrics


def _collapse_packets(
    packets: Sequence[HypothesisAgentPacket],
    *,
    selected_ids: frozenset[str],
    deferred_ids: frozenset[str],
    skipped_ids: frozenset[str],
) -> list[_GroupedPacketSet]:
    grouped: dict[tuple[str, str, str], _GroupedPacketSet] = {}
    for index, packet in enumerate(packets):
        source_key = _source_key(packet)
        surface_key = _surface_key(packet)
        family_key = str(packet.surface_family or surface_key or "electron-family").strip() or "electron-family"
        key = (source_key, surface_key, family_key)
        group = grouped.get(key)
        if group is None:
            group = _GroupedPacketSet(source_key=source_key, surface_key=surface_key, family_key=family_key)
            grouped[key] = group
        group.add(
            packet,
            index=index,
            selected_ids=selected_ids,
            deferred_ids=deferred_ids,
            skipped_ids=skipped_ids,
        )
    return list(grouped.values())


def _group_is_eligible(
    group: _GroupedPacketSet,
    selected_ids: frozenset[str],
    deferred_ids: frozenset[str],
    skipped_ids: frozenset[str],
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


def _attach_adjacent_packets(groups: Sequence[_GroupedPacketSet]) -> None:
    by_source: dict[str, list[HypothesisAgentPacket]] = {}
    for group in groups:
        by_source.setdefault(_source_identity(group.source_key), []).extend(group.packets)

    for group in groups:
        seen = set(group.member_ids)
        adjacent: list[HypothesisAgentPacket] = []
        for packet in by_source.get(_source_identity(group.source_key), []):
            if packet.id in seen:
                continue
            seen.add(packet.id)
            adjacent.append(packet)
        group.adjacent_packets = adjacent


def _group_to_agent_spec(
    group: _GroupedPacketSet,
    *,
    program: str,
    snapshot_id: str,
    created_at: str,
) -> AgentSpec:
    primary = group.primary_packet
    source_files = _source_files(group)
    focus_globs = source_files or list(dict.fromkeys(primary.focus_files))
    patterns = _code_patterns(group)
    key = _group_key(group)
    metadata = {
        "logical_team": "electron",
        "beta": True,
        "adapter": ADAPTER_NAME,
        "runtime_handoff": {
            "conversion_only": False,
            "spawn_enabled": True,
            "ledger_writes_enabled": True,
            "boundary": "explicit-electron-team-cli",
        },
        "source_group": {
            "source": group.source_key,
            "surface": group.surface_key,
            "family": group.family_key,
            "status": group.status,
            "hypothesis_ids": sorted(group.member_ids),
        },
        "grouped_evidence": _grouped_evidence(group),
        "source_files": source_files,
        "source_path_kind": "pipeline-hypothesis-plan",
    }
    return AgentSpec(
        key=key,
        vuln_class=group.family_key,
        surface=group.surface_key,
        prompt_template=_group_prompt(group),
        focus_globs=focus_globs,
        code_patterns=patterns,
        program=str(program).strip(),
        created_at=created_at,
        snapshot_id=str(snapshot_id).strip(),
        metadata=metadata,
    )


def _group_prompt(group: _GroupedPacketSet) -> str:
    primary = group.primary_packet
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
        f'You are a beta Electron Team grouped static-analysis hunter for "{_format_safe(group.family_key)}".\n\n'
        "Program: {program}\n"
        "Logical team: electron-team beta\n"
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
        "Rules:\n"
        "- Static review only. Do not run the Electron app, launch browsers, attach debuggers, or perform live validation.\n"
        "- This group is a starting point, not a hard gate. If adjacent source-backed branches look strong, pursue them and document how they branch from this evidence cluster.\n"
        "- Stay anchored to grouped evidence, source files, and Electron privilege boundaries before widening scope.\n"
        "- Treat stale or ambiguous branches as hypotheses until code evidence proves reachability.\n"
        "- If there is no real issue, print exactly: {{}}\n"
        "- When you find an issue, append a single-line JSON object to {findings_path} and print the same JSON line to stdout.\n"
        "- Use keys: agent, category, class_name, type, file, line, description, severity, context, source, trust_boundary, flow_path, sink, exploitability.\n\n"
        "Hunting policy:\n"
        "{hunting_policy_snippet}"
    )


def _group_key(group: _GroupedPacketSet) -> str:
    primary = group.primary_packet
    source = _slug(group.source_key.split("|")[0] if "|" in group.source_key else group.source_key)
    family = _slug(group.family_key)
    surface = _slug(group.surface_key)
    suffix = _slug(primary.id or primary.key)
    return f"electron-hypothesis-{family}-{surface}-{source}-{suffix}".strip("-")


def _code_patterns(group: _GroupedPacketSet) -> list[str]:
    values: list[str] = []
    for packet in group.packets:
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


def _top_source_coverage(groups: Sequence[_GroupedPacketSet]) -> list[dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = {}
    for group in groups:
        item = coverage.setdefault(group.source_key, {"source": group.source_key, "groups": 0, "hypotheses": 0})
        item["groups"] += 1
        item["hypotheses"] += len(group.member_ids)
    ranked = sorted(coverage.values(), key=lambda item: (-int(item["groups"]), -int(item["hypotheses"]), item["source"]))
    return ranked[:3]


def _decision_status_sets(payload: Any) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    if not isinstance(payload, Mapping):
        return frozenset(), frozenset(), frozenset()
    return (
        frozenset(_decision_hypothesis_ids(payload.get("selected"))),
        frozenset(_decision_hypothesis_ids(payload.get("deferred"))),
        frozenset(_decision_hypothesis_ids(payload.get("skipped"))),
    )


def _decision_hypothesis_ids(items: Any) -> list[str]:
    values: list[str] = []
    for item in items or ():
        if not isinstance(item, Mapping):
            continue
        for hypothesis_id in (item.get("hypothesis_id"), *(item.get("member_hypothesis_ids") or ())):
            cleaned = str(hypothesis_id or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return values


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
    return packet.surface_family or "electron-surface"


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
    return slug or "electron-hypothesis"


def _optional_text(value: Any) -> str | None:
    cleaned = str(value or "").strip()
    return cleaned or None


def _load_payload(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        return rows


def _format_safe(value: Any) -> str:
    return str(value).replace("{", "{{").replace("}", "}}")


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
