"""Adapters from brainstorm-spec intents into team-specific agent profiles."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any, Iterable, Sequence

from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.dynamic_agent_builder import AgentSpec
from agents.hunting_policy import extract_policy_artifact_metadata

ensure_bounty_core_importable("bounty_core.brainstorm_spec")

from bounty_core.brainstorm_spec import BrainstormAgentIntent  # noqa: E402

APPMAP_CANDIDATE_RE = re.compile(r"\bappmap-(C\d{4})\b")
APPMAP_CONTEXT_RE = re.compile(r"\bappmap-context:([^:\s]+):(C\d{4}):([^\s]+)\b")


def brainstorm_finding_metadata(intent: BrainstormAgentIntent) -> dict[str, Any]:
    metadata = intent.finding_metadata()
    metadata["expected_chain"] = intent.expected_chain
    metadata["source_spec_path"] = str(intent.source_spec_path)
    packet = _load_appmap_packet_for_intent(intent)
    if packet is not None:
        metadata["appmap_context_packet"] = str(packet["_packet_path"])
        metadata["appmap_candidate_id"] = packet["candidate"]["id"]
        metadata["appmap_flow_id"] = packet["candidate"]["map_ids"]["flow_id"]
        metadata.update(_appmap_research_metadata(packet))
        metadata.update(extract_policy_artifact_metadata(packet))
    return metadata


def brainstorm_intent_to_dynamic_agent_spec(
    intent: BrainstormAgentIntent,
    *,
    program: str,
    version: str,
) -> AgentSpec:
    """Return the lossless dynamic-agent shape shared by procedural teams."""
    metadata = brainstorm_finding_metadata(intent)
    spec = AgentSpec(
        key=intent.agent_key,
        name=intent.name,
        description=intent.description,
        surface_type=intent.surface,
        vuln_class=intent.vuln_class,
        patterns=[intent.expected_chain, *intent.evidence, *intent.tags],
        focus_files_glob=list(intent.focus_files_glob),
        ignore_files_glob=list(intent.ignore_files_glob),
        agent_prompt_template=_brainstorm_prompt_addendum(intent, metadata),
        parent_keys=["brainstorm-spec", intent.hypothesis_id],
        created_by="brainstorm-spec",
        version=version,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    spec.brainstorm_metadata = metadata
    spec.program = program
    return spec


def spec_uses_category_master_agents(spec: Any) -> bool:
    metadata = getattr(spec, "metadata", {}) or {}
    agent_granularity = str(metadata.get("Agent granularity") or "").strip().lower()
    category_master_agents = str(metadata.get("Category master agents") or "").strip().lower()
    return agent_granularity == "category-master" or category_master_agents in {"1", "true", "yes", "category-master"}


def brainstorm_intents_to_dynamic_agent_specs(
    intents: Sequence[BrainstormAgentIntent],
    *,
    program: str,
    version: str,
    category_master: bool = False,
) -> list[AgentSpec]:
    if not category_master:
        return [
            brainstorm_intent_to_dynamic_agent_spec(intent, program=program, version=version)
            for intent in intents
        ]

    groups: dict[str, list[BrainstormAgentIntent]] = {}
    for intent in intents:
        groups.setdefault(intent.agent_key, []).append(intent)

    specs: list[AgentSpec] = []
    for _agent_key, group in groups.items():
        if len(group) == 1:
            spec = brainstorm_intent_to_dynamic_agent_spec(group[0], program=program, version=version)
            spec.brainstorm_metadata["agent_granularity"] = "category-master"
            spec.brainstorm_metadata["category_master"] = True
            specs.append(spec)
            continue
        specs.append(
            _brainstorm_category_master_dynamic_agent_spec(
                group,
                program=program,
                version=version,
            )
        )
    return specs


def _brainstorm_category_master_dynamic_agent_spec(
    intents: Sequence[BrainstormAgentIntent],
    *,
    program: str,
    version: str,
) -> AgentSpec:
    first = intents[0]
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    member_metadata = [brainstorm_finding_metadata(intent) for intent in intents]
    prompt_sections = [
        "Category-master brainstorm assignment:",
        f"- Static category agent key: {first.agent_key}",
        f"- Assigned hypotheses: {', '.join(metadata['hypothesis_id'] for metadata in member_metadata)}",
        "",
        "Evaluate every assigned hypothesis independently. Use the matching AppMap context packet for each hypothesis. "
        "When emitting a finding, preserve that member's source_spec_path, hypothesis_id, and brainstorm_agent_key exactly. "
        "If none of the assigned hypotheses has a real issue, output exactly {}.",
        "",
        "Category-master member metadata:",
        json.dumps(member_metadata, indent=2, sort_keys=True),
    ]
    for intent, metadata in zip(intents, member_metadata):
        prompt_sections.extend(
            [
                "",
                f"### Member {intent.hypothesis_id}: {intent.hypothesis_title}",
                _brainstorm_prompt_addendum(intent, metadata),
            ]
        )

    focus_files = _ordered_unique(
        glob
        for intent in intents
        for glob in intent.focus_files_glob
    )
    ignore_files = _ordered_unique(
        glob
        for intent in intents
        for glob in intent.ignore_files_glob
    )
    patterns = _ordered_unique(
        item
        for intent in intents
        for item in [intent.expected_chain, *intent.evidence, *intent.tags]
    )
    metadata = dict(member_metadata[0])
    metadata.update(
        {
            "agent_granularity": "category-master",
            "category_master": True,
            "brainstorm_cluster_id": _appmap_packet_file_key(first.agent_key),
            "brainstorm_cluster_size": len(member_metadata),
            "brainstorm_cluster_assignments": member_metadata,
            "member_agent_keys": _ordered_unique(metadata["brainstorm_agent_key"] for metadata in member_metadata),
            "member_hypothesis_ids": [metadata["hypothesis_id"] for metadata in member_metadata],
        }
    )
    spec = AgentSpec(
        key=first.agent_key,
        name=f"{first.name} Category Master",
        description=(
            f"Category-master brainstorm agent for {len(intents)} {first.agent_key} hypotheses. "
            "Explores one static zero_day_team vulnerability category while preserving per-hypothesis attribution."
        ),
        surface_type=first.surface,
        vuln_class=first.agent_key,
        patterns=patterns,
        focus_files_glob=focus_files,
        ignore_files_glob=ignore_files,
        agent_prompt_template="\n".join(prompt_sections).rstrip(),
        parent_keys=["brainstorm-spec", "category-master", first.agent_key, *[intent.hypothesis_id for intent in intents]],
        created_by="brainstorm-spec-category-master",
        version=version,
        created_at=created_at,
    )
    spec.brainstorm_metadata = metadata
    spec.program = program
    return spec


def brainstorm_intent_to_zero_day_profile(
    intent: BrainstormAgentIntent,
    *,
    program: str,
    version: str,
) -> Any:
    from agents.zero_day_team import _profile_from_agent_spec

    return _profile_from_agent_spec(
        brainstorm_intent_to_dynamic_agent_spec(
            intent,
            program=program,
            version=version,
        )
    )


def brainstorm_intent_to_apk_profile(
    intent: BrainstormAgentIntent,
    *,
    program: str,
    version: str,
) -> Any:
    from agents.apk_team import _profile_from_agent_spec

    return _profile_from_agent_spec(
        brainstorm_intent_to_dynamic_agent_spec(
            intent,
            program=program,
            version=version,
        )
    )


def _brainstorm_prompt_addendum(
    intent: BrainstormAgentIntent,
    metadata: dict[str, Any],
) -> str:
    packet = _load_appmap_packet_for_intent(intent)
    prompt_context = _appmap_packet_prompt(packet) if packet is not None else intent.prompt_context
    evidence_lines = "\n".join(f"- {item}" for item in intent.evidence) or "- None"
    finding_metadata = {
        key: metadata[key]
        for key in (
            "brainstorm_spec",
            "source_spec_path",
            "hypothesis_id",
            "hypothesis_title",
            "brainstorm_agent_key",
            "brainstorm_surface",
            "brainstorm_tags",
            "appmap_context_packet",
            "appmap_candidate_id",
            "appmap_flow_id",
            "appmap_research_technique_ids",
            "appmap_research_source_ids",
            "appmap_research_citations",
            "hunting_policy",
            "hunting_policy_id",
            "hunting_policy_mode",
            "hunting_policy_posture",
        )
        if key in metadata
    }
    return f"""Brainstorm-spec assignment:
- Hypothesis id: {intent.hypothesis_id}
- Hypothesis title: {intent.hypothesis_title}
- Brainstorm agent key: {intent.agent_key}
- Surface: {intent.surface}
- Expected chain: {intent.expected_chain}
- Source spec path: {intent.source_spec_path}

Evidence to start from:
{evidence_lines}

Brainstorm context:
{prompt_context}

When emitting any finding for this assignment, preserve the brainstorm metadata fields exactly:
{json.dumps(finding_metadata, indent=2, sort_keys=True)}
Do not rename hypothesis_id or brainstorm_agent_key. Keep these fields on class and novel findings."""


def _load_appmap_packet_for_intent(intent: BrainstormAgentIntent) -> dict[str, Any] | None:
    context_refs = [
        match.groups()
        for evidence in intent.evidence
        for match in APPMAP_CONTEXT_RE.finditer(str(evidence))
    ]
    if not context_refs:
        return None
    if len(context_refs) != 1:
        raise ValueError(f"AppMap hypothesis {intent.hypothesis_id} must include exactly one appmap-context evidence ref")
    context_hypothesis_id, context_candidate_id, context_agent_key = context_refs[0]
    if context_hypothesis_id != intent.hypothesis_id or context_agent_key != intent.agent_key:
        raise ValueError(
            "AppMap context evidence does not match intent: "
            f"expected {intent.hypothesis_id}/{intent.agent_key}, "
            f"got {context_hypothesis_id}/{context_agent_key}"
        )

    candidate_refs = [
        match.group(1)
        for evidence in intent.evidence
        for match in APPMAP_CANDIDATE_RE.finditer(str(evidence))
    ]
    unique_refs = sorted(set(candidate_refs))
    if len(candidate_refs) != len(unique_refs):
        raise ValueError(f"AppMap hypothesis {intent.hypothesis_id} contains duplicate candidate evidence")
    if len(unique_refs) != 1:
        raise ValueError(
            f"AppMap hypothesis {intent.hypothesis_id} aggregates multiple candidate IDs: "
            f"{', '.join(unique_refs)}"
        )
    candidate_id = unique_refs[0]
    if candidate_id != context_candidate_id:
        raise ValueError(
            "AppMap context candidate does not match appmap-C#### evidence: "
            f"{context_candidate_id} != {candidate_id}"
        )

    contexts_dir = _appmap_contexts_dir(Path(intent.source_spec_path))
    safe_agent_key = _appmap_packet_file_key(intent.agent_key)
    expected_name = f"{intent.hypothesis_id}-{candidate_id}-{safe_agent_key}.json"
    candidates = [contexts_dir / expected_name]
    if not candidates[0].is_file():
        candidates = sorted(contexts_dir.glob(f"*-{candidate_id}-{safe_agent_key}.json"))
    if not candidates:
        raise FileNotFoundError(
            "missing AppMap context packet for "
            f"hypothesis {intent.hypothesis_id}, candidate {candidate_id}, agent {intent.agent_key}: "
            f"expected under {contexts_dir}"
        )

    matches: list[dict[str, Any]] = []
    spec_run_id = _appmap_run_id_from_spec(Path(intent.source_spec_path))
    run_id_mismatches: list[tuple[Path, str]] = []
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid AppMap context packet {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"invalid AppMap context packet {path}: expected JSON object")
        linkage = payload.get("hypothesis_linkage") if isinstance(payload.get("hypothesis_linkage"), dict) else {}
        packet_candidate = payload.get("candidate") if isinstance(payload.get("candidate"), dict) else {}
        packet_run_id = str(payload.get("run_id") or "").strip()
        if spec_run_id and packet_run_id and packet_run_id != spec_run_id:
            run_id_mismatches.append((path, packet_run_id))
            continue
        if (
            str(linkage.get("hypothesis_id")) == intent.hypothesis_id
            and str(linkage.get("agent_key")) == intent.agent_key
            and str(packet_candidate.get("id")) == candidate_id
        ):
            payload["_packet_path"] = path
            matches.append(payload)
    if not matches and run_id_mismatches:
        details = ", ".join(f"{path} has {packet_run_id}" for path, packet_run_id in run_id_mismatches)
        raise ValueError(
            "AppMap context packet run_id does not match spec AppMap run id "
            f"{spec_run_id}: {details}"
        )
    if len(matches) != 1:
        raise ValueError(
            "ambiguous AppMap context packet lookup for "
            f"hypothesis {intent.hypothesis_id}, candidate {candidate_id}, agent {intent.agent_key}: "
            f"{len(matches)} matches"
        )
    return matches[0]


def _appmap_run_id_from_spec(spec_path: Path) -> str:
    try:
        text = spec_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r"(?m)^-\s*AppMap run id:\s*(\S+)\s*$", text)
    return match.group(1).strip() if match else ""


def _appmap_packet_file_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", str(value).strip().lower()).strip("-_") or "agent"


def _appmap_contexts_dir(spec_path: Path) -> Path:
    resolved = spec_path.expanduser().resolve(strict=False)
    if resolved.parent.name == "generated_specs":
        return resolved.parent.parent / "agent_contexts"
    return resolved.parent / "agent_contexts"


def _appmap_research_metadata(packet: dict[str, Any]) -> dict[str, list[str]]:
    research = packet.get("research") if isinstance(packet.get("research"), dict) else {}
    summaries = [
        summary
        for summary in research.get("technique_summaries") or []
        if isinstance(summary, dict)
    ]
    sources = [
        source
        for source in research.get("sources") or []
        if isinstance(source, dict)
    ]
    technique_ids = _stable_unique(str(summary.get("id") or "").strip() for summary in summaries)
    source_ids = _stable_unique(str(source.get("id") or "").strip() for source in sources)
    citations = _stable_unique(
        [
            *(str(citation).strip() for summary in summaries for citation in summary.get("citations") or []),
            *(str(source.get("citation") or "").strip() for source in sources),
        ]
    )
    metadata: dict[str, list[str]] = {}
    if technique_ids:
        metadata["appmap_research_technique_ids"] = technique_ids
    if source_ids:
        metadata["appmap_research_source_ids"] = source_ids
    if citations:
        metadata["appmap_research_citations"] = citations
    return metadata


def _stable_unique(values: Any) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _ordered_unique(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _appmap_packet_prompt(packet: dict[str, Any]) -> str:
    packet_for_prompt = {
        key: value
        for key, value in packet.items()
        if key != "_packet_path"
    }
    return (
        "Use this AppMap context packet as the complete assignment context. "
        "Do not expand from the full brainstorm mental model or unrelated impact primitives.\n"
        + json.dumps(packet_for_prompt, indent=2, sort_keys=True)
    )
