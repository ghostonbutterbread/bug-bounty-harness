"""Adapters from brainstorm-spec intents into team-specific agent profiles."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any

from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.dynamic_agent_builder import AgentSpec

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
            "hypothesis_id",
            "hypothesis_title",
            "brainstorm_agent_key",
            "brainstorm_surface",
            "brainstorm_tags",
            "appmap_context_packet",
            "appmap_candidate_id",
            "appmap_flow_id",
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
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid AppMap context packet {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"invalid AppMap context packet {path}: expected JSON object")
        linkage = payload.get("hypothesis_linkage") if isinstance(payload.get("hypothesis_linkage"), dict) else {}
        packet_candidate = payload.get("candidate") if isinstance(payload.get("candidate"), dict) else {}
        if (
            str(linkage.get("hypothesis_id")) == intent.hypothesis_id
            and str(linkage.get("agent_key")) == intent.agent_key
            and str(packet_candidate.get("id")) == candidate_id
        ):
            payload["_packet_path"] = path
            matches.append(payload)
    if len(matches) != 1:
        raise ValueError(
            "ambiguous AppMap context packet lookup for "
            f"hypothesis {intent.hypothesis_id}, candidate {candidate_id}, agent {intent.agent_key}: "
            f"{len(matches)} matches"
        )
    return matches[0]


def _appmap_packet_file_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", str(value).strip().lower()).strip("-_") or "agent"


def _appmap_contexts_dir(spec_path: Path) -> Path:
    resolved = spec_path.expanduser().resolve(strict=False)
    if resolved.parent.name == "generated_specs":
        return resolved.parent.parent / "agent_contexts"
    return resolved.parent / "agent_contexts"


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
