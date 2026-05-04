"""Adapters from brainstorm-spec intents into team-specific agent profiles."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.dynamic_agent_builder import AgentSpec

ensure_bounty_core_importable("bounty_core.brainstorm_spec")

from bounty_core.brainstorm_spec import BrainstormAgentIntent  # noqa: E402


def brainstorm_finding_metadata(intent: BrainstormAgentIntent) -> dict[str, Any]:
    metadata = intent.finding_metadata()
    metadata["expected_chain"] = intent.expected_chain
    metadata["source_spec_path"] = str(intent.source_spec_path)
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
{intent.prompt_context}

When emitting any finding for this assignment, preserve the brainstorm metadata fields exactly:
{json.dumps(finding_metadata, indent=2, sort_keys=True)}
Do not rename hypothesis_id or brainstorm_agent_key. Keep these fields on class and novel findings."""
