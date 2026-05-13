"""Compatibility facade for shared brainstorm spec helpers.

Existing harness imports from ``agents.brainstorm_spec`` remain supported while
the implementation lives in ``bounty_core.brainstorm_spec``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.brainstorm_spec")

import bounty_core.brainstorm_spec as _core  # noqa: E402
from bounty_core.brainstorm_spec import *  # noqa: F401,F403,E402


def parse_brainstorm_spec(
    path: str | Path,
    *,
    validate_paths: bool = True,
) -> BrainstormSpec:
    spec_path = Path(path).expanduser().resolve(strict=False)
    text = spec_path.read_text(encoding="utf-8")
    sections = _core._split_sections(text)

    spec = BrainstormSpec(
        path=spec_path,
        metadata=_core._parse_metadata(sections.get("metadata", [])),
        mental_model=_core._plain_section_text(sections.get("target mental model", [])),
        impact_primitives=_core._parse_impact_primitives(sections.get("impact primitives", [])),
        hypotheses=_core._parse_hypotheses(sections.get("hypotheses", [])),
    )
    validate_brainstorm_spec(spec, validate_paths=validate_paths)
    return spec


def validate_brainstorm_spec(
    spec: BrainstormSpec,
    *,
    validate_paths: bool = True,
) -> None:
    allow_duplicate_active_agent_keys = _spec_uses_category_master_agents(spec)
    _validate_brainstorm_spec_local(
        spec,
        validate_paths=validate_paths,
        allow_duplicate_active_agent_keys=allow_duplicate_active_agent_keys,
    )


def _spec_uses_category_master_agents(spec: BrainstormSpec) -> bool:
    metadata = getattr(spec, "metadata", {}) or {}
    return _truthy_metadata_value(metadata.get("Agent granularity")) == "category-master" or _truthy_metadata_value(
        metadata.get("Category master agents")
    ) in {"true", "yes", "1", "category-master"}


def _truthy_metadata_value(value: Any) -> str:
    return str(value or "").strip().lower()


def _validate_brainstorm_spec_local(
    spec: BrainstormSpec,
    *,
    validate_paths: bool,
    allow_duplicate_active_agent_keys: bool,
) -> None:
    if not spec.hypotheses:
        raise BrainstormSpecError("brainstorm spec must contain at least one hypothesis")

    seen_ids: set[str] = set()
    active_agent_keys: dict[str, str] = {}
    required_fields = {
        "status",
        "priority",
        "surface",
        "entry_point",
        "expected_chain",
        "suggested_agents",
        "tags",
    }

    for hypothesis in spec.hypotheses:
        if hypothesis.id in seen_ids:
            raise BrainstormSpecError(f"duplicate hypothesis id: {hypothesis.id}")
        seen_ids.add(hypothesis.id)

        values = {
            "status": hypothesis.status,
            "priority": hypothesis.priority,
            "surface": hypothesis.surface,
            "entry_point": hypothesis.entry_point,
            "expected_chain": hypothesis.expected_chain,
            "suggested_agents": hypothesis.suggested_agents,
            "tags": hypothesis.tags,
        }
        missing = [
            name
            for name in sorted(required_fields)
            if not values[name] or values[name] == []
        ]
        if missing:
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} missing required field(s): {', '.join(missing)}"
            )
        if hypothesis.status not in VALID_HYPOTHESIS_STATUSES:
            expected = ", ".join(sorted(VALID_HYPOTHESIS_STATUSES))
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} has invalid status {hypothesis.status!r}; "
                f"expected one of: {expected}"
            )
        if hypothesis.priority not in VALID_PRIORITIES:
            expected = ", ".join(sorted(VALID_PRIORITIES))
            raise BrainstormSpecError(
                f"hypothesis {hypothesis.id} has invalid priority {hypothesis.priority!r}; "
                f"expected one of: {expected}"
            )

        local_agent_keys: dict[str, str] = {}
        for agent_key in hypothesis.suggested_agents:
            normalized_agent_key = _core._validate_suggested_agent_key(agent_key, hypothesis.id)
            previous_local_key = local_agent_keys.get(normalized_agent_key)
            if previous_local_key is not None:
                raise BrainstormSpecError(
                    "duplicate suggested agent key "
                    f"{agent_key!r} conflicts with {previous_local_key!r} "
                    f"in hypothesis {hypothesis.id}"
                )
            local_agent_keys[normalized_agent_key] = agent_key

            if hypothesis.status == "retired":
                continue

            previous_id = active_agent_keys.get(normalized_agent_key)
            if previous_id and previous_id != hypothesis.id and not allow_duplicate_active_agent_keys:
                raise BrainstormSpecError(
                    "duplicate suggested agent key "
                    f"{agent_key!r} across active hypotheses {previous_id} and {hypothesis.id}"
                )
            active_agent_keys[normalized_agent_key] = hypothesis.id

    if validate_paths:
        _core._validate_spec_paths(spec)
