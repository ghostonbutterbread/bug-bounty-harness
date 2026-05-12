"""Reusable scheduler adapter for BaseTeam-style runtimes.

This module is intentionally runtime-facing but storage-agnostic: it adapts
team profiles/specs into the pure scheduler core and returns decisions without
writing coverage, ledgers, or team-specific decision files.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal, Sequence

from agents.agent_scheduler import (
    AgentAssignment,
    SchedulerMode,
    assignments_from_profiles,
    decision_events,
    plan_agent_wave,
)
from agents.agent_scheduler import SchedulerConfig as CoreSchedulerConfig

AgentWaveSize = int | Literal["all"]


@dataclass(frozen=True, slots=True)
class BaseTeamSchedulerOptions:
    """Scheduler knobs shared by team runtimes."""

    mode: SchedulerMode = "policy-aware"
    agent_wave_size: AgentWaveSize = "all"
    max_per_surface_family: int = 2
    max_amplifier_family_first_wave: int = 3
    max_hypotheses_per_master_agent: int = 6
    prefer_deferred: bool = True
    category_master_mode: bool = False
    fresh: bool = False
    scheduler_wave_id: str | None = None
    run_id: str | None = None


@dataclass(frozen=True, slots=True)
class BaseTeamSchedulerResult:
    """Runtime-neutral scheduler output."""

    selected_profiles: tuple[Any, ...]
    deferred_keys: tuple[str, ...]
    skipped_keys: tuple[str, ...]
    summary: dict[str, Any]
    decision_events: tuple[dict[str, Any], ...]
    selected_assignments: tuple[AgentAssignment, ...] = field(default_factory=tuple)
    deferred_assignments: tuple[AgentAssignment, ...] = field(default_factory=tuple)
    skipped_assignments: tuple[AgentAssignment, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class _SchedulerProfileView:
    original: Any
    key: str
    display_name: str
    description: str
    focus_globs: tuple[str, ...]
    brainstorm_metadata: dict[str, Any]


def schedule_profiles(
    profiles: Sequence[Any],
    *,
    policy: Any | None = None,
    options: BaseTeamSchedulerOptions | None = None,
    source: str | None = None,
) -> BaseTeamSchedulerResult:
    """Plan a scheduler wave for team profiles/specs.

    The caller remains responsible for applying any team-specific annotations
    before scheduling and for persisting returned decision events afterward.
    """

    scheduler_options = options or BaseTeamSchedulerOptions()
    schedulable_profiles = tuple(_schedulable_profile(profile) for profile in profiles)
    plan = plan_agent_wave(
        assignments_from_profiles(schedulable_profiles, source=source, policy=policy),
        CoreSchedulerConfig(
            mode=scheduler_options.mode,
            agent_wave_size=scheduler_options.agent_wave_size,
            max_per_surface_family=scheduler_options.max_per_surface_family,
            max_amplifier_family_first_wave=scheduler_options.max_amplifier_family_first_wave,
            max_hypotheses_per_master_agent=scheduler_options.max_hypotheses_per_master_agent,
            prefer_deferred=scheduler_options.prefer_deferred,
            category_master_mode=scheduler_options.category_master_mode,
            fresh=scheduler_options.fresh,
        ),
    )
    summary = plan.summary()
    summary.update(
        {
            "wave_size": scheduler_options.agent_wave_size,
            "deferred_profiles": [assignment.key for assignment in plan.deferred],
            "skipped_profiles": [assignment.key for assignment in plan.skipped],
        }
    )
    events = decision_events(
        plan,
        scheduler_wave_id=scheduler_options.scheduler_wave_id,
        run_id=scheduler_options.run_id,
    )
    return BaseTeamSchedulerResult(
        selected_profiles=tuple(_original_profile(assignment.profile) for assignment in plan.selected),
        deferred_keys=tuple(assignment.key for assignment in plan.deferred),
        skipped_keys=tuple(assignment.key for assignment in plan.skipped),
        summary=summary,
        decision_events=tuple(events),
        selected_assignments=_restore_assignment_profiles(plan.selected),
        deferred_assignments=_restore_assignment_profiles(plan.deferred),
        skipped_assignments=_restore_assignment_profiles(plan.skipped),
    )


def _schedulable_profile(profile: Any) -> Any:
    metadata = getattr(profile, "brainstorm_metadata", None)
    if isinstance(metadata, dict):
        return profile
    if not _looks_like_agent_spec(profile):
        return profile
    key = str(getattr(profile, "key", "") or "").strip()
    surface = str(getattr(profile, "surface", "") or "").strip()
    vuln_class = str(getattr(profile, "vuln_class", "") or "").strip()
    code_patterns = tuple(str(item) for item in getattr(profile, "code_patterns", ()) or () if str(item))
    focus_globs = tuple(str(item) for item in getattr(profile, "focus_globs", ()) or () if str(item))
    original_metadata = getattr(profile, "metadata", None)
    original_metadata = dict(original_metadata) if isinstance(original_metadata, dict) else {}
    metadata = {
        **original_metadata,
        "agent_key": original_metadata.get("agent_key") or key,
        "surface": original_metadata.get("surface") or surface,
        "vuln_class": original_metadata.get("vuln_class") or vuln_class,
        "description": original_metadata.get("description") or f"{vuln_class}\n{surface}".strip(),
        "focus_files": original_metadata.get("focus_files") or list(focus_globs),
        "code_patterns": original_metadata.get("code_patterns") or list(code_patterns),
        **({"agent_metadata": original_metadata} if original_metadata else {}),
        "agent_spec": {
            "key": key,
            "vuln_class": vuln_class,
            "surface": surface,
            "focus_globs": list(focus_globs),
            "code_patterns": list(code_patterns),
            "program": str(getattr(profile, "program", "") or "").strip(),
            "created_at": str(getattr(profile, "created_at", "") or "").strip(),
            "snapshot_id": str(getattr(profile, "snapshot_id", "") or "").strip(),
        },
    }
    return _SchedulerProfileView(
        original=profile,
        key=key,
        display_name=vuln_class or key,
        description=f"{vuln_class}\n{surface}".strip(),
        focus_globs=focus_globs,
        brainstorm_metadata={key: value for key, value in metadata.items() if value not in ("", [], ())},
    )


def _looks_like_agent_spec(profile: Any) -> bool:
    return all(hasattr(profile, attr) for attr in ("key", "surface", "vuln_class", "focus_globs"))


def _original_profile(profile: Any) -> Any:
    return profile.original if isinstance(profile, _SchedulerProfileView) else profile


def _restore_assignment_profiles(assignments: tuple[AgentAssignment, ...]) -> tuple[AgentAssignment, ...]:
    restored: list[AgentAssignment] = []
    for assignment in assignments:
        original = _original_profile(assignment.profile)
        if original is assignment.profile:
            restored.append(assignment)
        else:
            restored.append(replace(assignment, profile=original))
    return tuple(restored)


__all__ = [
    "AgentWaveSize",
    "BaseTeamSchedulerOptions",
    "BaseTeamSchedulerResult",
    "schedule_profiles",
]
