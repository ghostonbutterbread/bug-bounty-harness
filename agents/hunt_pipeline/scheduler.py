from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Sequence

from agents.agent_scheduler import SchedulerConfig, assignments_from_profiles, decision_events, plan_agent_wave
from agents.hunt_pipeline.models import HypothesisAgentPacket, PipelineSchedulerPlan, ResolvedRuleset
from agents.hunt_pipeline.runtime_adapter import runtime_adapter_availability, runtime_handoff_boundary
from agents.hunt_pipeline.rulesets import hunting_policy_view


@dataclass(frozen=True, slots=True)
class _PacketProfile:
    key: str
    description: str
    sink_categories: tuple[str, ...] = ()
    focus_globs: tuple[str, ...] = ()
    ignore_globs: tuple[str, ...] = ()
    brainstorm_metadata: dict[str, Any] = field(default_factory=dict)


def plan_hypothesis_packets(
    packets: Sequence[HypothesisAgentPacket],
    *,
    ruleset: ResolvedRuleset,
    config: SchedulerConfig | None = None,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
) -> PipelineSchedulerPlan:
    scheduler_config = config or _scheduler_config_from_ruleset(ruleset)
    overrides: dict[str, Any] = {}
    if max_agents is not None:
        overrides["max_agents"] = max(0, int(max_agents))
    if concurrent_agents is not None:
        overrides["concurrent_agents"] = max(1, int(concurrent_agents))
    if overrides:
        scheduler_config = replace(scheduler_config, **overrides)
    profiles = [_profile_for_packet(packet, index=index) for index, packet in enumerate(packets)]
    plan = plan_agent_wave(
        assignments_from_profiles(profiles, source="hunt_pipeline", policy=hunting_policy_view(ruleset)),
        scheduler_config,
    )
    events = decision_events(plan, scheduler_wave_id="dry-run")
    by_id = {event.get("hypothesis_id"): event for event in events if event.get("hypothesis_id")}
    summary = plan.summary()
    summary["unrun"] = len(plan.deferred) + len(plan.skipped)
    return PipelineSchedulerPlan(
        mode=plan.mode,
        selected=tuple(_decision_dict(item, by_id) for item in plan.selected),
        deferred=tuple(_decision_dict(item, by_id) for item in plan.deferred),
        skipped=tuple(_decision_dict(item, by_id) for item in plan.skipped),
        selected_batches=_selected_batches(plan.selected, scheduler_config.concurrent_agents),
        summary=summary,
        config={
            "mode": scheduler_config.mode,
            "agent_wave_size": scheduler_config.agent_wave_size,
            "max_agents": scheduler_config.max_agents,
            "concurrent_agents": scheduler_config.concurrent_agents,
            "max_per_surface_family": scheduler_config.max_per_surface_family,
            "max_amplifier_family_first_wave": scheduler_config.max_amplifier_family_first_wave,
            "category_master_mode": scheduler_config.category_master_mode,
        },
    )


def _profile_for_packet(packet: HypothesisAgentPacket, *, index: int) -> _PacketProfile:
    metadata = dict(packet.scheduler_metadata)
    metadata.setdefault("hypothesis_id", packet.id)
    metadata.setdefault("brainstorm_agent_key", packet.key)
    metadata.setdefault("surface_family", packet.surface_family)
    metadata.setdefault("secondary_families", list(packet.secondary_families))
    metadata.setdefault("priority", packet.priority)
    metadata.setdefault("finding_role", packet.role)
    metadata.setdefault("brainstorm_tags", list(packet.tags))
    metadata["input_index"] = index
    return _PacketProfile(
        key=packet.key,
        description=packet.title,
        sink_categories=(packet.surface_family, packet.role, *packet.tags),
        focus_globs=tuple(packet.focus_files),
        brainstorm_metadata=metadata,
    )


def _scheduler_config_from_ruleset(ruleset: ResolvedRuleset) -> SchedulerConfig:
    guidance = ruleset.scheduler_guidance or {}
    wave_size = guidance.get("agent_wave_size", "all")
    if wave_size != "all":
        wave_size = int(wave_size)
    return SchedulerConfig(
        mode="policy-aware",
        agent_wave_size=wave_size,
        max_agents=_optional_int(guidance.get("max_agents")),
        concurrent_agents=_optional_positive_int(guidance.get("concurrent_agents")),
        max_per_surface_family=int(guidance.get("max_per_surface_family") or 2),
        max_amplifier_family_first_wave=int(guidance.get("max_amplifier_family_first_wave") or 3),
        category_master_mode=bool(guidance.get("category_master_mode", False)),
    )


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return max(0, int(value))


def _optional_positive_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return max(1, int(value))


def _selected_batches(selected: Sequence[Any], concurrent_agents: int | None) -> tuple[dict[str, Any], ...]:
    if not selected:
        return ()
    if concurrent_agents is None:
        return ()
    max_concurrent = max(1, int(concurrent_agents))
    batches: list[dict[str, Any]] = []
    for index, offset in enumerate(range(0, len(selected), max_concurrent), start=1):
        chunk = selected[offset : offset + max_concurrent]
        agents = [_batch_agent(item) for item in chunk]
        batches.append(
            {
                "batch_index": index,
                "max_concurrent": max_concurrent,
                "agent_keys": [agent["agent_key"] for agent in agents],
                "hypothesis_ids": [
                    hypothesis_id
                    for agent in agents
                    for hypothesis_id in agent.get("hypothesis_ids", ())
                ],
                "agents": agents,
            }
        )
    return tuple(batches)


def _batch_agent(item: Any) -> dict[str, Any]:
    member_hypothesis_ids = [
        str(hypothesis.get("hypothesis_id") or "").strip()
        for hypothesis in getattr(item, "assigned_hypotheses", ())
        if str(hypothesis.get("hypothesis_id") or "").strip()
    ]
    hypothesis_ids = member_hypothesis_ids or ([item.hypothesis_id] if item.hypothesis_id else [])
    record = {
        "agent_key": item.key,
        "hypothesis_ids": hypothesis_ids,
    }
    if member_hypothesis_ids:
        record["member_hypothesis_ids"] = member_hypothesis_ids
    return record


def _decision_dict(item: Any, events_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    event = events_by_id.get(item.hypothesis_id, {})
    member_hypothesis_ids = [
        str(hypothesis.get("hypothesis_id") or "").strip()
        for hypothesis in getattr(item, "assigned_hypotheses", ())
        if str(hypothesis.get("hypothesis_id") or "").strip()
    ]
    member_events = [events_by_id[hypothesis_id] for hypothesis_id in member_hypothesis_ids if hypothesis_id in events_by_id]
    is_category_master = item.hypothesis_id is None and len(member_hypothesis_ids) > 1
    if is_category_master and not event and member_events:
        event = {
            "event": "category_master_decision",
            "agent_key": item.key,
            "member_hypothesis_ids": member_hypothesis_ids,
            "member_events": member_events,
        }
    record = {
        "decision": item.decision,
        "reason": item.decision_reason,
        "agent_key": item.key,
        "hypothesis_id": item.hypothesis_id,
        "surface_family": item.surface_family,
        "family_role": item.family_role,
        "priority": item.priority,
        "final_score": item.final_score,
        "event": event,
    }
    if is_category_master:
        record["member_hypothesis_ids"] = member_hypothesis_ids
        record["member_events"] = member_events
    return record
