from __future__ import annotations

from agents.agent_scheduler import SchedulerConfig
from agents.hunt_pipeline.models import HypothesisAgentPacket
from agents.hunt_pipeline.rulesets import resolve_ruleset
from agents.hunt_pipeline.scheduler import plan_hypothesis_packets, runtime_adapter_availability


def _packet(packet_id: str, family: str, role: str = "entry") -> HypothesisAgentPacket:
    return HypothesisAgentPacket(
        id=packet_id,
        key=f"{family}-{packet_id.lower()}",
        title=f"{family} {packet_id}",
        role=role,  # type: ignore[arg-type]
        surface_family=family,
        priority="high" if role == "entry" else "medium",
        target_kind="electron",
        ruleset_id="electron-overlay",
        scheduler_metadata={
            "hypothesis_id": packet_id,
            "brainstorm_agent_key": f"{family}-{packet_id.lower()}",
            "surface_family": family,
            "priority": "high" if role == "entry" else "medium",
        },
    )


def test_scheduler_adapter_reuses_agent_scheduler_decisions_without_spawn() -> None:
    ruleset = resolve_ruleset("electron-overlay")
    packets = [
        _packet("HP-1", "ipc-bridge", "amplifier"),
        _packet("HP-2", "ipc-bridge", "amplifier"),
        _packet("HP-3", "ipc-bridge", "amplifier"),
        _packet("HP-4", "rendering-content-parser", "entry"),
    ]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(mode="policy-aware", agent_wave_size=2, max_per_surface_family=1, max_amplifier_family_first_wave=1),
    )

    assert plan.summary["selected"] == 2
    assert plan.summary["deferred"] == 2
    assert any(item["decision"] == "defer" and item["surface_family"] == "ipc-bridge" for item in plan.deferred)
    assert runtime_adapter_availability()["spawn_enabled"] is False
    assert runtime_adapter_availability()["ledger_writes_enabled"] is False
