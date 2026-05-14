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


def test_scheduler_max_agents_caps_selected_and_concurrent_batches() -> None:
    ruleset = resolve_ruleset("desktop-baseline")
    packets = [
        _packet("HP-1", "rendering-content-parser", "entry"),
        _packet("HP-2", "file-ingestion-import", "entry"),
        _packet("HP-3", "navigation-popup", "entry"),
        _packet("HP-4", "auth-session-callback", "entry"),
        _packet("HP-5", "storage-cache-state", "entry"),
    ]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(
            mode="policy-aware",
            agent_wave_size="all",
            max_agents=3,
            concurrent_agents=2,
            max_per_surface_family=10,
            max_amplifier_family_first_wave=10,
        ),
    )

    assert plan.summary["selected"] == 3
    assert plan.summary["deferred"] == 2
    assert plan.summary["unrun"] == 2
    assert plan.config["max_agents"] == 3
    assert plan.config["concurrent_agents"] == 2
    assert {item["reason"] for item in plan.deferred} == {"max agents cap reached"}
    assert [batch["batch_index"] for batch in plan.selected_batches] == [1, 2]
    assert [batch["max_concurrent"] for batch in plan.selected_batches] == [2, 2]
    assert plan.selected_batches[0]["agent_keys"] == [item["agent_key"] for item in plan.selected[:2]]
    assert plan.selected_batches[1]["agent_keys"] == [plan.selected[2]["agent_key"]]
    assert plan.selected_batches[0]["hypothesis_ids"] == [item["hypothesis_id"] for item in plan.selected[:2]]


def test_category_master_mode_preserves_member_hypothesis_events() -> None:
    ruleset = resolve_ruleset("electron-overlay")
    packets = [
        _packet("HP-1", "rendering-content-parser", "entry"),
        _packet("HP-2", "rendering-content-parser", "entry"),
    ]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(mode="policy-aware", agent_wave_size="all", category_master_mode=True),
    )

    assert plan.summary["selected"] == 1
    selected = plan.selected[0]
    assert selected["agent_key"] == "rendering-content-parser-master"
    assert selected["hypothesis_id"] is None
    assert selected["member_hypothesis_ids"] == ["HP-1", "HP-2"]
    assert [event["hypothesis_id"] for event in selected["member_events"]] == ["HP-1", "HP-2"]
    assert selected["event"]["member_hypothesis_ids"] == ["HP-1", "HP-2"]
    assert [event["event"] for event in selected["event"]["member_events"]] == ["agent_selected", "agent_selected"]


def test_non_master_decision_does_not_emit_member_fields() -> None:
    ruleset = resolve_ruleset("desktop-baseline")
    packets = [_packet("HP-1", "file-ingestion-import", "entry")]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(mode="policy-aware", agent_wave_size="all", category_master_mode=False),
    )

    selected = plan.selected[0]
    assert selected["hypothesis_id"] == "HP-1"
    assert "member_hypothesis_ids" not in selected
    assert "member_events" not in selected


def test_notes_only_packet_role_overrides_application_entry_family_role() -> None:
    ruleset = resolve_ruleset("desktop-baseline")
    packets = [_packet("HP-1", "file-ingestion-import", "notes_only")]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(mode="policy-aware", agent_wave_size="all"),
    )

    selected = plan.selected[0]
    assert selected["surface_family"] == "file-ingestion-import"
    assert selected["family_role"] == "notes_only"
    assert selected["event"]["family_role"] == "notes_only"
    assert "application-entry family" not in selected["reason"]


def test_entry_packet_role_overrides_amplifier_family_role() -> None:
    ruleset = resolve_ruleset("electron-overlay")
    packets = [_packet("HP-1", "ipc-bridge", "entry")]

    plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        config=SchedulerConfig(mode="policy-aware", agent_wave_size="all"),
    )

    selected = plan.selected[0]
    assert selected["surface_family"] == "ipc-bridge"
    assert selected["family_role"] == "application-entry"
    assert selected["event"]["family_role"] == "application-entry"
    assert "application-entry family" in selected["reason"]
