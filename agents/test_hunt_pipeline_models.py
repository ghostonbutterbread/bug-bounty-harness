from __future__ import annotations

from agents.hunt_pipeline.models import (
    CategoryPack,
    CategoryPackPlan,
    HypothesisAgentPacket,
    NormalizedMapResult,
    PipelineDryRunArtifact,
    ResolvedRuleset,
)


def test_hunt_pipeline_models_render_schema_friendly_dicts() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=({"id": "S0001"},),
        flows=({"id": "F0001"},),
        legacy_candidates=({"id": "C0001"},),
        legacy_policy_shaped=True,
    )
    ruleset = ResolvedRuleset(
        id="desktop-baseline",
        version=1,
        requested_id="auto",
        base_id="desktop-baseline",
        selected_rulesets=("desktop-baseline",),
    )
    packet = HypothesisAgentPacket(
        id="HP-1",
        key="file-ingestion-import-s0001",
        title="Investigate file surface",
        role="entry",
        surface_family="file-ingestion-import",
        priority="high",
        target_kind="desktop",
        ruleset_id=ruleset.id,
    )
    artifact = PipelineDryRunArtifact(
        schema_version=1,
        run_id="hunt-20260514T000000Z-model",
        program="demo",
        target_path="/tmp/demo",
        target_kind="desktop",
        selected_rulesets=ruleset.to_dict(),
        appmap_source={"mode": "loaded-existing"},
        normalized_map=normalized.to_dict(),
        hypotheses=(packet.to_dict(),),
        artifact_metadata={},
        scheduler_plan={"selected": []},
        runtime_adapter_availability={"spawn_enabled": False},
        runtime_handoff_boundary={"status": "explicit-non-live-boundary"},
        runtime_handoff_contract={"schema_version": 1, "status": "blocked", "promotion_allowed": False},
        runtime_promotion_protocol={"schema_version": 1, "status": "draft", "promotion_enabled": False},
        static_team_handoffs={"enabled": False},
        dynamic_validation_queue={"enabled": False},
        safety={"dry_run_only": True},
        live_testing_playbook={"status": "planned-only"},
        runtime_environment_approval={"status": "approval_required"},
        runtime_action_policy={"status": "active"},
    )

    rendered = artifact.to_dict()

    assert rendered["schema_version"] == 1
    assert rendered["run_id"] == "hunt-20260514T000000Z-model"
    assert rendered["normalized_map"]["counts"]["surfaces"] == 1
    assert rendered["normalized_map"]["legacy_policy_shaped"] is True
    assert rendered["hypotheses"][0]["id"] == "HP-1"
    assert rendered["live_testing_playbook"]["status"] == "planned-only"
    assert rendered["runtime_environment_approval"]["status"] == "approval_required"
    assert rendered["runtime_action_policy"]["status"] == "active"


def test_category_pack_models_render_schema_friendly_dicts() -> None:
    pack = CategoryPack(
        pack_id="ipc.family-ipc-bridge.ipc-filesystem.src-main-ipc-ts.pack001",
        vuln_class="ipc",
        subclass="ipc-filesystem",
        surface_family="ipc-bridge",
        context_cluster_id="src/main/ipc.ts",
        source_files=("src/main/ipc.ts",),
        route_or_endpoint_keys=("dialog:openProject",),
        sink_types=("filesystem",),
        entry_paths=("renderer-ipc",),
        policy_id="electron-policy",
        hypothesis_ids=("HP-1", "HP-2"),
        evidence_ids=("S0001", "S0002"),
        priority_score=35.0,
        reason="Packed same-file Electron IPC hypotheses",
        expected_outputs=("per-hypothesis verdicts",),
        specialist_followup_allowed=True,
    )
    plan = CategoryPackPlan(
        packs=(pack,),
        hypothesis_to_pack_id={"HP-1": pack.pack_id, "HP-2": pack.pack_id},
        pack_to_hypothesis_ids={pack.pack_id: ("HP-1", "HP-2")},
        mode="auto",
        max_pack_size=10,
    )

    rendered = plan.to_dict()

    assert rendered["packs"][0]["pack_id"] == pack.pack_id
    assert rendered["packs"][0]["subclass"] == "ipc-filesystem"
    assert rendered["hypothesis_to_pack_id"]["HP-1"] == pack.pack_id
    assert rendered["pack_to_hypothesis_ids"][pack.pack_id] == ("HP-1", "HP-2")
    assert rendered["max_pack_size"] == 10
