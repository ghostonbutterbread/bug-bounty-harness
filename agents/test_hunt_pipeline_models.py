from __future__ import annotations

from agents.hunt_pipeline.models import HypothesisAgentPacket, NormalizedMapResult, PipelineDryRunArtifact, ResolvedRuleset


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
        static_team_handoffs={"enabled": False},
        dynamic_validation_queue={"enabled": False},
        safety={"dry_run_only": True},
    )

    rendered = artifact.to_dict()

    assert rendered["schema_version"] == 1
    assert rendered["normalized_map"]["counts"]["surfaces"] == 1
    assert rendered["normalized_map"]["legacy_policy_shaped"] is True
    assert rendered["hypotheses"][0]["id"] == "HP-1"
