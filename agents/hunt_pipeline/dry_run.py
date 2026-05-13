from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.app_mapper import map_application, write_artifacts
from agents.hunt_pipeline.appmap_loader import load_appmap_run
from agents.hunt_pipeline.hypothesis_builder import build_hypothesis_packets
from agents.hunt_pipeline.models import PipelineDryRunArtifact
from agents.hunt_pipeline.rulesets import resolve_ruleset
from agents.hunt_pipeline.scheduler import plan_hypothesis_packets, runtime_adapter_availability, runtime_handoff_boundary
from agents.hunt_pipeline.target_classifier import classify_target_kind
from agents.hunting_policy import disabled_policy

SCHEMA_VERSION = 1


def build_dry_run_plan(
    *,
    program: str,
    target_path: str | Path,
    target_kind: str | None = "auto",
    ruleset_id: str | None = "auto",
    appmap_run: str | Path | None = None,
    output_dir: str | Path,
    run_id: str = "pipeline-dry-run",
    max_hypotheses: int | None = None,
) -> tuple[PipelineDryRunArtifact, Path]:
    output_root = Path(output_dir).expanduser().resolve(strict=False)
    output_root.mkdir(parents=True, exist_ok=True)
    target = Path(target_path).expanduser().resolve(strict=False)

    if appmap_run is None:
        map_result = map_application(program, target, target_kind=target_kind or "auto")
        paths = write_artifacts(
            map_result,
            output_root=output_root,
            run_id=run_id,
            write_specs=False,
            hunting_policy=disabled_policy(),
            agent_granularity="category-master",
        )
        appmap_root = paths["run_root"]
        appmap_source = {"mode": "generated-neutral", "run_root": str(appmap_root)}
    else:
        appmap_root = Path(appmap_run).expanduser().resolve(strict=False)
        appmap_source = {"mode": "loaded-existing", "run_root": str(appmap_root)}

    normalized = load_appmap_run(appmap_root)
    resolved_target_kind = classify_target_kind(
        target,
        requested_kind=target_kind,
        appmap_profile=normalized.target_profile,
    )
    ruleset = resolve_ruleset(ruleset_id, target_kind=resolved_target_kind, target_path=target)
    packets = build_hypothesis_packets(
        normalized,
        ruleset,
        target_kind=resolved_target_kind,
        max_packets=max_hypotheses,
    )
    scheduler_plan = plan_hypothesis_packets(packets, ruleset=ruleset)
    artifact = PipelineDryRunArtifact(
        schema_version=SCHEMA_VERSION,
        program=str(program),
        target_path=str(target),
        target_kind=resolved_target_kind,
        selected_rulesets=ruleset.to_dict(),
        appmap_source={
            **appmap_source,
            "preferred_neutral_artifacts": ["surfaces.jsonl", "flows.jsonl"],
            "legacy_compatibility_artifacts": ["candidates.jsonl", "rejected_candidates.jsonl"],
        },
        normalized_map=normalized.to_dict(),
        hypotheses=tuple(packet.to_dict() for packet in packets),
        scheduler_plan=scheduler_plan.to_dict(),
        runtime_adapter_availability=runtime_adapter_availability(),
        runtime_handoff_boundary=runtime_handoff_boundary(),
        static_team_handoffs={
            "enabled": False,
            "planned": [],
            "placeholder": "static team handoffs are not invoked in the dry-run slice",
        },
        dynamic_validation_queue={
            "enabled": False,
            "queued": [],
            "placeholder": "dynamic validation is not invoked in the dry-run slice",
        },
        safety={
            "dry_run_only": True,
            "spawn_agents": False,
            "live_dynamic_validation": False,
            "ledger_writes": False,
        },
    )
    plan_path = output_root / "pipeline_plan.json"
    plan_path.write_text(json.dumps(artifact.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact, plan_path


def load_plan(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"pipeline plan must be a JSON object: {path}")
    return payload
