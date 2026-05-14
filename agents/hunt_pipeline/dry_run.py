from __future__ import annotations

import hashlib
import json
import os
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
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
    write_hypotheses: bool = False,
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
    scheduler_plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        max_agents=max_agents,
        concurrent_agents=concurrent_agents,
    )
    scheduler_plan_payload = scheduler_plan.to_dict()
    decision_artifacts = _write_decision_artifacts(output_root, scheduler_plan_payload)
    scheduler_plan_payload["decision_artifacts"] = decision_artifacts
    hypotheses_payload = tuple(packet.to_dict() for packet in packets)
    artifact_metadata: dict[str, Any] = {}
    if write_hypotheses:
        artifact_metadata["hypotheses"] = _write_jsonl_artifact(output_root / "hypotheses.jsonl", list(hypotheses_payload))
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
        hypotheses=hypotheses_payload,
        artifact_metadata=artifact_metadata,
        scheduler_plan=scheduler_plan_payload,
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
    _write_json_artifact(plan_path, artifact.to_dict())
    return artifact, plan_path


def load_plan(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"pipeline plan must be a JSON object: {path}")
    return payload


def _write_decision_artifacts(output_root: Path, scheduler_plan: dict[str, Any]) -> dict[str, Any]:
    selected = [_decision_log_record(item, "selected") for item in scheduler_plan.get("selected", ())]
    deferred = [_decision_log_record(item, "deferred") for item in scheduler_plan.get("deferred", ())]
    skipped = [_decision_log_record(item, "skipped") for item in scheduler_plan.get("skipped", ())]
    unrun = [*deferred, *skipped]
    artifacts = {
        "selected_agents": _write_jsonl_artifact(output_root / "selected_agents.jsonl", selected),
        "deferred_agents": _write_jsonl_artifact(output_root / "deferred_agents.jsonl", deferred),
        "skipped_agents": _write_jsonl_artifact(output_root / "skipped_agents.jsonl", skipped),
        "unrun_agents": _write_jsonl_artifact(output_root / "unrun_agents.jsonl", unrun),
    }
    summary = scheduler_plan.setdefault("summary", {})
    summary["selected"] = artifacts["selected_agents"]["count"]
    summary["deferred"] = artifacts["deferred_agents"]["count"]
    summary["skipped"] = artifacts["skipped_agents"]["count"]
    summary["unrun"] = artifacts["unrun_agents"]["count"]
    return artifacts


def _decision_log_record(decision: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        **decision,
        "status": status,
        "reason": decision.get("reason") or decision.get("event", {}).get("decision_reason"),
    }


def _write_jsonl_artifact(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    _atomic_write_text(path, text)
    return {
        "path": str(path),
        "count": len(rows),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _write_json_artifact(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(path)
