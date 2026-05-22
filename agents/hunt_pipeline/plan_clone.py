from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.hunt_pipeline.dry_run import (
    _amplifier_hypotheses,
    _chain_activation_index,
    _write_amplifier_report_artifact,
    _write_json_artifact_with_metadata,
    _write_jsonl_artifact,
)
from agents.hunt_pipeline.live_testing import build_live_testing_playbook
from agents.hunt_pipeline.models import PipelineDryRunArtifact
from agents.hunt_pipeline.operator_approval_schema import build_runtime_operator_approval_schema
from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report
from agents.hunt_pipeline.promotion_readiness import build_runtime_promotion_readiness_checklist, non_live_readiness_stub
from agents.hunt_pipeline.promotion_request_packet import build_runtime_promotion_request_packet
from agents.hunt_pipeline.run_state import CONTROL_FILENAME, RUN_STATE_FILENAME, load_pipeline_plan, validate_run_id
from agents.hunt_pipeline.runtime_action_policy import build_runtime_action_policy
from agents.hunt_pipeline.runtime_contract import build_runtime_handoff_contract, build_runtime_promotion_protocol
from agents.hunt_pipeline.runtime_environment_approval import build_runtime_environment_approval


def clone_pipeline_plan(
    source_plan_path: str | Path,
    *,
    output_dir: str | Path,
    run_id: str,
    sample_agents: int,
    concurrent_agents: int | None = None,
    force: bool = False,
) -> tuple[PipelineDryRunArtifact, Path]:
    """Clone an existing plan into a fresh, state-safe sample run.

    The clone keeps the original hypothesis corpus, rewrites scheduler decision
    artifacts into the new output directory, selects only the requested sample
    size, and rebuilds plan-scoped runtime policy artifacts for the new
    pipeline_plan.json path. It intentionally does not copy run_state/control
    files from the source run.
    """

    source_path = Path(source_plan_path).expanduser().resolve(strict=False)
    source = load_pipeline_plan(source_path)
    output_root = Path(output_dir).expanduser().resolve(strict=False)
    if output_root.exists() and not force and any(output_root.iterdir()):
        raise FileExistsError(f"output directory is not empty; use --force to overwrite clone artifacts: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    _remove_stale_runtime_state(output_root)

    resolved_run_id = validate_run_id(run_id)
    selected, deferred, skipped = _sample_scheduler_records(source, sample_agents=sample_agents)
    scheduler_plan = _scheduler_plan_for_clone(
        source,
        selected=selected,
        deferred=deferred,
        skipped=skipped,
        concurrent_agents=concurrent_agents,
        sample_agents=sample_agents,
    )
    scheduler_plan["decision_artifacts"] = _write_decision_artifacts(output_root, selected, deferred, skipped)
    hypotheses = tuple(dict(item) for item in source.get("hypotheses") or () if isinstance(item, Mapping))
    artifact_metadata = _artifact_metadata_for_clone(
        source,
        output_root=output_root,
        run_id=resolved_run_id,
        hypotheses=hypotheses,
        source_plan_path=source_path,
    )

    plan_path = output_root / "pipeline_plan.json"
    base_plan = {
        **source,
        "run_id": resolved_run_id,
        "artifact_metadata": artifact_metadata,
        "scheduler_plan": scheduler_plan,
    }
    base_plan.pop("runtime_promotion_decision", None)

    regenerated = _regenerate_scoped_runtime_artifacts(base_plan, plan_path)
    artifact = PipelineDryRunArtifact(
        schema_version=int(regenerated.get("schema_version") or source.get("schema_version") or 1),
        run_id=resolved_run_id,
        program=str(regenerated.get("program") or ""),
        target_path=str(regenerated.get("target_path") or ""),
        target_kind=str(regenerated.get("target_kind") or ""),
        selected_rulesets=dict(regenerated.get("selected_rulesets") or {}),
        appmap_source=dict(regenerated.get("appmap_source") or {}),
        normalized_map=dict(regenerated.get("normalized_map") or {}),
        hypotheses=hypotheses,
        artifact_metadata=artifact_metadata,
        scheduler_plan=scheduler_plan,
        runtime_adapter_availability=dict(regenerated.get("runtime_adapter_availability") or {}),
        runtime_handoff_boundary=dict(regenerated.get("runtime_handoff_boundary") or {}),
        runtime_handoff_contract=dict(regenerated.get("runtime_handoff_contract") or {}),
        runtime_promotion_protocol=dict(regenerated.get("runtime_promotion_protocol") or {}),
        static_team_handoffs=dict(regenerated.get("static_team_handoffs") or {}),
        dynamic_validation_queue=dict(regenerated.get("dynamic_validation_queue") or {}),
        safety=dict(regenerated.get("safety") or {}),
        live_testing_playbook=dict(regenerated.get("live_testing_playbook") or {}),
        runtime_environment_approval=dict(regenerated.get("runtime_environment_approval") or {}),
        runtime_action_policy=dict(regenerated.get("runtime_action_policy") or {}),
        runtime_promotion_readiness=dict(regenerated.get("runtime_promotion_readiness") or {}),
        runtime_operator_approval_schema=dict(regenerated.get("runtime_operator_approval_schema") or {}),
        runtime_promotion_request_packet=dict(regenerated.get("runtime_promotion_request_packet") or {}),
    )
    _atomic_write_json(plan_path, artifact.to_dict())
    return artifact, plan_path


def _sample_scheduler_records(
    plan: Mapping[str, Any],
    *,
    sample_agents: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if sample_agents < 0:
        raise ValueError("sample_agents must be non-negative")
    selected_source = _scheduler_records(plan, "selected")
    deferred_source = _scheduler_records(plan, "deferred")
    skipped = _scheduler_records(plan, "skipped")
    runnable = [*selected_source, *deferred_source]
    selected = [dict(item) for item in runnable[:sample_agents]]
    deferred = [dict(item) for item in runnable[sample_agents:]]
    return selected, deferred, skipped


def _scheduler_plan_for_clone(
    source: Mapping[str, Any],
    *,
    selected: Sequence[Mapping[str, Any]],
    deferred: Sequence[Mapping[str, Any]],
    skipped: Sequence[Mapping[str, Any]],
    concurrent_agents: int | None,
    sample_agents: int,
) -> dict[str, Any]:
    original = source.get("scheduler_plan") if isinstance(source.get("scheduler_plan"), Mapping) else {}
    config = dict(original.get("config") if isinstance(original.get("config"), Mapping) else {})
    if concurrent_agents is not None:
        config["concurrent_agents"] = max(1, int(concurrent_agents))
    selected_limit = max(0, int(sample_agents))
    config["max_agents"] = selected_limit
    batches = _selected_batches(selected, int(config.get("concurrent_agents") or 1))
    summary = dict(original.get("summary") if isinstance(original.get("summary"), Mapping) else {})
    summary.update(
        {
            "selected": len(selected),
            "deferred": len(deferred),
            "skipped": len(skipped),
            "unrun": len(deferred) + len(skipped),
        }
    )
    return {
        **dict(original),
        "selected": [dict(item) for item in selected],
        "deferred": [dict(item) for item in deferred],
        "skipped": [dict(item) for item in skipped],
        "selected_batches": batches,
        "summary": summary,
        "config": config,
    }


def _artifact_metadata_for_clone(
    source: Mapping[str, Any],
    *,
    output_root: Path,
    run_id: str,
    hypotheses: tuple[dict[str, Any], ...],
    source_plan_path: Path,
) -> dict[str, Any]:
    created_at = _timestamp_iso()
    metadata = dict(source.get("artifact_metadata") if isinstance(source.get("artifact_metadata"), Mapping) else {})
    metadata["run"] = {
        **dict(metadata.get("run") if isinstance(metadata.get("run"), Mapping) else {}),
        "run_id": run_id,
        "created_at": created_at,
        "output_dir": str(output_root),
        "cloned_from_pipeline_plan": str(source_plan_path),
    }
    metadata["hypotheses"] = _write_jsonl_artifact(output_root / "hypotheses.jsonl", list(hypotheses))
    amplifier_rows = _amplifier_hypotheses(hypotheses)
    metadata["amplifier_hypotheses"] = _write_jsonl_artifact(output_root / "amplifier_hypotheses.jsonl", amplifier_rows)
    metadata["chain_activation_index"] = _write_json_artifact_with_metadata(
        output_root / "chain_activation_index.json",
        _chain_activation_index(hypotheses, amplifier_rows),
    )
    metadata["amplifier_report"] = _write_amplifier_report_artifact(
        output_root / "reports" / "findings" / "amplifier.md",
        amplifier_rows,
        program=str(source.get("program") or ""),
        target_kind=str(source.get("target_kind") or ""),
        run_id=run_id,
    )
    if isinstance(metadata.get("appmap"), Mapping):
        metadata["appmap"] = dict(metadata["appmap"])
    return metadata


def _regenerate_scoped_runtime_artifacts(plan: dict[str, Any], plan_path: Path) -> dict[str, Any]:
    regenerated = dict(plan)
    regenerated["runtime_environment_approval"] = build_runtime_environment_approval(plan_path, plan=regenerated).to_dict()
    regenerated["runtime_action_policy"] = build_runtime_action_policy(plan_path, plan=regenerated).to_dict()
    regenerated["runtime_promotion_protocol"] = build_runtime_promotion_protocol().to_dict()
    regenerated.setdefault("runtime_promotion_readiness", non_live_readiness_stub())
    regenerated.setdefault(
        "live_testing_playbook",
        build_live_testing_playbook(
            target_kind=str(regenerated.get("target_kind") or "auto"),
            ruleset_id=str((regenerated.get("selected_rulesets") or {}).get("id") or "auto"),
        ).to_dict(),
    )
    regenerated["runtime_handoff_contract"] = build_runtime_handoff_contract(
        {**regenerated, "runtime_handoff_contract": {"schema_version": 1}}
    ).to_dict()
    status_summary = {
        "selected": len(regenerated.get("scheduler_plan", {}).get("selected") or ()),
        "completed": 0,
        "failed": 0,
        "running": 0,
        "deferred": len(regenerated.get("scheduler_plan", {}).get("deferred") or ()),
        "stopped_requested": False,
        "pause_requested": False,
    }
    regenerated["runtime_preflight_report"] = build_runtime_preflight_report(plan_path, plan=regenerated)
    regenerated["runtime_promotion_readiness"] = build_runtime_promotion_readiness_checklist(
        plan_path,
        plan=regenerated,
        status_summary=status_summary,
    ).to_dict()
    regenerated["runtime_operator_approval_schema"] = build_runtime_operator_approval_schema(
        plan_path,
        plan=regenerated,
    ).to_dict()
    regenerated["runtime_promotion_request_packet"] = build_runtime_promotion_request_packet(
        plan_path,
        plan=regenerated,
        status_summary=status_summary,
    ).to_dict()
    regenerated["runtime_handoff_contract"] = build_runtime_handoff_contract(
        {**regenerated, "runtime_handoff_contract": {"schema_version": 1}}
    ).to_dict()
    return regenerated


def _write_decision_artifacts(
    output_root: Path,
    selected: Sequence[Mapping[str, Any]],
    deferred: Sequence[Mapping[str, Any]],
    skipped: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    selected_rows = [_decision_log_record(item, "selected") for item in selected]
    deferred_rows = [_decision_log_record(item, "deferred") for item in deferred]
    skipped_rows = [_decision_log_record(item, "skipped") for item in skipped]
    return {
        "selected_agents": _write_jsonl_artifact(output_root / "selected_agents.jsonl", selected_rows),
        "deferred_agents": _write_jsonl_artifact(output_root / "deferred_agents.jsonl", deferred_rows),
        "skipped_agents": _write_jsonl_artifact(output_root / "skipped_agents.jsonl", skipped_rows),
        "unrun_agents": _write_jsonl_artifact(output_root / "unrun_agents.jsonl", [*deferred_rows, *skipped_rows]),
    }


def _scheduler_records(plan: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    scheduler_plan = plan.get("scheduler_plan") if isinstance(plan.get("scheduler_plan"), Mapping) else {}
    inline = scheduler_plan.get(key)
    if isinstance(inline, Sequence) and not isinstance(inline, (str, bytes)):
        return [dict(item) for item in inline if isinstance(item, Mapping)]
    artifacts = scheduler_plan.get("decision_artifacts") if isinstance(scheduler_plan.get("decision_artifacts"), Mapping) else {}
    artifact = artifacts.get(f"{key}_agents") if isinstance(artifacts.get(f"{key}_agents"), Mapping) else {}
    path = str(artifact.get("path") or "").strip()
    return _read_jsonl(Path(path)) if path else []


def _selected_batches(selected: Sequence[Mapping[str, Any]], concurrent_agents: int) -> list[dict[str, Any]]:
    if not selected:
        return []
    max_concurrent = max(1, int(concurrent_agents))
    batches: list[dict[str, Any]] = []
    for index, offset in enumerate(range(0, len(selected), max_concurrent), start=1):
        chunk = selected[offset : offset + max_concurrent]
        agents = [_batch_agent(item) for item in chunk]
        batches.append(
            {
                "batch_index": index,
                "max_concurrent": max_concurrent,
                "agent_keys": [item["agent_key"] for item in agents],
                "hypothesis_ids": [hypothesis_id for item in agents for hypothesis_id in item.get("hypothesis_ids", ())],
                "agents": agents,
            }
        )
    return batches


def _batch_agent(record: Mapping[str, Any]) -> dict[str, Any]:
    hypothesis_ids = _hypothesis_ids(record)
    payload = {
        "agent_key": str(record.get("agent_key") or "").strip(),
        "hypothesis_ids": hypothesis_ids,
    }
    if record.get("member_hypothesis_ids"):
        payload["member_hypothesis_ids"] = [str(item) for item in record.get("member_hypothesis_ids") or ()]
    return payload


def _hypothesis_ids(record: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    hypothesis_id = str(record.get("hypothesis_id") or "").strip()
    if hypothesis_id:
        values.append(hypothesis_id)
    for item in record.get("member_hypothesis_ids") or ():
        cleaned = str(item).strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return values


def _decision_log_record(decision: Mapping[str, Any], status: str) -> dict[str, Any]:
    return {
        **dict(decision),
        "status": status,
        "reason": decision.get("reason") or (decision.get("event") if isinstance(decision.get("event"), Mapping) else {}).get("decision_reason"),
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _remove_stale_runtime_state(output_root: Path) -> None:
    for name in (RUN_STATE_FILENAME, CONTROL_FILENAME):
        try:
            (output_root / name).unlink()
        except FileNotFoundError:
            pass


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
