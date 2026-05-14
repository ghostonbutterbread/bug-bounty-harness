from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import fcntl

from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report
from agents.hunt_pipeline.operator_approval_schema import build_runtime_operator_approval_schema
from agents.hunt_pipeline.promotion_readiness import build_runtime_promotion_readiness_checklist
from agents.hunt_pipeline.runtime_contract import evaluate_runtime_handoff_contract, evaluate_runtime_promotion_protocol

RUN_STATE_SCHEMA_VERSION = 1
RUN_STATE_FILENAME = "run_state.json"
PLAN_FILENAME = "pipeline_plan.json"

RUNNABLE_STATUSES = {"selected", "deferred"}
TERMINAL_STATUSES = {"completed", "failed", "skipped"}


def resolve_pipeline_plan_path(*, output_dir: str | Path | None = None, pipeline_plan: str | Path | None = None) -> Path:
    if pipeline_plan is not None:
        path = Path(pipeline_plan).expanduser().resolve(strict=False)
        if path.is_dir():
            return path / PLAN_FILENAME
        return path
    if output_dir is None:
        raise ValueError("either output_dir or pipeline_plan is required")
    return Path(output_dir).expanduser().resolve(strict=False) / PLAN_FILENAME


def load_pipeline_plan(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"pipeline plan must be a JSON object: {path}")
    return payload


def run_state_path_for_plan(plan_path: str | Path) -> Path:
    return Path(plan_path).expanduser().resolve(strict=False).parent / RUN_STATE_FILENAME


def load_run_state(path: str | Path) -> dict[str, Any]:
    state_path = Path(path)
    if not state_path.exists():
        return {}
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"run state must be a JSON object: {path}")
    return payload


def initialize_run_state(plan_path: str | Path, plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    plan_payload = dict(plan or load_pipeline_plan(resolved_plan_path))
    existing = load_run_state(run_state_path_for_plan(resolved_plan_path))
    agents = _merge_agent_records(plan_payload, existing.get("agents") if isinstance(existing.get("agents"), dict) else {})
    return {
        "schema_version": RUN_STATE_SCHEMA_VERSION,
        "run_id": str(plan_payload.get("appmap_source", {}).get("run_root") or plan_payload.get("program") or "hunt-pipeline"),
        "pipeline_plan": str(resolved_plan_path),
        "pause_requested": bool(existing.get("pause_requested", False)),
        "stopped": bool(existing.get("stopped", False)),
        "updated_at": _timestamp_iso(),
        "agents": agents,
        "last_wave": existing.get("last_wave") if isinstance(existing.get("last_wave"), dict) else {},
    }


def save_run_state(state: Mapping[str, Any], path: str | Path) -> Path:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(state)
    payload["updated_at"] = _timestamp_iso()
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tmp_path = state_path.with_name(f".{state_path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(state_path)
    return state_path


@contextmanager
def pipeline_runtime_lock(plan_path: str | Path) -> Iterator[None]:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    state_path = run_state_path_for_plan(resolved_plan_path)
    lock_path = state_path.parent / ".hunt_pipeline_runtime.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def request_pause(plan_path: str | Path) -> dict[str, Any]:
    with pipeline_runtime_lock(plan_path):
        state = initialize_run_state(plan_path)
        state["pause_requested"] = True
        save_run_state(state, run_state_path_for_plan(plan_path))
        return state


def request_stop(plan_path: str | Path) -> dict[str, Any]:
    with pipeline_runtime_lock(plan_path):
        state = initialize_run_state(plan_path)
        state["stopped"] = True
        save_run_state(state, run_state_path_for_plan(plan_path))
        return state


def clear_pause(plan_path: str | Path) -> dict[str, Any]:
    """Clear a previously requested pause while preserving all agent state."""

    with pipeline_runtime_lock(plan_path):
        state = initialize_run_state(plan_path)
        state["pause_requested"] = False
        save_run_state(state, run_state_path_for_plan(plan_path))
        return state


def summarize_run(plan_path: str | Path, *, max_agents: int | None = None, concurrent_agents: int | None = None) -> dict[str, Any]:
    plan = load_pipeline_plan(plan_path)
    state = initialize_run_state(plan_path, plan)
    agents = _agent_list(state)
    counts = {
        "total": len(agents),
        "selected": _count_status(agents, "selected"),
        "completed": _count_status(agents, "completed"),
        "running": _count_status(agents, "running"),
        "failed": _count_status(agents, "failed"),
        "paused": _count_status(agents, "paused"),
        "stopped": _count_status(agents, "stopped"),
        "deferred": _count_status(agents, "deferred"),
        "skipped": _count_status(agents, "skipped"),
    }
    counts["unrun"] = sum(1 for item in agents if item.get("status") in RUNNABLE_STATUSES)
    next_wave = next_wave_records(plan, state, max_agents=max_agents, concurrent_agents=concurrent_agents)
    status_snapshot = {
        **counts,
        "pause_requested": bool(state.get("pause_requested", False)),
        "stopped_requested": bool(state.get("stopped", False)),
        "next_wave_count": len(next_wave),
    }
    return {
        **counts,
        "pause_requested": bool(state.get("pause_requested", False)),
        "stopped_requested": bool(state.get("stopped", False)),
        "next_wave_count": len(next_wave),
        "next_wave_agent_keys": [item["agent_key"] for item in next_wave],
        "runtime_handoff_contract": evaluate_runtime_handoff_contract(plan),
        "runtime_promotion_protocol": evaluate_runtime_promotion_protocol(plan),
        "runtime_preflight_report": build_runtime_preflight_report(plan_path, plan=plan),
        "runtime_promotion_readiness": build_runtime_promotion_readiness_checklist(
            plan_path,
            plan=plan,
            status_summary=status_snapshot,
        ).to_dict(),
        "runtime_operator_approval_schema": build_runtime_operator_approval_schema(plan_path, plan=plan).to_dict(),
        "pipeline_plan": str(Path(plan_path).expanduser().resolve(strict=False)),
        "run_state": str(run_state_path_for_plan(plan_path)),
    }


def next_wave_records(
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
    *,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
) -> list[dict[str, Any]]:
    if state.get("pause_requested") or state.get("stopped"):
        return []
    agents_by_key = state.get("agents") if isinstance(state.get("agents"), dict) else {}
    selected_pending = [
        record
        for record in _ordered_selected_records(plan)
        if _state_status(agents_by_key, record["agent_key"]) == "selected"
    ]
    candidates = selected_pending or [
        record
        for record in _ordered_unrun_records(plan)
        if _state_status(agents_by_key, record["agent_key"]) == "deferred"
    ]
    if not candidates:
        return []
    limit = _wave_limit(plan, max_agents=max_agents, concurrent_agents=concurrent_agents)
    return candidates[:limit]




def recover_running_agents(state: Mapping[str, Any]) -> dict[str, Any]:
    """Treat persisted running records as stale after the runtime lock is acquired."""

    updated = dict(state)
    agents = dict(updated.get("agents") or {})
    for key, value in list(agents.items()):
        if not isinstance(value, dict) or value.get("status") != "running":
            continue
        recovered = dict(value)
        recovered["status"] = _recovered_runnable_status(value)
        recovered["updated_at"] = _timestamp_iso()
        recovered["recovered_from_running"] = True
        agents[key] = recovered
    updated["agents"] = agents
    return updated


def update_agent_statuses(
    state: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    *,
    status: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    updated = dict(state)
    agents = dict(updated.get("agents") or {})
    for record in records:
        key = str(record.get("agent_key") or "").strip()
        if not key:
            continue
        current = dict(agents.get(key) or _agent_state_record(record, str(record.get("status") or "selected")))
        current["status"] = status
        current["updated_at"] = _timestamp_iso()
        if details:
            current["details"] = dict(details)
        agents[key] = current
    updated["agents"] = agents
    return updated


def _recovered_runnable_status(record: Mapping[str, Any]) -> str:
    decision = record.get("decision") if isinstance(record.get("decision"), Mapping) else {}
    if str(decision.get("decision") or "").strip() == "defer":
        return "deferred"
    if str(record.get("reason") or "").strip() == "max agents cap reached":
        return "deferred"
    return "selected"


def _merge_agent_records(plan: Mapping[str, Any], existing_agents: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for status, record in _plan_agent_records(plan):
        key = record["agent_key"]
        current = existing_agents.get(key) if isinstance(existing_agents, Mapping) else None
        if isinstance(current, dict):
            merged[key] = {**_agent_state_record(record, status), **current}
        else:
            merged[key] = _agent_state_record(record, status)
    return merged


def _plan_agent_records(plan: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    records: list[tuple[str, dict[str, Any]]] = []
    for status, key, artifact_key in (
        ("selected", "selected", "selected_agents"),
        ("deferred", "deferred", "deferred_agents"),
        ("skipped", "skipped", "skipped_agents"),
    ):
        for item in _scheduler_items(plan, key, artifact_key):
            records.append((status, _runtime_record(item, status)))
    return records


def _runtime_record(decision: Mapping[str, Any], status: str) -> dict[str, Any]:
    agent_key = str(decision.get("agent_key") or "").strip()
    hypothesis_ids = _hypothesis_ids(decision)
    return {
        "agent_key": agent_key,
        "hypothesis_id": str(decision.get("hypothesis_id") or "").strip(),
        "hypothesis_ids": hypothesis_ids,
        "status": status,
        "decision": dict(decision),
        "reason": decision.get("reason"),
    }


def _agent_state_record(record: Mapping[str, Any], status: str) -> dict[str, Any]:
    return {
        "agent_key": str(record.get("agent_key") or "").strip(),
        "hypothesis_id": str(record.get("hypothesis_id") or "").strip(),
        "hypothesis_ids": list(record.get("hypothesis_ids") or _hypothesis_ids(record)),
        "status": status,
        "decision": dict(record.get("decision") or record),
        "reason": record.get("reason"),
        "updated_at": _timestamp_iso(),
    }


def _ordered_selected_records(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    scheduler_plan = plan.get("scheduler_plan") if isinstance(plan.get("scheduler_plan"), dict) else {}
    decisions_by_key = {
        str(item.get("agent_key") or "").strip(): _runtime_record(item, "selected")
        for item in _scheduler_items(plan, "selected", "selected_agents")
    }
    ordered: list[dict[str, Any]] = []
    for batch in scheduler_plan.get("selected_batches") or ():
        if not isinstance(batch, dict):
            continue
        for agent in batch.get("agents") or ():
            if not isinstance(agent, dict):
                continue
            key = str(agent.get("agent_key") or "").strip()
            if key and key in decisions_by_key and key not in {item["agent_key"] for item in ordered}:
                ordered.append(decisions_by_key[key])
    for key, record in decisions_by_key.items():
        if key not in {item["agent_key"] for item in ordered}:
            ordered.append(record)
    return ordered


def _ordered_unrun_records(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    deferred = _scheduler_items(plan, "deferred", "deferred_agents")
    if not deferred:
        deferred = [
            item
            for item in _scheduler_items(plan, "unrun", "unrun_agents")
            if str(item.get("status") or "deferred").strip() == "deferred"
        ]
    for item in deferred:
        records.append(_runtime_record(item, "deferred"))
    return records


def _scheduler_items(plan: Mapping[str, Any], key: str, artifact_key: str) -> list[dict[str, Any]]:
    scheduler_plan = plan.get("scheduler_plan") if isinstance(plan.get("scheduler_plan"), dict) else {}
    inline = [dict(item) for item in scheduler_plan.get(key) or () if isinstance(item, dict)]
    if inline:
        return inline
    artifacts = scheduler_plan.get("decision_artifacts") if isinstance(scheduler_plan.get("decision_artifacts"), dict) else {}
    artifact = artifacts.get(artifact_key) if isinstance(artifacts.get(artifact_key), dict) else {}
    path = str(artifact.get("path") or "").strip()
    if not path:
        return []
    return _read_jsonl(Path(path))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _wave_limit(plan: Mapping[str, Any], *, max_agents: int | None, concurrent_agents: int | None) -> int:
    scheduler_plan = plan.get("scheduler_plan") if isinstance(plan.get("scheduler_plan"), dict) else {}
    config = scheduler_plan.get("config") if isinstance(scheduler_plan.get("config"), dict) else {}
    configured_concurrent = concurrent_agents or config.get("concurrent_agents")
    selected_batches = scheduler_plan.get("selected_batches") or ()
    if configured_concurrent:
        limit = max(1, int(configured_concurrent))
    elif selected_batches and isinstance(selected_batches[0], dict) and selected_batches[0].get("max_concurrent"):
        limit = max(1, int(selected_batches[0]["max_concurrent"]))
    else:
        limit = 1
    if max_agents is not None:
        limit = min(limit, max(0, int(max_agents)))
    return max(0, limit)


def _state_status(agents_by_key: Any, agent_key: str) -> str:
    if isinstance(agents_by_key, Mapping) and isinstance(agents_by_key.get(agent_key), dict):
        return str(agents_by_key[agent_key].get("status") or "").strip()
    return ""


def _agent_list(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    agents = state.get("agents") if isinstance(state.get("agents"), dict) else {}
    return [dict(item) for item in agents.values() if isinstance(item, dict)]


def _count_status(agents: Sequence[Mapping[str, Any]], status: str) -> int:
    return sum(1 for item in agents if item.get("status") == status)


def _hypothesis_ids(record: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    hypothesis_id = str(record.get("hypothesis_id") or "").strip()
    if hypothesis_id:
        values.append(hypothesis_id)
    for item in record.get("member_hypothesis_ids") or ():
        cleaned = str(item).strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    for item in record.get("hypothesis_ids") or ():
        cleaned = str(item).strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return values


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
