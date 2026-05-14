from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from agents.base_team import AgentSpec
from agents.hunt_pipeline.run_state import (
    initialize_run_state,
    load_pipeline_plan,
    load_run_state,
    next_wave_records,
    pipeline_runtime_lock,
    recover_running_agents,
    run_state_path_for_plan,
    save_run_state,
    summarize_run,
    update_agent_statuses,
)
from agents.hunt_pipeline.runtime_adapter import selected_decisions_to_base_team_agent_specs


class PipelineRuntimeAdapter(Protocol):
    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        ...


class DryRunBaseTeamAdapter:
    """Mockable execution boundary that never spawns Codex or touches live targets."""

    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        return {spec.key: "completed" for spec in specs}


def execute_next_wave(
    plan_path: str | Path,
    *,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
    execute_live: bool = False,
    adapter: PipelineRuntimeAdapter | None = None,
) -> dict[str, Any]:
    if execute_live:
        return {
            "ok": False,
            "error": "live AppMap hunt execution is not enabled in this runtime-control pass",
            "executed": 0,
        }

    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    with pipeline_runtime_lock(resolved_plan_path):
        plan = load_pipeline_plan(resolved_plan_path)
        state = recover_running_agents(initialize_run_state(resolved_plan_path, plan))
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))
        wave = next_wave_records(plan, state, max_agents=max_agents, concurrent_agents=concurrent_agents)
        if not wave:
            save_run_state(state, run_state_path_for_plan(resolved_plan_path))
            return {
                "ok": True,
                "executed": 0,
                "agent_keys": [],
                "summary": summarize_run(resolved_plan_path, max_agents=max_agents, concurrent_agents=concurrent_agents),
            }

        state = update_agent_statuses(state, wave, status="running")
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))

        specs_path: Path | None = None
        try:
            specs = selected_decisions_to_base_team_agent_specs(
                [record["decision"] for record in wave],
                plan.get("hypotheses") or (),
                program=str(plan.get("program") or "").strip(),
                snapshot_id=_snapshot_id(plan, resolved_plan_path),
            )
            specs_path = _append_runtime_specs(resolved_plan_path.parent / "runtime_agent_specs.jsonl", specs)
            result = (adapter or DryRunBaseTeamAdapter()).execute(specs)
        except Exception as exc:  # keep durable state resumable after adapter/conversion failures
            state = update_agent_statuses(
                state,
                wave,
                status="failed",
                details={"adapter": "dry-run", "error": f"{type(exc).__name__}: {exc}"},
            )
            state = _preserve_control_flags(state, run_state_path_for_plan(resolved_plan_path))
            save_run_state(state, run_state_path_for_plan(resolved_plan_path))
            return {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "executed": 0,
                "agent_keys": [record["agent_key"] for record in wave],
                "summary": summarize_run(resolved_plan_path, max_agents=max_agents, concurrent_agents=concurrent_agents),
            }

        completed = [record for record in wave if result.get(record["agent_key"]) == "completed"]
        failed = [record for record in wave if result.get(record["agent_key"]) != "completed"]
        if completed:
            state = update_agent_statuses(
                state,
                completed,
                status="completed",
                details={"adapter": "dry-run", "specs_path": str(specs_path)},
            )
        for record in failed:
            state = update_agent_statuses(
                state,
                [record],
                status="failed",
                details={
                    "adapter": "dry-run",
                    "specs_path": str(specs_path),
                    "adapter_status": result.get(record["agent_key"], "missing"),
                },
            )
        state["last_wave"] = {
            "agent_keys": [record["agent_key"] for record in wave],
            "specs_path": str(specs_path),
            "live_execution": False,
        }
        state = _preserve_control_flags(state, run_state_path_for_plan(resolved_plan_path))
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))
        return {
            "ok": not failed,
            "executed": len(wave),
            "agent_keys": [record["agent_key"] for record in wave],
            "specs_path": str(specs_path),
            "summary": summarize_run(resolved_plan_path, max_agents=max_agents, concurrent_agents=concurrent_agents),
        }



def _preserve_control_flags(state: Mapping[str, Any], state_path: Path) -> dict[str, Any]:
    latest = load_run_state(state_path)
    if not latest:
        return dict(state)
    updated = dict(state)
    updated["pause_requested"] = bool(updated.get("pause_requested", False) or latest.get("pause_requested", False))
    updated["stopped"] = bool(updated.get("stopped", False) or latest.get("stopped", False))
    return updated


def _append_runtime_specs(path: Path, specs: Sequence[AgentSpec]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for spec in specs:
            handle.write(json.dumps(asdict(spec), sort_keys=True) + "\n")
    return path


def _snapshot_id(plan: Mapping[str, Any], plan_path: Path) -> str:
    source = plan.get("appmap_source") if isinstance(plan.get("appmap_source"), dict) else {}
    run_root = str(source.get("run_root") or "").strip()
    if run_root:
        return Path(run_root).name
    return plan_path.parent.name
