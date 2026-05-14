from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from agents.base_team import AgentSpec, BaseTeam
from agents.hunt_pipeline.promotion_decision import (
    evaluate_runtime_promotion_decision,
    runtime_execution_mode,
)
from agents.hunt_pipeline.run_state import (
    initialize_run_state,
    load_pipeline_plan,
    load_control_flags,
    load_run_state,
    next_wave_records,
    pipeline_runtime_lock,
    recover_running_agents,
    run_state_path_for_plan,
    save_run_state,
    summarize_run,
    update_agent_statuses,
)
from agents.hunt_pipeline.operator_approval_schema import evaluate_runtime_operator_approval_schema
from agents.hunt_pipeline.promotion_request_packet import evaluate_runtime_promotion_request_packet
from agents.hunt_pipeline.runtime_contract import (
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    evaluate_runtime_promotion_readiness,
    failed_required_gates,
)
from agents.hunt_pipeline.runtime_adapter import selected_decisions_to_base_team_agent_specs


class PipelineRuntimeAdapter(Protocol):
    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        ...


class DryRunBaseTeamAdapter:
    """Mockable execution boundary that never spawns Codex or touches live targets."""

    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        return {spec.key: "completed" for spec in specs}


class _HuntPipelineBaseTeam(BaseTeam):
    def get_static_profiles(self) -> list[AgentSpec]:
        return []

    def generate_dynamic_from_surfaces(
        self,
        surfaces: Sequence[dict[str, Any]],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        return []


class LiveBaseTeamAdapter:
    """Live execution boundary for promoted plans.

    This adapter deliberately executes only the already-selected bounded wave it is
    handed. It renders prompts and spawns through BaseTeam methods, which delegate
    to the shared BaseTeam runtime primitives.
    """

    def __init__(
        self,
        *,
        program: str,
        target_path: str | Path,
        output_root: str | Path,
        max_agents: int,
        target_kind: str | None = None,
    ) -> None:
        self.team = _HuntPipelineBaseTeam(
            program,
            "0day_team",
            Path(target_path),
            output_root=Path(output_root),
            max_agents=max(1, int(max_agents)),
            target_kind=target_kind,
        )

    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        handles = {}
        log_paths: dict[str, Path] = {}
        specs_by_key = {spec.key: spec for spec in specs}
        try:
            for spec in specs:
                prompt = self.team._render_prompt(spec)
                log_path = self.team.agents_dir / f"{_safe_name(spec.key)}.log"
                log_paths[spec.key] = log_path
                handles[spec.key] = self.team.spawn_agent(prompt, spec.key, log_path)
        except Exception:
            _terminate_live_handles(self.team, handles)
            raise
        completed = self.team.wait_for_agents(handles, self.team.agent_timeout)
        self._persist_findings(specs_by_key, log_paths)
        return {
            key: "completed" if completed.get(key, ("", 1))[1] == 0 else "failed"
            for key in (spec.key for spec in specs)
        }

    def _persist_findings(self, specs_by_key: Mapping[str, AgentSpec], log_paths: Mapping[str, Path]) -> None:
        raw_findings: list[dict[str, Any]] = []
        findings_by_agent: dict[str, list[dict[str, Any]]] = {}
        for key, spec in specs_by_key.items():
            agent_findings = self.team._collect_agent_findings(spec, log_paths.get(key))
            findings_by_agent[key] = agent_findings
            raw_findings.extend(agent_findings)
        ledger = self.team.load_ledger()
        new_findings = self.team.deduplicate_findings(raw_findings, ledger)
        confirmed, dormant, novel = self.team.stage2_review(new_findings, self.team.target_path)
        reviewed = self.team.update_reviewed_findings(confirmed + dormant + novel)
        for key, spec in specs_by_key.items():
            self.team.update_coverage(
                agent_name=key,
                surface=spec.surface,
                finding_count=len(findings_by_agent.get(key, [])),
            )
        self.team.write_traces(
            [
                {
                    "event": "hunt_pipeline_live_review_complete",
                    "raw_findings": len(raw_findings),
                    "new_findings": len(new_findings),
                    "confirmed": len(confirmed),
                    "dormant": len(dormant),
                    "novel": len(novel),
                    "persisted": len(reviewed),
                }
            ]
        )



def _terminate_live_handles(team: BaseTeam, handles: Mapping[str, Any]) -> None:
    for key, handle in handles.items():
        try:
            if handle.poll() is None:
                handle.terminate()
                handle.wait(timeout=5)
        except Exception:
            try:
                handle.kill()
                handle.wait(timeout=5)
            except Exception:
                pass
        finally:
            try:
                team._cleanup_handle(handle)
            except Exception:
                pass
            try:
                team.write_traces([{"event": "spawn_cleanup", "agent_name": str(key)}])
            except Exception:
                pass


def execute_next_wave(
    plan_path: str | Path,
    *,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
    execute_live: bool = False,
    live_testing_enabled: bool | None = None,
    adapter: PipelineRuntimeAdapter | None = None,
) -> dict[str, Any]:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    if execute_live:
        plan = load_pipeline_plan(resolved_plan_path)
        decision = evaluate_runtime_promotion_decision(plan, plan_path=resolved_plan_path)
        if decision.get("promoted") is not True:
            return _blocked_live_execution_result(plan, resolved_plan_path, decision)

    with pipeline_runtime_lock(resolved_plan_path):
        plan = load_pipeline_plan(resolved_plan_path)
        execution_mode = "live" if execute_live else "dry-run"
        promotion_decision = evaluate_runtime_promotion_decision(plan, plan_path=resolved_plan_path)
        if execute_live and promotion_decision.get("promoted") is not True:
            return _blocked_live_execution_result(plan, resolved_plan_path, promotion_decision)
        state = recover_running_agents(initialize_run_state(resolved_plan_path, plan))
        state["run_config"] = _resolved_run_config(state, live_testing_enabled=live_testing_enabled)
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))
        wave = next_wave_records(plan, state, max_agents=max_agents, concurrent_agents=concurrent_agents)
        if not wave:
            save_run_state(state, run_state_path_for_plan(resolved_plan_path))
            return {
                "ok": True,
                "executed": 0,
                "agent_keys": [],
                "execution_mode": execution_mode,
                "runtime_promotion_decision": promotion_decision,
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
            runtime_adapter = adapter or _default_adapter(
                execute_live=execute_live,
                plan=plan,
                plan_path=resolved_plan_path,
                wave_size=len(wave),
            )
            result = runtime_adapter.execute(specs)
        except Exception as exc:  # keep durable state resumable after adapter/conversion failures
            state = update_agent_statuses(
                state,
                wave,
                status="failed",
                details={"adapter": execution_mode, "error": f"{type(exc).__name__}: {exc}"},
            )
            state = _preserve_control_flags(state, run_state_path_for_plan(resolved_plan_path))
            save_run_state(state, run_state_path_for_plan(resolved_plan_path))
            return {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "executed": 0,
                "agent_keys": [record["agent_key"] for record in wave],
                "execution_mode": execution_mode,
                "runtime_promotion_decision": promotion_decision,
                "summary": summarize_run(resolved_plan_path, max_agents=max_agents, concurrent_agents=concurrent_agents),
            }

        completed = [record for record in wave if result.get(record["agent_key"]) == "completed"]
        failed = [record for record in wave if result.get(record["agent_key"]) != "completed"]
        if completed:
            state = update_agent_statuses(
                state,
                completed,
                status="completed",
                details={"adapter": execution_mode, "specs_path": str(specs_path)},
            )
        for record in failed:
            state = update_agent_statuses(
                state,
                [record],
                status="failed",
                details={
                    "adapter": execution_mode,
                    "specs_path": str(specs_path),
                    "adapter_status": result.get(record["agent_key"], "missing"),
                },
            )
        state["last_wave"] = {
            "agent_keys": [record["agent_key"] for record in wave],
            "specs_path": str(specs_path),
            "live_execution": bool(execute_live),
            "live_testing_enabled": bool(state["run_config"].get("live_testing_enabled", False)),
            "execution_mode": execution_mode,
        }
        state = _preserve_control_flags(state, run_state_path_for_plan(resolved_plan_path))
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))
        return {
            "ok": not failed,
            "executed": len(wave),
            "agent_keys": [record["agent_key"] for record in wave],
            "specs_path": str(specs_path),
            "execution_mode": execution_mode,
            "runtime_promotion_decision": promotion_decision,
            "summary": summarize_run(resolved_plan_path, max_agents=max_agents, concurrent_agents=concurrent_agents),
        }


def _blocked_live_execution_result(
    plan: Mapping[str, Any],
    plan_path: Path,
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    contract = evaluate_runtime_handoff_contract(plan)
    return {
        "ok": False,
        "error": "live AppMap hunt execution is blocked by the runtime handoff contract: requires a valid runtime promotion decision record",
        "executed": 0,
        "promotion_allowed": False,
        "execution_mode": "blocked",
        "runtime_execution": {
            "mode": "blocked",
            "default_mode": "blocked",
            "dry_run": False,
            "live": False,
            "promotion_required": True,
            "runtime_promotion_decision": dict(decision),
        },
        "runtime_promotion_decision": dict(decision),
        "runtime_handoff_contract": contract,
        "runtime_promotion_protocol": evaluate_runtime_promotion_protocol(plan),
        "runtime_promotion_readiness": evaluate_runtime_promotion_readiness(plan),
        "runtime_operator_approval_schema": evaluate_runtime_operator_approval_schema(plan),
        "runtime_promotion_request_packet": evaluate_runtime_promotion_request_packet(plan),
        "failed_gates": failed_required_gates(contract),
    }


def _default_adapter(
    *,
    execute_live: bool,
    plan: Mapping[str, Any],
    plan_path: Path,
    wave_size: int,
) -> PipelineRuntimeAdapter:
    if not execute_live:
        return DryRunBaseTeamAdapter()
    return LiveBaseTeamAdapter(
        program=str(plan.get("program") or "").strip(),
        target_path=str(plan.get("target_path") or "").strip(),
        output_root=plan_path.parent,
        max_agents=wave_size,
        target_kind=str(plan.get("target_kind") or "").strip() or None,
    )


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or "").strip())
    return cleaned or "agent"



def _preserve_control_flags(state: Mapping[str, Any], state_path: Path) -> dict[str, Any]:
    latest = load_run_state(state_path)
    control = load_control_flags(state_path.parent / "pipeline_plan.json")
    updated = dict(state)
    updated["pause_requested"] = bool(
        updated.get("pause_requested", False)
        or latest.get("pause_requested", False)
        or control.get("pause_requested", False)
    )
    updated["stopped"] = bool(
        updated.get("stopped", False)
        or latest.get("stopped", False)
        or control.get("stopped", False)
    )
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


def _resolved_run_config(
    state: Mapping[str, Any],
    *,
    live_testing_enabled: bool | None,
) -> dict[str, Any]:
    current = state.get("run_config") if isinstance(state.get("run_config"), Mapping) else {}
    return {
        "live_testing_enabled": (
            bool(live_testing_enabled)
            if live_testing_enabled is not None
            else bool(current.get("live_testing_enabled", False))
        ),
    }
