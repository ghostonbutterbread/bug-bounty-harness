from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from agents.base_team import AgentSpec, BaseTeam
from agents.hunt_pipeline.promotion_decision import evaluate_runtime_promotion_decision
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
from agents.hunt_pipeline.efficiency_logging import finalize_efficiency_logging, initialize_efficiency_logging
from agents.hunt_pipeline.operator_approval_schema import evaluate_runtime_operator_approval_schema
from agents.hunt_pipeline.promotion_request_packet import evaluate_runtime_promotion_request_packet
from agents.hunt_pipeline.runtime_contract import (
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    evaluate_runtime_promotion_readiness,
    failed_required_gates,
)
from agents.hunt_pipeline.runtime_adapter import grouped_decisions_to_base_team_agent_specs


class PipelineRuntimeAdapter(Protocol):
    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        ...


class DryRunBaseTeamAdapter:
    """Mockable execution boundary that never spawns Codex or touches live targets."""

    def __init__(self) -> None:
        self.last_execution_details: dict[str, dict[str, Any]] = {}

    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        self.last_execution_details = {spec.key: {"cwd": "", "prompt_marker": _prompt_marker(spec)} for spec in specs}
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
    """Source-hunting execution boundary for selected dynamic pipeline waves.

    This adapter deliberately executes only the already-selected bounded wave it is
    handed. It renders prompts and spawns through BaseTeam methods. The target
    source remains read-only by convention; generated PoCs/notes should be written
    under the scoped pipeline artifacts directory.
    """

    def __init__(
        self,
        *,
        program: str,
        target_path: str | Path,
        output_root: str | Path,
        max_agents: int,
        target_kind: str | None = None,
        no_ledger: bool = False,
    ) -> None:
        self.no_ledger = bool(no_ledger)
        self.artifacts_dir = Path(output_root) / "agent_artifacts"
        self.team = _HuntPipelineBaseTeam(
            program,
            "0day_team",
            Path(target_path),
            output_root=Path(output_root),
            max_agents=max(1, int(max_agents)),
            target_kind=target_kind,
        )
        self.team.agent_sandbox_mode = "artifact-write"
        self.team.writable_artifact_dir = self.artifacts_dir
        self.last_execution_details: dict[str, dict[str, Any]] = {}
        self.last_promising_entry_ids: tuple[str, ...] = ()

    def execute(self, specs: Sequence[AgentSpec]) -> dict[str, str]:
        handles = {}
        log_paths: dict[str, Path] = {}
        artifact_dirs: dict[str, Path] = {}
        prompts: dict[str, str] = {}
        specs_by_key = {spec.key: spec for spec in specs}
        self.last_execution_details = {}
        try:
            for spec in specs:
                prompt = self._render_source_hunt_prompt(spec)
                prompts[spec.key] = prompt
                log_path = self.team.agents_dir / f"{_safe_name(spec.key)}.log"
                artifact_dir = self.artifacts_dir / _safe_name(spec.key)
                artifact_dirs[spec.key] = artifact_dir
                log_paths[spec.key] = log_path
                handles[spec.key] = self.team.spawn_agent(prompt, spec.key, log_path)
        except Exception:
            _terminate_live_handles(self.team, handles, write_traces=not self.no_ledger)
            raise
        completed = self.team.wait_for_agents(handles, self.team.agent_timeout)
        self.last_execution_details = {
            key: {
                "log_path": str(log_paths.get(key) or ""),
                "prompt_path": str(getattr(handles.get(key), "_bbh_prompt_path", "") or ""),
                "artifact_dir": str(artifact_dirs.get(key) or ""),
                "prompt_marker": _prompt_marker(specs_by_key[key]),
                "cwd": str(artifact_dirs.get(key) or self.team.workdir),
            }
            for key in specs_by_key
        }
        if not self.no_ledger:
            self._persist_findings(specs_by_key, log_paths)
        return {
            key: "completed" if completed.get(key, ("", 1))[1] == 0 else "failed"
            for key in (spec.key for spec in specs)
        }

    def _render_source_hunt_prompt(self, spec: AgentSpec) -> str:
        prompt = self.team._render_prompt(spec)
        artifact_dir = self.artifacts_dir / _safe_name(spec.key)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        marker = _prompt_marker(spec)
        return (
            f"{prompt}\n\n"
            f"{marker}\n"
            f"Category pack id: {spec.metadata.get('category_pack_id') or spec.key}\n"
            f"Agent key: {spec.key}\n\n"
            "Hunt-pipeline source-only execution rules:\n"
            "- Treat the target source tree as read-only. Do not modify vendor/source files.\n"
            f"- You may write PoCs, repro notes, scratch files, and evidence only under: {artifact_dir}\n"
            "- Do not launch the target app, browse live vendor services, send network traffic to Canva, "
            "or perform VM/live-testing actions unless a separate live-testing approval is present.\n"
            "- If you produce a PoC, keep it benign and local/source-backed, and include a short README or notes file.\n"
        )

    def _persist_findings(self, specs_by_key: Mapping[str, AgentSpec], log_paths: Mapping[str, Path]) -> None:
        raw_findings: list[dict[str, Any]] = []
        findings_by_agent: dict[str, list[dict[str, Any]]] = {}
        for key, spec in specs_by_key.items():
            agent_findings = self.team._collect_agent_findings(spec, log_paths.get(key))
            findings_by_agent[key] = agent_findings
            raw_findings.extend(agent_findings)
        self.last_promising_entry_ids = _promising_entry_trigger_ids(raw_findings)
        amplifier_findings, review_findings = _split_amplifier_hold_findings(raw_findings)
        if amplifier_findings:
            _append_run_amplifier_findings(self.team.storage.reports_root, amplifier_findings)
        ledger = self.team.load_ledger()
        new_findings = self.team.deduplicate_findings(review_findings, ledger)
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
                    "amplifier_hold_findings": len(amplifier_findings),
                    "new_findings": len(new_findings),
                    "confirmed": len(confirmed),
                    "dormant": len(dormant),
                    "novel": len(novel),
                    "persisted": len(reviewed),
                }
            ]
        )



def _terminate_live_handles(team: BaseTeam, handles: Mapping[str, Any], *, write_traces: bool = True) -> None:
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
            if write_traces:
                try:
                    team.write_traces([{"event": "spawn_cleanup", "agent_name": str(key)}])
                except Exception:
                    pass


def _split_amplifier_hold_findings(findings: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    amplifier: list[dict[str, Any]] = []
    reviewable: list[dict[str, Any]] = []
    for finding in findings:
        record = dict(finding)
        role = str(record.get("finding_role") or "").strip().lower()
        entry_status = str(record.get("entry_status") or "").strip().lower()
        reportability = str(record.get("reportability") or "").strip().lower()
        if role in {"amplifier", "chain"} and (
            entry_status in {"", "missing", "plausible"} or reportability == "hold_for_chain"
        ):
            record["reportability"] = reportability or "hold_for_chain"
            record["entry_status"] = entry_status or "missing"
            record["finding_role"] = role
            amplifier.append(record)
            continue
        reviewable.append(record)
    return amplifier, reviewable


def _append_run_amplifier_findings(reports_root: Path, findings: Sequence[Mapping[str, Any]]) -> Path:
    path = reports_root / "findings" / "amplifier.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Amplifier Findings\n\n"
    blocks = []
    for finding in findings:
        title = str(finding.get("description") or finding.get("type") or finding.get("class_name") or "Untitled amplifier").strip()
        blocks.extend(
            [
                f"## {_markdown_text(title)}",
                "",
                f"- Role: `{_markdown_inline(finding.get('finding_role'))}`",
                f"- Entry status: `{_markdown_inline(finding.get('entry_status'))}`",
                f"- Reportability: `{_markdown_inline(finding.get('reportability'))}`",
                f"- File: `{_markdown_inline(finding.get('file'))}`",
                f"- Required entry primitives: {_markdown_list(finding.get('required_entry_primitives'))}",
                f"- Chain handles: {_markdown_list(finding.get('chain_handles'))}",
                f"- Unlocked amplifiers: {_markdown_list(finding.get('unlocked_amplifiers'))}",
                "",
            ]
        )
    path.write_text(existing.rstrip() + "\n\n" + "\n".join(blocks).rstrip() + "\n", encoding="utf-8")
    return path


def _promising_entry_trigger_ids(findings: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    values: list[str] = []
    for finding in findings:
        role = str(finding.get("finding_role") or "").strip().lower()
        entry_status = str(finding.get("entry_status") or "").strip().lower()
        reportability = str(finding.get("reportability") or "").strip().lower()
        if role != "entry":
            continue
        if entry_status not in {"proven", "plausible"}:
            continue
        if reportability not in {"submit", "validate_entry"}:
            continue
        for key in ("hypothesis_id", "hypothesis_key", "brainstorm_agent_key", "agent"):
            cleaned = str(finding.get(key) or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return tuple(values)


def _markdown_list(value: Any) -> str:
    if isinstance(value, str):
        return f"`{_markdown_inline(value)}`" if value.strip() else "none"
    if not isinstance(value, Sequence):
        return "none"
    rendered = [f"`{_markdown_inline(item)}`" for item in value if str(item or "").strip()]
    return ", ".join(rendered) if rendered else "none"


def _markdown_inline(value: Any) -> str:
    return str(value or "").replace("`", "'").strip()


def _markdown_text(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def execute_next_wave(
    plan_path: str | Path,
    *,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
    skip_chain: bool = False,
    trigger_entry_ids: Sequence[str] = (),
    execute_live: bool = False,
    live_testing_enabled: bool | None = None,
    no_ledger: bool | None = None,
    adapter: PipelineRuntimeAdapter | None = None,
) -> dict[str, Any]:
    resolved_plan_path = Path(plan_path).expanduser().resolve(strict=False)
    plan = load_pipeline_plan(resolved_plan_path)
    live_testing_requested = bool(live_testing_enabled)
    if execute_live and live_testing_requested:
        decision = evaluate_runtime_promotion_decision(plan, plan_path=resolved_plan_path)
        if decision.get("promoted") is not True:
            return _blocked_live_execution_result(plan, resolved_plan_path, decision)

    with pipeline_runtime_lock(resolved_plan_path):
        plan = load_pipeline_plan(resolved_plan_path)
        execution_mode = "live" if execute_live and live_testing_requested else ("source-hunt" if execute_live else "dry-run")
        promotion_decision = evaluate_runtime_promotion_decision(plan, plan_path=resolved_plan_path)
        if execute_live and live_testing_requested and promotion_decision.get("promoted") is not True:
            return _blocked_live_execution_result(plan, resolved_plan_path, promotion_decision)
        state = recover_running_agents(initialize_run_state(resolved_plan_path, plan))
        state["run_config"] = _resolved_run_config(
            state,
            live_testing_enabled=live_testing_enabled,
            no_ledger=no_ledger,
            skip_chain=skip_chain,
        )
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))
        pending_trigger_entry_ids = tuple(
            str(item).strip()
            for item in state.get("pending_trigger_entry_ids", ())
            if str(item).strip()
        )
        effective_trigger_entry_ids = tuple(trigger_entry_ids) or pending_trigger_entry_ids
        using_pending_trigger_ids = bool(pending_trigger_entry_ids and not trigger_entry_ids)
        triggered_hypothesis_ids = _triggered_hypothesis_ids(
            plan,
            resolved_plan_path,
            trigger_entry_ids=effective_trigger_entry_ids,
        )
        wave = next_wave_records(
            plan,
            state,
            max_agents=max_agents,
            concurrent_agents=concurrent_agents,
            skip_chain=False if effective_trigger_entry_ids else bool(state["run_config"].get("skip_chain", False)),
            only_hypothesis_ids=triggered_hypothesis_ids if effective_trigger_entry_ids else None,
        )
        if not wave:
            save_run_state(state, run_state_path_for_plan(resolved_plan_path))
            return {
                "ok": True,
                "executed": 0,
                "agent_keys": [],
                "execution_mode": execution_mode,
                "runtime_promotion_decision": promotion_decision,
                "skip_chain": bool(state["run_config"].get("skip_chain", False)),
                "trigger_entry_ids": list(trigger_entry_ids),
                "auto_trigger_entry_ids": list(pending_trigger_entry_ids),
                "triggered_hypothesis_ids": sorted(triggered_hypothesis_ids),
                "summary": summarize_run(
                    resolved_plan_path,
                    max_agents=max_agents,
                    concurrent_agents=concurrent_agents,
                    skip_chain=bool(state["run_config"].get("skip_chain", False)),
                ),
            }

        state = update_agent_statuses(state, wave, status="running")
        if using_pending_trigger_ids:
            state["pending_trigger_entry_ids"] = []
        save_run_state(state, run_state_path_for_plan(resolved_plan_path))

        specs_path: Path | None = None
        try:
            specs, spec_metrics = grouped_decisions_to_base_team_agent_specs(
                [record["decision"] for record in wave],
                plan.get("hypotheses") or (),
                program=str(plan.get("program") or "").strip(),
                snapshot_id=_snapshot_id(plan, resolved_plan_path),
                max_agents=len(wave),
                include_candidate_packets=False,
            )
            specs = _annotate_runtime_specs(
                specs,
                run_id=str(state.get("run_id") or "").strip() or resolved_plan_path.parent.name,
                plan_path=resolved_plan_path,
            )
            specs_path = _append_runtime_specs(resolved_plan_path.parent / "runtime_agent_specs.jsonl", specs)
            efficiency_dir = initialize_efficiency_logging(
                resolved_plan_path,
                plan,
                specs=specs,
                wave=wave,
                spec_metrics=spec_metrics,
                execution_mode=execution_mode,
                selected_wave=_selected_wave_number(state),
            )
            runtime_adapter = adapter or _default_adapter(
                execute_live=execute_live,
                plan=plan,
                plan_path=resolved_plan_path,
                wave_size=len(wave),
                no_ledger=bool(state["run_config"].get("no_ledger", False)),
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
                "skip_chain": bool(state["run_config"].get("skip_chain", False)),
                "trigger_entry_ids": list(trigger_entry_ids),
                "auto_trigger_entry_ids": list(pending_trigger_entry_ids),
                "triggered_hypothesis_ids": sorted(triggered_hypothesis_ids),
                "summary": summarize_run(
                    resolved_plan_path,
                    max_agents=max_agents,
                    concurrent_agents=concurrent_agents,
                    skip_chain=bool(state["run_config"].get("skip_chain", False)),
                ),
            }

        record_statuses = _record_statuses_from_grouped_specs(wave, specs, result)
        completed = [record for record in wave if record_statuses.get(record["agent_key"]) == "completed"]
        failed = [record for record in wave if record_statuses.get(record["agent_key"]) != "completed"]
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
                    "adapter_status": record_statuses.get(record["agent_key"], "missing"),
                },
            )
        execution_details = getattr(runtime_adapter, "last_execution_details", {})
        new_trigger_entry_ids = _adapter_promising_entry_ids(runtime_adapter)
        if new_trigger_entry_ids:
            state["pending_trigger_entry_ids"] = _merge_trigger_ids(
                state.get("pending_trigger_entry_ids", ()),
                new_trigger_entry_ids,
            )
        efficiency_dir = finalize_efficiency_logging(
            resolved_plan_path,
            plan,
            specs=specs,
            result=result,
            execution_details=execution_details if isinstance(execution_details, Mapping) else {},
        )
        state["last_wave"] = {
            "agent_keys": [record["agent_key"] for record in wave],
            "specs_path": str(specs_path),
            "efficiency_dir": str(efficiency_dir),
            "source_hunt_execution": bool(execute_live),
            "live_execution": bool(execute_live and live_testing_requested),
            "live_testing_enabled": bool(state["run_config"].get("live_testing_enabled", False)),
            "no_ledger": bool(state["run_config"].get("no_ledger", False)),
            "skip_chain": bool(state["run_config"].get("skip_chain", False)),
            "trigger_entry_ids": list(trigger_entry_ids),
            "auto_trigger_entry_ids": list(pending_trigger_entry_ids),
            "queued_trigger_entry_ids": list(new_trigger_entry_ids),
            "triggered_hypothesis_ids": sorted(triggered_hypothesis_ids),
            "execution_mode": execution_mode,
            "spec_metrics": spec_metrics,
            "selected_wave": _selected_wave_number(state),
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
            "skip_chain": bool(state["run_config"].get("skip_chain", False)),
            "trigger_entry_ids": list(trigger_entry_ids),
            "auto_trigger_entry_ids": list(pending_trigger_entry_ids),
            "queued_trigger_entry_ids": list(new_trigger_entry_ids),
            "triggered_hypothesis_ids": sorted(triggered_hypothesis_ids),
            "summary": summarize_run(
                resolved_plan_path,
                max_agents=max_agents,
                concurrent_agents=concurrent_agents,
                skip_chain=bool(state["run_config"].get("skip_chain", False)),
            ),
            "efficiency_dir": str(efficiency_dir),
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
    no_ledger: bool = False,
) -> PipelineRuntimeAdapter:
    if not execute_live:
        return DryRunBaseTeamAdapter()
    return LiveBaseTeamAdapter(
        program=str(plan.get("program") or "").strip(),
        target_path=str(plan.get("target_path") or "").strip(),
        output_root=plan_path.parent,
        max_agents=wave_size,
        target_kind=str(plan.get("target_kind") or "").strip() or None,
        no_ledger=no_ledger,
    )


def _triggered_hypothesis_ids(
    plan: Mapping[str, Any],
    plan_path: Path,
    *,
    trigger_entry_ids: Sequence[str],
) -> frozenset[str]:
    requested = {str(item).strip() for item in trigger_entry_ids if str(item).strip()}
    if not requested:
        return frozenset()
    activation_index = _load_chain_activation_index(plan, plan_path)
    matched: set[str] = set()
    for activation in activation_index.get("activations") or ():
        if not isinstance(activation, Mapping):
            continue
        activation_keys = {
            str(activation.get("id") or "").strip(),
            str(activation.get("key") or "").strip(),
        }
        if not requested.intersection(activation_keys):
            continue
        for amplifier in activation.get("unlocked_amplifiers") or ():
            if not isinstance(amplifier, Mapping):
                continue
            hypothesis_id = str(amplifier.get("id") or "").strip()
            if hypothesis_id:
                matched.add(hypothesis_id)
    return frozenset(matched)


def _adapter_promising_entry_ids(adapter: PipelineRuntimeAdapter) -> tuple[str, ...]:
    return tuple(
        str(item).strip()
        for item in getattr(adapter, "last_promising_entry_ids", ()) or ()
        if str(item).strip()
    )


def _merge_trigger_ids(existing: Any, new_values: Sequence[str]) -> list[str]:
    merged: list[str] = []
    existing_values = [existing] if isinstance(existing, str) else list(existing or ())
    for item in [*existing_values, *new_values]:
        cleaned = str(item).strip()
        if cleaned and cleaned not in merged:
            merged.append(cleaned)
    return merged


def _load_chain_activation_index(plan: Mapping[str, Any], plan_path: Path) -> dict[str, Any]:
    metadata = plan.get("artifact_metadata") if isinstance(plan.get("artifact_metadata"), Mapping) else {}
    artifact = metadata.get("chain_activation_index") if isinstance(metadata.get("chain_activation_index"), Mapping) else {}
    path = Path(str(artifact.get("path") or plan_path.parent / "chain_activation_index.json")).expanduser().resolve(strict=False)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or "").strip())
    return cleaned or "agent"



def _prompt_marker(spec: AgentSpec) -> str:
    tracking = spec.metadata.get("runtime_tracking") if isinstance(spec.metadata, Mapping) else {}
    run_id = str(tracking.get("run_id") or "").strip() or "unknown"
    agent_key = str(tracking.get("agent_key") or spec.key).strip() or spec.key
    return f"Hunt pipeline run id: {run_id} | agent key: {agent_key}"



def _annotate_runtime_specs(
    specs: Sequence[AgentSpec],
    *,
    run_id: str,
    plan_path: Path,
) -> list[AgentSpec]:
    annotated: list[AgentSpec] = []
    for spec in specs:
        metadata = dict(spec.metadata or {})
        metadata["runtime_tracking"] = {
            "run_id": run_id,
            "pipeline_plan": str(plan_path),
            "category_pack_id": str(metadata.get("category_pack_id") or spec.key).strip(),
            "agent_key": spec.key,
        }
        spec.metadata = metadata
        annotated.append(spec)
    return annotated



def _selected_wave_number(state: Mapping[str, Any]) -> int | None:
    last_wave = state.get("last_wave") if isinstance(state.get("last_wave"), Mapping) else {}
    try:
        previous = int(last_wave.get("selected_wave") or 0)
    except (TypeError, ValueError):
        previous = 0
    return previous + 1 if previous else 1



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


def _record_statuses_from_grouped_specs(
    wave: Sequence[Mapping[str, Any]],
    specs: Sequence[AgentSpec],
    result: Mapping[str, str],
) -> dict[str, str]:
    spec_key_by_record_key: dict[str, str] = {}
    for spec in specs:
        source_group = spec.metadata.get("source_group") if isinstance(spec.metadata, Mapping) else {}
        decision_agent_keys = source_group.get("decision_agent_keys") if isinstance(source_group, Mapping) else []
        for agent_key in decision_agent_keys or ():
            cleaned = str(agent_key or "").strip()
            if cleaned:
                spec_key_by_record_key[cleaned] = spec.key
        spec_key_by_record_key.setdefault(spec.key, spec.key)
    statuses: dict[str, str] = {}
    for record in wave:
        agent_key = str(record.get("agent_key") or "").strip()
        spec_key = spec_key_by_record_key.get(agent_key, agent_key)
        statuses[agent_key] = result.get(spec_key, result.get(agent_key, "missing"))
    return statuses


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
    no_ledger: bool | None,
    skip_chain: bool | None,
) -> dict[str, Any]:
    current = state.get("run_config") if isinstance(state.get("run_config"), Mapping) else {}
    return {
        "live_testing_enabled": (
            bool(live_testing_enabled)
            if live_testing_enabled is not None
            else bool(current.get("live_testing_enabled", False))
        ),
        "no_ledger": (
            bool(no_ledger)
            if no_ledger is not None
            else bool(current.get("no_ledger", False))
        ),
        "skip_chain": (
            bool(skip_chain)
            if skip_chain is not None
            else bool(current.get("skip_chain", False))
        ),
    }
