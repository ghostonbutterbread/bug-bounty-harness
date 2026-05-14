from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.base_team import AgentSpec
from agents.hunt_pipeline.cli import build_parser
from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report, write_runtime_preflight_report
from agents.hunt_pipeline.run_state import (
    initialize_run_state,
    request_pause,
    request_stop,
    run_state_path_for_plan,
    save_run_state,
    summarize_run,
)
from agents.hunt_pipeline.runtime import execute_next_wave
from agents.hunt_pipeline.runtime_contract import (
    build_runtime_handoff_contract,
    build_runtime_promotion_protocol,
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
)
from agents.hunt_pipeline.runtime_adapter import selected_decision_to_base_team_agent_spec




class MissingResultAdapter:
    def execute(self, specs):
        return {}


class RaisingAdapter:
    def execute(self, specs):
        raise RuntimeError("adapter exploded")


class FailingIfCalledAdapter:
    def execute(self, specs):
        raise AssertionError("adapter must not be called")


def _decision(index: int, status: str = "selected") -> dict:
    return {
        "decision": "spawn" if status == "selected" else "defer",
        "reason": "selected" if status == "selected" else "max agents cap reached",
        "agent_key": f"agent-{index}",
        "hypothesis_id": f"HP-{index}",
        "surface_family": "ipc-bridge",
        "family_role": "application-entry",
        "priority": "high",
        "final_score": 1.0,
        "event": {"hypothesis_id": f"HP-{index}", "agent_key": f"agent-{index}"},
    }


def _packet(index: int) -> dict:
    return {
        "id": f"HP-{index}",
        "key": f"agent-{index}",
        "title": f"hypothesis {index}",
        "role": "entry",
        "surface_family": "ipc-bridge",
        "priority": "high",
        "target_kind": "electron",
        "ruleset_id": "electron-overlay",
        "source_evidence": [{"id": f"S{index:04d}", "kind": "ipc", "file": f"src/ipc{index}.ts"}],
        "evidence_requirements": ["trace ipc channel"],
        "focus_files": [f"src/ipc{index}.ts"],
        "scheduler_metadata": {"hypothesis_id": f"HP-{index}", "brainstorm_agent_key": f"agent-{index}"},
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _write_plan(tmp_path: Path, *, selected_count: int, deferred_count: int, concurrent_agents: int = 2) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    selected = [_decision(index, "selected") for index in range(1, selected_count + 1)]
    deferred = [_decision(index, "deferred") for index in range(selected_count + 1, selected_count + deferred_count + 1)]
    plan = {
        "program": "demo",
        "target_path": str(tmp_path / "target"),
        "appmap_source": {"mode": "loaded-existing", "run_root": str(tmp_path / "appmap" / "run-1")},
        "hypotheses": [_packet(index) for index in range(1, selected_count + deferred_count + 1)],
        "scheduler_plan": {
            "selected": selected,
            "deferred": deferred,
            "skipped": [],
            "selected_batches": [
                {
                    "batch_index": batch_index + 1,
                    "max_concurrent": concurrent_agents,
                    "agent_keys": [item["agent_key"] for item in selected[offset : offset + concurrent_agents]],
                    "hypothesis_ids": [item["hypothesis_id"] for item in selected[offset : offset + concurrent_agents]],
                    "agents": [
                        {"agent_key": item["agent_key"], "hypothesis_ids": [item["hypothesis_id"]]}
                        for item in selected[offset : offset + concurrent_agents]
                    ],
                }
                for batch_index, offset in enumerate(range(0, len(selected), concurrent_agents))
            ],
            "config": {"concurrent_agents": concurrent_agents, "max_agents": selected_count},
            "decision_artifacts": {
                "selected_agents": {"path": str(out / "selected_agents.jsonl"), "count": len(selected)},
                "deferred_agents": {"path": str(out / "deferred_agents.jsonl"), "count": len(deferred)},
                "unrun_agents": {"path": str(out / "unrun_agents.jsonl"), "count": len(deferred)},
            },
        },
    }
    _write_jsonl(out / "selected_agents.jsonl", [{**item, "status": "selected"} for item in selected])
    _write_jsonl(out / "deferred_agents.jsonl", [{**item, "status": "deferred"} for item in deferred])
    _write_jsonl(out / "unrun_agents.jsonl", [{**item, "status": "deferred"} for item in deferred])
    plan_path = out / "pipeline_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan_path


def _add_non_live_contract_sections(plan_path: Path) -> dict:
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["runtime_adapter_availability"] = {
        "base_team_agent_spec": True,
        "dynamic_agent_builder_agent_spec": True,
        "conversion_only": True,
        "spawn_enabled": False,
        "ledger_writes_enabled": False,
    }
    payload["static_team_handoffs"] = {
        "enabled": False,
        "invocation_enabled": False,
        "planned": [{"team": "zero_day_team", "invocation_status": "planned-only"}],
    }
    payload["dynamic_validation_queue"] = {"enabled": False, "queued": []}
    payload["safety"] = {
        "dry_run_only": True,
        "spawn_agents": False,
        "live_dynamic_validation": False,
        "ledger_writes": False,
    }
    payload["runtime_promotion_protocol"] = build_runtime_promotion_protocol().to_dict()
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(
        {**payload, "runtime_handoff_contract": {"schema_version": 1}}
    ).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def test_runtime_contract_treats_malformed_gate_shapes_as_failed(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["runtime_handoff_contract"]["schema_version"] = "not-an-int"
    payload["static_team_handoffs"]["planned"] = "planned-only"
    payload["dynamic_validation_queue"]["queued"] = "agent-key"

    contract = evaluate_runtime_handoff_contract(payload)

    failed_gate_ids = {gate["gate_id"] for gate in contract["gate_results"] if not gate["passed"]}
    assert "runtime_handoff_contract_present" in failed_gate_ids
    assert "static_team_invocation_disabled" in failed_gate_ids
    assert "dynamic_validation_disabled" in failed_gate_ids
    assert contract["promotion_allowed"] is False


def test_runtime_contract_treats_missing_or_malformed_protocol_as_not_promoted(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_promotion_protocol")
    missing_contract = evaluate_runtime_handoff_contract(payload)
    missing_protocol = evaluate_runtime_promotion_protocol(payload)
    missing_failed_gate_ids = {gate["gate_id"] for gate in missing_contract["gate_results"] if not gate["passed"]}

    assert missing_protocol["status"] == "missing"
    assert missing_protocol["promotion_enabled"] is False
    assert "promotion_protocol_non_live" in missing_failed_gate_ids
    assert missing_contract["promotion_allowed"] is False

    payload["runtime_promotion_protocol"] = {
        "schema_version": "not-an-int",
        "status": "promoted",
        "promotion_enabled": True,
        "required_approvals": "operator",
    }
    malformed_contract = evaluate_runtime_handoff_contract(payload)
    malformed_protocol = evaluate_runtime_promotion_protocol(payload)
    malformed_failed_gate_ids = {gate["gate_id"] for gate in malformed_contract["gate_results"] if not gate["passed"]}

    assert malformed_protocol["promotion_enabled"] is False
    assert malformed_protocol["stored_promotion_enabled"] is True
    assert malformed_protocol["valid"] is False
    assert "promotion_protocol_non_live" in malformed_failed_gate_ids
    assert malformed_contract["promotion_allowed"] is False


def test_status_summary_counts_completed_and_unrun_from_plan_state(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=7, deferred_count=3, concurrent_agents=3)
    state = initialize_run_state(plan_path)
    state["agents"] = {
        key: ({**value, "status": "completed"} if value["status"] == "selected" else value)
        for key, value in state["agents"].items()
    }
    save_run_state(state, run_state_path_for_plan(plan_path))

    summary = summarize_run(plan_path, concurrent_agents=3)

    assert summary["total"] == 10
    assert summary["completed"] == 7
    assert summary["unrun"] == 3
    assert summary["deferred"] == 3
    assert summary["next_wave_count"] == 3


def test_pause_and_stop_write_run_state_flags(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0)

    paused = request_pause(plan_path)
    stopped = request_stop(plan_path)

    assert paused["pause_requested"] is True
    assert stopped["stopped"] is True
    payload = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert payload["pause_requested"] is True
    assert payload["stopped"] is True


def test_resume_executes_next_deferred_wave_without_remapping(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=3, concurrent_agents=2)
    state = initialize_run_state(plan_path)
    state["agents"]["agent-1"]["status"] = "completed"
    state["agents"]["agent-2"]["status"] = "completed"
    save_run_state(state, run_state_path_for_plan(plan_path))

    result = execute_next_wave(plan_path, max_agents=2, concurrent_agents=2)

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-3", "agent-4"]
    assert result["summary"]["completed"] == 4
    assert result["summary"]["unrun"] == 1
    specs = [json.loads(line) for line in Path(result["specs_path"]).read_text(encoding="utf-8").splitlines()]
    assert [item["key"] for item in specs] == ["agent-3", "agent-4"]
    assert specs[0]["metadata"]["scheduler_decision"]["reason"] == "max agents cap reached"


def test_selected_decision_to_base_team_agent_spec_preserves_appmap_metadata() -> None:
    packet = _packet(1)
    decision = _decision(1)

    spec = selected_decision_to_base_team_agent_spec(
        decision,
        {"HP-1": packet},
        program="demo",
        snapshot_id="snapshot-1",
        created_at="2026-05-13T12:00:00Z",
    )

    assert isinstance(spec, AgentSpec)
    assert spec.key == "agent-1"
    assert spec.metadata["hypothesis_id"] == "HP-1"
    assert spec.metadata["selected_agent_key"] == "agent-1"
    assert spec.metadata["selected_hypothesis_ids"] == ["HP-1"]
    assert spec.metadata["source_evidence"][0]["file"] == "src/ipc1.ts"
    assert spec.focus_globs == ["src/ipc1.ts"]


def test_cli_help_exposes_subcommands_and_runtime_flags(capsys: pytest.CaptureFixture[str]) -> None:
    help_text = build_parser().format_help()
    with pytest.raises(SystemExit):
        build_parser().parse_args(["run", "--help"])
    run_help = capsys.readouterr().out

    assert "plan" in help_text
    assert "status" in help_text
    assert "resume" in help_text
    assert "--execute-live" in run_help
    assert "--write-hypotheses" in run_help


def test_resume_clears_pause_and_executes_next_wave(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0, concurrent_agents=2)
    request_pause(plan_path)

    from agents.hunt_pipeline.cli import main

    code = main(["resume", "--pipeline-plan", str(plan_path), "--concurrent-agents", "2"])

    assert code == 0
    summary = summarize_run(plan_path, concurrent_agents=2)
    assert summary["pause_requested"] is False
    assert summary["completed"] == 2


def test_adapter_missing_result_marks_wave_failed_not_running(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    result = execute_next_wave(plan_path, adapter=MissingResultAdapter())

    assert result["ok"] is False
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["status"] == "failed"
    assert state["agents"]["agent-1"]["details"]["adapter_status"] == "missing"


def test_adapter_exception_marks_wave_failed_not_running(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    result = execute_next_wave(plan_path, adapter=RaisingAdapter())

    assert result["ok"] is False
    assert "adapter exploded" in result["error"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["status"] == "failed"
    assert "adapter exploded" in state["agents"]["agent-1"]["details"]["error"]


def test_cli_main_none_reads_sys_argv(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    monkeypatch.setattr("sys.argv", ["hunt-pipeline", "--help"])

    with pytest.raises(SystemExit) as exc:
        main(None)

    assert exc.value.code == 0
    assert "Plan and control bounded AppMap" in capsys.readouterr().out


def test_status_text_format_includes_counts_and_control_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=1, concurrent_agents=2)
    state = initialize_run_state(plan_path)
    state["agents"]["agent-1"]["status"] = "completed"
    state["pause_requested"] = True
    save_run_state(state, run_state_path_for_plan(plan_path))

    code = main(["status", "--pipeline-plan", str(plan_path), "--format", "text", "--concurrent-agents", "2"])

    assert code == 0
    output = capsys.readouterr().out.strip()
    assert "completed=1" in output
    assert "unrun=2" in output
    assert "next_wave=0" in output
    assert "pause_requested=true" in output
    assert "stopped_requested=false" in output


def test_status_json_is_default_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    code = main(["status", "--pipeline-plan", str(plan_path)])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["completed"] == 0
    assert payload["unrun"] == 1
    assert payload["pause_requested"] is False
    assert payload["runtime_handoff_contract"]["promotion_allowed"] is False
    assert payload["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert payload["runtime_promotion_protocol"]["status"] == "missing"
    assert payload["runtime_preflight_report"]["promotion_enabled"] is False
    assert payload["runtime_preflight_report"]["status"] == "blocked"
    failed_gate_ids = {
        result["gate_id"]
        for result in payload["runtime_handoff_contract"]["gate_results"]
        if not result["passed"]
    }
    assert "runtime_handoff_contract_present" in failed_gate_ids


def test_run_planning_inputs_accept_write_hypotheses_without_live_execution(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    appmap = tmp_path / "appmap" / "run-1"
    appmap.mkdir(parents=True)
    (appmap / "manifest.json").write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    (appmap / "target_profile.json").write_text('{"program":"demo","target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(appmap / "surfaces.jsonl", [{"id": "S0001", "kind": "ipc", "file": "src/main.js"}])
    out = tmp_path / "out"

    code = main(
        [
            "run",
            "demo",
            str(tmp_path / "target"),
            "--from-appmap-run",
            str(appmap),
            "--output-dir",
            str(out),
            "--write-hypotheses",
        ]
    )

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    payload = json.loads((out / "pipeline_plan.json").read_text(encoding="utf-8"))
    metadata = payload["artifact_metadata"]["hypotheses"]
    rows = [json.loads(line) for line in (out / "hypotheses.jsonl").read_text(encoding="utf-8").splitlines()]
    assert result["executed"] == 1
    assert result["summary"]["completed"] == 1
    assert metadata["path"] == str(out / "hypotheses.jsonl")
    assert metadata["count"] == len(rows) == 1


def test_status_text_exposes_runtime_contract_promotion_state(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    code = main(["status", "--pipeline-plan", str(plan_path), "--format", "text"])

    assert code == 0
    output = capsys.readouterr().out.strip()
    assert "runtime_contract_status=blocked" in output
    assert "promotion_allowed=false" in output
    assert "promotion_protocol_status=draft" in output
    assert "promotion_enabled=false" in output
    assert "preflight_status=blocked" in output
    assert "static_team_handoffs=planned-only" in output
    assert "dynamic_validation_queue=disabled" in output


def test_preflight_report_summarizes_non_live_runtime_sections(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    report, report_path = write_runtime_preflight_report(plan_path)

    assert report_path == plan_path.parent / "runtime_preflight_report.json"
    assert json.loads(report_path.read_text(encoding="utf-8")) == report
    assert report["status"] == "blocked"
    assert report["promotion_enabled"] is False
    assert report["runtime_handoff_contract"]["status"] == "blocked"
    assert report["runtime_handoff_contract"]["promotion_allowed"] is False
    assert [gate["gate_id"] for gate in report["failed_required_gates"]] == ["explicit_contract_promotion"]
    assert report["runtime_promotion_protocol"]["status"] == "draft"
    assert report["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert report["runtime_promotion_protocol"]["valid"] is True
    assert report["static_team_handoffs"]["state"] == "planned-only"
    assert report["static_team_handoffs"]["planned_teams"] == ["zero_day_team"]
    assert report["dynamic_validation_queue"]["state"] == "disabled"
    blocker_ids = {item["id"] for item in report["blockers_before_future_promotion"]}
    assert "explicit_contract_promotion" in blocker_ids
    assert "operator_live_execution_approval" in blocker_ids
    assert "flip_promotion_enabled" in blocker_ids


def test_status_can_write_preflight_report_artifact(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    code = main(["status", "--pipeline-plan", str(plan_path), "--write-preflight-report"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    report_path = Path(payload["runtime_preflight_report_path"])
    assert report_path == plan_path.parent / "runtime_preflight_report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["promotion_enabled"] is False
    assert report["static_team_handoffs"]["state"] == "planned-only"
    assert report["dynamic_validation_queue"]["state"] == "disabled"


def test_preflight_report_blocks_missing_or_malformed_protocol(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_promotion_protocol")
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    missing_report = build_runtime_preflight_report(plan_path)

    assert missing_report["runtime_promotion_protocol"]["status"] == "missing"
    assert missing_report["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert "promotion_protocol_non_live" in {gate["gate_id"] for gate in missing_report["failed_required_gates"]}
    assert "runtime_promotion_protocol" in {item["id"] for item in missing_report["blockers_before_future_promotion"]}

    payload["runtime_promotion_protocol"] = {
        "schema_version": "not-an-int",
        "status": "promoted",
        "promotion_enabled": True,
        "required_approvals": "operator",
        "future_promotion_steps": 7,
    }
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    malformed_report = build_runtime_preflight_report(plan_path)

    assert malformed_report["runtime_promotion_protocol"]["status"] == "promoted"
    assert malformed_report["runtime_promotion_protocol"]["stored_promotion_enabled"] is True
    assert malformed_report["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert malformed_report["runtime_promotion_protocol"]["valid"] is False
    assert "promotion_protocol_non_live" in {gate["gate_id"] for gate in malformed_report["failed_required_gates"]}
    blocker_ids = {item["id"] for item in malformed_report["blockers_before_future_promotion"]}
    assert "required_approvals" in blocker_ids
    assert "future_promotion_steps" in blocker_ids


def test_execute_live_rejected_when_contract_missing_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    result = execute_next_wave(plan_path, execute_live=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert "runtime handoff contract" in result["error"]
    assert "runtime_handoff_contract_present" in {gate["gate_id"] for gate in result["failed_gates"]}
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_cli_execute_live_rejected_before_adapter_or_state_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    def fail_if_called(self, specs):
        raise AssertionError("adapter must not be called")

    monkeypatch.setattr(runtime.DryRunBaseTeamAdapter, "execute", fail_if_called)

    code = main(["run", "--pipeline-plan", str(plan_path), "--execute-live"])

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_cli_resume_execute_live_rejected_before_clearing_pause_or_state_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    def fail_if_called(self, specs):
        raise AssertionError("adapter must not be called")

    monkeypatch.setattr(runtime.DryRunBaseTeamAdapter, "execute", fail_if_called)

    code = main(["resume", "--pipeline-plan", str(plan_path), "--execute-live"])

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_execute_live_rejected_when_required_gate_fails_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["static_team_handoffs"]["invocation_enabled"] = True
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    failed_gate_ids = {gate["gate_id"] for gate in result["failed_gates"]}
    assert "static_team_invocation_disabled" in failed_gate_ids
    assert "explicit_contract_promotion" in failed_gate_ids
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_protocol_claims_enabled_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["runtime_promotion_protocol"]["promotion_enabled"] = True
    payload["runtime_promotion_protocol"]["status"] = "promoted"
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert result["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert result["runtime_promotion_protocol"]["stored_promotion_enabled"] is True
    failed_gate_ids = {gate["gate_id"] for gate in result["failed_gates"]}
    assert "promotion_protocol_non_live" in failed_gate_ids
    assert "explicit_contract_promotion" in failed_gate_ids
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_resume_recovers_stale_running_agents_after_interrupted_process(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    state = initialize_run_state(plan_path)
    state["agents"]["agent-1"]["status"] = "running"
    save_run_state(state, run_state_path_for_plan(plan_path))

    result = execute_next_wave(plan_path)

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-1"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["status"] == "completed"
    assert state["agents"]["agent-1"]["recovered_from_running"] is True


def test_resume_recovers_stale_running_deferred_agents_as_deferred(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=2, concurrent_agents=2)
    state = initialize_run_state(plan_path)
    state["agents"]["agent-1"]["status"] = "completed"
    state["agents"]["agent-2"]["status"] = "running"
    save_run_state(state, run_state_path_for_plan(plan_path))

    result = execute_next_wave(plan_path, max_agents=2, concurrent_agents=2)

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-2", "agent-3"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-2"]["status"] == "completed"
    assert state["agents"]["agent-2"]["recovered_from_running"] is True
