from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.base_team import AgentSpec
from agents.hunt_pipeline.cli import build_parser
from agents.hunt_pipeline.run_state import (
    initialize_run_state,
    request_pause,
    request_stop,
    run_state_path_for_plan,
    save_run_state,
    summarize_run,
)
from agents.hunt_pipeline.runtime import execute_next_wave
from agents.hunt_pipeline.runtime_adapter import selected_decision_to_base_team_agent_spec




class MissingResultAdapter:
    def execute(self, specs):
        return {}


class RaisingAdapter:
    def execute(self, specs):
        raise RuntimeError("adapter exploded")


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
