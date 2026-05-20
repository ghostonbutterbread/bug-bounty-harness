from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from agents.base_team import AgentSpec
from agents.hunt_pipeline.efficiency_logging import (
    finalize_efficiency_logging,
    find_matching_rollout,
    initialize_efficiency_logging,
    parse_rollout_usage,
    resolve_efficiency_dir,
)


def _spec() -> AgentSpec:
    return AgentSpec(
        key="ipc.filesystem.dist-main.pack001",
        vuln_class="ipc",
        surface="ipc-bridge",
        prompt_template="prompt",
        focus_globs=["dist/main.js"],
        code_patterns=["filesystem"],
        program="demo",
        created_at="2026-05-15T12:00:00Z",
        snapshot_id="run-1",
        metadata={
            "category_pack": {
                "pack_id": "ipc.filesystem.dist-main.pack001",
                "vuln_class": "ipc",
                "subclass": "ipc-filesystem",
                "surface_family": "ipc-bridge",
                "context_cluster_id": "dist-main",
                "source_files": ["dist/main.min.js"],
                "hypothesis_ids": ["HP-1", "HP-2"],
                "evidence_ids": ["S0001"],
                "reason": "same source cluster",
            },
            "category_pack_id": "ipc.filesystem.dist-main.pack001",
            "category_pack_hypothesis_ids": ["HP-1", "HP-2"],
            "category_pack_evidence_ids": ["S0001"],
            "source_files": ["dist/main.min.js"],
            "runtime_tracking": {"run_id": "run-eff", "pipeline_plan": "/tmp/pipeline_plan.json", "agent_key": "ipc.filesystem.dist-main.pack001"},
        },
    )


def _plan(plan_path: Path) -> dict:
    return {
        "run_id": "run-eff",
        "artifact_metadata": {"run": {"run_id": "run-eff"}},
        "program": "demo",
        "target_path": str(plan_path.parent / "target"),
    }


def _write_rollout(root: Path, *, marker: str, cwd: str, name: str = "rollout-test.jsonl") -> Path:
    rollout = root / ".codex" / "sessions" / "2026" / "05" / "15" / name
    rollout.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "timestamp": "2026-05-15T20:45:38.625Z",
            "type": "session_meta",
            "payload": {"id": "session-123", "cwd": cwd, "originator": "codex_exec", "cli_version": "0.129.0"},
        },
        {
            "timestamp": "2026-05-15T20:45:38.885Z",
            "type": "event_msg",
            "payload": {"type": "task_started", "started_at": 1778877938},
        },
        {
            "timestamp": "2026-05-15T20:45:40.809Z",
            "type": "event_msg",
            "payload": {"type": "user_message", "message": marker},
        },
        {
            "timestamp": "2026-05-15T20:45:47.002Z",
            "type": "response_item",
            "payload": {"type": "function_call", "name": "exec_command", "call_id": "call-1", "arguments": json.dumps({"cmd": "rg filesystem dist/main.min.js"})},
        },
        {
            "timestamp": "2026-05-15T20:45:54.568Z",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "call-1", "output": "Chunk ID: abc\nOriginal token count: 30001\nOutput:\n..."},
        },
        {
            "timestamp": "2026-05-15T20:46:21.059Z",
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {
                        "input_tokens": 1000,
                        "cached_input_tokens": 250,
                        "output_tokens": 200,
                        "reasoning_output_tokens": 10,
                        "total_tokens": 1200,
                    }
                },
            },
        },
    ]
    rollout.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return rollout


def test_initialize_efficiency_logging_writes_pack_plan_and_spawn_decisions(tmp_path: Path) -> None:
    plan_path = tmp_path / "run-eff" / "pipeline_plan.json"
    plan_path.parent.mkdir(parents=True)
    plan = _plan(plan_path)
    spec = _spec()

    efficiency_dir = initialize_efficiency_logging(
        plan_path,
        plan,
        specs=[spec],
        wave=[{"agent_key": "agent-1", "decision": "spawn", "reason": "selected", "final_score": 9.5}],
        spec_metrics={"collapsed_groups": 1},
        execution_mode="source-hunt",
        selected_wave=1,
    )

    assert efficiency_dir == resolve_efficiency_dir(plan_path, plan)
    pack_rows = [json.loads(line) for line in (efficiency_dir / "pack_plan.jsonl").read_text(encoding="utf-8").splitlines() if line]
    decision_rows = [json.loads(line) for line in (efficiency_dir / "spawn_decisions.jsonl").read_text(encoding="utf-8").splitlines() if line]
    assert pack_rows[0]["pack_id"] == "ipc.filesystem.dist-main.pack001"
    assert pack_rows[0]["pack_size"] == 2
    assert decision_rows[0]["decision"] == "spawn"
    assert decision_rows[0]["selected_wave"] == 1


def test_finalize_efficiency_logging_matches_rollout_and_writes_summary(tmp_path: Path) -> None:
    plan_path = tmp_path / "run-eff" / "pipeline_plan.json"
    plan_path.parent.mkdir(parents=True)
    plan = _plan(plan_path)
    spec = _spec()
    artifact_dir = tmp_path / "artifacts" / spec.key
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "README.txt").write_text("notes", encoding="utf-8")
    (artifact_dir / "specialist_requests.jsonl").write_text(
        json.dumps({"request_type": "specialist_followup", "parent_pack_id": spec.key}) + "\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "agent.log"
    log_path.write_text("Process running with session ID session-123\n", encoding="utf-8")
    marker = "Hunt pipeline run id: run-eff"
    _write_rollout(tmp_path, marker=marker, cwd="/home/ryushe/projects/bug_bounty_harness")

    with patch.object(Path, "home", return_value=tmp_path):
        efficiency_dir = finalize_efficiency_logging(
            plan_path,
            plan,
            specs=[spec],
            result={spec.key: "completed"},
            execution_details={
                spec.key: {
                    "log_path": str(log_path),
                    "prompt_path": str(tmp_path / "prompt.txt"),
                    "artifact_dir": str(artifact_dir),
                    "prompt_marker": marker,
                    "cwd": "/home/ryushe/projects/bug_bounty_harness",
                }
            },
        )

    usage_rows = [json.loads(line) for line in (efficiency_dir / "agent_usage.jsonl").read_text(encoding="utf-8").splitlines() if line]
    spike_rows = [json.loads(line) for line in (efficiency_dir / "tool_output_spikes.jsonl").read_text(encoding="utf-8").splitlines() if line]
    specialist_rows = [json.loads(line) for line in (efficiency_dir / "specialist_requests.jsonl").read_text(encoding="utf-8").splitlines() if line]
    summary = json.loads((efficiency_dir / "summary.json").read_text(encoding="utf-8"))

    assert usage_rows[0]["codex_session_id"] == "session-123"
    assert usage_rows[0]["tokens_total"] == 1200
    assert usage_rows[0]["max_tool_output_tokens"] == 30001
    assert spike_rows[0]["warning"] == "minified-broad-rg"
    assert specialist_rows[0]["request_type"] == "specialist_followup"
    assert summary["tool_output_spike_count"] == 1
    assert summary["specialist_request_count"] == 1


def test_find_matching_rollout_uses_unique_marker_and_artifact_cwd(tmp_path: Path) -> None:
    artifact_one = tmp_path / "artifacts" / "pack-1"
    artifact_two = tmp_path / "artifacts" / "pack-2"
    artifact_one.mkdir(parents=True)
    artifact_two.mkdir(parents=True)
    expected = _write_rollout(
        tmp_path,
        marker="Hunt pipeline run id: run-eff | agent key: pack-1",
        cwd=str(artifact_one),
        name="rollout-pack-1.jsonl",
    )
    _write_rollout(
        tmp_path,
        marker="Hunt pipeline run id: run-eff | agent key: pack-2",
        cwd=str(artifact_two),
        name="rollout-pack-2.jsonl",
    )

    with patch.object(Path, "home", return_value=tmp_path):
        matched = find_matching_rollout(
            marker="Hunt pipeline run id: run-eff | agent key: pack-1",
            cwd=str(artifact_one),
        )

    assert matched == expected



def test_parse_rollout_usage_extracts_token_totals_and_tool_calls(tmp_path: Path) -> None:
    rollout = _write_rollout(tmp_path, marker="Hunt pipeline run id: run-eff | agent key: pack-1", cwd="/repo")

    usage = parse_rollout_usage(rollout)

    assert usage["session_meta_id"] == "session-123"
    assert usage["tool_calls"] == 1
    assert usage["total_token_usage"]["total_tokens"] == 1200
    assert usage["original_token_counts"] == [30001]
