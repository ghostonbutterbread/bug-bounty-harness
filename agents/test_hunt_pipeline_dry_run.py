from __future__ import annotations

import json
from pathlib import Path

from agents.hunt_pipeline.dry_run import build_dry_run_plan, load_plan


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_dry_run_writes_pipeline_plan_without_spawn_or_ledger(tmp_path: Path) -> None:
    appmap = tmp_path / "appmap" / "run-1"
    appmap.mkdir(parents=True)
    (appmap / "manifest.json").write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    (appmap / "target_profile.json").write_text('{"program":"demo","target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(
        appmap / "surfaces.jsonl",
        [
            {"id": "S0001", "kind": "ipc", "file": "src/main.js"},
            {"id": "S0002", "kind": "rendering", "file": "src/view.js"},
        ],
    )
    _write_jsonl(appmap / "flows.jsonl", [{"id": "F0001", "source_id": "S0002", "sink_id": "S0001"}])
    _write_jsonl(appmap / "candidates.jsonl", [{"id": "C0001", "surface_id": "S0001"}])

    artifact, plan_path = build_dry_run_plan(
        program="demo",
        target_path=tmp_path / "target",
        target_kind="auto",
        ruleset_id="auto",
        appmap_run=appmap,
        output_dir=tmp_path / "out",
    )
    payload = load_plan(plan_path)

    assert plan_path.name == "pipeline_plan.json"
    assert payload == json.loads(json.dumps(artifact.to_dict(), sort_keys=True))
    assert payload["selected_rulesets"]["selected_rulesets"] == ["desktop-baseline", "electron-overlay"]
    assert payload["normalized_map"]["counts"]["surfaces"] == 2
    assert [item["id"] for item in payload["normalized_map"]["surfaces"]] == ["S0001", "S0002"]
    assert payload["normalized_map"]["flows"] == [{"id": "F0001", "source_id": "S0002", "sink_id": "S0001"}]
    assert payload["normalized_map"]["legacy_candidates"][0]["pipeline_context"]["neutral_truth"] is False
    assert payload["normalized_map"]["legacy_policy_shaped"] is True
    assert {item["role"] for item in payload["hypotheses"]} == {"entry", "amplifier"}
    assert payload["runtime_adapter_availability"]["spawn_enabled"] is False
    assert payload["runtime_adapter_availability"]["ledger_writes_enabled"] is False
    assert payload["runtime_adapter_availability"]["conversion_only"] is True
    assert payload["runtime_adapter_availability"]["base_team_agent_spec"] is True
    assert payload["runtime_adapter_availability"]["dynamic_agent_builder_agent_spec"] is True
    assert payload["runtime_handoff_boundary"]["status"] == "explicit-non-live-boundary"
    assert "spawn BaseTeam/zero_day_team/apk_team/electron_team agents" in payload["runtime_handoff_boundary"]["prohibited_actions"]
    assert "operator approval of the runtime handoff contract" in payload["runtime_handoff_boundary"]["required_before_live_execution"]
    contract = payload["runtime_handoff_contract"]
    assert contract["schema_version"] == 1
    assert contract["status"] == "blocked"
    assert contract["promotion_allowed"] is False
    assert {gate["id"] for gate in contract["required_gates"]} >= {
        "runtime_handoff_contract_present",
        "runtime_adapter_non_live",
        "static_team_invocation_disabled",
        "dynamic_validation_disabled",
        "safety_flags_non_live",
        "explicit_contract_promotion",
    }
    gate_results = {result["gate_id"]: result for result in contract["gate_results"]}
    assert gate_results["runtime_handoff_contract_present"]["passed"] is True
    assert gate_results["runtime_adapter_non_live"]["passed"] is True
    assert gate_results["static_team_invocation_disabled"]["passed"] is True
    assert gate_results["dynamic_validation_disabled"]["passed"] is True
    assert gate_results["safety_flags_non_live"]["passed"] is True
    assert gate_results["explicit_contract_promotion"]["passed"] is False
    assert payload["safety"] == {
        "dry_run_only": True,
        "spawn_agents": False,
        "live_dynamic_validation": False,
        "ledger_writes": False,
    }
    assert payload["static_team_handoffs"]["enabled"] is False
    assert payload["static_team_handoffs"]["invocation_enabled"] is False
    assert [item["team"] for item in payload["static_team_handoffs"]["planned"]] == ["electron_team", "zero_day_team"]
    assert {item["invocation_status"] for item in payload["static_team_handoffs"]["planned"]} == {"planned-only"}
    assert payload["dynamic_validation_queue"]["enabled"] is False


def test_dry_run_writes_scheduler_decision_jsonl_artifacts(tmp_path: Path) -> None:
    appmap = tmp_path / "appmap" / "run-1"
    appmap.mkdir(parents=True)
    (appmap / "manifest.json").write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    (appmap / "target_profile.json").write_text('{"program":"demo","target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(
        appmap / "surfaces.jsonl",
        [
            {"id": "S0001", "kind": "ipc", "file": "src/main.js"},
            {"id": "S0002", "kind": "rendering", "file": "src/view.js"},
        ],
    )
    _write_jsonl(appmap / "flows.jsonl", [{"id": "F0001", "source_id": "S0002", "sink_id": "S0001"}])

    artifact, plan_path = build_dry_run_plan(
        program="demo",
        target_path=tmp_path / "target",
        target_kind="auto",
        ruleset_id="auto",
        appmap_run=appmap,
        output_dir=tmp_path / "out",
        max_agents=1,
        concurrent_agents=1,
    )
    payload = load_plan(plan_path)

    assert len(artifact.hypotheses) == 2
    assert payload["scheduler_plan"]["summary"]["selected"] == 1
    assert payload["scheduler_plan"]["summary"]["deferred"] == 1
    assert payload["scheduler_plan"]["summary"]["skipped"] == 0
    assert payload["scheduler_plan"]["summary"]["unrun"] == 1
    assert payload["scheduler_plan"]["selected_batches"][0]["max_concurrent"] == 1
    artifacts = payload["scheduler_plan"]["decision_artifacts"]
    selected_rows = _read_jsonl(Path(artifacts["selected_agents"]["path"]))
    deferred_rows = _read_jsonl(Path(artifacts["deferred_agents"]["path"]))
    skipped_rows = _read_jsonl(Path(artifacts["skipped_agents"]["path"]))
    unrun_rows = _read_jsonl(Path(artifacts["unrun_agents"]["path"]))

    assert artifacts["selected_agents"]["count"] == len(selected_rows) == 1
    assert artifacts["deferred_agents"]["count"] == len(deferred_rows) == 1
    assert artifacts["skipped_agents"]["count"] == len(skipped_rows) == 0
    assert artifacts["unrun_agents"]["count"] == len(unrun_rows) == 1
    assert deferred_rows == unrun_rows
    assert deferred_rows[0]["status"] == "deferred"
    assert deferred_rows[0]["reason"] == "max agents cap reached"
    assert selected_rows[0]["status"] == "selected"


def test_write_hypotheses_option_writes_jsonl_artifact_metadata(tmp_path: Path) -> None:
    appmap = tmp_path / "appmap" / "run-1"
    appmap.mkdir(parents=True)
    (appmap / "manifest.json").write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    (appmap / "target_profile.json").write_text('{"program":"demo","target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(
        appmap / "surfaces.jsonl",
        [
            {"id": "S0001", "kind": "ipc", "file": "src/main.js"},
            {"id": "S0002", "kind": "rendering", "file": "src/view.js"},
        ],
    )

    _, plan_path = build_dry_run_plan(
        program="demo",
        target_path=tmp_path / "target",
        target_kind="auto",
        ruleset_id="auto",
        appmap_run=appmap,
        output_dir=tmp_path / "out",
        write_hypotheses=True,
    )
    payload = load_plan(plan_path)
    metadata = payload["artifact_metadata"]["hypotheses"]
    rows = _read_jsonl(Path(metadata["path"]))

    assert Path(metadata["path"]).name == "hypotheses.jsonl"
    assert Path(metadata["path"]).parent == plan_path.parent
    assert metadata["count"] == len(payload["hypotheses"]) == len(rows) == 2
    assert [row["id"] for row in rows] == [item["id"] for item in payload["hypotheses"]]
    assert metadata["sha256"]
