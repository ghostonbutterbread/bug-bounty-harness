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
    environment_approval = payload["runtime_environment_approval"]
    assert environment_approval["schema_version"] == 1
    assert environment_approval["status"] == "approval_required"
    assert environment_approval["scope"]["program"] == "demo"
    assert environment_approval["scope"]["run_intent"] == "hunt-pipeline-live-testing"
    assert environment_approval["route_policy"]["denied_routes_override_allowed_routes"] is True
    assert environment_approval["surface_policy"]["default_decision"] == "allow_in_environment"
    assert environment_approval["surface_policy"]["allowed_by_default"] == [
        "ghidra-mcp",
        "mcp",
        "cdp",
        "ssh-local",
        "target-local-process",
        "localhost-tunnel-binding",
    ]
    action_policy = payload["runtime_action_policy"]
    assert action_policy["schema_version"] == 1
    assert action_policy["status"] == "active"
    assert action_policy["policy_id"] == "private-by-default-v1"
    assert action_policy["default_classification"] == "approval_required"
    assert action_policy["scope"]["program"] == "demo"
    assert "payment" not in action_policy["classifications"]["allowed_private"]["action_tags"]
    assert "payment" in action_policy["classifications"]["approval_required"]["action_tags"]
    protocol = payload["runtime_promotion_protocol"]
    assert protocol["schema_version"] == 1
    assert protocol["status"] == "draft"
    assert protocol["promotion_enabled"] is False
    assert [item["approval"] for item in protocol["required_approvals"]] == [
        "operator_live_execution_approval",
        "runtime_contract_update_review",
        "ledger_review_owner_assignment",
    ]
    assert protocol["adapter_ownership_boundaries"][0]["owner"] == "hunt_pipeline.runtime_adapter"
    assert "agent spawning" in protocol["adapter_ownership_boundaries"][0]["does_not_own"]
    assert protocol["ledger_review_ownership_boundaries"][0]["owner"] == "base_team.review"
    assert protocol["rollback_stop_semantics"]["default_on_protocol_error"] == "block promotion and keep execute-live rejected"
    assert protocol["future_promotion_steps"][-1]["step"] == "flip_promotion_enabled"
    assert protocol["future_promotion_steps"][-1]["status"] == "blocked"
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
        "promotion_protocol_non_live",
        "promotion_readiness_non_live",
        "explicit_contract_promotion",
    }
    gate_results = {result["gate_id"]: result for result in contract["gate_results"]}
    assert gate_results["runtime_handoff_contract_present"]["passed"] is True
    assert gate_results["runtime_adapter_non_live"]["passed"] is True
    assert gate_results["static_team_invocation_disabled"]["passed"] is True
    assert gate_results["dynamic_validation_disabled"]["passed"] is True
    assert gate_results["safety_flags_non_live"]["passed"] is True
    assert gate_results["promotion_protocol_non_live"]["passed"] is True
    assert gate_results["promotion_readiness_non_live"]["passed"] is True
    assert gate_results["explicit_contract_promotion"]["passed"] is False
    readiness = payload["runtime_promotion_readiness"]
    assert readiness["schema_version"] == 1
    assert readiness["status"] == "not_ready"
    assert readiness["promoted"] is False
    assert readiness["promotion_enabled"] is False
    assert readiness["live_execution_ready"] is False
    assert readiness["gates"]["promotion_allowed"] is False
    assert readiness["runtime_environment_approval"]["status"] == "approval_required"
    assert readiness["runtime_environment_approval"]["approved"] is False
    assert readiness["runtime_action_policy"]["status"] == "active"
    assert readiness["runtime_action_policy"]["valid"] is True
    assert readiness["preflight_states"]["runtime_environment_approval"]["status"] == "approval_required"
    assert readiness["preflight_states"]["runtime_action_policy"]["status"] == "active"
    assert readiness["preflight_states"]["static_team_handoffs"]["state"] == "planned-only"
    assert readiness["preflight_states"]["dynamic_validation_queue"]["state"] == "disabled"
    assert readiness["preflight_states"]["live_testing_playbook"]["state"] == "planned-only"
    approval_schema = payload["runtime_operator_approval_schema"]
    assert approval_schema["schema_version"] == 1
    assert approval_schema["status"] == "blocked"
    assert approval_schema["promotion_enabled"] is False
    assert approval_schema["promoted"] is False
    assert approval_schema["explicit_status"]["not_promoted"] is True
    assert list(approval_schema["required_approval_ids"]) == [
        "operator_live_execution_approval",
        "runtime_contract_update_review",
        "ledger_review_owner_assignment",
    ]
    assert {record["decision"] for record in approval_schema["approval_records"]} == {"missing"}
    request_packet = payload["runtime_promotion_request_packet"]
    assert request_packet["schema_version"] == 1
    assert request_packet["status"] == "blocked"
    assert request_packet["requested_action"] == "review_only"
    assert request_packet["promotion_enabled"] is False
    assert request_packet["promoted"] is False
    assert request_packet["explicit_status"]["not_promoted"] is True
    assert set(request_packet["evidence_sections"]) == {
        "runtime_handoff_contract",
        "runtime_promotion_protocol",
        "runtime_preflight_report",
        "runtime_promotion_readiness",
        "runtime_operator_approval_schema",
    }
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
    live_testing = payload["live_testing_playbook"]
    assert live_testing["status"] == "planned-only"
    assert live_testing["enabled"] is False
    assert live_testing["execution_enabled"] is False
    assert live_testing["environment_requirements"]["startup_policy"]["pipeline_target_launch_enabled"] is False
    assert [item["surface"] for item in live_testing["attachment_surfaces"]] == ["cdp", "ghidra", "mcp", "ssh"]


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


def test_dry_run_reuses_prior_map_without_remapping(tmp_path: Path, monkeypatch) -> None:
    prior_appmap = tmp_path / "hunt_pipeline_out" / "run-old" / "appmap" / "run-old"
    prior_appmap.mkdir(parents=True)
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    (prior_appmap / "manifest.json").write_text(
        json.dumps({"run_id": "run-old", "created_at": "2099-05-15T22:00:00Z", "target_path": str(target), "target_kind": "electron"}) + "\n",
        encoding="utf-8",
    )
    (prior_appmap / "target_profile.json").write_text(
        json.dumps({"program": "demo", "target_kind": "electron", "target_path": str(target)}) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(prior_appmap / "surfaces.jsonl", [{"id": "S0001", "kind": "ipc", "file": "src/main.js"}])
    _write_jsonl(prior_appmap / "flows.jsonl", [])
    prior_plan = tmp_path / "hunt_pipeline_out" / "run-old" / "pipeline_plan.json"
    prior_plan.write_text(
        json.dumps(
            {
                "program": "demo",
                "target_path": str(target),
                "appmap_source": {
                    "mode": "generated-neutral",
                    "run_root": str(prior_appmap),
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    def _unexpected_map_application(*args, **kwargs):
        raise AssertionError("map_application should not run when a fresh prior map is reusable")

    monkeypatch.setattr("agents.hunt_pipeline.dry_run.map_application", _unexpected_map_application)

    _, plan_path = build_dry_run_plan(
        program="demo",
        target_path=target,
        target_kind="auto",
        ruleset_id="auto",
        output_dir=tmp_path / "hunt_pipeline_out" / "run-new",
        cache_search_root=tmp_path / "hunt_pipeline_out",
    )
    payload = load_plan(plan_path)

    assert payload["appmap_source"]["mode"] == "reused-cache"
    assert payload["appmap_source"]["run_root"] == str(prior_appmap)
    assert payload["appmap_source"]["map_reuse_decision"]["action"] == "reuse"
    assert payload["artifact_metadata"]["appmap"]["decision"]["reason"] == "reused prior fresh map"



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
