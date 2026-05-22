from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.base_team import AgentSpec
from agents.hunt_pipeline.cli import build_parser
from agents.hunt_pipeline.live_testing import build_live_testing_playbook
from agents.hunt_pipeline.operator_approval_schema import (
    build_runtime_operator_approval_schema,
    evaluate_runtime_operator_approval_schema,
    write_runtime_operator_approval_schema,
)
from agents.hunt_pipeline.preflight_report import build_runtime_preflight_report, write_runtime_preflight_report
from agents.hunt_pipeline.promotion_readiness import (
    build_runtime_promotion_readiness_checklist,
    non_live_readiness_stub,
    write_runtime_promotion_readiness_checklist,
)
from agents.hunt_pipeline.promotion_request_packet import (
    build_runtime_promotion_request_packet,
    evaluate_runtime_promotion_request_packet,
    write_runtime_promotion_request_packet,
)
from agents.hunt_pipeline.runtime_action_policy import build_runtime_action_policy
from agents.hunt_pipeline.runtime_environment_approval import build_runtime_environment_approval
from agents.hunt_pipeline.run_state import (
    initialize_run_state,
    request_pause,
    request_stop,
    run_state_path_for_plan,
    save_run_state,
    summarize_run,
)
from agents.hunt_pipeline.runtime import _append_run_amplifier_findings, _split_amplifier_hold_findings, execute_next_wave
from agents.hunt_pipeline.runtime_contract import (
    build_runtime_handoff_contract,
    build_runtime_promotion_protocol,
    evaluate_runtime_handoff_contract,
    evaluate_runtime_promotion_protocol,
    evaluate_runtime_promotion_readiness,
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


class PromisingEntryAdapter:
    def __init__(self, *entry_ids: str) -> None:
        self.last_promising_entry_ids = entry_ids

    def execute(self, specs):
        return {spec.key: "completed" for spec in specs}


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


def _packet(index: int, *, role: str = "entry") -> dict:
    return {
        "id": f"HP-{index}",
        "key": f"agent-{index}",
        "title": f"hypothesis {index}",
        "role": role,
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


def _write_appmap_run(tmp_path: Path, *, surface_count: int) -> Path:
    appmap = tmp_path / "appmap" / "run-1"
    appmap.mkdir(parents=True)
    (appmap / "manifest.json").write_text('{"run_id":"run-1"}\n', encoding="utf-8")
    (appmap / "target_profile.json").write_text('{"program":"demo","target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(
        appmap / "surfaces.jsonl",
        [
            {"id": f"S{index:04d}", "kind": "ipc", "file": f"src/ipc{index}.js"}
            for index in range(1, surface_count + 1)
        ],
    )
    return appmap


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


def _add_valid_runtime_promotion_decision(plan_path: Path, tmp_path: Path) -> dict:
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload = _add_phase20_safety_artifacts(plan_path, payload, approved_environment=True)
    payload.setdefault(
        "live_testing_playbook",
        build_live_testing_playbook(target_kind="electron", ruleset_id="electron-overlay").to_dict(),
    )
    payload["runtime_promotion_decision"] = {
        "schema_version": 1,
        "decision_id": "runtime-promotion-test",
        "decision": "promote-runtime",
        "status": "approved",
        "promotion_enabled": True,
        "execution_mode": "live",
        "approved_by": "operator@example.test",
        "approved_at": "2026-05-13T12:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "scope": {
            "pipeline_plan": str(plan_path.resolve(strict=False)),
            "program": "demo",
            "target_path": str((tmp_path / "target").resolve(strict=False)),
            "appmap_run": str((tmp_path / "appmap" / "run-1").resolve(strict=False)),
        },
        "controls": {
            "bounded_live_execution": True,
            "use_base_team_primitives": True,
            "scope_and_wave_controls": True,
            "live_testing_playbook_reviewed": True,
        },
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload["runtime_promotion_decision"]


def _add_phase20_safety_artifacts(
    plan_path: Path,
    payload: dict,
    *,
    approved_environment: bool,
) -> dict:
    environment_approval = build_runtime_environment_approval(plan_path, plan=payload).to_dict()
    if approved_environment:
        environment_approval.update(
            {
                "status": "approved",
                "environment_id": "aitestvm-1",
                "environment_type": "linux-vm",
                "approval_owner": "operator@example.test",
                "approved_at": "2026-05-13T12:00:00Z",
                "expires_at": "2999-01-01T00:00:00Z",
            }
        )
        environment_approval["route_policy"]["approved_route_roots"] = [
            {"kind": "hostname", "route": "vm.internal", "description": "approved VM control plane"},
            {"kind": "loopback", "route": "127.0.0.1:9222", "description": "approved CDP endpoint"},
            {"kind": "loopback", "route": "127.0.0.1:3300", "description": "approved MCP endpoint"},
        ]
    payload["runtime_environment_approval"] = environment_approval
    payload["runtime_action_policy"] = build_runtime_action_policy(plan_path, plan=payload).to_dict()
    return payload


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
    payload["live_testing_playbook"] = build_live_testing_playbook(
        target_kind="electron",
        ruleset_id="electron-overlay",
    ).to_dict()
    payload["safety"] = {
        "dry_run_only": True,
        "spawn_agents": False,
        "live_dynamic_validation": False,
        "ledger_writes": False,
    }
    payload["runtime_promotion_protocol"] = build_runtime_promotion_protocol().to_dict()
    payload["runtime_promotion_readiness"] = non_live_readiness_stub()
    payload = _add_phase20_safety_artifacts(plan_path, payload, approved_environment=False)
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(
        {**payload, "runtime_handoff_contract": {"schema_version": 1}}
    ).to_dict()
    payload["runtime_promotion_readiness"] = build_runtime_promotion_readiness_checklist(
        plan_path,
        plan=payload,
    ).to_dict()
    payload["runtime_operator_approval_schema"] = build_runtime_operator_approval_schema(
        plan_path,
        plan=payload,
    ).to_dict()
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(
        {**payload, "runtime_handoff_contract": {"schema_version": 1}}
    ).to_dict()
    payload["runtime_promotion_request_packet"] = build_runtime_promotion_request_packet(
        plan_path,
        plan=payload,
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


def test_runtime_contract_treats_missing_malformed_or_enabled_readiness_as_not_promoted(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_promotion_readiness")
    missing_contract = evaluate_runtime_handoff_contract(payload)
    missing_readiness = evaluate_runtime_promotion_readiness(payload)
    missing_failed_gate_ids = {gate["gate_id"] for gate in missing_contract["gate_results"] if not gate["passed"]}

    assert missing_readiness["status"] == "missing"
    assert missing_readiness["promotion_enabled"] is False
    assert missing_readiness["promoted"] is False
    assert "promotion_readiness_non_live" in missing_failed_gate_ids
    assert missing_contract["promotion_allowed"] is False

    payload["runtime_promotion_readiness"] = {
        "schema_version": "not-an-int",
        "status": "ready",
        "promotion_enabled": True,
        "promoted": True,
        "live_execution_ready": True,
        "required_approvals": "operator",
    }
    malformed_contract = evaluate_runtime_handoff_contract(payload)
    malformed_readiness = evaluate_runtime_promotion_readiness(payload)
    malformed_failed_gate_ids = {gate["gate_id"] for gate in malformed_contract["gate_results"] if not gate["passed"]}

    assert malformed_readiness["promotion_enabled"] is False
    assert malformed_readiness["stored_promotion_enabled"] is True
    assert malformed_readiness["promoted"] is False
    assert malformed_readiness["stored_promoted"] is True
    assert malformed_readiness["live_execution_ready"] is False
    assert malformed_readiness["stored_live_execution_ready"] is True
    assert malformed_readiness["valid"] is False
    assert "promotion_readiness_non_live" in malformed_failed_gate_ids
    assert malformed_contract["promotion_allowed"] is False

    payload["runtime_promotion_readiness"] = {
        "schema_version": 1,
        "status": "not_ready",
        "promotion_enabled": "true",
        "promoted": 1,
        "live_execution_ready": "false",
        "required_approvals": [{"approval": "operator", "required": True}],
        "blockers": [],
        "gates": {"status": "blocked", "promotion_allowed": True},
        "preflight_states": {"status": "blocked", "promotion_enabled": "true"},
    }
    stringy_contract = evaluate_runtime_handoff_contract(payload)
    stringy_readiness = evaluate_runtime_promotion_readiness(payload)
    stringy_failed_gate_ids = {gate["gate_id"] for gate in stringy_contract["gate_results"] if not gate["passed"]}

    assert stringy_readiness["promotion_enabled"] is False
    assert stringy_readiness["promoted"] is False
    assert stringy_readiness["live_execution_ready"] is False
    assert stringy_readiness["valid"] is False
    assert "promotion_readiness_non_live" in stringy_failed_gate_ids
    assert stringy_contract["promotion_allowed"] is False

    payload["runtime_promotion_readiness"] = {
        "schema_version": 1,
        "status": "not_ready",
        "required_approvals": [{"approval": "operator", "required": True}],
        "blockers": [],
        "gates": {"status": "blocked", "promotion_allowed": False},
        "preflight_states": {"status": "blocked", "promotion_enabled": False},
        "explicit_status": {"ready": False, "promoted": False},
    }
    missing_flags_contract = evaluate_runtime_handoff_contract(payload)
    missing_flags_readiness = evaluate_runtime_promotion_readiness(payload)
    missing_flags_failed_gate_ids = {
        gate["gate_id"] for gate in missing_flags_contract["gate_results"] if not gate["passed"]
    }

    assert missing_flags_readiness["valid"] is False
    assert "promotion_readiness_non_live" in missing_flags_failed_gate_ids
    assert missing_flags_contract["promotion_allowed"] is False

    payload["runtime_promotion_readiness"] = {
        "schema_version": 1,
        "status": "not_ready",
        "promotion_enabled": False,
        "promoted": False,
        "live_execution_ready": False,
        "required_approvals": [{"approval": "operator", "required": True}],
        "blockers": [],
        "gates": {"status": "blocked", "promotion_allowed": False},
        "preflight_states": {"status": "blocked", "promotion_enabled": False},
        "explicit_status": {"ready": True, "promoted": True},
    }
    explicit_claim_contract = evaluate_runtime_handoff_contract(payload)
    explicit_claim_readiness = evaluate_runtime_promotion_readiness(payload)
    explicit_claim_failed_gate_ids = {
        gate["gate_id"] for gate in explicit_claim_contract["gate_results"] if not gate["passed"]
    }

    assert explicit_claim_readiness["valid"] is False
    assert explicit_claim_readiness["live_execution_ready"] is False
    assert "promotion_readiness_non_live" in explicit_claim_failed_gate_ids
    assert explicit_claim_contract["promotion_allowed"] is False


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


def test_skip_chain_omits_pure_amplifier_wave_without_marking_terminal(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=3, deferred_count=0, concurrent_agents=3)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="amplifier")
    payload["hypotheses"][1] = _packet(2, role="chain")
    payload["hypotheses"][2] = _packet(3, role="entry")
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, max_agents=3, concurrent_agents=3, skip_chain=True)

    assert result["ok"] is True
    assert result["skip_chain"] is True
    assert result["agent_keys"] == ["agent-3"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["run_config"]["skip_chain"] is True
    assert state["agents"]["agent-1"]["status"] == "selected"
    assert state["agents"]["agent-2"]["status"] == "selected"
    assert state["agents"]["agent-3"]["status"] == "completed"


def test_skip_chain_falls_through_to_deferred_entry_when_selected_are_chain_only(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=1, concurrent_agents=3)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="amplifier")
    payload["hypotheses"][1] = _packet(2, role="chain")
    payload["hypotheses"][2] = _packet(3, role="entry")
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, max_agents=3, concurrent_agents=3, skip_chain=True)

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-3"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["status"] == "selected"
    assert state["agents"]["agent-2"]["status"] == "selected"
    assert state["agents"]["agent-3"]["status"] == "completed"


def test_skip_chain_keeps_mixed_entry_amplifier_group_runnable(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0, concurrent_agents=2)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="entry")
    payload["hypotheses"][1] = _packet(2, role="amplifier")
    payload["scheduler_plan"]["selected"][0]["member_hypothesis_ids"] = ["HP-1", "HP-2"]
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, max_agents=1, concurrent_agents=1, skip_chain=True)

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-1"]


def test_trigger_entry_id_runs_matching_amplifier_from_activation_index(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=1, concurrent_agents=2)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="entry")
    payload["hypotheses"][1] = _packet(2, role="amplifier")
    activation_path = plan_path.parent / "chain_activation_index.json"
    activation_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "activations": [
                    {
                        "id": "HP-1",
                        "key": "agent-1",
                        "unlocked_amplifiers": [{"id": "HP-2", "key": "agent-2"}],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    payload["artifact_metadata"] = {
        "run": {"run_id": "trigger-test"},
        "chain_activation_index": {"path": str(activation_path)},
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, max_agents=2, concurrent_agents=2, trigger_entry_ids=("HP-1",))

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-2"]
    assert result["trigger_entry_ids"] == ["HP-1"]
    assert result["triggered_hypothesis_ids"] == ["HP-2"]


def test_trigger_entry_id_overrides_skip_chain_for_focused_chain_runs(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=1, concurrent_agents=2)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="entry")
    payload["hypotheses"][1] = _packet(2, role="amplifier")
    activation_path = plan_path.parent / "chain_activation_index.json"
    activation_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "activations": [{"id": "HP-1", "unlocked_amplifiers": [{"id": "HP-2"}]}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    payload["artifact_metadata"] = {
        "run": {"run_id": "trigger-skip-chain-test"},
        "chain_activation_index": {"path": str(activation_path)},
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(
        plan_path,
        max_agents=2,
        concurrent_agents=2,
        skip_chain=True,
        trigger_entry_ids=("HP-1",),
    )

    assert result["ok"] is True
    assert result["agent_keys"] == ["agent-2"]
    assert result["skip_chain"] is True


def test_promising_entry_queues_next_resume_chain_wave(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=1, concurrent_agents=2)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][0] = _packet(1, role="entry")
    payload["hypotheses"][1] = _packet(2, role="amplifier")
    activation_path = plan_path.parent / "chain_activation_index.json"
    activation_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "activations": [{"id": "HP-1", "unlocked_amplifiers": [{"id": "HP-2"}]}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    payload["artifact_metadata"] = {
        "run": {"run_id": "auto-trigger-test"},
        "chain_activation_index": {"path": str(activation_path)},
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    entry_result = execute_next_wave(
        plan_path,
        max_agents=1,
        concurrent_agents=1,
        adapter=PromisingEntryAdapter("HP-1"),
    )
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))

    assert entry_result["agent_keys"] == ["agent-1"]
    assert entry_result["queued_trigger_entry_ids"] == ["HP-1"]
    assert state["pending_trigger_entry_ids"] == ["HP-1"]

    chain_result = execute_next_wave(plan_path, max_agents=2, concurrent_agents=2)
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))

    assert chain_result["agent_keys"] == ["agent-2"]
    assert chain_result["auto_trigger_entry_ids"] == ["HP-1"]
    assert chain_result["triggered_hypothesis_ids"] == ["HP-2"]
    assert state["pending_trigger_entry_ids"] == []


def test_runtime_parser_accepts_skip_chain_for_light_runs() -> None:
    args = build_parser().parse_args(["resume", "--output-dir", "/tmp/demo-run", "--skip-chain"])

    assert args.skip_chain is True


def test_runtime_parser_accepts_trigger_entry_ids_for_chain_runs() -> None:
    args = build_parser().parse_args(
        ["resume", "--output-dir", "/tmp/demo-run", "--trigger-entry-id", "HP-1", "--trigger-entry-id", "HP-2"]
    )

    assert args.trigger_entry_id == ["HP-1", "HP-2"]


def test_amplifier_hold_findings_are_split_from_reviewable_findings() -> None:
    amplifier, reviewable = _split_amplifier_hold_findings(
        [
            {
                "type": "hostrpc branch",
                "finding_role": "amplifier",
                "entry_status": "missing",
                "reportability": "hold_for_chain",
            },
            {
                "type": "import xss",
                "finding_role": "entry",
                "entry_status": "proven",
                "reportability": "submit",
            },
        ]
    )

    assert [item["type"] for item in amplifier] == ["hostrpc branch"]
    assert [item["type"] for item in reviewable] == ["import xss"]


def test_amplifier_findings_report_merges_duplicate_entries(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    finding = {
        "agent": "agent-1",
        "type": "hostrpc branch",
        "finding_role": "amplifier",
        "entry_status": "missing",
        "reportability": "hold_for_chain",
        "file": "src/main.js",
        "line": 7,
        "required_entry_primitives": ["renderer_xss"],
        "chain_handles": ["HostRpc.download"],
    }

    report_path = _append_run_amplifier_findings(reports_root, [finding])
    _append_run_amplifier_findings(reports_root, [finding])

    rows = [
        json.loads(line)
        for line in (reports_root / "findings" / "amplifier_findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    report = report_path.read_text(encoding="utf-8")

    assert len(rows) == 1
    assert rows[0]["type"] == "hostrpc branch"
    assert report.count("## hostrpc branch") == 1


def test_execute_next_wave_writes_efficiency_artifacts(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    result = execute_next_wave(plan_path)

    assert result["ok"] is True
    efficiency_dir = Path(result["efficiency_dir"])
    assert efficiency_dir.exists()
    assert (efficiency_dir / "pack_plan.jsonl").exists()
    assert (efficiency_dir / "spawn_decisions.jsonl").exists()
    assert (efficiency_dir / "agent_usage.jsonl").exists()
    assert (efficiency_dir / "summary.json").exists()
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["last_wave"]["efficiency_dir"] == str(efficiency_dir)



def test_runtime_collapses_duplicate_source_groups_and_marks_member_records_completed(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0, concurrent_agents=2)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["hypotheses"][1]["source_evidence"] = [{"id": "S0001", "kind": "ipc", "file": "src/ipc1.ts"}]
    payload["hypotheses"][1]["focus_files"] = ["src/ipc1.ts"]
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, max_agents=2, concurrent_agents=2)

    assert result["ok"] is True
    assert result["executed"] == 2
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["status"] == "completed"
    assert state["agents"]["agent-2"]["status"] == "completed"
    assert state["last_wave"]["spec_metrics"]["collapsed_groups"] == 1
    specs = [json.loads(line) for line in Path(result["specs_path"]).read_text(encoding="utf-8").splitlines()]
    assert len(specs) == 1
    assert specs[0]["metadata"]["source_group"]["decision_agent_keys"] == ["agent-1", "agent-2"]


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
    assert "runs" in help_text
    assert "list-runs" in help_text
    assert "live" in help_text
    assert "live-test" in help_text
    assert "--dry-run" in run_help
    assert "--live-testing" in run_help
    assert "--live" in run_help
    assert "--run-hypotheses" in run_help
    assert "--max-agents" in run_help
    assert "--remap" in run_help
    assert "--diff" in run_help
    assert "--write-hypotheses" in run_help
    assert "--no-write-hypotheses" in run_help
    assert "--no-ledger" in run_help
    assert "approved runtime" in run_help
    assert "environment" in run_help


def test_resume_clears_pause_and_executes_next_wave(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0, concurrent_agents=2)
    request_pause(plan_path)

    from agents.hunt_pipeline.cli import main

    code = main(["resume", "--pipeline-plan", str(plan_path), "--concurrent-agents", "2", "--dry-run"])

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
    assert payload["runtime_promotion_readiness"]["status"] == "not_ready"
    assert payload["runtime_promotion_readiness"]["promoted"] is False
    assert payload["runtime_promotion_readiness"]["promotion_enabled"] is False
    assert payload["runtime_promotion_readiness"]["live_execution_ready"] is False
    assert payload["runtime_promotion_decision"]["status"] == "missing"
    assert payload["runtime_promotion_decision"]["promoted"] is False
    assert payload["runtime_execution"]["mode"] == "blocked"
    failed_gate_ids = {
        result["gate_id"]
        for result in payload["runtime_handoff_contract"]["gate_results"]
        if not result["passed"]
    }
    assert "runtime_handoff_contract_present" in failed_gate_ids


def test_run_planning_inputs_write_hypotheses_by_default_without_live_execution(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    appmap = _write_appmap_run(tmp_path, surface_count=1)
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
            "--dry-run",
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


def test_plan_defaults_to_run_hypotheses_cap_10_and_writes_hypotheses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    appmap = _write_appmap_run(tmp_path, surface_count=12)
    out = tmp_path / "out"

    code = main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--output-dir", str(out)])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    payload = json.loads(Path(result["pipeline_plan"]).read_text(encoding="utf-8"))
    assert len(payload["hypotheses"]) == 12
    assert payload["scheduler_plan"]["summary"]["selected"] == 10
    assert payload["scheduler_plan"]["summary"]["deferred"] == 2
    assert payload["scheduler_plan"]["config"]["max_agents"] == 10
    assert Path(payload["artifact_metadata"]["hypotheses"]["path"]).exists()


def test_plan_run_hypotheses_n_and_all_control_selected_count(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    appmap = _write_appmap_run(tmp_path, surface_count=12)
    out_n = tmp_path / "out-n"
    out_all = tmp_path / "out-all"

    code_n = main(
        [
            "plan",
            "demo",
            str(tmp_path / "target"),
            "--from-appmap-run",
            str(appmap),
            "--output-dir",
            str(out_n),
            "--run-hypotheses",
            "3",
        ]
    )
    assert code_n == 0
    payload_n = json.loads((out_n / "pipeline_plan.json").read_text(encoding="utf-8"))
    assert payload_n["scheduler_plan"]["summary"]["selected"] == 3
    assert payload_n["scheduler_plan"]["summary"]["deferred"] == 9
    assert payload_n["scheduler_plan"]["config"]["max_agents"] == 3

    capsys.readouterr()
    code_all = main(
        [
            "plan",
            "demo",
            str(tmp_path / "target"),
            "--from-appmap-run",
            str(appmap),
            "--output-dir",
            str(out_all),
            "--run-hypotheses",
            "all",
        ]
    )
    assert code_all == 0
    payload_all = json.loads((out_all / "pipeline_plan.json").read_text(encoding="utf-8"))
    assert payload_all["scheduler_plan"]["summary"]["selected"] == 12
    assert payload_all["scheduler_plan"]["summary"]["deferred"] == 0
    assert payload_all["scheduler_plan"]["config"]["max_agents"] is None


def test_plan_tmp_uses_isolated_tmp_output_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    appmap = _write_appmap_run(tmp_path, surface_count=1)

    code = main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--tmp"])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    plan_path = Path(result["pipeline_plan"])
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan_path.parent != tmp_path / "hunt_pipeline_out"
    assert str(plan_path.parent).startswith("/tmp/")
    assert payload["artifact_metadata"]["tmp_output"]["enabled"] is True
    assert payload["artifact_metadata"]["tmp_output"]["root"] == str(plan_path.parent)
    assert Path(payload["artifact_metadata"]["hypotheses"]["path"]).parent == plan_path.parent


def test_default_plan_creates_unique_durable_run_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    monkeypatch.chdir(tmp_path)
    appmap = _write_appmap_run(tmp_path, surface_count=1)

    first_code = main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap)])
    assert first_code == 0
    first = json.loads(capsys.readouterr().out)
    second_code = main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap)])
    assert second_code == 0
    second = json.loads(capsys.readouterr().out)

    first_plan = Path(first["pipeline_plan"])
    second_plan = Path(second["pipeline_plan"])
    assert first["run_id"] == first_plan.parent.name
    assert second["run_id"] == second_plan.parent.name
    first_payload = json.loads(first_plan.read_text(encoding="utf-8"))
    second_payload = json.loads(second_plan.read_text(encoding="utf-8"))
    assert first_plan.parent.parent == tmp_path / "hunt_pipeline_out"
    assert second_plan.parent.parent == tmp_path / "hunt_pipeline_out"
    assert first_plan.parent != second_plan.parent
    assert first_payload["run_id"] == first_plan.parent.name
    assert second_payload["run_id"] == second_plan.parent.name
    assert Path(first_payload["artifact_metadata"]["hypotheses"]["path"]).parent == first_plan.parent
    assert Path(second_payload["artifact_metadata"]["hypotheses"]["path"]).parent == second_plan.parent


def test_run_id_status_runs_listing_and_latest_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    monkeypatch.chdir(tmp_path)
    appmap = _write_appmap_run(tmp_path, surface_count=2)

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "run-aaa"]) == 0
    capsys.readouterr()
    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "run-zzz"]) == 0
    capsys.readouterr()

    status_code = main(["status", "--run-id", "run-aaa", "--concurrent-agents", "2"])
    assert status_code == 0
    status = json.loads(capsys.readouterr().out)
    assert status["run_id"] == "run-aaa"
    assert status["pipeline_plan"].endswith("hunt_pipeline_out/run-aaa/pipeline_plan.json")

    runs_code = main(["runs", "--limit", "5"])
    assert runs_code == 0
    runs = json.loads(capsys.readouterr().out)["runs"]
    assert [row["run_id"] for row in runs[:2]] == ["run-zzz", "run-aaa"]
    assert {"program", "target_kind", "selected", "completed", "unrun", "next_wave", "path", "updated_at"}.issubset(runs[0])

    resume_code = main(["resume", "--dry-run", "--concurrent-agents", "2"])
    assert resume_code == 0
    resumed = json.loads(capsys.readouterr().out)
    assert resumed["summary"]["pipeline_plan"].endswith("hunt_pipeline_out/run-zzz/pipeline_plan.json")
    assert resumed["summary"]["completed"] == 2


def test_runs_excludes_tmp_and_latest_resume_ignores_tmp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    monkeypatch.chdir(tmp_path)
    appmap = _write_appmap_run(tmp_path, surface_count=1)

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "durable-run"]) == 0
    durable_plan = Path(json.loads(capsys.readouterr().out)["pipeline_plan"])

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--tmp"]) == 0
    tmp_plan = Path(json.loads(capsys.readouterr().out)["pipeline_plan"])
    tmp_state = initialize_run_state(tmp_plan)
    tmp_state["updated_at"] = "2999-01-01T00:00:00Z"
    run_state_path_for_plan(tmp_plan).write_text(json.dumps(tmp_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    runs_code = main(["runs"])
    assert runs_code == 0
    runs = json.loads(capsys.readouterr().out)["runs"]
    assert [row["run_id"] for row in runs] == ["durable-run"]

    resume_code = main(["resume", "--dry-run"])
    assert resume_code == 0
    resumed = json.loads(capsys.readouterr().out)
    assert Path(resumed["summary"]["pipeline_plan"]) == durable_plan
    assert resumed["summary"]["completed"] == 1
    assert summarize_run(tmp_plan)["completed"] == 0


def test_pause_stop_and_run_existing_plan_support_run_id_locator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    monkeypatch.chdir(tmp_path)
    appmap = _write_appmap_run(tmp_path, surface_count=1)

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "run-locator"]) == 0
    capsys.readouterr()

    pause_code = main(["pause", "--run-id", "run-locator"])
    assert pause_code == 0
    pause_payload = json.loads(capsys.readouterr().out)
    assert pause_payload["pause_requested"] is True

    stop_code = main(["stop", "--run-id", "run-locator"])
    assert stop_code == 0
    stop_payload = json.loads(capsys.readouterr().out)
    assert stop_payload["stopped"] is True

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "run-exec"]) == 0
    capsys.readouterr()

    run_code = main(["run", "--run-id", "run-exec", "--dry-run"])
    assert run_code == 0
    run_payload = json.loads(capsys.readouterr().out)
    assert run_payload["summary"]["run_id"] == "run-exec"
    assert run_payload["executed"] == 1


def test_live_supports_run_id_locator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    monkeypatch.chdir(tmp_path)
    appmap = _write_appmap_run(tmp_path, surface_count=1)
    (tmp_path / "target").mkdir()

    assert main(["plan", "demo", str(tmp_path / "target"), "--from-appmap-run", str(appmap), "--run-id", "live-locator"]) == 0
    plan_path = Path(json.loads(capsys.readouterr().out)["pipeline_plan"])
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)

    def fake_live_execute(self, specs):
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_live_execute)

    code = main(["live", "--run-id", "live-locator"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["execution_mode"] == "live"
    assert payload["summary"]["run_id"] == "live-locator"


def test_status_run_hypotheses_caps_next_wave(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=12, deferred_count=0, concurrent_agents=12)

    code = main(
        [
            "status",
            "--pipeline-plan",
            str(plan_path),
            "--concurrent-agents",
            "12",
            "--run-hypotheses",
            "4",
        ]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["next_wave_count"] == 4


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
    assert "readiness_status=not_ready" in output
    assert "readiness_promoted=false" in output
    assert "live_execution_ready=false" in output
    assert "promotion_decision_status=missing" in output
    assert "promotion_decision_promoted=false" in output
    assert "environment_approval_status=approval_required" in output
    assert "environment_approval_approved=false" in output
    assert "action_policy_status=active" in output
    assert "action_policy_valid=true" in output
    assert "execution_mode=blocked" in output
    assert "default_execution_mode=blocked" in output
    assert "preflight_status=blocked" in output
    assert "static_team_handoffs=planned-only" in output
    assert "dynamic_validation_queue=disabled" in output
    assert "live_testing=planned-only" in output


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
    assert report["runtime_environment_approval"]["status"] == "approval_required"
    assert report["runtime_environment_approval"]["valid"] is True
    assert report["runtime_environment_approval"]["approved"] is False
    assert report["runtime_action_policy"]["status"] == "active"
    assert report["runtime_action_policy"]["valid"] is True
    assert report["static_team_handoffs"]["state"] == "planned-only"
    assert report["static_team_handoffs"]["planned_teams"] == ["zero_day_team"]
    assert report["dynamic_validation_queue"]["state"] == "disabled"
    assert report["live_testing_playbook"]["state"] == "planned-only"
    assert report["live_testing_playbook"]["attachment_surfaces"] == ["cdp", "ghidra", "mcp", "ssh"]
    blocker_ids = {item["id"] for item in report["blockers_before_future_promotion"]}
    assert "explicit_contract_promotion" in blocker_ids
    assert "runtime_environment_approval_approval_required" in blocker_ids
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
    assert report["live_testing_playbook"]["state"] == "planned-only"


def test_status_can_write_readiness_checklist_artifact_without_runtime_side_effects(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    code = main(["status", "--pipeline-plan", str(plan_path), "--write-readiness-checklist"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    checklist_path = Path(payload["runtime_promotion_readiness_path"])
    assert checklist_path == plan_path.parent / "runtime_promotion_readiness.json"
    assert checklist_path.exists()
    checklist = json.loads(checklist_path.read_text(encoding="utf-8"))
    assert checklist["status"] == "not_ready"
    assert checklist["promoted"] is False
    assert checklist["promotion_enabled"] is False
    assert checklist["live_execution_ready"] is False
    assert checklist["runtime_environment_approval"]["status"] == "approval_required"
    assert checklist["runtime_environment_approval"]["approved"] is False
    assert checklist["runtime_action_policy"]["status"] == "active"
    assert checklist["runtime_action_policy"]["valid"] is True
    assert checklist["preflight_states"]["static_team_handoffs"]["state"] == "planned-only"
    assert checklist["preflight_states"]["dynamic_validation_queue"]["state"] == "disabled"
    assert checklist["preflight_states"]["live_testing_playbook"]["state"] == "planned-only"
    assert checklist["run_status"]["total"] == 1
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_preflight_report_blocks_malformed_live_testing_playbook(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["live_testing_playbook"]["execution_enabled"] = True

    report = build_runtime_preflight_report(plan_path, plan=payload)

    assert report["live_testing_playbook"]["state"] == "blocking"
    assert "live_testing_playbook.enabled must remain false" not in report["live_testing_playbook"]["blockers"]
    assert "live_testing_playbook.execution_enabled must remain false" in report["live_testing_playbook"]["blockers"]
    blocker_sources = {item["source"] for item in report["blockers_before_future_promotion"]}
    assert "live_testing_playbook" in blocker_sources


def test_operator_approval_schema_documents_required_records_without_promotion(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    schema, schema_path = write_runtime_operator_approval_schema(plan_path)
    payload["runtime_operator_approval_schema"] = schema
    evaluated = evaluate_runtime_operator_approval_schema(payload)

    assert schema_path == plan_path.parent / "runtime_operator_approval_schema.json"
    assert schema["schema_version"] == 1
    assert schema["status"] == "blocked"
    assert schema["promotion_enabled"] is False
    assert schema["promoted"] is False
    assert schema["explicit_status"]["not_promoted"] is True
    assert list(schema["approval_record_fields"]) == [
        "approval_id",
        "approver",
        "timestamp",
        "scope",
        "evidence",
        "decision",
    ]
    assert list(schema["required_approval_ids"]) == [
        "operator_live_execution_approval",
        "runtime_contract_update_review",
        "ledger_review_owner_assignment",
    ]
    assert {record["decision"] for record in schema["approval_records"]} == {"missing"}
    assert list(schema["missing_approval_ids"]) == list(schema["required_approval_ids"])
    assert evaluated["promotion_enabled"] is False
    assert evaluated["promoted"] is False
    assert evaluated["valid"] is True
    assert list(evaluated["missing_approval_ids"]) == list(schema["required_approval_ids"])


def test_operator_approval_schema_missing_malformed_or_claimed_approved_cannot_promote(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_operator_approval_schema")
    missing = evaluate_runtime_operator_approval_schema(payload)

    assert missing["status"] == "missing"
    assert missing["promotion_enabled"] is False
    assert missing["promoted"] is False
    assert missing["valid"] is False

    payload["runtime_operator_approval_schema"] = {
        "schema_version": "not-an-int",
        "status": "promoted",
        "promotion_enabled": True,
        "promoted": True,
        "required_approval_ids": "operator",
        "approval_record_fields": ["approval_id"],
        "approval_records": [{"approval_id": "operator_live_execution_approval", "decision": "approved"}],
        "blockers": {},
        "explicit_status": {"promoted": True, "promotion_enabled": True, "not_promoted": False},
    }
    malformed = evaluate_runtime_operator_approval_schema(payload)

    assert malformed["promotion_enabled"] is False
    assert malformed["stored_promotion_enabled"] is True
    assert malformed["promoted"] is False
    assert malformed["stored_promoted"] is True
    assert malformed["valid"] is False

    approved_schema = build_runtime_operator_approval_schema(plan_path, plan=payload).to_dict()
    approved_schema["status"] = "draft"
    approved_schema["approval_records"] = [
        {
            **record,
            "approver": "operator@example.test",
            "timestamp": "2026-05-13T12:00:00Z",
            "decision": "approved",
        }
        for record in approved_schema["approval_records"]
    ]
    approved_schema["missing_approval_ids"] = []
    approved_schema["blockers"] = []
    payload["runtime_operator_approval_schema"] = approved_schema
    claimed = evaluate_runtime_operator_approval_schema(payload)

    assert set(claimed["claimed_approved_ids"]) == set(approved_schema["required_approval_ids"])
    assert claimed["promotion_enabled"] is False
    assert claimed["promoted"] is False


def test_status_can_write_operator_approval_schema_without_runtime_side_effects(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    code = main(["status", "--pipeline-plan", str(plan_path), "--write-operator-approval-schema"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    schema_path = Path(payload["runtime_operator_approval_schema_path"])
    assert schema_path == plan_path.parent / "runtime_operator_approval_schema.json"
    assert schema_path.exists()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["status"] == "blocked"
    assert schema["promotion_enabled"] is False
    assert schema["promoted"] is False
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_promotion_request_packet_bundles_review_evidence_without_promotion(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    packet, packet_path = write_runtime_promotion_request_packet(plan_path)
    payload["runtime_promotion_request_packet"] = packet
    evaluated = evaluate_runtime_promotion_request_packet(payload)

    assert packet_path == plan_path.parent / "runtime_promotion_request_packet.json"
    assert packet["schema_version"] == 1
    assert packet["status"] == "blocked"
    assert packet["requested_action"] == "review_only"
    assert packet["promotion_enabled"] is False
    assert packet["promoted"] is False
    assert packet["explicit_status"]["not_promoted"] is True
    assert set(packet["evidence_paths"]) == {
        "runtime_handoff_contract",
        "runtime_promotion_protocol",
        "runtime_preflight_report",
        "runtime_promotion_readiness",
        "runtime_operator_approval_schema",
    }
    assert set(packet["evidence_sections"]) == set(packet["evidence_paths"])
    assert list(packet["missing_approvals"]) == [
        "operator_live_execution_approval",
        "runtime_contract_update_review",
        "ledger_review_owner_assignment",
    ]
    assert "explicit_contract_promotion" in {item["id"] for item in packet["blocker_summary"]}
    assert evaluated["promotion_enabled"] is False
    assert evaluated["promoted"] is False
    assert evaluated["valid"] is True


def test_promotion_request_packet_missing_malformed_or_claimed_promoted_cannot_promote(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_promotion_request_packet")
    missing = evaluate_runtime_promotion_request_packet(payload)

    assert missing["status"] == "missing"
    assert missing["promotion_enabled"] is False
    assert missing["promoted"] is False
    assert missing["valid"] is False

    payload["runtime_promotion_request_packet"] = {
        "schema_version": "not-an-int",
        "status": "promoted",
        "requested_action": "execute_live",
        "promotion_enabled": True,
        "promoted": True,
        "evidence_paths": [],
        "evidence_sections": {},
        "blocker_summary": {},
        "missing_approvals": "none",
        "next_review_steps": "execute",
        "explicit_status": {
            "promoted": True,
            "promotion_enabled": True,
            "not_promoted": False,
            "review_only": False,
        },
    }
    malformed = evaluate_runtime_promotion_request_packet(payload)

    assert malformed["promotion_enabled"] is False
    assert malformed["stored_promotion_enabled"] is True
    assert malformed["promoted"] is False
    assert malformed["stored_promoted"] is True
    assert malformed["valid"] is False

    claimed_packet = build_runtime_promotion_request_packet(plan_path, plan=payload).to_dict()
    claimed_packet["status"] = "draft"
    claimed_packet["promotion_enabled"] = True
    claimed_packet["promoted"] = True
    claimed_packet["requested_action"] = "execute_live"
    claimed_packet["explicit_status"] = {
        "promoted": True,
        "promotion_enabled": True,
        "not_promoted": False,
        "review_only": False,
    }
    payload["runtime_promotion_request_packet"] = claimed_packet
    claimed = evaluate_runtime_promotion_request_packet(payload)

    assert claimed["promotion_enabled"] is False
    assert claimed["promoted"] is False
    assert claimed["valid"] is False


def test_status_can_write_promotion_request_packet_without_runtime_side_effects(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_non_live_contract_sections(plan_path)

    code = main(["status", "--pipeline-plan", str(plan_path), "--write-promotion-request-packet"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    packet_path = Path(payload["runtime_promotion_request_packet_path"])
    assert packet_path == plan_path.parent / "runtime_promotion_request_packet.json"
    assert packet_path.exists()
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["status"] == "blocked"
    assert packet["requested_action"] == "review_only"
    assert packet["promotion_enabled"] is False
    assert packet["promoted"] is False
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


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


def test_readiness_checklist_blocks_missing_protocol_and_enabled_checklist_claim(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)

    payload.pop("runtime_promotion_protocol")
    payload["runtime_promotion_readiness"] = {
        "schema_version": 1,
        "status": "ready",
        "promotion_enabled": True,
        "promoted": True,
        "live_execution_ready": True,
        "required_approvals": [{"approval": "operator", "required": True}],
        "blockers": [],
        "gates": {"status": "passed", "promotion_allowed": True},
        "preflight_states": {"status": "passed", "promotion_enabled": True},
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checklist, checklist_path = write_runtime_promotion_readiness_checklist(plan_path)

    assert checklist_path == plan_path.parent / "runtime_promotion_readiness.json"
    assert checklist["status"] == "not_ready"
    assert checklist["promoted"] is False
    assert checklist["promotion_enabled"] is False
    assert checklist["live_execution_ready"] is False
    assert checklist["runtime_promotion_protocol"]["status"] == "missing"
    assert checklist["runtime_promotion_protocol"]["promotion_enabled"] is False
    blocker_ids = {item["id"] for item in checklist["blockers"]}
    assert "runtime_promotion_protocol" in blocker_ids
    assert "runtime_promotion_readiness" in blocker_ids
    assert "promotion_readiness_non_live" in blocker_ids


def test_live_testing_rejected_when_contract_missing_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    result = execute_next_wave(
        plan_path,
        execute_live=True,
        live_testing_enabled=True,
        adapter=FailingIfCalledAdapter(),
    )

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert "runtime handoff contract" in result["error"]
    assert "runtime_handoff_contract_present" in {gate["gate_id"] for gate in result["failed_gates"]}
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_default_run_executes_source_hunt_without_live_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    called = {}

    def fail_dry_run_execute(self, specs):
        raise AssertionError("dry-run adapter must not be called without --dry-run")

    def fake_source_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_source_execute)
    monkeypatch.setattr(runtime.DryRunBaseTeamAdapter, "execute", fail_dry_run_execute)

    code = main(["run", "--pipeline-plan", str(plan_path)])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["executed"] == 1
    assert result["runtime_promotion_decision"]["status"] == "missing"
    assert result["execution_mode"] == "source-hunt"
    assert called["keys"] == ["agent-1"]
    assert (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["details"]["adapter"] == "source-hunt"


def test_default_run_dry_run_flag_still_uses_dry_run_adapter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)

    code = main(["run", "--pipeline-plan", str(plan_path), "--dry-run"])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["executed"] == 1
    assert result["execution_mode"] == "dry-run"
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["details"]["adapter"] == "dry-run"
    assert state["run_config"]["live_testing_enabled"] is False


def test_default_source_hunt_run_calls_source_adapter_even_with_valid_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    called = {}

    def fail_dry_run_execute(self, specs):
        raise AssertionError("dry-run adapter must not be called without --dry-run")

    def fake_live_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_live_execute)
    monkeypatch.setattr(runtime.DryRunBaseTeamAdapter, "execute", fail_dry_run_execute)

    code = main(["run", "--pipeline-plan", str(plan_path)])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["execution_mode"] == "source-hunt"
    assert result["runtime_promotion_decision"]["status"] == "promoted"
    assert called["keys"] == ["agent-1"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["details"]["adapter"] == "source-hunt"
    assert state["run_config"]["live_testing_enabled"] is False


def test_no_ledger_reaches_live_adapter_without_real_codex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    captured = {}

    def fake_init(self, **kwargs):
        captured["no_ledger"] = kwargs["no_ledger"]

    def fake_execute(self, specs):
        captured["spec_keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "__init__", fake_init)
    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_execute)

    code = main(["run", "--pipeline-plan", str(plan_path), "--no-ledger"])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert captured == {"no_ledger": True, "spec_keys": ["agent-1"]}
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["run_config"]["no_ledger"] is True
    assert state["last_wave"]["no_ledger"] is True


def test_valid_decision_run_dry_run_uses_dry_run_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    called = {}

    def fail_live_execute(self, specs):
        raise AssertionError("live adapter must not be called with --dry-run")

    def fake_dry_run_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fail_live_execute)
    monkeypatch.setattr(runtime.DryRunBaseTeamAdapter, "execute", fake_dry_run_execute)

    code = main(["run", "--pipeline-plan", str(plan_path), "--dry-run"])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["execution_mode"] == "dry-run"
    assert called["keys"] == ["agent-1"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["details"]["adapter"] == "dry-run"
    assert state["run_config"]["live_testing_enabled"] is False



def test_live_decision_is_rechecked_inside_runtime_lock_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agents.hunt_pipeline import runtime

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    valid = _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    calls = {"count": 0}

    def flip_after_first_check(plan, *, plan_path):
        calls["count"] += 1
        if calls["count"] == 1:
            return {**valid, "status": "promoted", "promoted": True, "valid": True, "promotion_allowed": True}
        return {
            "schema_version": 1,
            "status": "expired",
            "valid": False,
            "promoted": False,
            "promotion_allowed": False,
            "execution_mode": "blocked",
            "decision_source": "pipeline_plan.runtime_promotion_decision",
            "details": "runtime promotion decision record has expired",
        }

    def fail_if_called(self, specs):
        raise AssertionError("adapter must not be called")

    monkeypatch.setattr(runtime, "evaluate_runtime_promotion_decision", flip_after_first_check)
    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fail_if_called)

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True)

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["runtime_promotion_decision"]["status"] == "expired"
    assert calls["count"] == 2
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_malformed_claimed_decision_live_testing_run_blocked_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["runtime_promotion_decision"] = {
        "schema_version": 1,
        "status": "promoted",
        "promotion_enabled": True,
        "execution_mode": "live",
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def fail_if_called(self, specs):
        raise AssertionError("adapter must not be called")

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fail_if_called)

    code = main(["run", "--pipeline-plan", str(plan_path), "--live-testing"])

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["runtime_promotion_decision"]["status"] == "claimed"
    assert result["runtime_promotion_decision"]["promoted"] is False
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_malformed_live_testing_playbook_blocks_promoted_live_testing_run_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["live_testing_playbook"]["execution_enabled"] = True
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def fail_if_called(self, specs):
        raise AssertionError("adapter must not be called")

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fail_if_called)

    code = main(["run", "--pipeline-plan", str(plan_path), "--live-testing"])

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["runtime_promotion_decision"]["status"] == "claimed"
    assert "live_testing_playbook.execution_enabled must remain false" in result["runtime_promotion_decision"]["details"]
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()



def test_resume_without_flags_uses_source_hunt_and_live_testing_uses_promotion_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    blocked_root = tmp_path / "blocked"
    blocked_root.mkdir()
    (blocked_root / "target").mkdir()
    blocked_plan = _write_plan(blocked_root, selected_count=1, deferred_count=0)
    blocked_called = {}

    def fake_source_execute(self, specs):
        blocked_called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_source_execute)

    blocked_code = main(["resume", "--pipeline-plan", str(blocked_plan)])

    assert blocked_code == 0
    blocked = json.loads(capsys.readouterr().out)
    assert blocked["runtime_promotion_decision"]["status"] == "missing"
    assert blocked["execution_mode"] == "source-hunt"
    assert blocked_called["keys"] == ["agent-1"]
    assert run_state_path_for_plan(blocked_plan).exists()

    live_root = tmp_path / "live"
    live_root.mkdir()
    (live_root / "target").mkdir()
    live_plan = _write_plan(live_root, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(live_plan, live_root)
    called = {}

    def fake_live_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_live_execute)

    live_code = main(["resume", "--pipeline-plan", str(live_plan)])

    assert live_code == 0
    live = json.loads(capsys.readouterr().out)
    assert live["execution_mode"] == "source-hunt"
    assert called["keys"] == ["agent-1"]


def test_cli_execute_live_compat_flag_keeps_default_blocked_behavior_before_adapter_or_state_writes(
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


def test_cli_dry_run_allows_live_testing_flag() -> None:
    args = build_parser().parse_args(["run", "--dry-run", "--live"])

    assert args.dry_run is True
    assert args.live_testing is True


def test_cli_resume_execute_live_compat_flag_rejected_before_clearing_pause_or_state_writes(
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


def test_live_subcommand_uses_same_gates_and_calls_live_adapter_when_approved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    called = {}

    def fake_live_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_live_execute)

    code = main(["live", "--pipeline-plan", str(plan_path)])

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["execution_mode"] == "live"
    assert result["runtime_promotion_decision"]["status"] == "promoted"
    assert called["keys"] == ["agent-1"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["agents"]["agent-1"]["details"]["adapter"] == "live"
    assert state["run_config"]["live_testing_enabled"] is True


def test_live_testing_flag_persists_and_resume_reads_saved_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agents.hunt_pipeline import runtime
    from agents.hunt_pipeline.cli import main

    (tmp_path / "target").mkdir()
    plan_path = _write_plan(tmp_path, selected_count=2, deferred_count=0, concurrent_agents=1)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)

    first_code = main(["run", "--pipeline-plan", str(plan_path), "--concurrent-agents", "1", "--dry-run", "--live-testing"])

    assert first_code == 0
    first = json.loads(capsys.readouterr().out)
    assert first["execution_mode"] == "dry-run"
    assert first["summary"]["live_testing_enabled"] is True

    called = {}

    def fake_live_execute(self, specs):
        called["keys"] = [spec.key for spec in specs]
        return {spec.key: "completed" for spec in specs}

    monkeypatch.setattr(runtime.LiveBaseTeamAdapter, "execute", fake_live_execute)

    second_code = main(["resume", "--pipeline-plan", str(plan_path), "--concurrent-agents", "1"])

    assert second_code == 0
    second = json.loads(capsys.readouterr().out)
    assert second["execution_mode"] == "live"
    assert second["summary"]["live_testing_enabled"] is True
    assert called["keys"] == ["agent-2"]
    state = json.loads(run_state_path_for_plan(plan_path).read_text(encoding="utf-8"))
    assert state["run_config"]["live_testing_enabled"] is True
    assert state["last_wave"]["live_testing_enabled"] is True


def test_execute_live_rejected_when_required_gate_fails_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["static_team_handoffs"]["invocation_enabled"] = True
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    failed_gate_ids = {gate["gate_id"] for gate in result["failed_gates"]}
    assert "static_team_invocation_disabled" in failed_gate_ids
    assert "explicit_contract_promotion" in failed_gate_ids
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_environment_approval_missing_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload.pop("runtime_environment_approval")
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["runtime_promotion_decision"]["status"] == "missing"
    assert "runtime_environment_approval is missing" in result["runtime_promotion_decision"]["details"]
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_environment_approval_expired_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["runtime_environment_approval"]["expires_at"] = "2000-01-01T00:00:00Z"
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["runtime_promotion_decision"]["status"] == "expired"
    assert "runtime_environment_approval has expired" in result["runtime_promotion_decision"]["details"]
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_environment_approval_scope_mismatches_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["runtime_environment_approval"]["scope"]["program"] = "other-program"
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["runtime_promotion_decision"]["status"] == "wrong_scope"
    assert "scope.program does not match this plan" in result["runtime_promotion_decision"]["details"]
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_action_policy_allows_payment_by_default_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    _add_valid_runtime_promotion_decision(plan_path, tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["runtime_action_policy"]["classifications"]["allowed_private"]["action_tags"].append("payment")
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["runtime_promotion_decision"]["status"] == "risky_default"
    assert "allows risky public/payment/message actions by default" in result["runtime_promotion_decision"]["details"]
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_protocol_claims_enabled_and_adapter_not_called(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["runtime_promotion_protocol"]["promotion_enabled"] = True
    payload["runtime_promotion_protocol"]["status"] = "promoted"
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert result["runtime_promotion_protocol"]["promotion_enabled"] is False
    assert result["runtime_promotion_protocol"]["stored_promotion_enabled"] is True
    failed_gate_ids = {gate["gate_id"] for gate in result["failed_gates"]}
    assert "promotion_protocol_non_live" in failed_gate_ids
    assert "explicit_contract_promotion" in failed_gate_ids
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()


def test_execute_live_rejected_when_readiness_claims_enabled_before_state_or_adapter_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    payload["runtime_promotion_readiness"] = {
        "schema_version": 1,
        "status": "ready",
        "promotion_enabled": True,
        "promoted": True,
        "live_execution_ready": True,
        "required_approvals": [{"approval": "operator", "required": True}],
        "blockers": [],
        "gates": {"status": "passed", "promotion_allowed": True},
        "preflight_states": {"status": "passed", "promotion_enabled": True},
    }
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert result["runtime_promotion_readiness"]["promotion_enabled"] is False
    assert result["runtime_promotion_readiness"]["stored_promotion_enabled"] is True
    assert result["runtime_promotion_readiness"]["promoted"] is False
    assert result["runtime_promotion_readiness"]["stored_promoted"] is True
    assert result["runtime_promotion_readiness"]["live_execution_ready"] is False
    assert result["runtime_promotion_readiness"]["stored_live_execution_ready"] is True
    failed_gate_ids = {gate["gate_id"] for gate in result["failed_gates"]}
    assert "promotion_readiness_non_live" in failed_gate_ids
    assert "explicit_contract_promotion" in failed_gate_ids
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_execute_live_rejected_when_operator_approval_schema_claims_approved_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    claimed_schema = build_runtime_operator_approval_schema(plan_path, plan=payload).to_dict()
    claimed_schema["status"] = "draft"
    claimed_schema["approval_records"] = [
        {
            **record,
            "approver": "operator@example.test",
            "timestamp": "2026-05-13T12:00:00Z",
            "decision": "approved",
        }
        for record in claimed_schema["approval_records"]
    ]
    claimed_schema["missing_approval_ids"] = []
    claimed_schema["blockers"] = []
    payload["runtime_operator_approval_schema"] = claimed_schema
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert result["runtime_operator_approval_schema"]["promotion_enabled"] is False
    assert result["runtime_operator_approval_schema"]["promoted"] is False
    assert set(result["runtime_operator_approval_schema"]["claimed_approved_ids"]) == set(
        claimed_schema["required_approval_ids"]
    )
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


def test_execute_live_rejected_when_request_packet_claims_promoted_before_writes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path, selected_count=1, deferred_count=0)
    payload = _add_non_live_contract_sections(plan_path)
    claimed_packet = build_runtime_promotion_request_packet(plan_path, plan=payload).to_dict()
    claimed_packet["status"] = "promoted"
    claimed_packet["requested_action"] = "execute_live"
    claimed_packet["promotion_enabled"] = True
    claimed_packet["promoted"] = True
    claimed_packet["explicit_status"] = {
        "promoted": True,
        "promotion_enabled": True,
        "not_promoted": False,
        "review_only": False,
    }
    payload["runtime_promotion_request_packet"] = claimed_packet
    payload["runtime_handoff_contract"] = build_runtime_handoff_contract(payload).to_dict()
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = execute_next_wave(plan_path, execute_live=True, live_testing_enabled=True, adapter=FailingIfCalledAdapter())

    assert result["ok"] is False
    assert result["executed"] == 0
    assert result["promotion_allowed"] is False
    assert result["runtime_promotion_request_packet"]["promotion_enabled"] is False
    assert result["runtime_promotion_request_packet"]["stored_promotion_enabled"] is True
    assert result["runtime_promotion_request_packet"]["promoted"] is False
    assert result["runtime_promotion_request_packet"]["stored_promoted"] is True
    assert result["runtime_promotion_request_packet"]["valid"] is False
    assert not run_state_path_for_plan(plan_path).exists()
    assert not (plan_path.parent / "runtime_agent_specs.jsonl").exists()
    assert not (plan_path.parent / "ledgers").exists()


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
