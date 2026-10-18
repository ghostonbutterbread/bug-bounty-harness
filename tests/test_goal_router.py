"""Behavior tests for the explicit /goal routing helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from agents.surface_coverage import SurfaceCoverageStore


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "goal_router.py"
SPEC = importlib.util.spec_from_file_location("goal_router", SCRIPT_PATH)
assert SPEC and SPEC.loader
goal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(goal)


def test_generic_find_vulnerability_uses_broad_program_mode() -> None:
    plan = goal.build_plan(program="example", objective="Find a new vulnerability")

    assert plan["mode"] == "broad-program"
    assert "hunter-loop" in plan["skills"]
    assert "hunt-orchestration-policy" in plan["skills"]
    assert "recon" in plan["skills"]
    assert "map-store" not in plan["skills"]
    assert "map-store-target-facts" in plan["capabilities"]
    assert "MapStore is available but must not be queried until a concrete current surface and decision question exist." in plan["research_contract"]
    assert plan["completion_contract"][0] == "Before a broad negative or exhaustion conclusion, ask: is there more to map?"
    assert "incomplete mapping is not a reason to interrupt it." in plan["opening_contract"][-1]
    assert plan["run_artifact_kind"] == "hunter-loop"


def test_focused_xss_goal_stays_narrow() -> None:
    plan = goal.build_plan(
        program="example",
        objective="Find XSS in this comment preview",
        url="https://app.example/comments/preview",
        vulnerability_class="xss",
    )

    assert plan["mode"] == "focused-surface"
    assert "hunter-loop" not in plan["skills"]
    assert "recon" not in plan["skills"]
    assert "map-store" not in plan["skills"]
    assert "map-store-target-facts" in plan["capabilities"]
    assert "MapStore is available but must not be queried until a concrete current surface and decision question exist." in plan["research_contract"]
    assert "xss" in plan["skills"]
    assert plan["completion_contract"] == []
    assert plan["run_artifact_kind"] == "attempts"


def test_technology_goal_selects_implementation_analysis() -> None:
    plan = goal.build_plan(
        program="example",
        objective="Understand the DOMPurify render path in this editor",
    )

    assert plan["mode"] == "technology-review"
    assert "js" in plan["skills"]
    assert "map-store" not in plan["skills"]
    assert "map-store-target-facts" in plan["capabilities"]
    assert "MapStore is available but must not be queried until a concrete current surface and decision question exist." in plan["research_contract"]
    assert "research-map" in plan["capabilities"]
    assert "official-docs-and-source" in plan["capabilities"]
    assert "hunt-orchestration-policy" not in plan["skills"]
    assert plan["completion_contract"] == []


def test_continue_goal_preserves_hunter_memory() -> None:
    plan = goal.build_plan(program="example", objective="Continue the warm URL validation lead")

    assert plan["mode"] == "continuation"
    assert "hunter-memory" in plan["skills"]
    assert "map-store" in plan["skills"]
    assert "research-map" in plan["capabilities"]
    assert "hunt-orchestration-policy" not in plan["skills"]
    assert plan["completion_contract"] == []


def test_revalidation_goal_allows_historical_review() -> None:
    plan = goal.build_plan(program="example", objective="Retest the old account-linking issue")

    assert plan["mode"] == "revalidation"
    assert "map-store" in plan["skills"]
    assert plan["historical_material"] == "primary"
    assert "hunt-orchestration-policy" not in plan["skills"]
    assert plan["completion_contract"] == []


def test_initialize_run_writes_small_routing_state(tmp_path: Path) -> None:
    plan = goal.build_plan(
        program="example",
        objective="Find XSS in this comment preview",
        vulnerability_class="xss",
    )

    state_path = goal.initialize_run(plan, tmp_path / "run")

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state_path.name == "goal-state.json"
    assert state["program"] == "example"
    assert state["mode"] == "focused-surface"
    assert state["retrieval_decision"] == "unselected"
    assert state["current_surface"] is None


def test_goal_plan_routes_coverage_checkpoint_only_in_explicit_goal_plan() -> None:
    broad = goal.build_plan(program="example", objective="Find a new vulnerability")
    focused = goal.build_plan(program="example", objective="Find XSS", vulnerability_class="xss")
    assert "coverage" in broad["skills"]
    assert "coverage" in focused["skills"]
    assert "before a negative stop" in focused["checkpoint_contract"].lower()


def test_checkpoint_empty_inventory_is_mapping_gap_without_creating_coverage(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                                     decision="map", reason="No registered XSS paths", next_step="Map preview inputs")
    assert receipt["inventory_state"] == "missing"
    assert receipt["coverage"]["total"] == 0
    assert receipt["goal_outcome"] == "in_progress"
    assert receipt["eligible_goal_complete"] is False
    assert not (tmp_path / "data" / "sample" / "web" / "ledgers" / "surface_coverage.sqlite").exists()
    assert json.loads((run / "goal-state.json").read_text())["last_checkpoint"] == receipt


def test_checkpoint_replays_blocked_and_unassessed_paths_as_bounded_pause(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path / "data")
    blocked = store.discover(kind="route", host="docs.example", surface_key="POST /ask",
                             input_key="prompt", consumer="reply", source_ref="recon/docs/ask.jsonl",
                             run_id="map-1", class_name="xss")
    store.assess(blocked, class_name="xss", status="blocked", expected_fingerprint="",
                 reason="challenge prevents reply render", reopen_when="owned browser challenge solved",
                 evidence_refs=["attempt:docs:A-1"])
    store.discover(kind="route", host="app.example", surface_key="GET /contexts",
                   input_key="attribute", consumer="list", source_ref="recon/app/contexts.jsonl",
                   run_id="map-1", class_name="xss")
    store.discover(kind="route", host="app.example", surface_key="GET /unrelated",
                   source_ref="recon/app/more.jsonl", run_id="map-1", class_name="idor")
    before = store.path.read_bytes()
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                                     decision="bounded-stop", reason="No safe target action now",
                                     next_step="Retry owned challenge after access returns",
                                     remaining=["docs reply blocked", "app context consumer unrendered"],
                                     inventory_refs=["recon/docs/ask.jsonl", "recon/app/contexts.jsonl"])
    assert receipt["coverage"]["counts"] == {"blocked": 1, "no_assessment": 1}
    assert receipt["coverage"]["total"] == 2
    assert receipt["goal_outcome"] == "paused_bounded"
    assert receipt["eligible_goal_complete"] is False
    assert {item["source_ref"] for item in receipt["coverage"]["items"]} == {
        "recon/docs/ask.jsonl", "recon/app/contexts.jsonl"}
    assert store.path.read_bytes() == before
    assert json.loads((run / "goal-checkpoints.jsonl").read_text().splitlines()[0]) == receipt


def test_checkpoint_rejects_unspecific_bounded_stop_and_mismatched_class(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    with pytest.raises(ValueError, match="remaining|inventory"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                               decision="bounded-stop", reason="Nothing found", next_step="Resume later")
    with pytest.raises(ValueError, match="class"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                               vulnerability_class="idor", decision="map", reason="New pass",
                               next_step="Find surface")
    assert not (run / "goal-checkpoints.jsonl").exists()


def test_bounded_stop_cannot_hide_open_questions_behind_inventory_pointer_or_host(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path / "data")
    store.discover(kind="route", host="docs.example", surface_key="POST /ask",
                   source_ref="recon/docs/ask.jsonl", run_id="map-1", class_name="xss")
    with pytest.raises(ValueError, match="remaining"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                               decision="bounded-stop", reason="No safe action", next_step="Resume later",
                               inventory_refs=["recon/docs/ask.jsonl"])
    with pytest.raises(ValueError, match="host"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                               host="app.example", decision="bounded-stop", reason="No action",
                               next_step="Resume later", remaining=["docs not reviewed"])
    assert not (run / "goal-checkpoints.jsonl").exists()
