"""Behavior tests for the explicit /goal routing helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "goal_router.py"
SPEC = importlib.util.spec_from_file_location("goal_router", SCRIPT_PATH)
assert SPEC and SPEC.loader
goal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(goal)


def test_generic_find_vulnerability_uses_broad_program_mode() -> None:
    plan = goal.build_plan(program="example", objective="Find a new vulnerability")

    assert plan["mode"] == "broad-program"
    assert "hunter-loop" in plan["skills"]
    assert "recon" in plan["skills"]
    assert "map-store" not in plan["skills"]
    assert "map-store-target-facts" in plan["capabilities"]
    assert "MapStore is available but must not be queried until a concrete current surface and decision question exist." in plan["research_contract"]
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


def test_continue_goal_preserves_hunter_memory() -> None:
    plan = goal.build_plan(program="example", objective="Continue the warm URL validation lead")

    assert plan["mode"] == "continuation"
    assert "hunter-memory" in plan["skills"]
    assert "map-store" in plan["skills"]
    assert "research-map" in plan["capabilities"]


def test_revalidation_goal_allows_historical_review() -> None:
    plan = goal.build_plan(program="example", objective="Retest the old account-linking issue")

    assert plan["mode"] == "revalidation"
    assert "map-store" in plan["skills"]
    assert plan["historical_material"] == "primary"


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
