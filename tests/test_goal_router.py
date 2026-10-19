"""Behavior tests for the explicit /goal routing helper."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
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


def test_bound_run_rejects_cross_lane_checkpoint_before_creating_receipt(tmp_path: Path) -> None:
    run = tmp_path / "run"
    plan = goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss")
    goal.initialize_run(plan, run, family="web_bounty", lane="web")
    state_path = run / "goal-state.json"
    original = state_path.read_bytes()
    with pytest.raises(ValueError, match="family/lane"):
        goal.record_checkpoint(run, family="web_bounty", lane="api", root=tmp_path,
                               decision="map", reason="Missing inventory", next_step="Map consumers")
    with pytest.raises(ValueError, match="family/lane"):
        goal.record_checkpoint(run, family="private_program", lane="web", root=tmp_path,
                               decision="map", reason="Missing inventory", next_step="Map consumers")
    assert state_path.read_bytes() == original
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                                     decision="map", reason="Missing inventory", next_step="Map consumers")
    assert receipt["family"] == "web_bounty"
    assert receipt["lane"] == "web"


def test_init_requires_family_and_lane_together(tmp_path: Path) -> None:
    plan = goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss")
    with pytest.raises(ValueError, match="family and lane"):
        goal.initialize_run(plan, tmp_path / "run", family="web_bounty")
    assert not (tmp_path / "run" / "goal-state.json").exists()


def test_reinitializing_existing_run_does_not_replace_checkpoint_history(tmp_path: Path) -> None:
    run = tmp_path / "run"
    plan = goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss")
    goal.initialize_run(plan, run, family="web_bounty", lane="web")
    goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                           decision="map", reason="Missing inventory", next_step="Map consumers")
    original = (run / "goal-state.json").read_bytes()
    with pytest.raises(ValueError, match="already initialized"):
        goal.initialize_run(plan, run, family="web_bounty", lane="api")
    assert (run / "goal-state.json").read_bytes() == original


def test_failed_init_does_not_strand_exclusive_run(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    plan = goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss")
    with monkeypatch.context() as context:
        context.setattr(goal.json, "dumps", lambda *a, **k: (_ for _ in ()).throw(OSError("serialization failed")))
        with pytest.raises(OSError, match="serialization failed"):
            goal.initialize_run(plan, run, family="web_bounty", lane="web")
    assert not (run / "goal-state.json").exists()
    assert not list(run.glob(".goal-state-*"))
    assert goal.initialize_run(plan, run, family="web_bounty", lane="web").is_file()


def test_failed_atomic_publish_cleans_temp_without_stranding_run(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    plan = goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss")
    with monkeypatch.context() as context:
        context.setattr(goal.os, "link", lambda *a: (_ for _ in ()).throw(OSError("link failed")))
        with pytest.raises(OSError, match="link failed"):
            goal.initialize_run(plan, run, family="web_bounty", lane="web")
    assert not (run / "goal-state.json").exists()
    assert not list(run.glob(".goal-state-*"))
    goal.initialize_run(plan, run, family="web_bounty", lane="web")


def test_cli_bound_goal_run_rejects_wrong_checkpoint_lane(tmp_path: Path) -> None:
    run = tmp_path / "run"
    base = [sys.executable, str(SCRIPT_PATH)]
    initialized = subprocess.run(base + ["init", "--program", "sample", "--objective", "Find XSS",
                                     "--class", "xss", "--run-dir", str(run),
                                     "--family", "web_bounty", "--lane", "web"],
                                 capture_output=True, text=True, check=True)
    assert initialized.stdout.strip() == str(run / "goal-state.json")
    common = ["--run-dir", str(run), "--family", "web_bounty", "--root", str(tmp_path / "data"),
              "--decision", "map", "--reason", "Missing inventory", "--next-step", "Map consumers"]
    rejected = subprocess.run(base + ["checkpoint", *common, "--lane", "api"],
                              capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "family/lane" in rejected.stderr
    assert json.loads((run / "goal-state.json").read_text())["checkpoints"] == []
    accepted = subprocess.run(base + ["checkpoint", *common, "--lane", "web"],
                              capture_output=True, text=True, check=True)
    assert json.loads(accepted.stdout)["inventory_state"] == "missing"


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


def test_goal_checkpoint_watches_exact_worker_run_without_assessing_it(tmp_path: Path) -> None:
    run = tmp_path / "run"
    root = tmp_path / "data"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run,
                        family="web_bounty", lane="web")
    stream = root / "web_bounty" / "sample" / "web" / "attempts" / "_runs" / "worker-1" / "attempts.jsonl"
    stream.parent.mkdir(parents=True)
    stream.write_text(json.dumps({"attempt_id": "A-1", "target": "https://private.example/?q=secret"}) + "\n")
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=root,
                                     attempt_run_id="worker-1", decision="map", reason="Inventory thin",
                                     next_step="Backfill the mapped question")
    assert receipt["coverage_uptake"]["signal"] == "needs_reconciliation"
    assert receipt["coverage_uptake"]["run_id"] == "worker-1"
    assert "private.example" not in json.dumps(receipt)
    assert not (root / "web_bounty" / "sample" / "web" / "ledgers" / "surface_coverage.sqlite").exists()


def test_goal_checkpoint_cannot_bounded_stop_on_missing_exact_worker_stream(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run,
                        family="web_bounty", lane="web")
    with pytest.raises(ValueError, match="remaining unknowns"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                               attempt_run_id="worker-typo", decision="bounded-stop", reason="Done",
                               next_step="Stop", inventory_refs=["recon/example.jsonl"])
    assert "last_checkpoint" not in json.loads((run / "goal-state.json").read_text())


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
    assert json.loads((run / "goal-state.json").read_text())["checkpoints"] == [receipt]


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
    assert "last_checkpoint" not in json.loads((run / "goal-state.json").read_text())


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
    assert "last_checkpoint" not in json.loads((run / "goal-state.json").read_text())


def test_focused_url_negative_stop_does_not_accept_unrelated_host_filter(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS",
                                        url="https://app.example/comments", vulnerability_class="xss"), run)
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path / "data")
    store.discover(kind="route", host="app.example", surface_key="GET /comments",
                   source_ref="recon/app/comments.jsonl", run_id="map-1", class_name="xss")
    with pytest.raises(ValueError, match="host"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                               host="unrelated.example", decision="bounded-stop", reason="No safe action",
                               next_step="Resume later", remaining=["Mapping gap"])
    assert "last_checkpoint" not in json.loads((run / "goal-state.json").read_text())


def test_broad_goal_negative_stop_cannot_filter_to_one_class(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find a vulnerability"), run)
    with pytest.raises(ValueError, match="class"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                               vulnerability_class="xss", decision="bounded-stop",
                               reason="No safe action", next_step="Resume later", remaining=["Other classes"])


def test_checkpoint_distinguishes_empty_ledger_from_no_matching_class(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path / "data")
    store.discover(kind="route", host="app.example", surface_key="GET /object",
                   source_ref="recon/app/object.jsonl", run_id="map-1", class_name="idor")
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                                     decision="map", reason="No XSS question", next_step="Map render consumers")
    assert receipt["inventory_state"] == "no_matching_questions"
    assert receipt["coverage"]["total"] == 0
    assert receipt["coverage"]["unfiltered_total"] == 1


def test_checkpoint_atomic_failure_keeps_prior_state_and_no_second_journal(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    original = (run / "goal-state.json").read_bytes()

    def fail_replace(*args):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(goal.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                               decision="map", reason="Missing inventory", next_step="Map consumers")
    assert (run / "goal-state.json").read_bytes() == original
    assert not (run / "goal-checkpoints.jsonl").exists()
    assert not list(run.glob(".goal-state-*"))


def test_checkpoint_serialization_failure_cleans_temp_and_keeps_prior_state(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    original = (run / "goal-state.json").read_bytes()
    with monkeypatch.context() as context:
        context.setattr(goal.json, "dumps", lambda *a, **k: (_ for _ in ()).throw(OSError("serialization failed")))
        with pytest.raises(OSError, match="serialization failed"):
            goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                                   decision="map", reason="Missing inventory", next_step="Map consumers")
    assert (run / "goal-state.json").read_bytes() == original
    assert not list(run.glob(".goal-state-*"))


def test_second_checkpoint_preserves_run_local_history(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find XSS", vulnerability_class="xss"), run)
    first = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                                   decision="map", reason="Inventory missing", next_step="Map contexts")
    second = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path,
                                    decision="unblock", reason="Challenge blocks reply", next_step="Resolve owned challenge")
    state = json.loads((run / "goal-state.json").read_text())
    assert state["checkpoints"] == [first, second]
    assert state["last_checkpoint"] == second


def test_broad_goal_receipt_retains_class_for_same_surface_questions(tmp_path: Path) -> None:
    run = tmp_path / "run"
    goal.initialize_run(goal.build_plan(program="sample", objective="Find a vulnerability"), run)
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path / "data")
    surface_id = store.discover(kind="route", host="app.example", surface_key="GET /preview",
                                input_key="id", consumer="preview", source_ref="recon/app/preview.jsonl",
                                run_id="map-1", class_name="xss")
    store.discover(kind="route", host="app.example", surface_key="GET /preview",
                   input_key="id", consumer="preview", source_ref="recon/app/preview.jsonl",
                   run_id="map-1", class_name="idor")
    store.assess(surface_id, class_name="idor", status="blocked", expected_fingerprint="",
                 reason="second principal unavailable", reopen_when="owned second principal available",
                 evidence_refs=["attempt:app:A-3"])
    receipt = goal.record_checkpoint(run, family="web_bounty", lane="web", root=tmp_path / "data",
                                     decision="map", reason="More consumers remain", next_step="Map inputs")
    assert {(item["surface_id"], item["class_name"], item["status"])
            for item in receipt["coverage"]["items"]} == {
                (surface_id, "idor", "blocked"), (surface_id, "xss", "no_assessment")}
