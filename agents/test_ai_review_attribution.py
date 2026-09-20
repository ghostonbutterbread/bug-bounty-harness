from __future__ import annotations

import json
from pathlib import Path

from agents import bounty_notes
from agents.attempts import append_attempt
from agents.map_store import MapStore


FIRST = {"agent_id": "map-agent", "model_id": "openai/gpt-5.6"}
SECOND = {"agent_id": "review-agent", "model_id": "anthropic/claude-4"}


def test_mapstore_observation_and_lifecycle_merge_ai_reviewer_tags(tmp_path) -> None:
    store = MapStore("demo", root=str(tmp_path))
    store.init()
    path = store.write(
        url="https://app.example.test/export", surface="api", body="Observed export behavior.",
        agent=FIRST["agent_id"], model_id=FIRST["model_id"], run_id="run-1",
    )
    relative = path.relative_to(store.maps_root).as_posix()
    updated = store.update_status(
        path=relative, status="needs_recheck", reason="second model requested a fresh comparison.",
        agent=SECOND["agent_id"], model_id=SECOND["model_id"],
    )

    assert updated["ai_reviewed_by"] == [FIRST, SECOND]
    content = path.read_text(encoding="utf-8")
    assert "AI Reviewed By: map-agent@openai/gpt-5.6, review-agent@anthropic/claude-4" in content


def test_mapstore_behavior_updates_merge_reviewer_tags(tmp_path) -> None:
    store = MapStore("demo", root=str(tmp_path))
    store.init()
    observation = store.write(
        url="https://app.example.test/export", surface="api", body="Observed export behavior.",
    )
    relative = observation.relative_to(store.maps_root).as_posix()
    first_path = store.write_behavior(
        name="Export worker", kinds=["export"], observation_paths=[relative], body="First model review.",
        agent=FIRST["agent_id"], model_id=FIRST["model_id"],
    )
    second_path = store.write_behavior(
        name="Export worker", kinds=["export"], observation_paths=[relative], body="Second model review.",
        agent=SECOND["agent_id"], model_id=SECOND["model_id"],
    )

    assert second_path == first_path
    behavior = store.query_behaviors(kind="export")[0]
    assert behavior["ai_reviewed_by"] == [FIRST, SECOND]
    assert "AI Reviewed By: map-agent@openai/gpt-5.6, review-agent@anthropic/claude-4" in second_path.read_text(encoding="utf-8")


def test_model_less_mapstore_and_notes_omit_optional_reviewer_field(tmp_path) -> None:
    store = MapStore("demo", root=str(tmp_path))
    store.init()
    observation = store.write(
        url="https://app.example.test/export", surface="api", body="Observed export behavior.",
    )
    assert "ai_reviewed_by" not in store.query()[0]
    store.write_behavior(
        name="Export worker", kinds=["export"],
        observation_paths=[observation.relative_to(store.maps_root).as_posix()], body="Observed worker.",
    )
    assert "ai_reviewed_by" not in store.query_behaviors(kind="export")[0]

    base = ["demo", "--family", "web_bounty", "--lane", "web", "--root", str(tmp_path)]
    assert bounty_notes.main([
        "note", *base, "--bucket", "hypotheses", "--title", "Model-less note",
        "--run-id", "run-1", "--body", "A durable note without model attribution.",
    ]) == 0
    notes_index = tmp_path / "web_bounty" / "demo" / "web" / "notes" / "_index" / "notes.json"
    assert "ai_reviewed_by" not in json.loads(notes_index.read_text(encoding="utf-8"))["notes"][0]

    source = tmp_path / "artifact.txt"
    source.write_text("artifact\n", encoding="utf-8")
    assert bounty_notes.main([
        "artifact", *base, "--source", str(source), "--run-id", "run-1",
    ]) == 0
    manifest = tmp_path / "web_bounty" / "demo" / "web" / "working" / "scratch" / "run-1" / "manifest.json"
    assert "ai_reviewed_by" not in json.loads(manifest.read_text(encoding="utf-8"))


def test_timeline_notes_render_and_merge_reviewer_tags(tmp_path) -> None:
    base = ["demo", "--family", "web_bounty", "--lane", "web", "--root", str(tmp_path), "--bucket", "timeline"]
    assert bounty_notes.main([
        "note", *base, "--title", "First review", "--agent", FIRST["agent_id"],
        "--model-id", FIRST["model_id"], "--run-id", "run-1", "--body", "First review body.",
    ]) == 0
    assert bounty_notes.main([
        "note", *base, "--title", "Second review", "--agent", SECOND["agent_id"],
        "--model-id", SECOND["model_id"], "--run-id", "run-2", "--body", "Second review body.",
    ]) == 0

    notes_root = tmp_path / "web_bounty" / "demo" / "web" / "notes"
    timeline = next((notes_root / "timeline").glob("*.md"))
    content = timeline.read_text(encoding="utf-8")
    assert "AI Reviewed By: map-agent@openai/gpt-5.6" in content
    assert "AI Reviewed By: review-agent@anthropic/claude-4" in content
    entry = json.loads((notes_root / "_index" / "notes.json").read_text(encoding="utf-8"))["notes"][0]
    assert entry["ai_reviewed_by"] == [FIRST, SECOND]


def test_attempts_attach_optional_ai_reviewer_to_the_event(tmp_path) -> None:
    stored = append_attempt(tmp_path / "attempts.jsonl", {
        "timestamp": "2026-09-20T00:00:00Z", "tool": "xss-agent", "target": "https://app.example.test/?q=marker",
        "outcome": "inert", "stop_reason": "fixture",
    }, agent_id=FIRST["agent_id"], model_id=FIRST["model_id"])

    assert stored["ai_reviewed_by"] == [FIRST]
