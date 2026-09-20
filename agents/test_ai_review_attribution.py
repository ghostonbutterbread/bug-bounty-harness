from __future__ import annotations

from agents.attempts import append_attempt
from agents.map_store import MapStore


FIRST = {"agent_id": "map-agent", "model_id": "openai/gpt-5.6"}
SECOND = {"agent_id": "review-agent", "model_id": "anthropic/claude-4"}


def test_mapstore_observation_and_lifecycle_merge_ai_reviewer_tags(tmp_path) -> None:
    store = MapStore("demo", root=str(tmp_path))
    store.init()
    path = store.write(
        url="https://app.example.test/export", surface="api", body="Observed export behavior.",
        agent="map-agent", model_id="openai/gpt-5.6", run_id="run-1",
    )
    relative = path.relative_to(store.maps_root).as_posix()
    updated = store.update_status(
        path=relative, status="needs_recheck", reason="second model requested a fresh comparison.",
        agent="review-agent", model_id="anthropic/claude-4",
    )

    assert updated["ai_reviewed_by"] == [FIRST, SECOND]
    content = path.read_text(encoding="utf-8")
    assert "AI Reviewed By: map-agent@openai/gpt-5.6, review-agent@anthropic/claude-4" in content


def test_attempts_attach_optional_ai_reviewer_to_the_event(tmp_path) -> None:
    stored = append_attempt(tmp_path / "attempts.jsonl", {
        "timestamp": "2026-09-20T00:00:00Z", "tool": "xss-agent", "target": "https://app.example.test/?q=marker",
        "outcome": "inert", "stop_reason": "fixture",
    }, agent_id="map-agent", model_id="openai/gpt-5.6")

    assert stored["ai_reviewed_by"] == [FIRST]
