"""Generic BBH Coverage routing is evidence-triggered, not Bunny-only."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_generic_entry_routes_coverage_without_per_attempt_writes():
    entry = (ROOT / "agents/index.md").read_text()
    skill = (ROOT / "skills/coverage/SKILL.md").read_text()
    assert "Every BBH agent, solo or coordinated" in entry
    assert "not a per-payload write or a Bunny/goal" in entry
    assert "if no question or review is justified" in entry
    assert "every BBH agent" in skill
    assert "returned" in skill and "display/media ID" in skill
    assert "watcher" not in skill.lower()
