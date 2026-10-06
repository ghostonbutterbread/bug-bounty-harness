"""Progressive disclosure and ownership of hunt freshness guidance."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "skills"
OWNER = ROOT / "hunter-loop"
REFERENCE = OWNER / "references" / "freshness-and-memory.md"


def read(path: Path) -> str:
    return " ".join(path.read_text().lower().split())


def test_conditional_route_and_single_owner():
    hunter = read(OWNER / "SKILL.md")
    map_store = read(ROOT / "map-store" / "SKILL.md")
    kanban = read(OWNER / "references" / "hunter-kanban.md")
    reference = read(REFERENCE)

    assert "historical leads start choosing targets" in hunter
    assert "references/freshness-and-memory.md" in hunter
    assert "historical leads start choosing targets" in map_store
    assert "references/freshness-and-memory.md" in map_store
    assert "freshness-and-memory.md" in kanban
    assert "one decisive observation can suffice" in reference
    assert "attach it to the handoff" in reference

    for entry in (hunter, map_store, kanban):
        assert "30-45" not in entry and "30–45" not in entry
        assert "three fresh" not in entry and "3-5 fresh" not in entry
    assert "one decisive observation can suffice" not in map_store


def test_targeted_reads_and_non_hunt_work_are_not_forced_to_load_reference():
    hunter = read(OWNER / "SKILL.md")
    map_store = read(ROOT / "map-store" / "SKILL.md")
    reference = read(REFERENCE)

    assert "ordinary targeted fact, dedupe, and coverage reads do not trigger" in hunter
    assert "do not load it for ordinary targeted" in map_store
    assert all(intent in map_store for intent in ("app-facts", "dedupe", "coverage"))
    assert "retest, repass, cleanup, duplicate triage" in map_store
    assert "do not block those queries" in reference
    assert "fresh current-run observation" in hunter
