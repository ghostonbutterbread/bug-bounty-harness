from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/agent-audit/SKILL.md"


def test_audit_skill_is_routed_from_entry_and_registry() -> None:
    text = SKILL.read_text(encoding="utf-8")
    entry = (ROOT / "agents/index.md").read_text(encoding="utf-8")
    registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
    assert "name: agent-audit" in text
    assert "load `/agent-audit`" in entry
    assert "skills/agent-audit/SKILL.md" in registry
    assert "no standalone runner" in registry


def test_audit_distinguishes_action_sources_from_attempt_history() -> None:
    text = SKILL.read_text(encoding="utf-8")
    for marker in (
        "different IDs",
        "SubagentLogger",
        "task-scoped MITM/proxy history",
        "read_attempt_bucket(program",
        "read_attempts(exact_path",
        "MapStore",
        "Hypothesis Ledger",
        "Findings",
        "cleanup",
        "empty query is not proof of no traffic",
        "root_override=<recorded-shared-root>",
        "family=<actual-family>",
        "private Hypothesis Ledger is not an audit feed",
        "Do not impersonate a run owner",
        "separately authorized afterward",
        "does not append Attempts",
        "partial audit",
    ):
        assert marker in text
    assert "def read_attempt_bucket(" in (ROOT / "agents/attempts.py").read_text(encoding="utf-8")


def test_attempt_discovery_uses_recorded_family_lane_and_custom_root(tmp_path: Path) -> None:
    from agents.attempts import append_attempt, read_attempt_bucket, resolve_attempts_path

    root = tmp_path / "shared"
    run_id = "run-audit-fixture"
    path = resolve_attempts_path("fixture-program", run_id=run_id, family="binaries", lane="apk", root_override=root)
    append_attempt(path, {
        "timestamp": datetime.now(UTC).isoformat(),
        "tool": "audit-fixture",
        "target": "owned-fixture",
        "outcome": "observed",
        "stop_reason": "fixture complete",
    })
    assert path.parent.parent.parent == root / "binaries" / "fixture-program" / "apk" / "attempts"
    rows = read_attempt_bucket("fixture-program", family="binaries", lane="apk", root_override=root, where={"run_id": run_id})
    assert len(rows) == 1 and rows[0]["run_id"] == run_id
    assert read_attempt_bucket("fixture-program", family="web_bounty", lane="apk", root_override=root, where={"run_id": run_id}) == []


def test_audit_output_is_source_linked_and_sanitized() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "supported, contradicted, or not verifiable" in text
    assert "sanitized receipt" in text
    assert "load `/bounty-notes`" in text
    assert "Do not broad-scan all programs" in text
