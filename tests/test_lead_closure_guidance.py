"""Review contracts for pausing scoped leads and downstream consumers."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def skill(name):
    return " ".join((ROOT / "skills" / name / "SKILL.md").read_text().split())


def test_lead_pause_preserves_question_without_archiving():
    text = skill("leads")
    assert "a pause, not evidence that a lead is negative or archived" in text
    assert "exact lead ID, remaining question, next discriminator or prerequisite" in text
    assert "meaningful reachable variants are covered" in text
    assert "explicit account, role, fixture, browser, artifact" in text


def test_coverage_review_does_not_require_browser_for_server_claims():
    text = skill("coverage")
    assert "not** a negative vulnerability verdict" in text
    assert "axes actually reviewed and material untested siblings" in text
    assert "browser evidence for browser behavior" in text
    assert "class-specific server, callback, state, or tool evidence" in text


def test_stored_value_watch_is_selective_and_reopenable():
    text = skill("xss-lifecycle")
    assert "does not establish the behavior of other consumers" in text
    assert "not a reason to keep a run alive or create a lead for every stored value" in text
    assert "reopen or branch the concrete XSS hypothesis" in text
    assert "Do not infer an executable sink from persistence alone" in text


def test_goal_pause_keeps_material_open_leads():
    text = skill("bug-goals")
    assert "hand off the IDs of material open leads" in text
    assert "explains the pause, not a negative verdict" in text
    assert "bounded-stop` is a **paused, evidence-bounded run**" in text
