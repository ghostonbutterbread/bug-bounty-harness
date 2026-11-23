"""Review contracts for pausing scoped leads and downstream consumers."""
from pathlib import Path

import pytest

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
    text = " ".join((ROOT / "skills/xss/references/lifecycle.md").read_text().split())
    assert "does not establish the behavior of other consumers" in text
    assert "not a reason to keep a run alive or create a lead for every stored value" in text
    assert "reopen or branch the concrete XSS hypothesis" in text
    assert "Do not infer an executable sink from persistence alone" in text


def test_goal_pause_keeps_material_open_leads():
    text = skill("bug-goals")
    assert "hand off the IDs of material open leads" in text
    assert "explains the pause, not a negative verdict" in text
    assert "bounded-stop` is a **paused, evidence-bounded run**" in text


def validate_closure_route(text, policy_root):
    """Validate an entry route and the owner reference in a supplied projection."""
    assert "`general-security-testing-policy`" in text
    assert "`references/testing-posture.md`" in text
    owner = policy_root / "general-security-testing-policy"
    assert (owner / "SKILL.md").is_file()
    assert (owner / "references" / "testing-posture.md").is_file()


@pytest.mark.parametrize("entry", ["coverage", "leads"])
def test_closure_owner_route_and_negative_cases(entry, tmp_path):
    owner = tmp_path / "general-security-testing-policy"
    (owner / "references").mkdir(parents=True)
    (owner / "SKILL.md").write_text("fixture owner")
    reference = owner / "references" / "testing-posture.md"
    reference.write_text("fixture reference")
    text = skill(entry)
    validate_closure_route(text, tmp_path)

    route = "`general-security-testing-policy`"
    assert text.count(route) == 1
    with pytest.raises(AssertionError):
        validate_closure_route(text.replace(route, "missing route", 1), tmp_path)
    ref = "`references/testing-posture.md`"
    assert text.count(ref) == 1
    with pytest.raises(AssertionError):
        validate_closure_route(text.replace(ref, "missing reference", 1), tmp_path)
    reference.unlink()
    with pytest.raises(AssertionError):
        validate_closure_route(text, tmp_path)


def test_browser_route_and_missing_owner(tmp_path):
    text = skill("coverage")
    route = "`browser-session-policy`"
    assert text.count(route) == 1
    browser = tmp_path / "browser-session-policy" / "SKILL.md"
    browser.parent.mkdir()
    browser.write_text("fixture owner")

    def validate(entry_text):
        assert route in entry_text
        assert browser.is_file()

    validate(text)
    with pytest.raises(AssertionError):
        validate(text.replace(route, "missing browser route", 1))
    browser.unlink()
    with pytest.raises(AssertionError):
        validate(text)
