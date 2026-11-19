"""Offline checks for review precedence at the actual handoff entry."""
from pathlib import Path


def test_handoff_requires_inspection_only_during_operator_review():
    text = " ".join((Path(__file__).resolve().parents[1] / "skills/chromium-handoff/SKILL.md").read_text().split())
    assert "`operator_review`" in text
    assert "<<<<<<<" not in text
    assert "inspection-only" in text
    assert "do not interact with the target" in text
    assert "including solving" in text
    assert "explicit authorized reset" in text
    assert "securely prefill" in text
    assert "Do not navigate away from an existing CAPTCHA" in text
    assert "interrupted challenge is ineligible" in text
