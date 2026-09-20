"""Regression checks for XSS sanitizer and WAF signal routing."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_xss_defense_signals_continue_the_same_consumer_path():
    xss = (ROOT / "skills/xss/SKILL.md").read_text(encoding="utf-8")

    assert "### Defense signals deepen the same XSS lane" in xss
    assert "not an independent failed XSS attempt" in xss
    assert "plausible executable consumer" in xss
    assert "xss-technology-research" in xss
    assert "xss-payload-engineering" in xss
    assert "waf-live-policy" in xss
    assert "non-equivalent, context-matched families" in xss
    assert "inherited safety or stop boundary" in xss
