"""Regression checks for XSS sanitizer and WAF signal routing."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_xss_defense_signals_continue_the_same_consumer_path():
    xss = (ROOT / "skills/xss/SKILL.md").read_text(encoding="utf-8")
    start = xss.index("A sanitizer hit, CSP violation, or WAF/filter block on an XSS vector is signal")
    end = xss.index("\nThe parent XSS agent", start)
    defense_route = xss[start:end]

    assert "not an independent failed XSS attempt" in defense_route
    assert "plausible executable consumer" in defense_route
    assert "keep pressure on that same vector" in defense_route
    assert "references/defense-chain.md" in defense_route
    assert "selected XSS lane still owns browser proof" in defense_route
    assert (
        "Sanitizer behavior: load `references/technology-research.md` and "
        "`references/payload-engineering.md`"
    ) in defense_route
    assert "WAF/filter behavior: load `waf-live-policy`" in defense_route
    assert "non-equivalent, context-matched families" in defense_route
    assert "inherited safety or stop boundary" in defense_route
