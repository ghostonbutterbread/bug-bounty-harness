"""Defense-chain continuation remains discoverable and evidence-led."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "skills/xss/SKILL.md"
CHAIN = ROOT / "skills/xss/references/defense-chain.md"


def test_warm_xss_routes_to_a_real_defense_chain_reference():
    router = ROUTER.read_text(encoding="utf-8")
    assert "locate the first observed blocker" in router
    assert "`references/defense-chain.md`" in router
    assert CHAIN.is_file()
    for signal in ("Sanitizer behavior", "CSP behavior", "WAF/filter behavior", "Changed or later consumer"):
        assert signal in router
    assert "no fixed bypass count" in router


def test_chain_keeps_all_layers_and_proof_separate():
    text = " ".join(CHAIN.read_text(encoding="utf-8").split())
    for phrase in (
        "client-side path", "delivered enforcing policy", "Report-Only",
        "Trusted Types", "xss-technology-research", "xss-payload-engineering",
        "waf-live-policy", "xss-waf-evasion", "xss-lifecycle",
        "More than one blocker", "negative control", "first failed",
        "no defense fingerprint or", "scope, rate, ownership", "confirmed only",
    ):
        assert phrase in text
    assert "CSP → sanitizer → WAF difficulty ranking" in text
    assert "attempt-recording-policy" in text
    assert "selected XSS lane" in text
