"""Adaptive WAF/XSS skill routing and evidence-contract regressions."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WAF = ROOT / "skills/waf/SKILL.md"
XSS = ROOT / "skills/xss/SKILL.md"
PAYLOAD = ROOT / "skills/xss-payload-engineering/SKILL.md"
OVERLAY = ROOT / "skills/xss-waf-evasion/SKILL.md"
TECHNIQUES = ROOT / "skills/xss-waf-evasion/references/technique-questions.md"
SOURCES = ROOT / "skills/xss-waf-evasion/references/vendor-and-mechanism-sources.md"
PLAYBOOK = ROOT / "prompts/waf-playbook.md"
PARSER_REFERENCE = ROOT / "skills/xss-payload-engineering/references/parser-stage-character-variants.md"


def test_general_waf_loop_starts_with_measured_control_not_vendor_rotation() -> None:
    text = WAF.read_text(encoding="utf-8")
    stages = (
        "**Baseline:**",
        "**Locate the control:**",
        "**Retrieve narrowly:**",
        "**Sufficiency gate:**",
        "**Test and learn:**",
    )
    positions = [text.index(stage) for stage in stages]
    assert positions == sorted(positions)
    assert "clean, in-scope request" in text
    assert "one-variable change" in text
    assert "green control" in text
    assert "origin application" in text
    assert "vendor fingerprint is a lead" in text
    assert "no local card or" in text
    assert "class-specific consumer" in text
    assert "200/challenge change alone is not a bypass proof" in text
    assert "Its `bypass_success` counter" in text
    assert "neither an Attempts replacement nor" in text
    assert "Load `xss-waf-evasion`" not in text  # conditional, not universal WAF load


def test_xss_routes_to_loadable_filter_consumer_overlay() -> None:
    assert OVERLAY.is_file()
    text = OVERLAY.read_text(encoding="utf-8")
    assert text.startswith("---\nname: xss-waf-evasion\n")
    assert "waf-live-policy" in text
    assert "xss-payload-engineering" in text
    assert "plausible bypass" in text
    assert "If no:" in text and "If yes:" in text
    assert "victim's actual request" in text
    assert "MapStore" in text and "ResearchMap" in text
    assert "never auto-promote a search" in text
    assert "DOM-only source" in text
    assert "reject-on-match filter" in text
    assert "browser/consumer" in text

    assert "`xss-waf-evasion`" in XSS.read_text(encoding="utf-8")
    assert "`xss-waf-evasion`" in PAYLOAD.read_text(encoding="utf-8")
    assert "`xss-waf-evasion`" in WAF.read_text(encoding="utf-8")


def test_references_are_packaged_conditional_and_source_linked() -> None:
    text = OVERLAY.read_text(encoding="utf-8")
    for reference in (TECHNIQUES, SOURCES):
        assert reference.is_file()
        assert reference.name in text
    technique = TECHNIQUES.read_text(encoding="utf-8")
    sources = SOURCES.read_text(encoding="utf-8")
    assert "negative control" in technique
    assert "victim" in technique
    assert "HTML entity in plain text" in technique
    assert "ResearchMap cards" in sources
    assert "do not copy the JSON" in sources
    assert "alert(" not in technique + sources
    urls = re.findall(r"\]\((https://[^)]+)\)", sources)
    assert len(urls) >= 20
    assert len(urls) == len(set(urls))


def test_live_harness_is_not_misdescribed_as_bounded_one_variable_probe() -> None:
    waf = WAF.read_text(encoding="utf-8")
    playbook = PLAYBOOK.read_text(encoding="utf-8")
    assert "--rps` setting does **not** govern every inner retry" in waf
    assert "Do **not** launch either" in waf
    assert "**not** a bounded one-variable" in playbook
    assert "Do not exhaust generic Tier 1/Tier 2" in playbook
    assert "bbh agents/bypass_harness.py --target" not in waf
    assert "bypass_harness.py --target" not in playbook
    assert "A different origin response" in playbook
    assert "not by itself confirmed" in playbook
    assert "owning lane's `attempt-recording-policy` writer" in playbook
    assert "not a parallel canonical Attempts or Findings ledger" in playbook


def test_unknown_vendor_uses_generic_mechanism_and_parser_reference_resolves() -> None:
    waf = WAF.read_text(encoding="utf-8")
    overlay = OVERLAY.read_text(encoding="utf-8")
    assert "an unknown vendor does not exclude a generic" in waf
    assert "Match a vendor only when" in waf
    assert PARSER_REFERENCE.is_file()
    assert "skills/xss-payload-engineering/references/parser-stage-character-variants.md" in overlay
