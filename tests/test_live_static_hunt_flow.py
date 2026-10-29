"""Discovery regression for the class-neutral live/static hunt guidance.

These source checks complement, not replace, an independent agent walkthrough.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").lower().split())


def test_hunt_entry_routes_to_class_neutral_application_understanding():
    entry = text("skills/hunt/SKILL.md")
    assert "live-map" in entry
    assert "browser" in entry
    assert "strong" in entry


def test_live_map_explains_two_way_runtime_and_source_correlation():
    mapping = text("skills/live-map/SKILL.md")
    assert "runtime → source" in mapping
    assert "source → runtime" in mapping
    assert "not a prerequisite" in mapping


def test_js_parent_reconnects_runtime_without_authorizing_offline_workers():
    js = text("skills/js-hunt/SKILL.md")
    assert "explicitly offline" in js
    assert "live-map" in js
    assert "offline workers never send target requests" in js
    assert "technology-research" in js


def test_xss_uses_generic_mapping_without_adding_generic_xss_routing():
    xss = text("skills/xss/SKILL.md")
    live = text("skills/live-map/SKILL.md")
    assert "live-map" in xss
    assert "load `xss`" not in live


def test_hunter_playbook_does_not_limit_browser_to_js_heavy_flows():
    playbook = text("prompts/hunter-loop-playbook.md")
    assert "browser/cdp first when the flow is js-heavy or stateful" not in playbook
    assert "browser-session-policy" in playbook
