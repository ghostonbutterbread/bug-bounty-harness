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


def test_existing_js_or_strong_lead_never_forces_online_collection():
    router = text("skills/js/SKILL.md")
    hunt = text("skills/js-hunt/SKILL.md")
    for body in (router, hunt):
        assert "available local" in body
        assert "strong lead" in body
        assert "explicitly offline" in body
        assert "no network" in body
    assert "`/js-hunt` calls `/js-pull` first" not in router
    assert "otherwise load `/js-pull` once for scoped collection" not in hunt
    playbook = text("prompts/js-playbook.md")
    assert "if there is no suitable inventory, pull first" not in playbook
    assert "explicitly offline" in playbook and "without network collection" in playbook


def test_offline_fanout_uses_existing_packets_not_acquisition():
    fanout = text("skills/js/references/offline-fanout.md")
    assert "explicitly offline" in fanout
    assert "do not run" in fanout and "inventory command" in fanout
    assert "existing local packets" in fanout
    pull = text("skills/js-pull/SKILL.md")
    assert "prerequisite when `/js-hunt` has no suitable current inventory" not in pull
    assert "explicitly offline" in pull and "no network" in pull


def test_partial_offline_fanout_does_not_require_final_inventory():
    fanout = text("skills/js/references/offline-fanout.md")
    assert "interrupted inventory" in fanout
    assert "without final indexes" in fanout
    assert "available provenance" in fanout
    assert "do not resume acquisition" in fanout
    assert "mark missing metadata" in fanout


def test_local_file_handoff_is_not_inventory_dependent():
    hunt = text("skills/js-hunt/SKILL.md")
    assert "standalone local" in hunt
    assert "inventory-backed" in hunt
    assert "without an inventory" in hunt
    assert "unavailable provenance" in hunt
    assert "do not invent" in hunt
    assert "when the library and indexes exist" in hunt


def test_known_shape_direct_http_is_an_explicit_browser_exception():
    for path in ("skills/hunt/SKILL.md", "skills/live-map/SKILL.md"):
        body = text(path)
        assert "known-shape" in body
        assert "direct http" in body
        assert "browser-session-policy" in body


def test_hunter_playbook_does_not_limit_browser_to_js_heavy_flows():
    playbook = text("prompts/hunter-loop-playbook.md")
    assert "browser/cdp first when the flow is js-heavy or stateful" not in playbook
    assert "browser-session-policy" in playbook
