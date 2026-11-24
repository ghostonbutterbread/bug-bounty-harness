"""Discovery regression for the class-neutral live/static hunt guidance.

These source checks complement, not replace, an independent agent walkthrough.
"""
from pathlib import Path

from agents.skill_text import norm, read_norm

def claims_ci(text: str, *fragments: str) -> None:
    """Assert each fragment appears, case-insensitively on normalised forms."""
    haystack = text.lower()
    missing = [f for f in fragments if norm(f).lower() not in haystack]
    assert not missing, f"missing claims: {missing}"

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


def test_js_hunt_defaults_to_live_validation_and_keeps_review_workers_offline():
    hunt = read_norm(ROOT / "skills/js-hunt/SKILL.md")
    live = read_norm(ROOT / "skills/js-hunt/references/live-validation.md")
    claims_ci(hunt, "defaults to online", "references/live-validation.md",
           "give each a disposition", "--offline", "no target traffic",
           "no network collection", "offline workers never send target requests",
           "review workers never do it",
           "live validators run after it as a separate stage",
           "never share review-worker slots",
           "leave each lead open with its next discriminator",
           "stop after `/js-pull`")
    claims_ci(live, "general-security-testing-policy", "live-testing-policy",
           "task browser", "task-MITM", "re-gate when the host",
           "a gate passed for a read does not cover a state change",
           "bbh agents/leads.py create", "hypothesis-ledger",
           "drive the feature", "analyze-endpoint",
           "finding linked", "enforcement established", "not reachable",
           "out of scope", "needs_recheck",
           "next discriminator and wake condition", "count for each disposition", "not yet live-validated")
    fanout = read_norm(ROOT / "skills/js/references/offline-fanout.md")
    claims_ci(fanout, "workers never send target requests",
           "skills/js-hunt/references/live-validation.md",
           "offline mode stops at the hypothesis queue")
    playbook = read_norm(ROOT / "prompts/js-playbook.md")
    claims_ci(playbook, "defaults to online",
           "skills/js-hunt/references/live-validation.md")
    router = read_norm(ROOT / "skills/js/SKILL.md")
    claims_ci(router, "defaults to online", "review workers stay offline")
    lens = read_norm(ROOT / "skills/js/references/analysis-lens.md")
    claims_ci(lens, "this lens itself never authorizes a live probe")



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


def test_partial_inventory_route_uses_available_artifacts_across_documents():
    hunt = text("skills/js-hunt/SKILL.md")
    playbook = text("prompts/js-playbook.md")
    fanout = text("skills/js/references/offline-fanout.md")
    for body in (hunt, playbook, fanout):
        assert "interrupted inventory" in body
        assert "missing" in body and "provenance" in body
    assert "only when the library exists" in hunt
    assert "when the required inventory records exist" in hunt
    assert "when available" in playbook
    assert "every meaningful js run should leave" not in playbook
    assert "exact local packet/provenance paths" not in playbook


def test_partial_evidence_conditions_apply_to_entire_js_playbook():
    playbook = text("prompts/js-playbook.md")
    assert "cite the available evidence" in playbook
    assert "when the required observation records exist" in playbook
    assert "when adjacent chunks and their indexes are available" in playbook
    assert "preserve the partial trace" in playbook
    assert "when a real js url or route and coverage records exist" in playbook
    assert "keep citations and durable handoffs tied to the jsonl row, manifest" not in playbook
    assert "after a worker reviews packets, write its pre-finding conclusions as jsonl and index them" not in playbook


def test_local_file_handoff_is_not_inventory_dependent():
    hunt = text("skills/js-hunt/SKILL.md")
    assert "standalone local" in hunt
    assert "when the required inventory records exist" in hunt
    assert "without an inventory" in hunt
    assert "unavailable provenance" in hunt
    assert "do not invent" in hunt
    assert "when the library and indexes exist" in text("skills/js/references/analysis-lens.md")


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
