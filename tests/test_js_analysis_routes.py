"""Navigation contracts for standalone and embedded JS analysis.

These checks do not substitute for an independent semantic walkthrough.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path):
    source = ROOT / path
    assert source.is_file(), f"missing expected route or analysis skill: {path}"
    return " ".join(source.read_text(encoding="utf-8").lower().split())


def test_standalone_hunt_acquires_missing_meaningful_inventory():
    hunt = text("skills/js-hunt/SKILL.md")
    assert "sufficient" in hunt and "relevance" in hunt and "freshness" in hunt
    assert "`/js-pull`" in hunt and "insufficient" in hunt
    assert "strong lead" in hunt and "not a prerequisite" in hunt
    assert "explicitly offline" in hunt and "no network" in hunt
    assert "collection-only" in hunt


def test_both_entry_points_reach_canonical_analysis_without_broad_escalation():
    router = text("skills/js/SKILL.md")
    standalone = text("skills/js-hunt/SKILL.md")
    entry = text("agents/index.md")
    lens = text("skills/js/references/analysis-lens.md")
    assert "`/js-hunt`" in router and "references/analysis-lens.md" in router
    assert "references/analysis-lens.md" in standalone
    assert "analysis-lens.md" in entry
    assert "broad" in lens and "current" in lens and "without" in lens
    for concept in ("request builders", "state", "controllability", "consumer", "evidence"):
        assert concept in lens
    assert "skills/js/references/analysis-lens.md" in text("SKILL_REGISTRY.md")


def test_shared_lens_resolves_through_projected_js_skill(tmp_path):
    projection = tmp_path / "js"
    projection.symlink_to(ROOT / "skills/js", target_is_directory=True)
    lens = projection / "references/analysis-lens.md"
    assert lens.resolve() == (ROOT / "skills/js/references/analysis-lens.md").resolve()
    assert "canonical analysis lens" in lens.read_text(encoding="utf-8").lower()


def test_ordinary_hunt_routes_relevant_code_to_lens_not_broad_campaign():
    for path in ("skills/live-map/SKILL.md", "skills/surface-expansion/SKILL.md"):
        body = text(path)
        assert "skills/js/references/analysis-lens.md" in body
        assert "broad" in body
    hunt = text("skills/js-hunt/SKILL.md")
    assert "if collection fails or is blocked" in hunt
    assert "continue with available artifacts" in hunt
    assert "do not claim a complete hunt" in hunt


def test_xss_embedded_tracing_uses_shared_lens_not_standalone_hunt():
    for path in ("skills/xss/SKILL.md", "skills/xss/references/source-acquisition.md"):
        body = text(path)
        assert "skills/js/references/analysis-lens.md" in body
        assert "use `js-hunt` when" not in body
        assert "js-pull" in body


def test_pull_handoff_respects_the_calling_objective():
    pull = text("skills/js-pull/SKILL.md")
    assert "standalone" in pull and "`/js-hunt`" in pull
    assert "current investigation" in pull and "analysis-lens.md" in pull
    assert "otherwise load `/js-hunt`" not in pull
    specialist = text("skills/rce-deserialization/SKILL.md")
    assert "analysis-lens.md" in specialist


def test_shared_lens_keeps_offline_and_partial_evidence_boundaries():
    lens = text("skills/js/references/analysis-lens.md")
    for concept in ("offline", "no network", "missing", "provenance", "unknown", "specialist"):
        assert concept in lens
