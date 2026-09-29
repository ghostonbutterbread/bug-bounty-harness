from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_business_logic_hunt_route_and_reference() -> None:
    skill = (ROOT / "skills/business-logic/SKILL.md").read_text(encoding="utf-8")
    reference = (ROOT / "skills/business-logic/references/business-model-and-issue-families.md").read_text(encoding="utf-8")
    js = (ROOT / "skills/js/SKILL.md").read_text(encoding="utf-8")
    registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")

    assert "name: business-logic\n" in skill
    assert "business-logic-modeling" in skill
    assert "references/business-model-and-issue-families.md" in skill
    assert "general-security-testing-policy" in skill
    assert "live-testing-policy" in skill
    assert "Distinguish creation authority, retrieval, possession, and downstream use" in reference
    assert "owner-created credential" in reference
    assert "route a concrete workflow lead to `/business-logic`" in js
    assert "skills/business-logic/SKILL.md" in registry
