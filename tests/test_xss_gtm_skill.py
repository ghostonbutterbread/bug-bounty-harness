"""The preconfigured GTM fixture is discoverable without GTM management."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_xss_gtm_fixture_and_routes() -> None:
    skill = (ROOT / "skills/xss-gtm/SKILL.md").read_text(encoding="utf-8")
    router = (ROOT / "skills/xss/SKILL.md").read_text(encoding="utf-8")
    registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
    assert skill.startswith("---\nname: xss-gtm\n")
    assert "GTM-NRM7SMTK" in skill
    assert "https://www.googletagmanager.com/gtm.js?id=GTM-NRM7SMTK" in skill
    assert "network load" in skill and "actual browser effect" in skill
    assert "Do not modify the container" in skill
    assert "## JavaScript Lens" in skill
    assert "`xss-gtm`" in router
    assert "| **xss-gtm** |" in registry
