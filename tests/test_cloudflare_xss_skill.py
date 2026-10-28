"""Cloudflare XSS knowledge is discoverable without a WAF-block prerequisite."""
from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OWNER = ROOT / "skills/cloudflare-xss/SKILL.md"
ENTRY_SKILLS = ("xss", "waf", "xss-waf-evasion")


def route_resolves(text: str, root: Path = ROOT) -> bool:
    return "`cloudflare-xss`" in text and (root / "skills/cloudflare-xss/SKILL.md").is_file()


def test_one_compact_knowledge_owner_has_a_discoverable_description():
    text = OWNER.read_text()
    metadata = yaml.safe_load(text.split("---", 2)[1])
    assert metadata["name"] == "cloudflare-xss"
    assert "Cloudflare" in metadata["description"][:57]
    assert "XSS" in metadata["description"][:57]
    assert len(text.split()) < 1500
    assert list(OWNER.parent.rglob("*")) == [OWNER]
    assert "no WAF block is needed" in text
    assert "not a required checklist" in text
    assert "## JavaScript Lens" in text
    assert "browser proof" in text
    assert "source-reported" in text


@pytest.mark.parametrize("name", ENTRY_SKILLS)
def test_each_existing_entry_routes_directly_to_the_same_owner(name):
    text = (ROOT / f"skills/{name}/SKILL.md").read_text()
    assert route_resolves(text)
    paragraph = next(p for p in text.split("\n\n") if "`cloudflare-xss`" in p)
    assert "Cloudflare" in paragraph and "XSS" in paragraph
    assert "block" in paragraph  # explicitly does not depend on a block
    assert "Cache-Control: no-cache=" not in text  # knowledge is not copied


def test_missing_route_or_packaged_owner_fails_discovery(tmp_path):
    entry = (ROOT / "skills/xss/SKILL.md").read_text()
    assert route_resolves(entry)
    assert not route_resolves(entry.replace("`cloudflare-xss`", "the vendor notes"))
    assert not route_resolves(entry, root=tmp_path)


def test_research_has_conditions_controls_and_historical_limits():
    text = OWNER.read_text()
    for signal in (
        "namespace", "serialization", "Cache-Control", "Content-Type",
        "BFCache", "HTTP cache", "initial URL", "returnTo",
        "email", "Rocket Loader", "CSPT", "innerHTML", "MCP",
    ):
        assert signal in text
    assert text.count("**Compare:") >= 5
    for boundary in (
        "not a claim that current deployments are vulnerable",
        "not CDN cache poisoning", "fixed", "source restriction",
        "image element", "executing origin", "MapStore", "ResearchMap",
    ):
        assert boundary.lower() in text.lower()
    assert "/home/ryushe/" not in text


def test_original_article_and_all_six_introductory_research_links_are_retained():
    urls = re.findall(r"\]\((https://[^)]+)\)", OWNER.read_text())
    expected = {
        "https://www.slcyber.io/research/cache-me-if-you-can-xss-in-cloudflares-cdn-cgi-image",
        "https://x.com/kinugawamasato/status/893404078365069312",
        "https://portswigger.net/research/when-security-features-collide",
        "https://x.com/kinugawamasato/status/1414648695904083988",
        "https://blog.criticalthinkingpodcast.io/p/0-days-htmx-ss-with-mathias",
        "https://kazama.in/mcp-server-portal-xss-to-ato/",
        "https://x.com/kevin_mizu/status/2074463929401516413",
    }
    assert expected <= set(urls)
    assert "https://developers.cloudflare.com/images/transform-images/sources/" in urls
    assert "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4" in urls
    registry = (ROOT / "SKILL_REGISTRY.md").read_text()
    assert "| **cloudflare-xss** |" in registry
