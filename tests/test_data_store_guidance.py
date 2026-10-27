"""Store-purpose directory: valid owners, early discovery, no workflow."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/data-store-guidance/SKILL.md"


def test_frontmatter_and_local_routes():
    text = SKILL.read_text()
    frontmatter, body = text.split("---\n", 2)[1:]
    assert "name: data-store-guidance" in frontmatter
    assert 'description: "Use when starting bounty work or choosing a store."' in frontmatter
    assert body.strip()
    routes = set(re.findall(r"`/([a-z][a-z0-9-]+)`", text))
    assert {"map-store", "coverage", "ledger", "bounty-storage", "url-ingest"} <= routes
    for name in routes:
        assert (ROOT / "skills" / name / "SKILL.md").is_file(), name
    assert not re.search(r"/home/[^/]+/", text)


def test_early_entry_and_single_store_map():
    entry = (ROOT / "agents/index.md").read_text()
    assert "/data-store-guidance" in entry.split("2. Authority order")[0]
    assert "store-ownership map" in entry
    assert "evidence-navigation workflow" not in entry
    assert "/account-registry" not in entry
    assert "/hypothesis-ledger" not in entry


def test_purpose_directory_not_an_operational_workflow():
    text = SKILL.read_text()
    assert not re.search(r"^\d+\. ", text, re.MULTILINE)
    assert "```" not in text
    assert "bbh " not in text
    assert "Locate, select, follow, verify" not in text
    assert "## Verification" not in text
    assert "same change" in text
    assert "procedures" in text and "owning skills" in text


def test_inventory_retains_store_responsibilities():
    text = SKILL.read_text()
    for name in (
        "Scope", "Recon", "URL/parameter review", "Runtime maps", "JavaScript",
        "Endpoint/API/parameter outputs", "MapStore", "Public Leads",
        "Private hypotheses", "Attempts", "Live Coverage", "Static Coverage",
        "Notes", "Program Docs", "Findings", "Reports", "Blockers", "Errors",
        "Safety incidents", "Owned accounts/resources/connections",
        "Owned public test artifacts", "Browser/proxy/auth state",
        "Static AppMap", "Portable ResearchMap", "Retained artifacts",
    ):
        assert f"**{name}**" in text, name


def test_storage_tier_owner_points_to_ownership_guide():
    storage = (ROOT / "skills/bounty-storage/SKILL.md").read_text()
    assert "/data-store-guidance" in storage
    assert "Shared vs mounted" in storage
