"""Ownership/discovery contracts; semantic navigation is independently reviewed."""
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
    # All slash-style skill routes are repository-owned; external policy owners
    # are named explicitly without pretending they are packaged in this repo.
    routes = set(re.findall(r"`/([a-z][a-z0-9-]+)`", text))
    assert {"map-store", "coverage", "ledger", "bounty-storage", "url-ingest"} <= routes
    for name in routes:
        assert (ROOT / "skills" / name / "SKILL.md").is_file(), name
    assert not re.search(r"/home/[^/]+/", text)


def test_early_entry_and_single_store_map():
    entry = (ROOT / "agents/index.md").read_text()
    assert "/data-store-guidance" in entry.split("2. Authority order")[0]
    assert "canonical store-ownership map" in entry
    assert "/account-registry" not in entry
    assert "/hypothesis-ledger" not in entry
    assert "Recon Bus `append`" not in entry


def test_owning_skill_maintenance_boundary():
    guide = " ".join(SKILL.read_text().split())
    assert "canonical store-ownership map" in guide
    assert "same change" in guide
    assert "Adding, renaming, retiring" in guide
    assert "commands" in guide and "schemas" in guide


def test_inventory_covers_distinct_domains_and_boundaries():
    text = " ".join(SKILL.read_text().split())
    for label in (
        "Scope and lane identity", "Recon corpora", "URL/parameter review",
        "Runtime maps", "JavaScript", "Endpoint/API/parameter outputs",
        "MapStore facts and Application Behaviors", "Public Leads",
        "Private hypotheses", "Attempts", "Live Coverage", "Static Coverage",
        "Notes and Program Docs", "Findings and reports", "Blockers and Errors",
        "Safety incidents", "Owned accounts/resources/connections",
        "Owned public test artifacts", "Browser/proxy/auth state",
        "Static AppMap", "Portable ResearchMap", "Retained artifacts",
    ):
        assert f"**{label}**" in text, label
    for boundary in (
        "not checked", "owning host", "read-only", "private", "unknown",
        "not a per-payload write", "no question or review is justified",
        "not automatically", "not a new database", "record/artifact IDs",
    ):
        assert boundary in text, boundary


def test_storage_tier_owner_points_to_ownership_guide():
    storage = (ROOT / "skills/bounty-storage/SKILL.md").read_text()
    assert "/data-store-guidance" in storage
    assert "Shared vs mounted" in storage
