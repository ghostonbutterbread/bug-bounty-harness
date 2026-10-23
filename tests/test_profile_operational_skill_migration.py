"""Offline route and safety regressions for operational skill migration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_adaptive_controller_has_discoverable_but_non_runtime_route():
    owner = read("skills/adaptive-rate-control/SKILL.md")
    router = read("skills/bounty-tools/SKILL.md")
    registry = read("SKILL_REGISTRY.md")
    assert owner.startswith("---\nname: adaptive-rate-control\n")
    assert "`/adaptive-rate-control`" in router
    assert "| **adaptive-rate-control** |" in registry
    for phrase in ("not a claim that BBH's current `tool-run` has adaptive scheduling",
                   "before** planning/rendering", "Retry-After", "operator review",
                   "In-flight", "explicitly marked low-rate stability probe",
                   "planner together", "cross-backend fallback"):
        assert phrase in owner
    assert "published program rules" in owner
    assert "/home/ryushe" not in owner


def test_behavior_owner_links_factual_stateful_mapping_reference():
    owner = read("skills/map-store/SKILL.md")
    ref = read("skills/map-store/references/application-behavior-mapping.md")
    assert "references/application-behavior-mapping.md" in owner
    for phrase in ("owned-session UI transition", "task-MITM request",
                   "unknown edges", "complete** supporting observation list",
                   "replaces the list", "failed vulnerability-class test",
                   "Hypothesis Ledger", "Attempts"):
        assert phrase in ref
    assert "Do not manufacture live traffic" in ref


def test_cross_engine_boundary_stays_in_browser_owner():
    browser = read("skills/chromium-test/SKILL.md")
    assert "Do not mount or copy a Chromium user-data directory into another browser engine" in browser
    assert "proves only cookie transport—not authenticated identity" in browser
    assert "verify the principal in that browser" in browser


def test_existing_canonical_routes_not_shadowed():
    for name in ("application-surface-mapping", "authentication-testing",
                 "browser-profile-coordination", "finding-ingestion",
                 "scanner-startup-validation"):
        assert not (ROOT / "skills" / name).exists()
    assert "## Admin-panel default credential campaign" in read("skills/credential-exposure-validation/SKILL.md")
    assert "--lane" in read("skills/manual-hunter/SKILL.md")
    assert "## Long-running startup qualification" in read("skills/bounty-tools/SKILL.md")
