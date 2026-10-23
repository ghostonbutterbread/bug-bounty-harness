"""Keep reviewed local-shadow guidance in its canonical BBH owner only."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"


def skill(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")


def test_account_guard_regression_guidance_preserves_current_migration_gate() -> None:
    account = skill("account-registry")
    assert "benign prose" in account and "opaque references writable" in account
    for case in ("JSON", "header containers", "indexed keys", "URL-decoded query keys", "camelCase", "prefixed/suffixed", "token_value", "secret_access_key"):
        assert case in account
    assert "not yet implemented" in account
    assert "Chromium launcher" in account and "This gate currently fails" in account
    assert "web_bounty" in account
    assert "bounty_web" not in account


def test_blocker_fixture_is_not_a_disclosure_gate() -> None:
    blocker = skill("blocker-first-analysis")
    assert "proof would otherwise mutate non-owned state" in blocker
    assert "not a prerequisite for in-scope disclosure testing" in blocker
    assert "smallest authorized unblock" in blocker
    assert "remediation-first" in blocker


def test_error_citations_are_routed_but_not_a_new_live_policy() -> None:
    parent = skill("error-intelligence")
    reference = SKILLS / "error-intelligence/references/error-behavior-signals.md"
    assert "references/error-behavior-signals.md" in parent
    assert reference.is_file()
    content = reference.read_text(encoding="utf-8")
    for citation in ("WSTG-ERRH-01", "WSTG-ERRH-02", "Error Handling Cheat Sheet"):
        assert citation in content
    assert "not proof of security impact" in content
    assert "do not authorize additional requests" in content
    assert "--novelty-basis" in parent
    assert "Never put cookies" in parent


def test_research_cards_are_query_checked_and_disclosures_not_overclaimed() -> None:
    research = skill("research-knowledge-management")
    assert "query each new card with likely" in research
    assert "reasonable query misses" in research
    assert "references/functionality-first-writeup-synthesis.md" in research
    reference = (SKILLS / "research-knowledge-management/references/functionality-first-writeup-synthesis.md").read_text(encoding="utf-8")
    assert "Deduplicate report identities" in reference
    assert "team-summary-only" in reference
    assert "researcher- versus team-assigned" in reference
    assert "proves neither prevalence nor current exposure" in reference
    assert "Never echo whole JSON" in reference
    assert "missing safe-fetch" in reference


def test_hunt_pressure_does_not_override_evidence_or_transport_gate() -> None:
    hunt = skill("hunt-orchestration")
    assert "motivation, not an observed fact or finding" in hunt
    assert "clean independent verifier" in hunt
    flat = " ".join(hunt.split())
    assert "one approved owned program account" in flat
    assert "not as a universal hunt-start gate" in flat
    assert "Public or anonymous in-scope work does not need an account" in flat
    assert "session collision from expiry" in hunt
    assert "through that affected transport path" in hunt
    assert "independently healthy transport lane" in hunt
    assert "Roughly 30–45 minutes" not in hunt
    assert "two historical-led target choices" not in hunt


def test_goal_router_does_not_absorb_claude_launch_instructions() -> None:
    goal = skill("bug-goals")
    assert "scripts/goal_router.py" in goal
    assert "Goal-only Coverage checkpoint" in goal
    assert "--permission-mode bypassPermissions" not in goal
    assert "claude.ai/code/session_" not in goal
