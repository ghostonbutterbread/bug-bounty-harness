from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def normalized(text: str) -> str:
    return " ".join(text.split())


def test_hoster_script_authority_uses_current_capability_not_machine_lists() -> None:
    guidance = normalized((ROOT / "AGENTS.md").read_text(encoding="utf-8"))
    hoster_guidance = guidance.split("Hoster is execution-only by default", 1)[1]

    assert "Hoster is execution-only by default" in guidance
    assert "explicitly authorized repository task" in guidance
    assert "current GitHub credential passes a non-mutating write check" in guidance
    assert "for this repository" in hoster_guidance
    assert "existing-script repair" in guidance
    assert "`coding-agent-operations-policy` and `branch-lifecycle`" in guidance
    assert "write access is unavailable" in guidance
    assert "`coding-proposal-packets-policy`" in guidance
    assert "skill or policy" in guidance
    assert "skill seed" in guidance
    assert "never authors, commits, merges, or pushes harness source" not in guidance
    for duplicated_allowlist_entry in ("bug-bounty-harness", "bounty-tools", "ghostonbread"):
        assert duplicated_allowlist_entry not in hoster_guidance.lower()
