from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def normalized(text: str) -> str:
    return " ".join(text.split())


def test_hoster_script_authority_uses_current_capability_not_machine_lists() -> None:
    guidance = normalized((ROOT / "AGENTS.md").read_text(encoding="utf-8"))
    hoster_guidance = guidance.split("Other agents, including agents on Hoster,", 1)[1]

    assert "may perform explicitly authorized script maintenance" in hoster_guidance
    assert "current GitHub credential passes a non-mutating write check for this repository" in hoster_guidance
    assert "Their skill-edit permission is limited to adding a script-map pointer" in hoster_guidance
    assert "Creating a script must update that map in the same change" in hoster_guidance
    assert "Unrelated skill-body and policy changes go to Hermes as a proposal or skill seed" in hoster_guidance
    assert "`coding-agent-operations-policy`, and `branch-lifecycle`" in hoster_guidance
    assert "If write access is unavailable, use `coding-proposal-packets-policy`" in hoster_guidance
    assert "never authors, commits, merges, or pushes harness source" not in guidance
    for duplicated_allowlist_entry in ("bug-bounty-harness", "bounty-tools", "ghostonbread"):
        assert duplicated_allowlist_entry not in hoster_guidance.lower()
