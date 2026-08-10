"""Regression checks for the compact BBH agent-context and memory routing contract."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_root_instructions_point_to_compact_agent_entry_card():
    entry = text("agents/index.md")
    root_instructions = text("AGENTS.md")
    legacy = text("INSTRUCTIONS.md")

    assert "general-security-testing-policy" in entry
    assert "live-testing-policy" in entry
    assert "/map-store" in entry
    assert "/hypothesis-ledger" in entry
    assert "agents/index.md" in root_instructions
    assert "Do not paste this file as a generic agent bootstrap" in legacy
    assert "~/Shared/bounty_recon/{program}/ghost/knowledge.md" in legacy
    assert "Do not use the retired" in legacy


def test_memory_layers_route_private_candidates_and_stable_facts_once():
    notes_skill = text("skills/bounty-notes/SKILL.md")
    notes_playbook = text("prompts/bounty-notes-playbook.md")
    hunter_skill = text("skills/hunter-memory/SKILL.md")
    hunter_loop = text("skills/hunter-loop/SKILL.md")

    assert "A newly generated agent hypothesis belongs in `/hypothesis-ledger`" in notes_skill
    assert "do not mirror it into `notes/hypotheses/`" in notes_playbook
    assert "/map-store" in hunter_skill and "stable enough" in hunter_skill
    assert "/hypothesis-ledger" in hunter_loop
    assert not (ROOT / "skills" / "deep-hunt").exists()
