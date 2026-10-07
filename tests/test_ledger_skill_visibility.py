"""Keep the ledger skill's default work query aligned with the CLI filter."""

from pathlib import Path


def test_ledger_skill_routes_work_selection_through_filtered_list() -> None:
    root = Path(__file__).resolve().parents[1]
    skill = (root / "skills/ledger/SKILL.md").read_text(encoding="utf-8")
    assert "bbh agents/me_ledger.py list --program {program}" in skill
    assert "bbh agents/me_ledger.py prior-work --program {program}" in skill
    assert "bbh agents/me_ledger.py get --program {program}" in skill
    hunter_loop = (root / "skills/hunter-loop/SKILL.md").read_text(encoding="utf-8")
    assert "`prior-work` check before repeating" in hunter_loop
    assert "`check` below is instead a targeted file/class dedupe lookup" in skill
    assert "--include-closed" in skill
    assert "Do not preload raw `ledger.json`" in skill
    assert "Submission status is operator-reported" in skill
