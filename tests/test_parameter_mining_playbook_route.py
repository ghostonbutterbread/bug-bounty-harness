"""The parameter-mining router resolves its playbook in the selected lane."""
from __future__ import annotations

import subprocess
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_parameter_mining_playbook_uses_checkout_resolver() -> None:
    skill = (ROOT / "skills/parameter-mining/SKILL.md").read_text(encoding="utf-8")
    assert "bbh --print-command prompts/parameter-mining-playbook.md" in skill
    assert "bbh --root" in skill
    assert "physical source checkout" in skill
    assert "provenance cannot be established" in skill
    launcher_docs = (ROOT / "docs/bbh-launcher.md").read_text(encoding="utf-8")
    assert "non-executable" in launcher_docs
    assert "without running" in launcher_docs
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/bbh.py"), "--print-command", "prompts/parameter-mining-playbook.md"],
        check=True, text=True, capture_output=True,
    )
    assert Path(result.stdout.strip()) == ROOT / "prompts/parameter-mining-playbook.md"
    assert Path(result.stdout.strip()).is_file()


def test_playbook_resolver_uses_launcher_checkout_and_fails_if_missing(tmp_path: Path) -> None:
    for lane in ("stable", "beta"):
        root = tmp_path / lane
        (root / "scripts").mkdir(parents=True)
        (root / "prompts").mkdir()
        (root / "skills/parameter-mining").mkdir(parents=True)
        (root / "skills/parameter-mining/SKILL.md").write_text(lane, encoding="utf-8")
        shutil.copyfile(ROOT / "scripts/bbh.py", root / "scripts/bbh.py")
        (root / "prompts/parameter-mining-playbook.md").write_text(lane, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(root / "scripts/bbh.py"), "--print-command", "prompts/parameter-mining-playbook.md"],
            check=True, text=True, capture_output=True,
        )
        path = Path(result.stdout.strip())
        assert path == root / "prompts/parameter-mining-playbook.md"
        assert path.read_text(encoding="utf-8") == lane

    projected = tmp_path / "projected-skill.md"
    projected.symlink_to(tmp_path / "stable/skills/parameter-mining/SKILL.md")
    skill_source_root = projected.resolve().parents[2]
    assert skill_source_root == tmp_path / "stable"
    assert skill_source_root != tmp_path / "beta"

    (tmp_path / "beta/prompts/parameter-mining-playbook.md").unlink()
    result = subprocess.run(
        [sys.executable, str(tmp_path / "beta/scripts/bbh.py"), "--print-command", "prompts/parameter-mining-playbook.md"],
        check=False, text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "missing from this checkout" in result.stderr
