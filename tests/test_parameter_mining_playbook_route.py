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
    assert "same checkout" in skill
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
        shutil.copyfile(ROOT / "scripts/bbh.py", root / "scripts/bbh.py")
        (root / "prompts/parameter-mining-playbook.md").write_text(lane, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(root / "scripts/bbh.py"), "--print-command", "prompts/parameter-mining-playbook.md"],
            check=True, text=True, capture_output=True,
        )
        path = Path(result.stdout.strip())
        assert path == root / "prompts/parameter-mining-playbook.md"
        assert path.read_text(encoding="utf-8") == lane

    (tmp_path / "beta/prompts/parameter-mining-playbook.md").unlink()
    result = subprocess.run(
        [sys.executable, str(tmp_path / "beta/scripts/bbh.py"), "--print-command", "prompts/parameter-mining-playbook.md"],
        check=False, text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "missing from this checkout" in result.stderr
