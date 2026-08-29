from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SkillSyncTests(unittest.TestCase):
    def test_sync_replaces_stale_files_only_inside_managed_skill_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "claude-skills"
            managed = destination / "xss"
            managed.mkdir(parents=True)
            (managed / "stale.txt").write_text("obsolete", encoding="utf-8")
            unrelated = destination / "local-skill"
            unrelated.mkdir()
            (unrelated / "keep.txt").write_text("keep", encoding="utf-8")
            env = {
                **os.environ,
                "CLAUDE_SKILLS_DIR": str(destination),
                "CODEX_SKILLS_DIR": str(Path(tmp) / "codex-skills"),
                "GHOST_SKILLS_DIR": str(Path(tmp) / "ghost-skills"),
            }
            completed = subprocess.run(
                ["bash", "sync_skills.sh", "--claude"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((managed / "stale.txt").exists())
            self.assertTrue((managed / "SKILL.md").is_file())
            self.assertEqual((managed / "SKILL.md").read_bytes(), (ROOT / "skills" / "xss" / "SKILL.md").read_bytes())
            self.assertEqual((unrelated / "keep.txt").read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
