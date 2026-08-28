from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [*ROOT.glob("skills/**/SKILL.md"), *ROOT.glob("prompts/*.md")]
BBH_TARGET = re.compile(r"\bbbh\s+((?:agents|scripts|skills)/[^\s`\"']+?\.(?:py|js|sh))")


class MigratedSkillCommandTests(unittest.TestCase):
    def test_every_documented_dispatcher_target_resolves_from_this_checkout(self) -> None:
        targets = {
            match.group(1)
            for path in DOCUMENTS
            for match in BBH_TARGET.finditer(path.read_text(encoding="utf-8"))
        }
        self.assertGreater(len(targets), 0)
        for target in sorted(targets):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["python3", "scripts/bbh.py", "--print-command", target],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                resolved = Path(result.stdout.strip()).resolve()
                self.assertTrue(resolved.is_relative_to(ROOT), resolved)
                self.assertTrue(resolved.is_file(), resolved)


if __name__ == "__main__":
    unittest.main()
