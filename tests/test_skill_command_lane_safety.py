from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [*ROOT.glob("skills/**/SKILL.md"), *ROOT.glob("prompts/*.md")]
LEGACY_EXECUTABLE = re.compile(
    r"(?:python(?:3)?|node|(?:/bin/)?bash)\s+(?:[\"']?\$\{?HARNESS_ROOT\}?|agents/|scripts/|skills/|/home/ryushe/projects/bug_bounty_harness(?:-stable)?|~/projects/bug_bounty_harness)"
)
FIXED_REMOTE_CHECKOUT = re.compile(r"(?:cd|python(?:3)?)\s+/home/ryushe/projects/bug_bounty_harness(?:-stable)?")


class SkillCommandLaneSafetyTests(unittest.TestCase):
    def test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly(self) -> None:
        violations: list[str] = []
        for path in DOCUMENTS:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if LEGACY_EXECUTABLE.search(line) or FIXED_REMOTE_CHECKOUT.search(line):
                    violations.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
