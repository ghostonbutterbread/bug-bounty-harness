from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [
    ROOT / "README.md",
    ROOT / "SKILL_REGISTRY.md",
    *ROOT.glob("skills/**/*.md"),
    *ROOT.glob("prompts/**/*.md"),
    *ROOT.glob("docs/**/*.md"),
    *ROOT.glob(".agents/**/*.md"),
    *ROOT.glob(".claude/**/*.md"),
]
DIRECT_BBH_EXECUTABLE = re.compile(
    r"(?:python(?:3)?|node|(?:/bin/)?bash)\s+(?:[\"']?(?:\$\{?HARNESS_ROOT\}?/)?|[\"']?)(?:agents|scripts|skills)/[^\s`\"']+"
)
FIXED_REMOTE_CHECKOUT = re.compile(r"(?:cd|python(?:3)?)\s+/home/ryushe/projects/bug_bounty_harness(?:-stable)?")
STALE_CHECKOUT_GUIDANCE = re.compile(r"the (?:active|selected) BBH checkout")
HOST_SPECIFIC_WORKSPACE = re.compile(r"/home/ryushe/\.(?:openclaw|claude)/workspace")
DISPATCHER_BYPASS = re.compile(r"PYTHONPATH=.*(?:bounty-core|\$PWD)")
ABSOLUTE_HARNESS_GUIDANCE = re.compile(r"absolute .*?(?:manual_hunter|me_ledger|agents/)")


class SkillCommandLaneSafetyTests(unittest.TestCase):
    def test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly(self) -> None:
        violations: list[str] = []
        for path in DOCUMENTS:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if DIRECT_BBH_EXECUTABLE.search(line) or FIXED_REMOTE_CHECKOUT.search(line):
                    violations.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(violations, [], "\n".join(violations))

    def test_canonical_skills_do_not_teach_stale_checkout_or_import_routing(self) -> None:
        violations: list[str] = []
        for path in ROOT.glob("skills/**/SKILL.md"):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if (
                    STALE_CHECKOUT_GUIDANCE.search(line)
                    or HOST_SPECIFIC_WORKSPACE.search(line)
                    or DISPATCHER_BYPASS.search(line)
                    or ABSOLUTE_HARNESS_GUIDANCE.search(line)
                ):
                    violations.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
