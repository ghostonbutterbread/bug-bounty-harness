from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "patch-analysis" / "SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


class PatchAnalysisSkillTests(unittest.TestCase):
    def test_skill_requires_a_provenance_backed_release_bracket(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("immutable `old_rev`", content)
        self.assertIn("first patched", content)
        self.assertIn("Confirm `old_rev` is an ancestor", content)
        self.assertIn("git merge-base --is-ancestor OLD_REV NEW_REV", content)

    def test_skill_treats_the_diff_as_a_hypothesis_not_impact_proof(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("does not prove reachability, exploitability, or program impact", content)
        self.assertIn("at least one caller and one alternate/sibling path", content)
        self.assertIn("**confirmed**, **disproven**, or **hypothesis**", content)

    def test_skill_is_listed_in_the_registry(self) -> None:
        self.assertIn(
            "| **patch-analysis** | `/patch-analysis {upstream-repository-or-component}` | `skills/patch-analysis/SKILL.md` |",
            REGISTRY.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
