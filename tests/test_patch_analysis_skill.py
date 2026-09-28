from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "patch-analysis" / "SKILL.md"
HUNTER_LOOP = ROOT / "skills" / "hunter-loop" / "SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


class PatchAnalysisSkillTests(unittest.TestCase):
    def test_skill_uses_the_release_diff_to_narrow_source_review(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("diff the version that was patched against the version immediately before it", content)
        self.assertIn("Use the exact changed code to narrow where to look next", content)
        self.assertIn("callers, and equivalent code paths", content)

    def test_skill_requires_an_exact_change_before_following_related_paths(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("isolate the actual security-relevant hunk", content)
        self.assertIn("State exactly what changed", content)
        self.assertIn("semantically equivalent or duplicated paths", content)
        self.assertIn("The diff is a starting point for source review, not proof", content)

    def test_skill_is_listed_in_the_registry(self) -> None:
        self.assertIn(
            "| **patch-analysis** | `/patch-analysis {upstream-repository-or-component}` | `skills/patch-analysis/SKILL.md` |",
            REGISTRY.read_text(encoding="utf-8"),
        )

    def test_observed_component_routes_to_parallel_research(self) -> None:
        patch = SKILL.read_text(encoding="utf-8")
        hunter = HUNTER_LOOP.read_text(encoding="utf-8")
        self.assertIn("load\n`vulnerability-patch-research` first", patch)
        self.assertIn("not a CVE-only trigger", patch)
        self.assertIn("start its\nbounded CVE and independent release-diff lanes alongside continuing recon", hunter)
        self.assertIn("neither lane waits for the other to fail", hunter)
        self.assertIn("by mechanism", hunter)
        self.assertIn("Keep\ntarget observations in MapStore", hunter)


if __name__ == "__main__":
    unittest.main()
