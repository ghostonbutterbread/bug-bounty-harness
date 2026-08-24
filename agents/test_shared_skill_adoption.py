#!/usr/bin/env python3
"""Regression coverage for BBH-owned shared-skill adoptions."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SharedSkillAdoptionTests(unittest.TestCase):
    def test_adopted_skills_and_references_are_local(self) -> None:
        expected = {
            "bounty-storage": ("references/storage-layout.md", "references/run-manifests.md"),
            "huge-ingest": ("references/bounty-storage-lanes.md",),
        }
        for skill, references in expected.items():
            skill_dir = ROOT / "skills" / skill
            skill_text = (skill_dir / "SKILL.md").read_text()
            self.assertIn(f"name: {skill}", skill_text)
            for reference in references:
                self.assertTrue((skill_dir / reference).is_file(), reference)

    def test_discovery_docs_and_skills_do_not_reference_source_repo(self) -> None:
        for path in (ROOT / "SKILL_REGISTRY.md", ROOT / "README.md", ROOT / "agents/index.md"):
            text = path.read_text()
            self.assertIn("bounty-storage", text)
            self.assertIn("huge-ingest", text)
        for path in (ROOT / "skills/bounty-storage/SKILL.md", ROOT / "skills/huge-ingest/SKILL.md"):
            self.assertNotIn("projects/general-skills", path.read_text())


if __name__ == "__main__":
    unittest.main()
