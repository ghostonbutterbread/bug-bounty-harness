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
            "vulnerability-patch-research": ("references/disposable-local-proof.md",),
        }
        for skill, references in expected.items():
            skill_dir = ROOT / "skills" / skill
            skill_text = (skill_dir / "SKILL.md").read_text()
            self.assertIn(f"name: {skill}", skill_text)
            for reference in references:
                self.assertTrue((skill_dir / reference).is_file(), reference)

    def test_discovery_docs_and_skills_do_not_reference_source_repo(self) -> None:
        for path in (ROOT / "SKILL_REGISTRY.md", ROOT / "README.md"):
            text = path.read_text()
            self.assertIn("bounty-storage", text)
            self.assertIn("huge-ingest", text)
            self.assertIn("vulnerability-patch-research", text)
        entry = (ROOT / "agents/index.md").read_text()
        stores = (ROOT / "skills/data-store-guidance/SKILL.md").read_text()
        registry = (ROOT / "SKILL_REGISTRY.md").read_text()
        self.assertIn("Load `/data-store-guidance` early", entry)
        retained = next(line for line in stores.splitlines() if "**Retained artifacts**" in line)
        self.assertIn("/bounty-storage", retained)
        self.assertIn("/vulnerability-patch-research", entry)
        self.assertIn("SKILL_REGISTRY.md", (ROOT / "README.md").read_text())
        for skill in ("bounty-storage", "huge-ingest", "vulnerability-patch-research"):
            row = next(line for line in registry.splitlines() if f"**{skill}**" in line)
            self.assertIn(f"skills/{skill}/SKILL.md", row)
        for path in (ROOT / "skills/bounty-storage/SKILL.md", ROOT / "skills/huge-ingest/SKILL.md", ROOT / "skills/vulnerability-patch-research/SKILL.md"):
            self.assertNotIn("projects/general-skills", path.read_text())


if __name__ == "__main__":
    unittest.main()
