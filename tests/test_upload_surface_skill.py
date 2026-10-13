from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "upload-surface" / "SKILL.md"
SOURCES = ROOT / "skills" / "upload-surface" / "references" / "public-cases.md"
PFP = ROOT / "skills" / "pfp" / "SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


class UploadSurfaceSkillTests(unittest.TestCase):
    def test_router_and_avatar_coordinator_have_distinct_ownership(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        pfp = PFP.read_text(encoding="utf-8")
        self.assertTrue(skill.startswith("---\nname: upload-surface\n"))
        self.assertIn("neither skill is a universal prerequisite", skill)
        self.assertIn("`upload-surface` to trace the file lifecycle", pfp)
        self.assertIn("URL fetch/import -> `/ssrf`", pfp)
        self.assertIn("object ownership, profile image IDs", pfp)

    def test_live_gate_and_execution_boundary_are_explicit(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        for phrase in (
            "program-testing-policy", "resource-safety-policy", "public-forums",
            "Before even a baseline upload", "An accepted file is not an RCE or XSS finding",
            "only owned objects", "No high-volume upload", "original→stored/derived transformation",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, skill)

    def test_all_runtime_citations_have_packaged_public_sources(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        sources = SOURCES.read_text(encoding="utf-8")
        ids = set(re.findall(r"\[(\d+)\]", skill))
        referenced = set(re.findall(r"^\[(\d+)\] https?://", sources, re.M))
        self.assertTrue(ids)
        self.assertEqual(ids, referenced)
        self.assertNotIn("skill_seeds", skill)
        self.assertNotIn("notes/appsec", skill)

    def test_discoverable_registry_route(self) -> None:
        self.assertIn("| **upload-surface** | `/upload-surface", REGISTRY.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
