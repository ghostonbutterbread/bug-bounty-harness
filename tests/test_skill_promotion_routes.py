"""Focused discovery and packaging guard for promoted BBH skills."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
PROMOTED = (
    "rce-exploration", "rce-surface-mapping", "rce-lifecycle",
    "rce-validation", "rce-technology-research", "account-registry",
    "blocker-first-analysis", "research-knowledge-management", "hunt-orchestration",
)


class SkillPromotionRoutesTest(unittest.TestCase):
    def test_all_named_skills_have_packaged_references_and_registry_rows(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        for name in ("rce", *PROMOTED):
            with self.subTest(name=name):
                path = SKILLS / name / "SKILL.md"
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.startswith(f"---\nname: {name}\n"))
                self.assertIn(f"| **{name}** |", registry)
                for ref in re.findall(r"`(references/[^`]+\.md)`", text):
                    self.assertTrue((path.parent / ref).is_file(), f"{name}: {ref}")
                self.assertNotIn("/home/ryushe/", text)

    def test_rce_class_entry_and_overlapping_owners(self):
        entry = (SKILLS / "rce" / "SKILL.md").read_text(encoding="utf-8")
        for name in PROMOTED[:5]:
            self.assertIn(f"`{name}`", entry)
        self.assertIn("which controlled", entry)
        routes = (ROOT / "agents" / "index.md").read_text(encoding="utf-8")
        self.assertIn("load `/rce` as the class entry", routes)
        self.assertIn("`hunt-orchestration-policy` for admission", routes)
        self.assertIn("`/account-registry` with `/account-management`", routes)
        self.assertIn("`/blockers` only for an external prerequisite", routes)
        self.assertIn("`/research-knowledge-management` owns source admission", routes)
        self.assertIn("`blockers` owns the optional external-prerequisite store",
                      (SKILLS / "blocker-first-analysis" / "SKILL.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
