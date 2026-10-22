"""Offline packaging contracts; semantic review is a separate release gate."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/rce-deserialization"


class DeserializationDepthTest(unittest.TestCase):
    def test_mechanism_teaching_and_js_lens_are_in_entry(self):
        text = (SKILL / "SKILL.md").read_text()
        for heading in ("## What It Is and Why It Happens", "## JavaScript Lens"):
            self.assertIn(heading, text)
        for reference in ("technology-mechanisms.md", "investigation-ideas.md"):
            self.assertIn(f"`references/{reference}`", text)
        self.assertIn("not a new analyzer mode", text)

    def test_discovery_routes_name_specialist(self):
        for name in ("rce", "js-hunt"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text()
            self.assertIn("`rce-deserialization`", text)
        entry = (ROOT / "skills/rce/SKILL.md").read_text()
        metadata = re.search(r"related_skills: \[([^\]]+)\]", entry)
        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertIn("rce-deserialization", metadata.group(1))

    def test_all_local_references_resolve_in_packaged_tree(self):
        for path in SKILL.rglob("*.md"):
            text = path.read_text()
            for target in re.findall(r"`(references/[^`]+\.md)`", text):
                self.assertTrue((SKILL / target).is_file(), (path, target))
            for target in re.findall(r"\]\(([^)]+\.md)(?:#[^)]+)?\)", text):
                if "://" not in target:
                    self.assertTrue((path.parent / target).is_file(), (path, target))
            self.assertNotIn("/home/", text)

    def test_technology_cards_have_prerequisites_and_primary_sources(self):
        text = (SKILL / "references/technology-mechanisms.md").read_text()
        cards = re.split(r"(?m)^## ", text)[1:]
        cards = [card for card in cards if not card.startswith("Sources")]
        self.assertEqual(len(cards), 10)
        for card in cards:
            self.assertIn("**Recognize:**", card)
            self.assertIn("**Mechanism and prerequisites:**", card)
            self.assertIn("**Next discriminator / benign alternative:**", card)
        for marker in ("ObjectInputStream", "ObjectInputFilter", "pickle", "unserialize",
                       "Jackson", "XStream", "BinaryFormatter", "TypeNameHandling",
                       "SafeLoader", "Marshal.load", "node-serialize"):
            self.assertIn(marker, text)
        self.assertIn("Starting in .NET 9", text)
        citations = {int(n) for n in re.findall(r"\[(\d+)\]", text.split("## Sources")[0])}
        sources = {int(n) for n in re.findall(r"(?m)^\[(\d+)\] ", text)}
        self.assertEqual(citations, sources)
        for field in ("Source:", "Captured:", "SHA-256:"):
            self.assertEqual(text.count(field), len(sources))
        self.assertEqual(len(re.findall(r"SHA-256: [a-f0-9]{64}", text)), len(sources))

    def test_ideas_keep_discriminators_and_falsifiers_together(self):
        text = (SKILL / "references/investigation-ideas.md").read_text()
        cards = re.split(r"(?m)^## ", text)[1:]
        self.assertGreaterEqual(len(cards), 6)
        for card in cards:
            for marker in ("**Signal / question:**", "**Discriminator and control:**", "**What would falsify it:**"):
                self.assertIn(marker, card)
        self.assertIn("not a ceiling", text)
        self.assertIn("`rce-validation`", text)
        self.assertIn("integrity", text)
        self.assertIn("later", text)


if __name__ == "__main__":
    unittest.main()
