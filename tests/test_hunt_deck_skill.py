"""Offline routing and safety contract for the HuntDeck discovery skill."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HuntDeckSkillTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = (ROOT / "skills/hunt-deck/SKILL.md").read_text()
        cls.finder = (ROOT / "skills/program-finder/SKILL.md").read_text()
        cls.registry = (ROOT / "SKILL_REGISTRY.md").read_text()

    def test_preferred_route_and_fallback(self):
        self.assertIn("Prefer `/hunt-deck` over `/bountylens`", self.finder)
        self.assertIn("fallback or complement", self.finder)
        self.assertIn("| **hunt-deck** |", self.registry)
        self.assertIn("continue\nwith BountyLens", self.skill)

    def test_discovery_is_not_authorization(self):
        for term in ("not permission to test", "authoritative platform/program page",
                     "No recon, target request or account creation", "JavaScript Lens"):
            self.assertIn(term, self.skill)
        for term in ("**minimum**", "own currency", "`total` and `programs`; `limit` and `offset`",
                     "visibility=public", "requires explicit authorization and a private output destination",
                     "null as unknown", "sample duration"):
            self.assertIn(term, self.skill)

    def test_recovery_preserves_existing_owner_and_private_data(self):
        for term in ("~/projects/huntdeck", "127.0.0.1:9000", "service-lifecycle-policy",
                     "docker compose start huntdeck", "docker compose up -d huntdeck",
                     "https://github.com/mdpsec/huntdeck.git", "do not run\n   a second owner",
                     "Never print `.env`", "no built-in login", "Do not\naccept invitations"):
            self.assertIn(term, self.skill)


if __name__ == "__main__":
    unittest.main()
