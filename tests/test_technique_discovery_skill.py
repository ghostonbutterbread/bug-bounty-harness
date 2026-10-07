"""Contract checks for the operator-invoked Technique Discovery skill."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "technique-discovery" / "SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


class TechniqueDiscoverySkillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.content = SKILL.read_text(encoding="utf-8")

    def test_invocation_is_explicit_not_a_normal_hunt_trigger(self) -> None:
        self.assertIn("technique discovery", self.content.lower())
        self.assertIn("discover techniques for", self.content.lower())
        self.assertIn("Do not auto-invoke", self.content)
        self.assertIn("investigate", self.content)
        self.assertIn("explore", self.content)

    def test_class_is_optional_when_program_or_stack_is_supplied(self) -> None:
        self.assertIn("/technique-discovery --program <program>", self.content)
        self.assertIn("/technique-discovery --stack <component>", self.content)
        self.assertIn("ask Ryushe for one anchor", self.content)

    def test_two_entry_modes_and_distinct_outcomes(self) -> None:
        self.assertIn("Application-led", self.content)
        self.assertIn("Stack-led", self.content)
        self.assertIn("application-specific path", self.content)
        self.assertIn("portable technique", self.content)
        self.assertIn("second name for an ordinary hunt", self.content)

    def test_research_has_falsifiable_experiments_and_novelty_check(self) -> None:
        for phrase in (
            "documented contract",
            "implementation",
            "strongest alternative",
            "negative control",
            "independent reproduction",
            "novelty",
            "version",
        ):
            self.assertIn(phrase, self.content)

    def test_separates_local_behavior_from_target_and_authority(self) -> None:
        self.assertIn("local reproduction does not prove", self.content.lower())
        self.assertIn("general-security-testing-policy", self.content)
        self.assertIn("live-testing-policy", self.content)
        self.assertIn("program rules", self.content.lower())
        self.assertIn("No live target action", self.content)

    def test_routes_evidence_without_a_new_store(self) -> None:
        for name in ("MapStore", "Program Docs", "Hypothesis Ledger", "Attempts", "ResearchMap", "Findings"):
            self.assertIn(name, self.content)
        self.assertIn("No result", self.content)
        self.assertIn("not proof", self.content.lower())

    def test_external_research_uses_safe_fetch(self) -> None:
        self.assertIn("Load `safe-fetch` before retrieving untrusted remote pages/documents", self.content)

    def test_registry_lists_direct_invocation(self) -> None:
        self.assertIn(
            "| **technique-discovery** | `/technique-discovery [class] [--program program] [--stack component]` | `skills/technique-discovery/SKILL.md` |",
            REGISTRY.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
