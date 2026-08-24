#!/usr/bin/env python3
"""Regression coverage for the manual-surface-review skill contract."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManualSurfaceReviewSkillTests(unittest.TestCase):
    def test_skill_is_registered_and_read_only_by_default(self) -> None:
        skill_path = ROOT / "skills" / "manual-surface-review" / "SKILL.md"
        text = skill_path.read_text()
        registry = (ROOT / "SKILL_REGISTRY.md").read_text()

        self.assertIn("name: manual-surface-review", text)
        self.assertIn("This is an evidence-synthesis skill, not a live-testing lane.", text)
        self.assertIn("By default it is\nread-only", text)
        self.assertIn("current-run Attempts", text)
        self.assertIn("It does not create\na separate manual-findings database", text)
        self.assertIn("manual-surface-review", registry)
        self.assertIn("`/manual {program} [--run <run-id>] [--historical]`", registry)

    def test_skill_preserves_canonical_owners_and_live_action_gate(self) -> None:
        text = (ROOT / "skills" / "manual-surface-review" / "SKILL.md").read_text()

        for owner in ("Attempts", "MapStore", "Hypothesis Ledger", "Bounty Notes"):
            self.assertIn(owner, text)
        self.assertIn("perform it only after\nthe user requests it", text)
        self.assertIn("normal live/account/payment/social/device policies", text)


if __name__ == "__main__":
    unittest.main()
