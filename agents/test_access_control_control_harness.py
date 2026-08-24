#!/usr/bin/env python3
"""Regression coverage for cross-account authorization controls."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AccessControlHarnessTests(unittest.TestCase):
    def test_router_requires_liveness_and_safe_recovery(self) -> None:
        text = (ROOT / "skills" / "access-control" / "SKILL.md").read_text()

        self.assertIn("## Cross-account control harness", text)
        self.assertIn("immediately before the test", text)
        self.assertIn("`invalid: auth/session`", text)
        self.assertIn("never an implicit substitute", text)

    def test_api_overlay_requires_controls_and_safe_single_use_handling(self) -> None:
        skill = (ROOT / "skills" / "access-control" / "SKILL.md").read_text()
        playbook = (ROOT / "prompts" / "access-control-playbook.md").read_text()

        for text in (skill, playbook):
            normalized = text.replace("\n", " ")
            self.assertIn("positive control", normalized)
            self.assertIn("nonexistent-object control", normalized)
            self.assertIn("protective non-disclosure", normalized)
            self.assertIn("`__typename`", normalized)
            self.assertIn("single-request-grabber", normalized)


if __name__ == "__main__":
    unittest.main()
