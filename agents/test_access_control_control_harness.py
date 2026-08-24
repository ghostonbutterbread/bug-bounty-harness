#!/usr/bin/env python3
"""Regression coverage for cross-account authorization controls."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AccessControlHarnessTests(unittest.TestCase):
    def test_router_requires_liveness_and_safe_recovery(self) -> None:
        text = (ROOT / "skills" / "access-control" / "SKILL.md").read_text()

        self.assertIn("## Cross-account control harness", text)
        self.assertIn("`idor-live-policy`", text)
        self.assertIn("access-control-playbook.md", text)
        self.assertIn("`/single-request-grabber`", text)

    def test_playbook_owns_api_controls_and_single_use_handling(self) -> None:
        playbook = (ROOT / "prompts" / "access-control-playbook.md").read_text()
        normalized = playbook.replace("\n", " ")

        self.assertIn("positive control", normalized)
        self.assertIn("nonexistent-object control", normalized)
        self.assertIn("protective non-disclosure", normalized)
        self.assertIn("`__typename`", normalized)
        self.assertIn("single-request-grabber", normalized)


if __name__ == "__main__":
    unittest.main()
