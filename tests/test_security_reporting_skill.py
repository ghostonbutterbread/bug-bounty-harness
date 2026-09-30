from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "security-reporting" / "SKILL.md"


class SecurityReportingSkillTests(unittest.TestCase):
    def test_canonical_owner_and_routes(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("name: security-reporting", text)
        self.assertIn("canonical BBH report-writing skill", text)
        self.assertIn("security-reporting", (ROOT / "skills/manual-hunter/SKILL.md").read_text())
        self.assertIn("security-reporting", (ROOT / "skills/bunny/SKILL.md").read_text())
        self.assertIn("security-reporting", (ROOT / "skills/bunny/agents/bunny-reporter.md").read_text())
        self.assertIn("skills/security-reporting/SKILL.md", (ROOT / "SKILL_REGISTRY.md").read_text())

    def test_evidence_submission_and_poc_contract(self):
        text = SKILL.read_text(encoding="utf-8")
        for marker in (
            "EVIDENCE.md", "SUBMISSION.md", "Judge Receipt", "PASS", "REVISE", "BLOCKED",
            "## Evidence index", "## Complete reproduction record", "## Demonstrated impact and negative boundaries",
            "## Reproduction variants, controls, and failed attempts", "## PoC and artifact references", "## Open questions / dated corrections",
            "## Technical details", "## How to reproduce", "**Prerequisites:**", "**PoC:**",
            "**Manual replay:**", "malicious request", "observed response", "Never cite, link, name",
            "REPORT.md", "FINALIZED.md", "poc-tooling-policy", "triager-first-poc-authoring",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)
        self.assertNotIn("evidence-first-vulnerability-reporting", (ROOT / "skills/manual-hunter/SKILL.md").read_text())


if __name__ == "__main__":
    unittest.main()
