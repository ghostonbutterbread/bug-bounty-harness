from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "security-reporting" / "SKILL.md"


class SecurityReportingSkillTests(unittest.TestCase):
    def test_single_owner_and_bunny_routes(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("name: security-reporting", text)
        self.assertIn("canonical **BBH handoff**", text)
        for path in (
            "skills/manual-hunter/SKILL.md",
            "skills/bunny/SKILL.md",
            "skills/bunny/agents/bunny-reporter.md",
            "skills/bunny-collaborative/SKILL.md",
            "agents/index.md",
        ):
            with self.subTest(path=path):
                self.assertIn("security-reporting", (ROOT / path).read_text(encoding="utf-8"))
        self.assertIn("skills/security-reporting/SKILL.md", (ROOT / "SKILL_REGISTRY.md").read_text())

    def test_evidence_only_and_one_final_bunny_file(self):
        text = SKILL.read_text(encoding="utf-8")
        for marker in (
            "EVIDENCE.md", "## Evidence index", "## Complete reproduction record",
            "## Demonstrated impact and negative boundaries", "## PoC and artifact references",
            "bunny-report-and-triage", "<target-domain>-<vuln-type>-<FID>.md",
            "not** a generated rough `REPORT.md` or `SUBMISSION.md`",
            "same FID packet", "poc-tooling-policy", "triager-first-poc-authoring",
            "full absolute **Report** path", "PASS", "REVISE", "BLOCKED",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)
        self.assertNotIn("finding_submission.py", text)
        self.assertNotIn("ledger-derived rough `REPORT.md`", (ROOT / "skills/manual-hunter/SKILL.md").read_text())

    def test_privacy_live_authority_and_old_packet_preservation(self):
        text = SKILL.read_text(encoding="utf-8")
        for marker in (
            "privacy rules take precedence", "explicit live-authorization limits",
            "Do not make a report writer rerun destructive", "not called live-tested", "preserve them",
            "Only Ryushe's confirmation", "full URL including scheme and authority",
            "independent reviewer", "scope", "material limits",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_entry_routes_poc_without_unnecessary_authoring(self):
        entry = (ROOT / "agents/index.md").read_text(encoding="utf-8")
        self.assertIn("Standalone or scripted PoC editing follows `triager-first-poc-authoring`", entry)
        self.assertIn("a simple inline `curl` does not load that authoring skill", entry)


if __name__ == "__main__":
    unittest.main()
