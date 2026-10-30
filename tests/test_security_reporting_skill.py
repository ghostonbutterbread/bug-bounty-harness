from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "security-reporting" / "SKILL.md"


class SecurityReportingSkillTests(unittest.TestCase):
    def test_direct_bunny_routes_and_deprecated_fallback(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("name: security-reporting", text)
        self.assertIn("DEPRECATED", text.split("#", 1)[-1][:350])
        self.assertIn("load `bunny-report-and-triage` directly", text)
        for path in (
            "skills/manual-hunter/SKILL.md",
            "skills/bunny/SKILL.md",
            "skills/bunny/agents/bunny-reporter.md",
            "skills/bunny-collaborative/SKILL.md",
            "agents/index.md",
        ):
            with self.subTest(path=path):
                route = (ROOT / path).read_text(encoding="utf-8")
                self.assertIn("bunny-report-and-triage", route)
                self.assertNotIn("`security-reporting`", route)
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        self.assertIn("**security-reporting**", registry)
        self.assertIn("deprecated compatibility redirect", registry.lower())
        self.assertIn("**bunny-report-and-triage**", registry)
        self.assertIn("standalone fork", registry)
        self.assertIn("bunny-report-and-triage", (ROOT / "agents/finding_submission.py").read_text())
        self.assertNotIn("via security-reporting", (ROOT / "agents/finding_submission.py").read_text())

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
        self.assertIn("`triager-first-poc-authoring` in the same package", entry)
        self.assertIn("A simple inline `curl` does not load the PoC authoring skill.", entry)


if __name__ == "__main__":
    unittest.main()
