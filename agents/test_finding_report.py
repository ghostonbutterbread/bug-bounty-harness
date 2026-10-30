"""Integration contract for registering a Bunny report without writing its body."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agents.finding_report import register
from bounty_core.ledger import add_finding, ledger_get, patch_finding_by_fid
from bounty_core.storage import resolve_storage


class BunnyReportRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.program = "fixture"
        self.layout = resolve_storage(
            self.program, family="web_bounty", lane="web",
            root_override=self.root, create=True,
        )
        added = add_finding(
            {"identity": "fixture:xss:owned", "title": "Owned XSS", "type": "xss",
             "class_name": "xss", "asset": "app.example", "status": "confirmed"},
            program=self.program, family="web_bounty", lane="web",
            root_override=self.root, packet_mode="evidence_only",
        )
        self.fid = added["finding"]["fid"]
        self.packet = Path(added["finding"]["report_dir"])

    def test_report_packet_and_submission_navigation_use_stable_descriptive_path(self):
        finding = ledger_get(self.program, self.fid, family="web_bounty", lane="web",
                             root_override=self.root)
        packet = Path(finding["report_dir"])
        self.assertEqual(packet.name, f"{self.fid}-owned-xss")
        evidence = packet / "EVIDENCE.md"
        self.assertTrue(evidence.is_file())
        final = packet / f"app-example-xss-{self.fid}.md"
        final.write_text("# Final report\n", encoding="utf-8")
        result = register(self.program, self.fid, final, lane="web", storage_root=self.root)
        self.assertEqual(result["report_path"], str(final))
        patch_finding_by_fid(self.program, self.fid, {"submission": {"state": "submitted"}},
                             family="web_bounty", lane="web", root_override=self.root,
                             packet_mode="evidence_only", write_report=False, refresh=True)
        submitted = self.layout.reports_root / "submitted" / "index.md"
        self.assertIn(self.fid, submitted.read_text(encoding="utf-8"))
        self.assertEqual(final.read_text(encoding="utf-8"), "# Final report\n")
        self.assertTrue(evidence.is_file())
        self.assertEqual(Path(ledger_get(self.program, self.fid, family="web_bounty",
                                         lane="web", root_override=self.root)["report_dir"]), packet)

    def test_provider_pin_is_accepted_evidence_only_revision(self):
        manifest = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")
        # The safety-alert pin retains the evidence-only packet implementation:
        # 035c9a165fb6addfebb814d66b1b7f6143ab7e69 is its provider ancestor.
        # The registration tests below exercise that contract, not just the SHA.
        self.assertIn(
            "bounty-core @ git+https://github.com/ghostonbutterbread/bounty-core.git@"
            "6c36ee88a60073e1b687ec32deeade24ffafdd4f",
            manifest.splitlines(),
        )
        self.assertNotIn("fd66f7ab9069a92c2aae624c85c00d15b6b34c90", manifest)
        self.assertNotIn("54ac5e8261edd313c815adde17d4fbb64fb4727d", manifest)

    def test_register_exact_fid_report_preserves_body_and_evidence(self):
        evidence = self.packet / "EVIDENCE.md"
        before = evidence.read_bytes()
        report = self.packet / f"app-example-xss-{self.fid}.md"
        report.write_text("# Verified owned fixture\n", encoding="utf-8")
        result = register(
            self.program, self.fid, report, lane="web", storage_root=self.root,
        )
        self.assertEqual(result["report_path"], str(report))
        self.assertIsNone(result["submission_state"])
        self.assertNotIn("ready", result)
        self.assertNotIn("submitted", result)
        self.assertEqual(report.read_text(encoding="utf-8"), "# Verified owned fixture\n")
        self.assertEqual(evidence.read_bytes(), before)
        self.assertFalse((self.packet / "REPORT.md").exists())
        self.assertFalse((self.packet / "SUBMISSION.md").exists())
        self.assertEqual(
            ledger_get(self.program, self.fid, family="web_bounty", lane="web",
                       root_override=self.root)["report_path"], str(report),
        )
        navigation = (self.layout.reports_root / "categories" / "xss" / "index.md").read_text()
        self.assertIn(f"[[../../{self.packet.name}/{report.stem}|{self.fid}]]", navigation)

    def test_registration_receipt_preserves_existing_submitted_state(self):
        report = self.packet / f"app-example-xss-{self.fid}.md"
        report.write_text("# historical final\n", encoding="utf-8")
        patch_finding_by_fid(
            self.program, self.fid, {"submission": {"state": "submitted"}},
            family="web_bounty", lane="web", root_override=self.root,
            packet_mode="evidence_only", write_report=False,
        )
        result = register(self.program, self.fid, report, lane="web", storage_root=self.root)
        self.assertEqual(result["submission_state"], "submitted")
        self.assertEqual(ledger_get(self.program, self.fid, family="web_bounty",
                                    lane="web", root_override=self.root)["submission"]["state"], "submitted")
        self.assertEqual(report.read_text(encoding="utf-8"), "# historical final\n")

    def test_cli_registers_existing_file_from_isolated_packet(self):
        report = self.packet / f"app-example-xss-{self.fid}.md"
        report.write_text("# Copy-paste-ready fixture\n", encoding="utf-8")
        command = [sys.executable, str(Path(__file__).with_name("finding_report.py")),
                   self.program, self.fid, "--lane", "web", "--report", str(report),
                   "--storage-root", str(self.root)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["report_path"], str(report))
        self.assertEqual(report.read_text(encoding="utf-8"), "# Copy-paste-ready fixture\n")
        self.assertFalse((self.packet / "REPORT.md").exists())
        self.assertFalse((self.packet / "SUBMISSION.md").exists())
        self.assertEqual(ledger_get(self.program, self.fid, family="web_bounty",
                                    lane="web", root_override=self.root)["report_path"], str(report))

    def test_registration_rejects_wrong_fid_and_outside_packet(self):
        report = self.packet / f"app-example-xss-{self.fid}.md"
        report.write_text("# verified\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "existing"):
            register(self.program, self.fid, self.root / report.name,
                     lane="web", storage_root=self.root)
        with self.assertRaisesRegex(ValueError, "no finding"):
            register(self.program, "D999", report, lane="web", storage_root=self.root)
        current = ledger_get(self.program, self.fid, family="web_bounty", lane="web",
                             root_override=self.root)
        self.assertFalse(current.get("report_path"))


if __name__ == "__main__":
    unittest.main()
