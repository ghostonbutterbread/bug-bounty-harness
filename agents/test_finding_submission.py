"""The retired SUBMISSION.md writer cannot create a competing artifact."""

import tempfile
import unittest
from pathlib import Path

from agents.finding_submission import main, prepare_submission


class RetiredSubmissionTests(unittest.TestCase):
    def test_legacy_writer_refuses_without_creating_or_rewriting_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "reports" / "D01"
            packet.mkdir(parents=True)
            existing = packet / "REPORT.md"
            existing.write_text("historical report\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SUBMISSION.md generation is retired"):
                prepare_submission("example", "D01", lane="web", root_override=tmp,
                                   from_file=existing, evidence_pointers=["owned proof"])
            self.assertFalse((packet / "SUBMISSION.md").exists())
            self.assertEqual(existing.read_text(encoding="utf-8"), "historical report\n")

    def test_cli_refuses_with_nonzero_exit(self):
        self.assertEqual(main(["example", "D01", "--lane", "web"]), 1)


if __name__ == "__main__":
    unittest.main()
