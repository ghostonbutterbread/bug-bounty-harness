"""Offline fixtures for the public directory candidate join."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "skills/stack-to-program/scripts/stack_to_program.py"


class StackToProgramTests(unittest.TestCase):
    def run_join(self, evidence, programs):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / "evidence.jsonl"
            programs_file = root / "data.json"
            evidence_file.write_text("\n".join(json.dumps(row) for row in evidence) + "\n", encoding="utf-8")
            programs_file.write_text(json.dumps({"programs": programs}), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_file), "--programs", str(programs_file)],
                text=True, capture_output=True,
            )

    def evidence(self, product="Acme", **extra):
        return {"component": "Widget 1.0", "product": product, "evidence_label": "source-derived",
                "source_url": "https://example.org/advisory", "observed_date": "2026-10-20", **extra}

    def test_exact_matches_no_substrings_or_owner_guess(self):
        programs = [{"name": "Acme", "url": "https://hackerone.com/acme", "bounty": True, "domains": ["acme.test"]},
                    {"name": "Widget", "url": "https://hackerone.com/widget", "bounty": False, "domains": ["widget.test"]}]
        rows = [self.evidence(product="acme"), self.evidence(product="Acme Labs"),
                self.evidence(product="Widget", product_domain="sub.widget.test"),
                self.evidence(product="Widget", program_url="https://hackerone.com/elsewhere"),
                self.evidence(product="Unrelated", product_domain="ACME.TEST."),
                self.evidence(product="Unrelated", program_url="https://hackerone.com/widget/")]
        result = self.run_join(rows, programs)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["count"], 2)
        self.assertEqual(len(data["unmatched"]), 3)
        self.assertEqual([len(candidate["matches"]) for candidate in data["candidates"]], [2, 1])
        self.assertEqual(data["candidates"][1]["program_url"], "https://hackerone.com/widget")
        self.assertFalse(data["exhaustive"])

    def test_duplicates_contradictory_labels_and_unverified_payment(self):
        programs = [{"name": "Acme", "url": "https://hackerone.com/acme", "bounty": True, "domains": []}]
        rows = [self.evidence(evidence_label="disclosure"), self.evidence(evidence_label="contradicted"),
                self.evidence(evidence_label="disclosure")]
        first = self.run_join(rows, programs)
        second = self.run_join(list(reversed(rows)), programs)
        self.assertEqual(first.stdout, second.stdout)
        candidate = json.loads(first.stdout)["candidates"][0]
        self.assertEqual(len(candidate["matches"]), 2)
        self.assertEqual(candidate["evidence_labels"], ["contradicted", "disclosure"])
        self.assertEqual(candidate["bounty_directory_flags_unverified"], [True])
        self.assertIn("current_paid_status", candidate["unknowns"])
        self.assertIn("authorized_scope", candidate["unknowns"])

    def test_invalid_evidence_fails_without_output(self):
        for row, message in [
            (self.evidence(source_url="not a url"), "invalid HTTP(S) URL"),
            (self.evidence(evidence_label="vulnerable"), "evidence_label must be"),
            (self.evidence(observed_date="tomorrow"), "ISO calendar date"),
        ]:
            with self.subTest(message=message):
                result = self.run_join([row], [])
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
