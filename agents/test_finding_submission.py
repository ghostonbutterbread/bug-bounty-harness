"""Isolated storage and real CLI tests for create-only submission preparation."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agents.finding_submission import prepare_submission
from agents.storage_resolver import resolve_storage
from bounty_core.ledger import ledger_add, ledger_get
from bounty_core.reports import write_finding_report

SCRIPT = Path(__file__).with_name("finding_submission.py")
EVIDENCE = """# {fid} — Boundary failure

## Claim and status
Verified: a reader without access crossed the resource boundary and received the owned fixture.

## Attacker model and prerequisites
An ordinary account and a separate owned resource are required.

## Evidence index
- capture-17: sanitized request and independent owned-resource verification.

## Complete reproduction record
The ordinary account requested the owned resource; access succeeded and a second lookup confirmed the effect.

## Demonstrated impact and negative boundaries
The owned resource was readable; broader access was not tested.
"""
DRAFT = """# Missing resource authorization allows owned-record disclosure

## Summary
The reader accessed a separate owned record despite lacking membership.

## Technical details
The record lookup did not enforce the resource membership boundary.

## How to reproduce
Create two owned accounts, request the other owned record, and compare its returned marker.

## Impact
An ordinary reader can access a record outside their authorized scope.

## Remediation
Enforce membership at the record lookup and test cross-account denial.
"""


class SubmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.program = "submission_fixture"
        _, self.fid = ledger_add(
            self.program,
            {"type": "Boundary failure", "file": "owned-resource", "class_name": "idor", "severity": "HIGH"},
            "snapshot", "v1", "run", "test", lane="web", family="web_bounty", root_override=self.root,
        )
        self.layout = resolve_storage(self.program, lane="web", root_override=self.root, create=False)
        self.packet = self.layout.reports_root / self.fid
        self.packet.mkdir(parents=True, exist_ok=True)
        self.source = self.root / "draft.md"
        self.source.write_text(DRAFT, encoding="utf-8")
        (self.packet / "REPORT.md").write_text(DRAFT, encoding="utf-8")

    def evidence(self, content: str | None = None) -> None:
        (self.packet / "EVIDENCE.md").write_text(
            EVIDENCE.format(fid=self.fid) if content is None else content, encoding="utf-8"
        )

    def prepare(self, **kwargs: object) -> Path:
        params = {"lane": "web", "root_override": self.root, "from_file": self.source,
                  "evidence_pointers": ["capture-17"]}
        params.update(kwargs)
        fid = params.pop("fid", self.fid)
        return prepare_submission(self.program, fid, **params)

    def cli(self, fid: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), self.program, fid or self.fid, "--lane", "web", "--root", str(self.root),
             "--from-file", str(self.source), "--evidence-pointer", "capture-17"],
            text=True, capture_output=True, check=False,
        )

    def test_missing_and_invalid_evidence_rejected_without_draft(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing EVIDENCE"):
            self.prepare()
        self.evidence(EVIDENCE.format(fid=self.fid).replace("Verified:", "Claim pending:"))
        with self.assertRaisesRegex(ValueError, "explicitly mark"):
            self.prepare()
        self.evidence(EVIDENCE.format(fid=self.fid).replace("capture-17:", "TODO:"))
        with self.assertRaisesRegex(ValueError, "placeholder"):
            self.prepare()
        self.assertFalse((self.packet / "SUBMISSION.md").exists())

    def test_exact_fid_and_pointer_are_required(self) -> None:
        self.evidence()
        with self.assertRaisesRegex(ValueError, "not found"):
            self.prepare(evidence_pointers=["other"], fid="other")
        with self.assertRaisesRegex(ValueError, "pointer"):
            self.prepare(evidence_pointers=["nonexistent"])
        with self.assertRaisesRegex(ValueError, "path-safe"):
            self.prepare(fid="../escape")
        self.assertFalse((self.packet / "SUBMISSION.md").exists())

    def test_pointer_requires_whole_index_identifier(self) -> None:
        self.evidence(EVIDENCE.format(fid=self.fid).replace("capture-17", "capture-170"))
        with self.assertRaisesRegex(ValueError, "pointer"):
            self.prepare()

    def test_packet_symlink_cannot_redirect_submission(self) -> None:
        retained = self.root / "original-packet"
        self.packet.rename(retained)
        outside = self.root / "outside"
        outside.mkdir()
        self.packet.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.prepare()
        self.assertFalse((outside / "SUBMISSION.md").exists())

    def test_program_mandated_form_uses_explicit_override(self) -> None:
        self.evidence()
        self.source.write_text("# Finding\n\n## Vendor summary\nA concrete issue.\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "headings"):
            self.prepare()
        self.source.write_text("# Finding\n\n## Vendor summary\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty"):
            self.prepare(program_form=True)
        self.source.write_text("# Finding\n\n## Vendor summary\nA concrete issue.\n", encoding="utf-8")
        self.assertEqual(self.prepare(program_form=True), self.packet / "SUBMISSION.md")

    def test_five_nonempty_ordered_sections(self) -> None:
        self.evidence()
        report = self.packet / "REPORT.md"
        report.unlink()
        with self.assertRaisesRegex(ValueError, "missing REPORT"):
            self.prepare()
        report.write_text(DRAFT.replace("## Impact\nAn ordinary reader can access a record outside their authorized scope.", "## Impact\n"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "REPORT.md section"):
            self.prepare()
        report.write_text(DRAFT, encoding="utf-8")
        for invalid in (DRAFT.replace("## Impact", "## Results"), DRAFT.replace("## Impact\nAn ordinary reader can access a record outside their authorized scope.", "## Impact\n"), DRAFT.replace("## Impact", "## TODO\ntext\n\n## Impact")):
            self.source.write_text(invalid, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "submission"):
                self.prepare()
        self.assertFalse((self.packet / "SUBMISSION.md").exists())

    def test_provider_packet_to_prepared_submission(self) -> None:
        finding = ledger_get(self.program, self.fid, lane="web", family="web_bounty", root_override=self.root)
        write_finding_report(self.layout, finding)
        evidence_path = self.packet / "EVIDENCE.md"
        self.assertIn("## Claim and status", evidence_path.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValueError, "EVIDENCE.md"):
            self.prepare()
        self.evidence()
        (self.packet / "REPORT.md").write_text(DRAFT, encoding="utf-8")
        self.assertEqual(self.prepare(), self.packet / "SUBMISSION.md")
        self.assertTrue((self.packet / "SUBMISSION.md").is_file())

    def test_cli_creates_once_and_leaves_ledger_unsubmitted(self) -> None:
        self.evidence()
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not externally submitted", result.stdout)
        destination = self.packet / "SUBMISSION.md"
        self.assertTrue(destination.is_file())
        text = destination.read_text(encoding="utf-8")
        self.assertIn("Prepared draft only", text)
        self.assertIn(DRAFT.strip(), text)
        self.assertEqual(self.cli().returncode, 1)
        self.assertEqual(text, destination.read_text(encoding="utf-8"))
        finding = ledger_get(self.program, self.fid, lane="web", family="web_bounty", root_override=self.root)
        self.assertNotEqual((finding.get("submission") or {}).get("state"), "submitted")


if __name__ == "__main__":
    unittest.main()
