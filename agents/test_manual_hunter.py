"""Tests for agents.manual_hunter."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from agents.coverage_store import CoverageStore
from agents.snapshot_identity import get_snapshot_identity
from agents.manual_hunter import (
    ManualHunter,
    _build_hunt_context,
    _build_subagent_handoff_bundle,
    main,
)
from agents.shared_brain import build_index, save_index
from agents.finding_report import register
from agents.storage_resolver import resolve_storage
from bounty_core.ledger import patch_finding_by_fid


class ManualHunterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.target_root = self.tmp / "workspace" / "source"
        (self.target_root / ".webpack" / "renderer").mkdir(parents=True, exist_ok=True)
        (self.target_root / ".webpack" / "renderer" / "preload.js").write_text(
            "\n".join(
                [
                    "function execSqliteStatement(sql) {",
                    "  return database.exec(sql);",
                    "}",
                    "window.addEventListener('message', (event) => {",
                    "  port.send(event.data.sql);",
                    "});",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.program = "notion"
        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

        index = build_index(self.target_root, self.program)
        save_index(index, self.program, family="binaries", lane="apk")

    def _storage(self):
        return resolve_storage(self.program, family="binaries", lane="apk", create=False)

    def _ledger_path(self) -> Path:
        return self._storage().ledgers_root / "ledger.json"

    def _coverage_path(self) -> Path:
        return self._storage().ledgers_root / "coverage.json"

    def _report_index_paths(self) -> list[Path]:
        return sorted(self._storage().reports_root.glob("*/*/index.md"))

    def test_from_file_ingests_then_dedupes_without_static_auto_review(self) -> None:
        note_path = self.tmp / "test_finding.md"
        note_path.write_text(
            "\n".join(
                [
                    "Title: SQLite injection via exposed IPC port",
                    "Type: arbitrary SQL execution",
                    "Class: native-module-abuse",
                    "Severity: HIGH",
                    "File: .webpack/renderer/preload.js:4",
                    "Source: renderer postMessage -> IPC port",
                    "Sink: execSqliteStatement()",
                    "Trust Boundary: renderer -> main process (IPC)",
                    "Flow: postMessage with SQL -> port.send -> execSqliteStatement",
                    "Exploitability: Needs XSS or renderer compromise to send postMessage",
                    "Description: The preload bridge exposes a SQLite connection that accepts arbitrary SQL.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        first_stdout = io.StringIO()
        with redirect_stdout(first_stdout):
            rc = main([self.program, "--lane", "apk", "--from-file", str(note_path)])
        self.assertEqual(rc, 0, first_stdout.getvalue())
        self.assertIn("Added finding D01", first_stdout.getvalue())

        ledger_payload = json.loads(self._ledger_path().read_text(encoding="utf-8"))
        self.assertEqual(len(ledger_payload["findings"]), 1)
        self.assertEqual(ledger_payload["findings"][0]["fid"], "D01")
        packet = Path(ledger_payload["findings"][0]["report_dir"])
        self.assertTrue((packet / "EVIDENCE.md").is_file())
        self.assertIn("## Claim and status", (packet / "EVIDENCE.md").read_text(encoding="utf-8"))
        self.assertFalse((packet / "REPORT.md").exists())
        self.assertFalse((packet / "SUBMISSION.md").exists())
        self.assertEqual(Path(ledger_payload["findings"][0]["evidence_path"]), packet / "EVIDENCE.md")
        self.assertFalse(ledger_payload["findings"][0].get("report_path"))
        self.assertEqual(ledger_payload["findings"][0]["class_name"], "native-module-abuse")

        report_files = sorted(self._storage().reports_root.rglob("*.md"))
        self.assertTrue(report_files)
        report_text = "\n".join(path.read_text(encoding="utf-8") for path in report_files)
        self.assertIn("SQLite injection via exposed IPC port", report_text)
        self.assertIn("execSqliteStatement()", ledger_payload["findings"][0]["sink"])
        self.assertFalse(list(self._storage().reports_root.glob("confirmed/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(self._storage().reports_root.glob("dormant/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(self._storage().reports_root.glob("novel/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))

        self.assertFalse(self._coverage_path().exists(), "a finding is not a completed file/class review")

        second_stdout = io.StringIO()
        with redirect_stdout(second_stdout):
            rc = main([self.program, "--lane", "apk", "--from-file", str(note_path)])
        self.assertEqual(rc, 1, second_stdout.getvalue())
        self.assertIn("Duplicate: D01 overlaps with SQLite injection via exposed IPC port", second_stdout.getvalue())

        ledger_payload = json.loads(self._ledger_path().read_text(encoding="utf-8"))
        self.assertEqual(len(ledger_payload["findings"]), 1)

    def test_set_submission_updates_existing_finding(self) -> None:
        note_path = self.tmp / "finding.md"
        note_path.write_text(
            "Title: SQLite injection via exposed IPC port\n"
            "Class: native-module-abuse\n"
            "File: .webpack/renderer/preload.js:4\n"
            "Description: Renderer-controlled input reaches SQLite execution.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note_path)]), 0)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main(
                [
                    self.program,
                    "--lane",
                    "apk",
                    "--set-submission",
                    "D01",
                    "--submission-state",
                    "submitted",
                    "--submission-report",
                    "H1-123",
                    "--submission-result",
                    "duplicate",
                ]
            )

        self.assertEqual(rc, 0, stdout.getvalue())
        self.assertIn("Submission updated: D01 -> submitted", stdout.getvalue())
        finding = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(
            finding["submission"],
            {"state": "submitted", "report": "H1-123", "result": "duplicate"},
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main([self.program, "--lane", "apk", "--set-submission", "D01", "--submission-state", "dropped"]),
                0,
            )
        finding = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(
            finding["submission"],
            {"state": "dropped", "report": "H1-123", "result": "duplicate"},
        )

    def test_operator_submission_follows_frozen_packet_without_moving_evidence(self) -> None:
        note_path = self.tmp / "finding.md"
        note_path.write_text(
            "Title: SQLite injection via exposed IPC port\n"
            "Class: native-module-abuse\n"
            "Severity: HIGH\n"
            "File: .webpack/renderer/preload.js:4\n"
            "Description: Owned fixture reached SQLite execution.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note_path)]), 0)
        finding = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        packet = Path(finding["report_dir"])
        self.assertEqual(packet.name, "D01-sqlite-injection-via-exposed-ipc-port")
        evidence = packet / "EVIDENCE.md"
        self.assertTrue(evidence.is_file())
        report = packet / "app-example-sqlite-injection-D01.md"
        report.write_text("# Controlled fixture\n\nOne physical paragraph line.\n", encoding="utf-8")
        self.assertEqual(register(self.program, "D01", report, lane="apk")["report_path"], str(report))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--set-submission", "D01",
                                   "--submission-state", "submitted"]), 0)
        submitted = self._storage().reports_root / "submitted" / "index.md"
        self.assertIn("D01", submitted.read_text(encoding="utf-8"))
        categories = list((self._storage().reports_root / "categories").glob("*/index.md"))
        self.assertTrue(any("D01" in path.read_text(encoding="utf-8") for path in categories))
        high = self._storage().reports_root / "severity" / "high" / "index.md"
        self.assertIn("D01", high.read_text(encoding="utf-8"))
        self.assertTrue(evidence.is_file())
        self.assertEqual(report.parent, packet)
        self.assertFalse((self._storage().reports_root / "daily").exists())
        self.assertFalse((self._storage().reports_root / "raw").exists())
        after = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(after["report_path"], str(report))
        self.assertEqual(after["report_dir"], str(packet))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--set-submission", "D01",
                                   "--submission-state", "not_submitted"]), 0)
        self.assertFalse(submitted.exists())
        self.assertTrue(report.is_file())

    def test_cli_packet_lifecycle_keeps_stable_path_and_submission_view(self) -> None:
        note = self.tmp / "owned-finding.md"
        note.write_text(
            "Title: SQLite injection via exposed IPC port\n"
            "Class: native-module-abuse\nSeverity: HIGH\n"
            "File: .webpack/renderer/preload.js:4\n"
            "Description: Controlled fixture reaches SQLite.\n",
            encoding="utf-8",
        )

        def cli(module: str, *args: str) -> dict[str, object] | None:
            result = subprocess.run([sys.executable, "-m", module, self.program, *args],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            return json.loads(result.stdout) if module == "agents.finding_report" else None

        cli("agents.manual_hunter", "--lane", "apk", "--from-file", str(note))
        finding = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(finding["fid"], "D01")
        packet = Path(finding["report_dir"])
        self.assertEqual(packet.name, "D01-sqlite-injection-via-exposed-ipc-port")
        evidence = packet / "EVIDENCE.md"
        evidence_before = evidence.read_bytes()
        self.assertFalse((packet / "poc").exists())
        self.assertFalse((packet / "evidence").exists())
        poc = packet / "poc.py"
        poc.write_text("# standalone fixture\n", encoding="utf-8")
        final = packet / "app-example-sqlite-D01.md"
        final.write_text("# Fixture report\n\nOne paragraph on one physical line.\n", encoding="utf-8")
        final_before = final.read_bytes()
        receipt = cli("agents.finding_report", "D01", "--lane", "apk", "--report", str(final),
                      "--storage-root", str(self.home / "Shared"))
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["report_path"], str(final))
        cli("agents.manual_hunter", "--lane", "apk", "--set-submission", "D01",
            "--submission-state", "submitted")
        submitted = self._storage().reports_root / "submitted" / "index.md"
        self.assertIn("D01", submitted.read_text(encoding="utf-8"))
        cli("agents.manual_hunter", "--lane", "apk", "--set-submission", "D01",
            "--submission-state", "dropped")
        self.assertFalse(submitted.exists())
        after = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(after["report_dir"], str(packet))
        self.assertEqual(after["report_path"], str(final))
        self.assertEqual(evidence.read_bytes(), evidence_before)
        self.assertEqual(poc.read_text(encoding="utf-8"), "# standalone fixture\n")
        self.assertEqual(final.read_bytes(), final_before)
        self.assertFalse((self._storage().reports_root / "daily").exists())

    def test_edit_finding_corrects_content_and_refreshes_report_without_new_fid(self) -> None:
        note = self.tmp / "finding.md"
        note.write_text(
            "Title: Incorrect SQL claim\nClass: native-module-abuse\n"
            "File: .webpack/renderer/preload.js:4\n"
            "Description: An unverified initial claim.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note)]), 0)
        before = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        patch_file = self.tmp / "correction.json"
        patch_file.write_text(json.dumps({
            "title": "Verified SQLite IPC injection",
            "description": "Controlled renderer input reached SQLite execution.",
            "impact": "Owned database rows were read.",
            "poc": "Owned fixture query returned the marker.",
            "severity": "P2",
            "file": ".webpack/renderer/preload.js",
            "line": 5,
        }), encoding="utf-8")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([self.program, "--lane", "apk", "--edit-finding", "D01", "--patch-file", str(patch_file)]), 0)
        self.assertIn("Finding updated: D01", output.getvalue())
        entries = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"]
        self.assertEqual(len(entries), 1)
        after = entries[0]
        self.assertEqual(after["title"], "Verified SQLite IPC injection")
        self.assertEqual(after["vulnerability_name"], "Verified SQLite IPC injection")
        self.assertEqual(after["description"], "Controlled renderer input reached SQLite execution.")
        self.assertEqual(after["impact"], "Owned database rows were read.")
        self.assertEqual(after["poc"], "Owned fixture query returned the marker.")
        self.assertEqual(after["severity"], "HIGH")
        self.assertEqual(after["severity_label"], "HIGH")
        self.assertEqual(after["line"], 5)
        self.assertEqual(after["fid"], before["fid"])
        self.assertEqual(after["sightings"], before["sightings"])
        self.assertEqual(after["submission"], before["submission"])
        self.assertEqual(Path(after["evidence_path"]), Path(before["report_dir"]) / "EVIDENCE.md")
        self.assertEqual(after["report_dir"], before["report_dir"])
        self.assertFalse(after.get("report_path"))
        self.assertFalse((Path(before["report_dir"]) / "REPORT.md").exists())

    def test_edit_finding_rejects_unknown_fid_and_protected_patch_without_writing(self) -> None:
        note = self.tmp / "finding.md"
        note.write_text(
            "Title: Initial claim\nClass: native-module-abuse\n"
            "File: .webpack/renderer/preload.js:4\nDescription: Initial details.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note)]), 0)
        before = self._ledger_path().read_bytes()
        patch_file = self.tmp / "patch.json"
        patch_file.write_text('{"fid":"D02","description":"Wrong target"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not editable"):
            main([self.program, "--lane", "apk", "--edit-finding", "D01", "--patch-file", str(patch_file)])
        self.assertEqual(self._ledger_path().read_bytes(), before)
        patch_file.write_text('{"description":"Wrong target"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no finding found"):
            main([self.program, "--lane", "apk", "--edit-finding", "D99", "--patch-file", str(patch_file)])
        self.assertEqual(self._ledger_path().read_bytes(), before)
        patch_file.write_text('{"description":null}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must be a string"):
            main([self.program, "--lane", "apk", "--edit-finding", "D01", "--patch-file", str(patch_file)])
        self.assertEqual(self._ledger_path().read_bytes(), before)

    def test_edit_finding_is_lane_scoped_and_keeps_hand_edited_report(self) -> None:
        note = self.tmp / "finding.md"
        note.write_text(
            "Title: Initial claim\nClass: native-module-abuse\n"
            "File: .webpack/renderer/preload.js:4\nDescription: Initial details.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note)]), 0)
        original = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        report = Path(original["report_dir"]) / f"app-example-sqlite-{original['fid']}.md"
        report.write_text("# Reviewer-edited report\nManual narrative.\n", encoding="utf-8")
        patch_finding_by_fid(
            self.program, original["fid"], {"report_path": str(report)},
            family="binaries", lane="apk", packet_mode="evidence_only",
            refresh=True,
        )
        patch_file = self.tmp / "patch.json"
        patch_file.write_text('{"description":"Corrected behavior","impact":"Owned rows read"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no finding found"):
            main([self.program, "--lane", "web", "--edit-finding", "D01", "--patch-file", str(patch_file)])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--edit-finding", "D01", "--patch-file", str(patch_file)]), 0)
        updated = json.loads(self._ledger_path().read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(updated["description"], "Corrected behavior")
        self.assertEqual(updated["impact"], "Owned rows read")
        self.assertEqual(updated["report_path"], str(report))
        self.assertIn("Manual narrative.", report.read_text(encoding="utf-8"))

    def test_edit_finding_class_retires_false_generated_category(self) -> None:
        note = self.tmp / "finding.md"
        note.write_text(
            "Title: Incorrect type claim\nType: obsolete-unique-type\n"
            "Class: obsolete-unique-class\nFile: .webpack/renderer/preload.js:4\n"
            "Description: Initial details.\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--from-file", str(note)]), 0)
        old_index = self._storage().reports_root / "categories" / "obsolete-unique-class" / "index.md"
        self.assertIn("Incorrect type claim", old_index.read_text(encoding="utf-8"))
        patch_file = self.tmp / "type-correction.json"
        patch_file.write_text('{"class_name":"corrected-class","type":"corrected-type","title":"Verified finding"}', encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.program, "--lane", "apk", "--edit-finding", "D01", "--patch-file", str(patch_file)]), 0)
        self.assertFalse(old_index.exists())
        new_index = self._storage().reports_root / "categories" / "corrected-class" / "index.md"
        self.assertIn("Verified finding", new_index.read_text(encoding="utf-8"))

    def test_minimal_note_is_parsed_tolerantly(self) -> None:
        hunter = ManualHunter(self.program)
        parsed = hunter.parse_text(
            "\n".join(
                [
                    "Found SQLite injection in preload.js:4. The exposed port accepts arbitrary SQL.",
                    "File: .webpack/renderer/preload.js",
                ]
            ),
            source_label="unit-test",
        )

        self.assertEqual(parsed.finding["file"], ".webpack/renderer/preload.js")
        self.assertEqual(parsed.finding["class_name"], "native-module-abuse")
        self.assertEqual(parsed.finding["review_tier"], "CONFIRMED")
        self.assertTrue(parsed.finding["sink"])

    def test_ambiguous_narrative_requires_explicit_review_tier(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Description: Reproduced reading another owned test account's record; "
            "impact may extend to sibling records.\n"
        )
        with self.assertRaisesRegex(ValueError, "Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

        confirmed = hunter.parse_text("Review Tier: CONFIRMED\n" + note, source_label="unit-test")
        self.assertEqual(confirmed.finding["review_tier"], "CONFIRMED")
        hypothetical = hunter.parse_text(
            "Review Tier: DORMANT_HYPOTHETICAL\n" + note, source_label="unit-test"
        )
        self.assertEqual(hypothetical.finding["review_tier"], "DORMANT_HYPOTHETICAL")

    def test_uncertain_note_with_neutral_fields_and_proof_in_review_notes_requires_tier(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Description: The response includes the other owned account's record; "
            "impact may extend to sibling records.\n"
            "Review Notes: The response body contained the other account ID and private field.\n"
            "Exploitability: none\n"
            "Blocked Reason: none\n"
            "Chain Requirements: none\n"
        )
        with self.assertRaisesRegex(ValueError, "Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

    def test_uncertain_appears_to_note_requires_explicit_tier(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Description: The response includes another owned account's record; "
            "this appears to expose sibling records.\n"
        )
        with self.assertRaisesRegex(ValueError, "Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

    def test_neutral_preconditions_do_not_downgrade_observed_finding(self) -> None:
        hunter = ManualHunter(self.program)
        base = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Description: The response contains another owned account's private record.\n"
        )
        for field in ("Blocked Reason: none", "Chain Requirements: none"):
            with self.subTest(field=field):
                parsed = hunter.parse_text(base + field + "\n", source_label="unit-test")
                self.assertEqual(parsed.finding["review_tier"], "CONFIRMED")

    def test_pure_hypothetical_hedges_stay_dormant_without_proof(self) -> None:
        hunter = ManualHunter(self.program)
        for hedge in ("may", "might"):
            with self.subTest(hedge=hedge):
                note = (
                    "Title: Possible record access\nClass: idor\nFile: src/access.py\n"
                    f"Description: This {hedge} permit reading another account record.\n"
                )
                parsed = hunter.parse_text(note, source_label="unit-test")
                self.assertEqual(parsed.finding["review_tier"], "DORMANT_HYPOTHETICAL")

    def test_poc_with_concrete_response_and_potential_impact_requires_tier(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\nClass: idor\nFile: src/access.py\n"
            "Description: The response includes another owned account's private record; "
            "potential sibling-record exposure.\n"
            "PoC: GET /records/other-owned-ID showed the private field in the body.\n"
        )
        with self.assertRaisesRegex(ValueError, "Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

    def test_conflicting_duplicate_review_tiers_are_rejected(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\nClass: idor\nFile: src/access.py\n"
            "Review Tier: CONFIRMED\nStatus: DORMANT_HYPOTHETICAL\n"
            "Description: Reproduced reading another owned account's record.\n"
        )
        with self.assertRaisesRegex(ValueError, "Conflicting Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

    def test_bold_markdown_tier_is_accepted(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\nClass: idor\nFile: src/access.py\n"
            "**Tier:** CONFIRMED\n"
            "Description: Reproduced reading another owned account's record; "
            "impact may extend.\n"
        )
        parsed = hunter.parse_text(note, source_label="unit-test")
        self.assertEqual(parsed.finding["review_tier"], "CONFIRMED")

    def test_invalid_explicit_tier_is_rejected(self) -> None:
        hunter = ManualHunter(self.program)
        note = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Review Tier: CONFRIMED\n"
            "Description: Reproduced reading another owned account's record; "
            "impact may extend to sibling records.\n"
        )
        with self.assertRaisesRegex(ValueError, "Review Tier"):
            hunter.parse_text(note, source_label="unit-test")

    def test_scoring_fields_are_parsed_into_the_finding(self) -> None:
        hunter = ManualHunter(self.program)
        parsed = hunter.parse_text(
            "\n".join(
                [
                    "# Stored XSS in profile bio enables admin session theft",
                    "Type: Stored XSS",
                    "Class: dom-xss",
                    "Severity: HIGH",
                    "Scoring Authority: Bugcrowd VRT",
                    "Severity Rationale: Confirmed admin cookie exfiltration in live session.",
                    "Program Constraint: Program caps XSS at High without ATO proof.",
                    "File: assets/config.json",
                    "Description: Bio field renders unsanitized.",
                ]
            ),
            source_label="unit-test",
        )

        self.assertEqual(parsed.finding["severity"], "HIGH")
        self.assertEqual(parsed.finding["scoring_authority"], "Bugcrowd VRT")
        self.assertEqual(parsed.finding["severity_rationale"], "Confirmed admin cookie exfiltration in live session.")
        self.assertEqual(parsed.finding["program_constraint"], "Program caps XSS at High without ATO proof.")

    def test_severity_note_values_normalize_through_bounty_core(self) -> None:
        """Note severity values go through bounty_core normalization so platform
        labels (P0, P1, lowercase names) map to the canonical enum instead of
        being dropped to UNKNOWN by a local membership set."""
        hunter = ManualHunter(self.program)
        cases = {
            "P0": "EXCEPTIONAL",
            "P1": "CRITICAL",
            "p2": "HIGH",
            "critical": "CRITICAL",
            "bogus": "UNKNOWN",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                parsed = hunter.parse_text(
                    "\n".join(
                        [
                            "# XSS finding",
                            "Type: Stored XSS",
                            "Class: dom-xss",
                            f"Severity: {raw}",
                            "File: assets/config.json",
                            "Description: Bio field renders unsanitized.",
                        ]
                    ),
                    source_label="unit-test",
                )
                self.assertEqual(parsed.finding["severity"], expected)

    def test_hostname_is_not_mistaken_for_a_source_file(self) -> None:
        """Regression: '.c' inside 'www.example.com' used to be read as a C source file,
        silently truncating the finding's identity field to 'www.example.c'."""
        from agents.manual_hunter import FILE_HINT_RE

        for hostname in ("www.superdrugmobile.com", "www.example.go", "www.example.rs", "www.example.js"):
            with self.subTest(hostname=hostname):
                self.assertIsNone(FILE_HINT_RE.search(f"Asset: {hostname} (in scope)"))
        match = FILE_HINT_RE.search("Found SQLite injection in preload.js:4.")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("path"), "preload.js")
        self.assertEqual(match.group("line"), "4")

    def test_unlabelled_slash_path_is_inferred_by_parse_text(self) -> None:
        hunter = ManualHunter(self.program)
        parsed = hunter.parse_text(
            "Potential error-handling flaw in src/api/validate.py#12.",
            source_label="unit-test",
        )

        self.assertEqual(parsed.finding["file"], "src/api/validate.py")
        self.assertEqual(parsed.finding["line"], 12)

    def test_explicit_file_value_remains_authoritative_for_hostname_shaped_value(self) -> None:
        hunter = ManualHunter(self.program)
        parsed = hunter.parse_text(
            "\n".join(
                [
                    "File: www.example.go",
                    "Description: The explicitly supplied value must not be replaced by fallback inference.",
                ]
            ),
            source_label="unit-test",
        )

        self.assertEqual(parsed.finding["file"], "www.example.go")

    def test_web_ingest_uses_route_identity_instead_of_technology_label(self) -> None:
        root = self.tmp / "web-storage"
        hunter = ManualHunter(self.program, family="web_bounty", lane="web", storage_root=root)
        note = "\n".join([
            "Title: Login return DOM-XSS", "Class: dom-xss", "Review Tier: CONFIRMED",
            "File: Next.js", "Description: Observed at https://auth.example.test/im-logged-in?code=x. "
            "The affected page uses Next.js.",
        ])
        parsed = hunter.parse_text(note, source_label="unit-test")
        self.assertEqual(parsed.finding["file"], "https://auth.example.test/im-logged-in")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(hunter.ingest(parsed), 0)
        entries = json.loads((root / "web_bounty" / self.program / "web" / "ledgers" / "ledger.json").read_text())["findings"]
        self.assertEqual(entries[0]["file"], "https://auth.example.test/im-logged-in")
        self.assertEqual(entries[0]["asset"], "https://auth.example.test/im-logged-in")

    def test_web_explicit_url_wins_but_source_file_without_route_is_preserved(self) -> None:
        hunter = ManualHunter(self.program, family="web_bounty", lane="web", storage_root=self.tmp / "web-storage")
        note = "\n".join([
            "Class: dom-xss", "File: src/render.js", "URL: https://auth.example.test/one?code=x",
            "Description: This route is affected.",
        ])
        parsed = hunter.parse_text(note, source_label="unit-test")
        self.assertEqual(parsed.finding["file"], "https://auth.example.test/one")
        self.assertNotIn("url", parsed.finding)
        source_only = hunter.parse_text(note.replace("URL: https://auth.example.test/one?code=x\n", ""), source_label="unit-test")
        self.assertEqual(source_only.finding["file"], "src/render.js")
        route_only = hunter.parse_text(note.replace("File: src/render.js\n", ""), source_label="unit-test")
        self.assertEqual(route_only.finding["file"], "https://auth.example.test/one")

    def test_markdown_note_without_file_field_is_rejected_not_corrupted(self) -> None:
        """Regression: a markdown note with no 'File:' used to be rescued by a bogus
        hostname match instead of failing loudly."""
        hunter = ManualHunter(self.program)
        note = "\n".join(
            [
                "# Uncaught exception on www.example.com/api/validate",
                "**Asset:** `www.example.com` (in scope).",
                "Sending a brace pair returns a 500 with the internal exception text.",
            ]
        )
        with self.assertRaises(ValueError) as ctx:
            hunter.parse_text(note, source_label="unit-test")
        self.assertIn("File", str(ctx.exception))

    def test_markdown_heading_yields_a_clean_title(self) -> None:
        """Regression: the title used to run the heading and the next paragraph together."""
        hunter = ManualHunter(self.program)
        note = "\n".join(
            [
                "# Uncaught exception on the validate endpoint",
                "**Asset:** `www.example.com` (in scope). **Severity:** low.",
                "File: src/api/validate.py",
                "Class: error-handling",
            ]
        )
        parsed = hunter.parse_text(note, source_label="unit-test")
        self.assertEqual(parsed.finding["title"], "Uncaught exception on the validate endpoint")
        self.assertEqual(parsed.finding["type"], "Uncaught exception on the validate endpoint")
        self.assertNotIn("**", parsed.finding["title"])
        self.assertNotIn("#", parsed.finding["title"])

    def test_inferred_class_is_flagged_and_stated_class_is_not(self) -> None:
        """Regression: a class guessed from keywords was written to the ledger with the
        same confidence as one the operator stated. Text that DENIES a class used to be
        classified as that class."""
        hunter = ManualHunter(self.program)
        denial = "\n".join(
            [
                "No SSRF was demonstrated: every path and authority probe returned the ordinary 404.",
                "It is a precondition for SSRF, not evidence of it.",
                "File: src/api/validate.py",
            ]
        )
        inferred = hunter.parse_text(denial, source_label="unit-test").finding
        self.assertTrue(inferred["class_inferred"])

        stated = hunter.parse_text(denial + "\nClass: error-handling", source_label="unit-test").finding
        self.assertFalse(stated["class_inferred"])
        self.assertEqual(stated["class_name"], "error-handling")

    @patch("agents.manual_hunter.update_team_finding")
    def test_ingest_uses_team_finding_adapter_after_duplicate_reservation(self, mock_update_team_finding) -> None:
        storage_root = self.tmp / "explicit-storage"
        hunter = ManualHunter(self.program, source_root=self.target_root, storage_root=storage_root)
        parsed = hunter.parse_text(
            "\n".join(
                [
                    "Title: SQLite injection via exposed IPC port",
                    "Type: arbitrary SQL execution",
                    "Class: native-module-abuse",
                    "Severity: HIGH",
                    "File: .webpack/renderer/preload.js:4",
                    "Description: The preload bridge exposes SQLite execution to renderer-controlled messages.",
                ]
            ),
            source_label="unit-test",
        )
        reserved_finding = {**parsed.finding, "fid": "D77"}
        hunter.ledger = Mock(wraps=hunter.ledger)
        hunter.ledger.check.return_value = (False, None, reserved_finding)
        mock_update_team_finding.return_value = reserved_finding

        with (
            patch.object(hunter, "_print_chain_suggestions"),
            redirect_stdout(io.StringIO()),
        ):
            rc = hunter.ingest(parsed)

        self.assertEqual(rc, 0)
        hunter.ledger.check.assert_called_once_with(parsed.finding)
        hunter.ledger.update.assert_not_called()
        mock_update_team_finding.assert_called_once()
        self.assertEqual(mock_update_team_finding.call_args.args[:2], (self.program, reserved_finding))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], storage_root.resolve(strict=False))
        self.assertFalse(mock_update_team_finding.call_args.kwargs["write_report"])
        self.assertTrue(mock_update_team_finding.call_args.kwargs["refresh"])

    def test_hunt_context_static_coverage_is_lane_scoped(self) -> None:
        (self.target_root / "renderer").mkdir(parents=True, exist_ok=True)
        (self.target_root / "renderer" / "view.js").write_text("document.body.textContent = 'ok';\n", encoding="utf-8")
        index = build_index(self.target_root, self.program)
        save_index(index, self.program, family="binaries", lane="apk")
        save_index(index, self.program, family="web_bounty", lane="web")
        snapshot_id = get_snapshot_identity(self.target_root)["snapshot_id"]
        apk = CoverageStore(self.program, self.target_root, family="binaries", lane="apk")
        apk.mark_examined("native-module-abuse", [".webpack/renderer/preload.js"],
                          method="test", snapshot_id=snapshot_id)
        web = CoverageStore(self.program, self.target_root, family="web_bounty", lane="web")
        web.mark_examined("dom-xss", ["renderer/view.js"], method="test",
                          snapshot_id=snapshot_id)

        context = _build_hunt_context(self.program, source_root=self.target_root,
                                      family="web_bounty", lane="web", hunt_type="web")
        self.assertIn("renderer/view.js (dom-xss) ✅", context)
        self.assertNotIn(".webpack/renderer/preload.js (native-module-abuse) ✅", context)

        api_context = _build_hunt_context(self.program, source_root=self.target_root,
                                          family="web_bounty", lane="api", hunt_type="api")
        self.assertIn("Coverage unavailable:", api_context)
        self.assertNotIn("renderer/view.js (dom-xss) ✅", api_context)
        self.assertNotIn(".webpack/renderer/preload.js (native-module-abuse) ✅", api_context)

    def test_source_root_explicit_override_wins_over_shared_brain(self) -> None:
        explicit_root = self.tmp / "explicit-source"
        explicit_root.mkdir(parents=True, exist_ok=True)

        hunter = ManualHunter(self.program, source_root=explicit_root)

        self.assertEqual(hunter.source_root, explicit_root.resolve(strict=False))

    def test_build_hunt_context_uses_shared_brain_target_before_default_source_root(self) -> None:
        fallback_root = self.home / "source" / self.program
        fallback_root.mkdir(parents=True, exist_ok=True)

        context = _build_hunt_context(self.program, lane="apk")

        self.assertIn(f"Target: {self.target_root}", context)
        self.assertNotIn(f"Target: {fallback_root}", context)

    def test_build_hunt_context_falls_back_to_default_source_root_without_shared_brain(self) -> None:
        program = "fallback_only"
        fallback_root = self.home / "source" / program
        fallback_root.mkdir(parents=True, exist_ok=True)

        context = _build_hunt_context(program, lane="apk", storage_root=self.tmp / "fallback-storage")

        self.assertIn(f"Target: ~/source/{program}", context)

    def test_build_hunt_context_includes_findings_examined_and_unexplored_surface(self) -> None:
        (self.target_root / "renderer").mkdir(parents=True, exist_ok=True)
        (self.target_root / "renderer" / "view.js").write_text(
            "document.body.innerHTML = userHtml;\n",
            encoding="utf-8",
        )
        (self.target_root / "updater.ts").write_text(
            "const child_process = require('child_process');\nchild_process.exec(userCommand);\n",
            encoding="utf-8",
        )
        save_index(build_index(self.target_root, self.program), self.program, family="binaries", lane="apk")

        hunter = ManualHunter(self.program, source_root=self.target_root)
        parsed = hunter.parse_text(
            "\n".join(
                [
                    "Title: SQLite injection via exposed IPC port",
                    "Type: arbitrary SQL execution",
                    "Class: native-module-abuse",
                    "Severity: HIGH",
                    "File: .webpack/renderer/preload.js:4",
                    "Description: The preload bridge exposes SQLite execution to renderer-controlled messages.",
                ]
            ),
            source_label="unit-test",
        )
        with redirect_stdout(io.StringIO()):
            rc = hunter.ingest(parsed)
        self.assertEqual(rc, 0)

        before_review = _build_hunt_context(self.program, source_root=self.target_root, lane="apk")
        self.assertNotIn(".webpack/renderer/preload.js (native-module-abuse) ✅", before_review)
        CoverageStore(self.program, self.target_root, family="binaries", lane="apk").mark_examined(
            "native-module-abuse", [".webpack/renderer/preload.js"],
            method="manual-review", snapshot_id=hunter.snapshot_id)

        context = _build_hunt_context(self.program, source_root=self.target_root, lane="apk")
        self.assertIn(f"Program: {self.program}", context)
        self.assertIn(f"Target: {self.target_root}", context)
        self.assertIn("Output: ~/Shared/binaries/notion/apk/reports/raw", context)
        self.assertNotIn("D01: SQLite injection via exposed IPC port", context)
        self.assertIn("## Prior findings lookup:", context)
        self.assertIn("Do not read or summarize the full findings ledger as the opening move.", context)
        self.assertIn("Confirmed, submitted, and dropped findings are closed to default work selection", context)
        self.assertIn(".webpack/renderer/preload.js (native-module-abuse) ✅", context)
        self.assertIn("renderer/view.js (dom-xss)", context)
        self.assertIn("updater.ts (exec-sink-reachability)", context)

    def test_hunt_context_does_not_trust_legacy_finding_auto_marks(self) -> None:
        (self.target_root / "renderer").mkdir(parents=True, exist_ok=True)
        (self.target_root / "renderer" / "view.js").write_text(
            "document.body.innerHTML = userHtml;\n", encoding="utf-8")
        save_index(build_index(self.target_root, self.program), self.program,
                   family="binaries", lane="apk")
        store = CoverageStore(self.program, self.target_root, family="binaries", lane="apk")
        snapshot_id = get_snapshot_identity(self.target_root)["snapshot_id"]
        store.mark_examined("dom-xss", ["renderer/view.js"],
                            method="manual-hunter", snapshot_id=snapshot_id)
        store.mark_examined("legacy-unindexed-class", ["renderer/view.js"],
                            method="sync-reports", snapshot_id=snapshot_id)
        before = self._coverage_path().read_bytes()

        context = _build_hunt_context(self.program, source_root=self.target_root, lane="apk")
        examined = context.split("## Already examined indexed source-file/class pairs:\n", 1)[1].split(
            "## Unexplored indexed source-file/class pairs:", 1)[0]
        unexplored = context.split("## Unexplored indexed source-file/class pairs:\n", 1)[1].split(
            "## Coordination:", 1)[0]
        self.assertNotIn("dom-xss", examined)
        self.assertNotIn("legacy-unindexed-class", examined)
        self.assertIn("renderer/view.js (dom-xss)", unexplored)
        self.assertNotIn("legacy-unindexed-class", unexplored)
        self.assertIn("Legacy manual-hunter/sync-reports auto-marks are not evidence of review", context)
        self.assertEqual(self._coverage_path().read_bytes(), before)

    def test_build_hunt_context_fresh_mode_rejects_historical_findings_as_success(self) -> None:
        context = _build_hunt_context(self.program, source_root=self.target_root, lane="apk", fresh=True)

        self.assertIn("Fresh context", context)
        self.assertIn("Historical findings are never a success condition", context)
        self.assertNotIn("## Current findings (from ledger):", context)

    def test_build_hunt_context_honors_web_lane(self) -> None:
        context = _build_hunt_context(
            self.program,
            source_root=self.target_root,
            family="web_bounty",
            lane="web",
            hunt_type="web",
        )

        self.assertIn("Output: ~/Shared/web_bounty/notion/web/reports/raw", context)
        self.assertIn("Hunt for vulnerabilities in this web application.", context)

    def test_build_subagent_handoff_bundle_includes_context_files(self) -> None:
        hunter = ManualHunter(self.program, source_root=self.target_root)
        hunter.snapshot_identity = {"snapshot_id": "snap-1", "version_label": "v1"}
        write_ctx = hunter.storage.context_root
        write_ctx.mkdir(parents=True, exist_ok=True)
        (write_ctx / "target_profile.json").write_text('{"program":"notion"}\n', encoding="utf-8")
        (write_ctx / "me_context.md").write_text("Program: notion\n", encoding="utf-8")
        (write_ctx / "session_handoff.md").write_text("# Session Handoff\n", encoding="utf-8")

        bundle = _build_subagent_handoff_bundle(
            hunter.storage,
            program=hunter.program,
            source_root=self.target_root,
            hunt_prompt="hunt here",
        )

        self.assertIn('"program": "notion"', bundle)
        self.assertIn('"hunt_prompt": "hunt here"', bundle)
        self.assertIn("target_profile.json", bundle)
        self.assertIn("me_context.md", bundle)
        self.assertIn("session_handoff.md", bundle)
        self.assertIn("Child-agent rules", bundle)

    @patch("agents.sync_reports.sync_reports_main", return_value=0)
    @patch("agents.manual_hunter._run_codex_hunt")
    def test_default_mode_runs_hunt_then_sync_reports(
        self,
        mock_run_codex_hunt: patch,
        mock_sync_reports_main: patch,
    ) -> None:
        mock_run_codex_hunt.return_value = subprocess.CompletedProcess(
            args=["codex", "exec"],
            returncode=0,
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = main([self.program, "--lane", "apk"])

        self.assertEqual(rc, 0, stdout.getvalue())
        mock_run_codex_hunt.assert_called_once()
        prompt, workdir = mock_run_codex_hunt.call_args.args
        self.assertIn("## Task:", prompt)
        self.assertEqual(workdir, self.target_root)
        self.assertIn("extra_instructions", mock_run_codex_hunt.call_args.kwargs)
        self.assertIn("/ledger context handoff bundle", mock_run_codex_hunt.call_args.kwargs["extra_instructions"])
        reports_dir = self._storage().reports_root / "raw"
        mock_sync_reports_main.assert_called_once_with(
            self.program,
            source_dir=str(reports_dir),
            source_root=str(self.target_root),
            family="binaries",
            lane="apk",
            hunt_type="apk",
            verbose=True,
        )
        self.assertTrue(reports_dir.is_dir())


if __name__ == "__main__":
    unittest.main()
