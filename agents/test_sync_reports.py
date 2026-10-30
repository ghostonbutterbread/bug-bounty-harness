import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agents.shared_brain import RepoIndex, save_index
from agents.storage_resolver import resolve_storage
from agents.report_paths import discover_report_files, select_report_source
from agents.manual_hunter import ManualHunter, ReviewTierDecisionRequired
from agents.sync_reports import _candidates_for_file, _flexible_findings_for_file, _resolve_source_root, sync_reports_main


def _brain_file(sha1: str) -> dict[str, object]:
    return {
        "lang": "javascript",
        "size": 123,
        "mtime_ns": 1,
        "sha1": sha1,
        "roles": [],
        "signals": {
            "entries": [],
            "trust_boundaries": [],
            "sinks": [],
            "class_scores": {"dom-xss": 1},
        },
    }


class TestSyncReports(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.source_dir = self.tmp / "reports"
        self.source_dir.mkdir(parents=True)
        self.report_path = self.source_dir / "finding.md"
        self.report_path.write_text("# Finding\n\nsrc/app.js:12\n", encoding="utf-8")

    def _hunter(self, *, check_side_effect: list[tuple[bool, str | None, dict] | Exception]) -> SimpleNamespace:
        ledger = Mock()
        ledger.path = self.tmp / "ledger.json"
        ledger.check.side_effect = check_side_effect
        ledger.update.side_effect = lambda finding: {**finding, "fid": finding.get("fid") or "D01"}
        return SimpleNamespace(
            ledger=ledger,
            family="binaries",
            lane="apk",
            storage_root=self.tmp / "storage-root",
            snapshot_id="snap-test",
            version_label="v-test",
            storage=SimpleNamespace(
                lane_root=self.tmp / "lane",
                reports_root=self.tmp / "reports-root",
                ledgers_root=self.tmp / "ledgers",
            ),
        )

    def test_conflicting_class_is_not_downgraded_by_sync_fallback(self):
        text = "Title: Synthetic access\nFile: src/access.py\nDescription: Owned fixture.\nClass: idor\n## Class\ndom-xss\n"
        self.report_path.write_text(text, encoding="utf-8")
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ValueError, "Conflicting Class"):
            _flexible_findings_for_file(hunter, self.report_path, text)
        errors = io.StringIO()
        with patch("agents.sync_reports.update_team_finding") as write, redirect_stderr(errors):
            rc = sync_reports_main("synthetic_program", lane="apk", source_dir=str(self.source_dir), storage_root=self.tmp / "storage-root")
        self.assertEqual(rc, 1)
        write.assert_not_called()
        self.assertIn("Conflicting Class", errors.getvalue())

    def test_mixed_tiers_do_not_hide_class_conflict_or_write_first_finding(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\nReview Tier: CONFIRMED\nClass: idor\n### Description\nOwned first.\n"
            "## [DORMANT_ACTIVE] Second\nFile: src/second.py\nReview Tier: DORMANT_ACTIVE\nClass: idor\nClass: ssrf\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        errors = io.StringIO()
        with redirect_stderr(errors), redirect_stdout(io.StringIO()):
            rc = sync_reports_main("synthetic_program", lane="apk", source_dir=str(self.source_dir), storage_root=self.tmp / "storage-root")
        self.assertEqual(rc, 1)
        self.assertIn("Conflicting Class", errors.getvalue())
        ledgers = list((self.tmp / "storage-root").rglob("ledger.json"))
        for ledger in ledgers:
            self.assertEqual(json.loads(ledger.read_text()).get("findings", []), [])

    def test_separate_report_failure_does_not_roll_back_earlier_report(self):
        self.report_path.rename(self.source_dir / "a.md")
        (self.source_dir / "a.md").write_text("Title: First\nFile: src/first.py\nDescription: Owned fixture.\nClass: unknown\n")
        (self.source_dir / "b.md").write_text("Title: Second\nFile: src/second.py\nDescription: Owned fixture.\nClass: idor\nClass: ssrf\n")
        errors, output = io.StringIO(), io.StringIO()
        with redirect_stderr(errors), redirect_stdout(output):
            rc = sync_reports_main("synthetic_program", lane="apk", source_dir=str(self.source_dir), storage_root=self.tmp / "storage-root")
        self.assertEqual(rc, 1)
        self.assertIn("Conflicting Class", errors.getvalue())
        ledgers = list((self.tmp / "storage-root").rglob("ledger.json"))
        self.assertEqual(len(ledgers), 1)
        rows = json.loads(ledgers[0].read_text())["findings"]
        self.assertEqual([(r["file"], r["class_name"]) for r in rows], [("src/first.py", "unknown")])

    def test_sync_rejects_fenced_class_example_and_uses_local_block_inference(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\n### Description\nOwned fixture.\n"
            "```\nClass: ssrf\n```\n"
            "## [CONFIRMED] Second\nFile: src/second.py\nClass: dom-xss\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)
        self.assertEqual(candidates[0]["class_name"], "unknown")
        self.assertEqual(candidates[1]["class_name"], "dom-xss")

    def test_fenced_structured_heading_is_not_a_new_finding(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\nClass: idor\n### Description\nOwned fixture.\n"
            "```md\n## [CONFIRMED] Example\nFile: src/fake.py\nClass: ssrf\n### Description\nExample only.\n```\n"
            "## [CONFIRMED] Second\nFile: src/second.py\nClass: custom\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)
        self.assertEqual([(c["file"], c["class_name"]) for c in candidates], [("src/first.py", "idor"), ("src/second.py", "custom")])

    def test_structured_block_preserves_flexible_metadata(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/a.py\nClass: idor\n"
            "Impact: Synthetic impact.\nRemediation: Synthetic fix.\n### Description\nOwned fixture.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidate = _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)[0]
        self.assertEqual(candidate["impact"], "Synthetic impact.")
        self.assertEqual(candidate["remediation"], "Synthetic fix.")

    def test_structured_headings_and_unknown_are_preserved_per_finding(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\n### Class\nunknown\n### Description\nOwned DOM XSS fixture.\n"
            "## [DORMANT_ACTIVE] Second\nFile: src/second.py\n### Class\ncustom-v1\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)
        self.assertEqual([c["class_name"] for c in candidates], ["unknown", "custom-v1"])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = sync_reports_main("synthetic_program", lane="apk", source_dir=str(self.source_dir), storage_root=self.tmp / "storage-root")
        self.assertEqual(rc, 0)
        ledger = next((self.tmp / "storage-root").rglob("ledger.json"))
        self.assertEqual([r["class_name"] for r in json.loads(ledger.read_text())["findings"]], ["unknown", "custom-v1"])

    def test_structured_distinct_classes_are_not_a_conflict_across_findings(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\nClass: idor\n### Description\nOwned first.\n"
            "## [CONFIRMED] Second\nFile: src/second.py\nClass: dom-xss\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)
        self.assertEqual([c["class_name"] for c in candidates], ["idor", "dom-xss"])

    def test_structured_class_conflict_inside_one_finding_is_rejected(self):
        self.report_path.write_text(
            "## [CONFIRMED] First\nFile: src/first.py\nClass: idor\n### Description\nOwned first.\n"
            "## [CONFIRMED] Second\nFile: src/second.py\nClass: dom-xss\n"
            "## Class\nssrf\n### Description\nOwned second.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("synthetic_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ValueError, "Conflicting Class"):
            _candidates_for_file("synthetic_program", "apk", hunter, self.report_path)

    def test_ambiguous_tier_is_skipped_without_loose_fallback(self):
        text = (
            "Title: Cross-account record read\n"
            "Class: idor\n"
            "File: src/access.py\n"
            "Description: The response includes another owned account's record; "
            "impact may extend to sibling records.\n"
        )
        self.report_path.write_text(text, encoding="utf-8")
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaises(ReviewTierDecisionRequired):
            _flexible_findings_for_file(hunter, self.report_path, text)

        errors = io.StringIO()
        with patch("agents.sync_reports.update_team_finding") as write, redirect_stderr(errors):
            rc = sync_reports_main(
                "test_program", lane="apk", source_dir=self.source_dir.as_posix(),
                storage_root=self.tmp / "storage-root",
            )
        self.assertEqual(rc, 1)
        write.assert_not_called()
        self.assertIn("Review Tier", errors.getvalue())

    def test_invalid_tier_without_description_never_uses_loose_fallback(self):
        text = "Title: Cross-account read\nFile: src/access.py\nReview Tier: CONFRIMED\n"
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaises(ReviewTierDecisionRequired):
            _flexible_findings_for_file(hunter, self.report_path, text)

    def test_structured_confirmed_heading_overrides_whole_file_ambiguity(self):
        self.report_path.write_text(
            "# Findings\n\n## [CONFIRMED] Cross-account record read\n"
            "File: src/access.py\nClass: idor\n"
            "### Description\nReproduced reading another owned account's record; "
            "impact may extend to sibling records.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("test_program", "apk", hunter, self.report_path)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["review_tier"], "CONFIRMED")

    def test_structured_tiers_are_preserved_per_finding(self):
        self.report_path.write_text(
            "# Findings\n\n## [CONFIRMED] Cross-account record read\n"
            "File: src/access.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record; impact may extend.\n"
            "\n## [DORMANT_HYPOTHETICAL] Possible second record read\n"
            "File: src/other.py\nClass: idor\n"
            "### Description\nThis may permit reading another account record.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("test_program", "apk", hunter, self.report_path)
        self.assertEqual([item["review_tier"] for item in candidates], ["CONFIRMED", "DORMANT_HYPOTHETICAL"])

    def test_structured_report_starting_with_heading_keeps_both_findings(self):
        self.report_path.write_text(
            "## [CONFIRMED] First cross-account read\n"
            "File: src/first.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record.\n"
            "\n## [DORMANT_HYPOTHETICAL] Possible second read\n"
            "File: src/second.py\nClass: idor\n"
            "### Description\nThis may permit reading another account record.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("test_program", "apk", hunter, self.report_path)
        self.assertEqual([item["file"] for item in candidates], ["src/first.py", "src/second.py"])
        self.assertEqual(
            [item["review_tier"] for item in candidates],
            ["CONFIRMED", "DORMANT_HYPOTHETICAL"],
        )

    def test_conflict_in_first_heading_at_file_start_is_not_ignored(self):
        self.report_path.write_text(
            "## [CONFIRMED] First cross-account read\n"
            "File: src/first.py\nClass: idor\n"
            "Review Tier: DORMANT_HYPOTHETICAL\n"
            "### Description\nReproduced reading another owned record.\n"
            "\n## [DORMANT_HYPOTHETICAL] Possible second read\n"
            "File: src/second.py\nClass: idor\n"
            "### Description\nThis may permit reading another account record.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ReviewTierDecisionRequired, "Conflicting Review Tier"):
            _candidates_for_file("test_program", "apk", hunter, self.report_path)

    def test_unparsed_structured_heading_rejects_partial_import(self):
        self.report_path.write_text(
            "## [CONFIRMED] First read\n"
            "File: src/first.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record.\n"
            "\n## [confirmed] Second read\n"
            "File: src/second.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ReviewTierDecisionRequired, "heading count"):
            _candidates_for_file("test_program", "apk", hunter, self.report_path)

    def test_misspelled_uppercase_heading_tier_is_not_inferred(self):
        self.report_path.write_text(
            "## [CONFIRMED] First read\n"
            "File: src/first.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record.\n"
            "\n## [CONFRIMED] Second read\n"
            "File: src/second.py\nClass: idor\n"
            "### Description\nReproduced reading another owned record.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ReviewTierDecisionRequired, "Unsupported Review Tier heading"):
            _candidates_for_file("test_program", "apk", hunter, self.report_path)

    def test_conflicting_structured_heading_and_field_are_rejected(self):
        self.report_path.write_text(
            "# Findings\n\n## [CONFIRMED] Cross-account record read\n"
            "File: src/access.py\nClass: idor\n"
            "Review Tier: DORMANT_HYPOTHETICAL\n"
            "### Description\nReproduced reading another owned account's record; "
            "impact may extend.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        with self.assertRaisesRegex(ReviewTierDecisionRequired, "Conflicting Review Tier"):
            _candidates_for_file("test_program", "apk", hunter, self.report_path)

    def test_generic_bold_markdown_tier_is_preserved(self):
        self.report_path.write_text(
            "# Cross-account record read\n**Tier:** CONFIRMED\n"
            "File: src/access.py\nClass: idor\n"
            "Description: Reproduced reading another owned account's record; "
            "impact may extend.\n",
            encoding="utf-8",
        )
        hunter = ManualHunter("test_program", lane="apk", storage_root=self.tmp / "storage-root")
        candidates = _candidates_for_file("test_program", "apk", hunter, self.report_path)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["review_tier"], "CONFIRMED")

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_import_new_findings(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        finding1 = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        finding2 = {"type": "sqli", "class_name": "sqli", "file": "src/db.py"}
        hunter = self._hunter(
            check_side_effect=[
                (False, None, {**finding1, "fid": "D01"}),
                (False, None, {**finding2, "fid": "D02"}),
            ]
        )
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding1, finding2]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", lane="apk", source_dir=self.source_dir.as_posix())

        self.assertEqual(hunter.ledger.check.call_count, 2)
        self.assertEqual(mock_update_team_finding.call_count, 2)
        mock_update_team_finding.assert_any_call(
            "test_program",
            {**finding1, "fid": "D01"},
            snapshot_id="snap-test",
            version_label="v-test",
            run_id=mock_update_team_finding.call_args_list[0].kwargs["run_id"],
            agent="sync-reports",
            family="binaries",
            lane="apk",
            root_override=self.tmp / "storage-root",
            write_report=False,
            refresh=True,
            update_current=False,
            update_sighting=False,
        )
        self.assertEqual(mock_update_team_finding.call_args_list[1].args[:2], ("test_program", {**finding2, "fid": "D02"}))
        self.assertEqual(mock_update_team_finding.call_args_list[1].kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args_list[1].kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args_list[1].kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_skip_duplicates(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        finding1 = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        finding2 = {"type": "sqli", "class_name": "sqli", "file": "src/db.py"}
        hunter = self._hunter(
            check_side_effect=[
                (True, "D01", {**finding1, "fid": "D01"}),
                (False, None, {**finding2, "fid": "D02"}),
            ]
        )
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding1, finding2]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", lane="apk", source_dir=self.source_dir.as_posix())

        self.assertEqual(hunter.ledger.check.call_count, 2)
        mock_update_team_finding.assert_called_once()
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding2, "fid": "D02"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_report_fid_collision_is_skipped_and_reported(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        finding1 = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js", "fid": "D06"}
        finding2 = {"type": "sqli", "class_name": "sqli", "file": "src/db.py"}
        hunter = self._hunter(
            check_side_effect=[
                ValueError("finding FID already assigned: D06"),
                (False, None, {**finding2, "fid": "D02"}),
            ]
        )
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding1, finding2]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = sync_reports_main("test_program", lane="apk", source_dir=self.source_dir.as_posix())

        self.assertEqual(hunter.ledger.check.call_count, 2)
        mock_update_team_finding.assert_called_once()
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding2, "fid": "D02"}))
        self.assertEqual(exit_code, 1)
        self.assertIn("FID collisions: 1 report needs manual reconciliation", output.getvalue())
        self.assertIn("finding FID already assigned: D06", errors.getvalue())
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    def test_real_ledger_fid_collision_continues_import_and_returns_nonzero(
        self, mock_candidates, _mock_chain
    ):
        program = "collision_fixture"
        storage_root = self.tmp / "collision-storage"
        source_root = self.tmp / "collision-source"
        source_root.mkdir()
        hunter = ManualHunter(
            program, lane="apk", source_root=source_root, storage_root=storage_root
        )
        self.assertEqual(hunter.ledger.__class__.__name__, "VersionedFindingsLedger")
        existing = {
            "fid": "D06", "type": "Existing DOM XSS", "class_name": "dom-xss",
            "file": "src/existing.js", "line": 1,
        }
        collision = {
            "fid": "D06", "type": "Different DOM XSS", "class_name": "dom-xss",
            "file": "src/different.js", "line": 2,
        }
        next_finding = {
            "fid": "D07", "type": "Independent SQL injection", "class_name": "sqli",
            "file": "src/query.py", "line": 3,
        }
        self.assertEqual(hunter.ledger.check(existing)[1], "D06")
        with self.assertRaisesRegex(ValueError, "finding FID already assigned: D06"):
            hunter.ledger.check(collision)
        mock_candidates.return_value = [collision, next_finding]

        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = sync_reports_main(
                program, lane="apk", source_dir=self.source_dir.as_posix(),
                source_root=source_root, storage_root=storage_root,
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("finding FID already assigned: D06", errors.getvalue())
        self.assertIn("FID collisions: 1 report needs manual reconciliation", output.getvalue())
        self.assertIn("ADDED D07", output.getvalue())
        self.assertEqual(mock_candidates.call_count, 1)
        findings = hunter.ledger.list_all()
        self.assertEqual({item["fid"] for item in findings}, {"D06", "D07"})
        self.assertEqual(next(item for item in findings if item["fid"] == "D06")["file"], "src/existing.js")
        self.assertEqual(next(item for item in findings if item["fid"] == "D07")["file"], "src/query.py")
        self.assertTrue(str(hunter.ledger.path).startswith(str(storage_root)))

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_report_preserves_reserved_fid_on_update(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js", "fid": "G01"}
        hunter = self._hunter(check_side_effect=[(False, None, finding)])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", lane="apk", source_dir=self.source_dir.as_posix())

        mock_update_team_finding.assert_called_once()
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", finding))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    def test_source_root_explicit_override_wins_over_shared_brain_and_fallback(self):
        program = "root_precedence"
        storage_root = self.tmp / "storage"
        explicit_root = self.tmp / "explicit-source"
        shared_root = self.tmp / "shared-source"
        fallback_reports = self.tmp / "fallback" / "reports"
        for path in (explicit_root, shared_root, fallback_reports):
            path.mkdir(parents=True, exist_ok=True)
        save_index(
            RepoIndex(
                target_root=str(shared_root),
                target_id="target-shared",
                generated_at="2026-04-28T12:00:00Z",
                git_head="shared-head",
                manifest_hash="shared-manifest",
                files={},
            ),
            program,
            family="binaries",
            lane="apk",
            root_override=storage_root,
        )

        resolved = _resolve_source_root(
            program,
            fallback_reports,
            "source",
            root_override=storage_root,
            source_root_override=explicit_root,
        )

        self.assertEqual(resolved, explicit_root.resolve(strict=False))

    def test_source_root_shared_brain_wins_over_report_dir_fallback(self):
        program = "shared_precedence"
        storage_root = self.tmp / "storage"
        shared_root = self.tmp / "shared-source"
        fallback_reports = self.tmp / "fallback" / "reports"
        for path in (shared_root, fallback_reports):
            path.mkdir(parents=True, exist_ok=True)
        save_index(
            RepoIndex(
                target_root=str(shared_root),
                target_id="target-shared",
                generated_at="2026-04-28T12:00:00Z",
                git_head="shared-head",
                manifest_hash="shared-manifest",
                files={},
            ),
            program,
            family="binaries",
            lane="apk",
            root_override=storage_root,
        )

        resolved = _resolve_source_root(program, fallback_reports, "source", root_override=storage_root)

        self.assertEqual(resolved, shared_root.resolve(strict=False))

    def test_source_root_falls_back_to_report_dir_derivation_without_overrides(self):
        program = "fallback_precedence"
        fallback_root = self.tmp / "fallback-source"
        fallback_reports = fallback_root / "reports"
        fallback_reports.mkdir(parents=True, exist_ok=True)

        resolved = _resolve_source_root(
            program,
            fallback_reports,
            "source",
            root_override=self.tmp / "storage",
        )

        self.assertEqual(resolved, fallback_root.resolve(strict=False))

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_imports_from_canonical_raw_reports(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        home = self.tmp / "home"
        report_dir = home / "Shared" / "binaries" / "test_program" / "apk" / "reports" / "raw"
        report_dir.mkdir(parents=True)
        report_path = report_dir / "canonical.md"
        report_path.write_text("# Canonical\n\nsrc/app.js:12\n", encoding="utf-8")
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        hunter = self._hunter(check_side_effect=[(False, None, {**finding, "fid": "D01"})])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program", lane="apk")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_reads_legacy_reports_as_fallback(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        home = self.tmp / "home"
        report_dir = home / "Shared" / "bounty_recon" / "test_program" / "ghost" / "reports_source"
        dated_dir = report_dir / "01-01-2026"
        dated_dir.mkdir(parents=True)
        report_path = dated_dir / "legacy.md"
        report_path.write_text("# Legacy\n\nsrc/app.js:12\n", encoding="utf-8")
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        hunter = self._hunter(check_side_effect=[(False, None, {**finding, "fid": "D01"})])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program", lane="apk")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_prefers_source_reports_over_seeded_canonical_raw_indexes(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        home = self.tmp / "home"
        seeded_index = (
            home
            / "Shared"
            / "binaries"
            / "test_program"
            / "apk"
            / "reports"
            / "raw"
            / "dom-xss"
            / "index.md"
        )
        seeded_index.parent.mkdir(parents=True)
        seeded_index.write_text("# Raw DOM-XSS\n\n", encoding="utf-8")
        report_dir = home / "source" / "test_program" / "reports"
        report_dir.mkdir(parents=True)
        report_path = report_dir / "finding.md"
        report_path.write_text("# Source report\n\nsrc/app.js:12\n", encoding="utf-8")
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        hunter = self._hunter(check_side_effect=[(False, None, {**finding, "fid": "D01"})])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program", lane="apk")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    def test_discover_report_files_ignores_registered_packet_artifacts(self):
        reports_root = self.tmp / "reports"
        packet = reports_root / "D01-owned-xss"
        packet.mkdir(parents=True)
        (packet / "EVIDENCE.md").write_text("# Owned proof\n", encoding="utf-8")
        (packet / "app-example-xss-D01.md").write_text("# Final submission\n", encoding="utf-8")
        legacy = reports_root / "D02"
        legacy.mkdir()
        (legacy / "REPORT.md").write_text("# Historical report\n", encoding="utf-8")
        submitted = reports_root / "submitted" / "index.md"
        submitted.parent.mkdir()
        submitted.write_text("<!-- generated: bounty-core-report-navigation -->\n# Submitted\n", encoding="utf-8")
        raw = reports_root / "raw" / "finding.md"
        raw.parent.mkdir()
        raw.write_text("# Candidate input\n", encoding="utf-8")
        self.assertEqual(discover_report_files(reports_root), [self.report_path, raw])

    def test_discover_report_files_excludes_generated_output_but_keeps_raw_reports(self):
        reports_root = self.tmp / "canonical-reports"
        nav_files = [
            reports_root / "dormant.md",
            reports_root / "daily" / "05-06-2026" / "dormant.md",
            reports_root / "categories" / "renderer" / "index.md",
            reports_root / "severity" / "high" / "index.md",
        ]
        for path in nav_files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "<!-- generated: bounty-core-report-navigation -->\n# Generated Navigation\n",
                encoding="utf-8",
            )
        canonical_body = reports_root / "findings" / "dormant" / "D01 - HIGH - Body.md"
        canonical_body.parent.mkdir(parents=True, exist_ok=True)
        canonical_body.write_text(
            "# Canonical Body\n",
            encoding="utf-8",
        )
        raw_body = reports_root / "raw" / "finding.md"
        raw_body.parent.mkdir(parents=True, exist_ok=True)
        raw_body.write_text("# Raw Body\n", encoding="utf-8")

        discovered = discover_report_files(reports_root)

        self.assertEqual(discovered, [raw_body])

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_skips_generated_canonical_findings_but_imports_raw(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        reports_root = self.tmp / "canonical-reports"
        generated_body = reports_root / "findings" / "confirmed" / "D01 - HIGH - Generated.md"
        generated_body.parent.mkdir(parents=True, exist_ok=True)
        generated_body.write_text(
            "<!-- generated: bounty-core-finding-report -->\n# Generated\n\nsrc/generated.js:1\n",
            encoding="utf-8",
        )
        raw_body = reports_root / "raw" / "raw-finding.md"
        raw_body.parent.mkdir(parents=True, exist_ok=True)
        raw_body.write_text("# Raw Body\n\nsrc/app.js:12\n", encoding="utf-8")

        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        hunter = self._hunter(check_side_effect=[(False, None, {**finding, "fid": "D01"})])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", lane="apk", source_dir=reports_root.as_posix())

        mock_candidates.assert_called_once()
        self.assertEqual(mock_candidates.call_args.args[3], raw_body)
        mock_update_team_finding.assert_called_once()

    def test_generated_only_canonical_navigation_does_not_suppress_source_fallback(self):
        home = self.tmp / "home"
        generated_nav = home / "Shared" / "binaries" / "test_program" / "apk" / "reports" / "dormant.md"
        generated_nav.parent.mkdir(parents=True, exist_ok=True)
        generated_nav.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n# Dormant Findings\n",
            encoding="utf-8",
        )
        source_report = home / "source" / "test_program" / "reports" / "finding.md"
        source_report.parent.mkdir(parents=True, exist_ok=True)
        source_report.write_text("# Source report\n\nsrc/app.js:12\n", encoding="utf-8")

        with patch.dict(os.environ, {"HOME": str(home)}):
            selected = select_report_source("test_program")

        self.assertEqual(selected.path, source_report.parent.resolve(strict=False))
        self.assertEqual(selected.mode, "source_reports")

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    def test_sync_reports_import_from_source_dir_writes_canonical_report_and_coverage(self, _mock_chain):
        program = "source_import_program"
        storage_root = self.tmp / "canonical-root"
        target_root = self.tmp / "target"
        reports_dir = self.tmp / "import-reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        (target_root / "src").mkdir(parents=True, exist_ok=True)
        (target_root / "src" / "app.js").write_text(
            "document.body.innerHTML = location.hash;\n",
            encoding="utf-8",
        )
        report_path = reports_dir / "finding.md"
        report_path.write_text(
            "\n".join(
                [
                    "Title: DOM XSS via location hash",
                    "Type: DOM XSS",
                    "Class: dom-xss",
                    "Severity: HIGH",
                    "File: src/app.js:1",
                    "Sink: innerHTML",
                    "Description: The renderer writes attacker-controlled hash content into innerHTML.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        save_index(
            RepoIndex(
                target_root=str(target_root),
                target_id="target-source-import",
                generated_at="2026-04-28T12:00:00Z",
                git_head="snap-source-import",
                manifest_hash="manifest-source-import",
                files={"src/app.js": _brain_file("sha-app")},
            ),
            program,
            family="binaries",
            lane="apk",
            root_override=storage_root,
        )

        rc = sync_reports_main(
            program,
            lane="apk",
            source_dir=reports_dir.as_posix(),
            storage_root=storage_root,
        )

        self.assertEqual(rc, 0)
        storage = resolve_storage(
            program,
            family="binaries",
            lane="apk",
            root_override=storage_root,
            create=False,
        )
        ledger_payload = json.loads((storage.ledgers_root / "ledger.json").read_text(encoding="utf-8"))
        self.assertEqual([finding["fid"] for finding in ledger_payload["findings"]], ["D01"])

        packet = Path(ledger_payload["findings"][0]["report_dir"])
        evidence = packet / "EVIDENCE.md"
        self.assertTrue(evidence.is_file())
        self.assertFalse((packet / "REPORT.md").exists())

        self.assertFalse((storage.ledgers_root / "coverage.json").exists(),
                         "report import is not a completed file/class review")

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_does_not_parse_generated_navigation_files(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_chain,
    ):
        nav = self.source_dir / "dormant.md"
        nav.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n# Dormant Findings\n",
            encoding="utf-8",
        )
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js"}
        hunter = self._hunter(check_side_effect=[(False, None, {**finding, "fid": "D01"})])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", lane="apk", source_dir=self.source_dir.as_posix())

        mock_candidates.assert_called_once()
        self.assertEqual(mock_candidates.call_args.args[3], self.report_path)
        mock_update_team_finding.assert_called_once()

    def test_sync_reports_explicit_root_writes_ledger_reports_and_coverage_canonically(self):
        program = "explicit_program"
        home = self.tmp / "home"
        home.mkdir(parents=True, exist_ok=True)
        explicit_root = self.tmp / "canonical-root"
        target_root = self.tmp / "target"
        (target_root / "src").mkdir(parents=True, exist_ok=True)
        (target_root / "src" / "app.js").write_text(
            "document.body.innerHTML = location.hash;\n",
            encoding="utf-8",
        )
        save_index(
            RepoIndex(
                target_root=str(target_root),
                target_id="target-explicit",
                generated_at="2026-04-28T12:00:00Z",
                git_head="snap-explicit",
                manifest_hash="manifest-explicit",
                files={"src/app.js": _brain_file("sha-app")},
            ),
            program,
            family="binaries",
            lane="apk",
            root_override=explicit_root,
        )
        storage = resolve_storage(
            program,
            family="binaries",
            lane="apk",
            root_override=explicit_root,
            create=False,
        )
        raw_reports = storage.reports_root / "raw"
        raw_reports.mkdir(parents=True, exist_ok=True)
        report_path = raw_reports / "finding.md"
        report_path.write_text(
            "\n".join(
                [
                    "Title: DOM XSS via location hash",
                    "Type: DOM XSS",
                    "Class: dom-xss",
                    "Severity: HIGH",
                    "File: src/app.js:1",
                    "Sink: innerHTML",
                    "Description: The renderer writes attacker-controlled hash content into innerHTML.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"HOME": str(home)}):
            rc = sync_reports_main(program, lane="apk", storage_root=explicit_root)

        self.assertEqual(rc, 0)
        explicit_prefix = str(explicit_root.resolve(strict=False))
        ledger_path = storage.ledgers_root / "ledger.json"
        self.assertTrue(ledger_path.is_file())
        self.assertTrue(str(ledger_path).startswith(explicit_prefix))
        ledger_payload = json.loads(ledger_path.read_text(encoding="utf-8"))
        self.assertEqual([finding["fid"] for finding in ledger_payload["findings"]], ["D01"])

        self.assertTrue(str(raw_reports.resolve(strict=False)).startswith(explicit_prefix))
        evidence = Path(ledger_payload["findings"][0]["report_dir"]) / "EVIDENCE.md"
        self.assertTrue(evidence.is_file())
        self.assertTrue(str(evidence).startswith(explicit_prefix))
        self.assertFalse((evidence.parent / "REPORT.md").exists())
        self.assertFalse(list(storage.reports_root.glob("confirmed/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(storage.reports_root.glob("dormant/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(storage.reports_root.glob("novel/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))

        shared_brain_path = storage.ledgers_root / "shared_brain" / "index.json"
        coverage_path = storage.ledgers_root / "coverage.json"
        self.assertTrue(shared_brain_path.is_file())
        self.assertFalse(coverage_path.exists())
        self.assertTrue(str(shared_brain_path).startswith(explicit_prefix))

        legacy_ghost_root = home / "Shared" / "bounty_recon" / program / "ghost"
        self.assertFalse(legacy_ghost_root.exists())
        self.assertFalse((home / "Shared" / "binaries" / program).exists())



if __name__ == "__main__":
    unittest.main()
