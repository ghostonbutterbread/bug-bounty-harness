import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agents.shared_brain import RepoIndex, save_index
from agents.snapshot_identity import get_snapshot_id
from agents.storage_resolver import resolve_storage
from agents.report_paths import discover_report_files, select_report_source
from agents.sync_reports import _resolve_source_root, _mark_coverage, sync_reports_main


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

    def _hunter(self, *, check_side_effect: list[tuple[bool, str | None, dict]]) -> SimpleNamespace:
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

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_import_new_findings(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", source_dir=self.source_dir.as_posix())

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
            write_report=True,
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
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_skip_duplicates(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", source_dir=self.source_dir.as_posix())

        self.assertEqual(hunter.ledger.check.call_count, 2)
        mock_update_team_finding.assert_called_once()
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding2, "fid": "D02"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()
        mock_append.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_report_preserves_reserved_fid_on_update(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        _mock_append,
        _mock_coverage,
        _mock_chain,
    ):
        finding = {"type": "xss", "class_name": "dom-xss", "file": "src/app.js", "fid": "G01"}
        hunter = self._hunter(check_side_effect=[(False, None, finding)])
        mock_hunter_cls.return_value = hunter
        mock_candidates.return_value = [finding]
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", source_dir=self.source_dir.as_posix())

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
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_imports_from_canonical_raw_reports(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_reads_legacy_reports_as_fallback(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

    @patch("agents.sync_reports._chain_suggestions", return_value=[])
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_prefers_source_reports_over_seeded_canonical_raw_indexes(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        with patch.dict(os.environ, {"HOME": str(home)}):
            sync_reports_main("test_program")

        self.assertEqual(mock_candidates.call_args.args[3], report_path)
        self.assertEqual(mock_update_team_finding.call_args.args[:2], ("test_program", {**finding, "fid": "D01"}))
        self.assertEqual(mock_update_team_finding.call_args.kwargs["family"], "binaries")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["lane"], "apk")
        self.assertEqual(mock_update_team_finding.call_args.kwargs["root_override"], self.tmp / "storage-root")
        hunter.ledger.update.assert_not_called()

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
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_skips_generated_canonical_findings_but_imports_raw(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", source_dir=reports_root.as_posix())

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
    @patch("agents.sync_reports._mark_coverage", return_value=None)
    @patch("agents.sync_reports._append_canonical_report")
    @patch("agents.sync_reports._candidates_for_file")
    @patch("agents.sync_reports.update_team_finding")
    @patch("agents.sync_reports.ManualHunter")
    def test_sync_reports_does_not_parse_generated_navigation_files(
        self,
        mock_hunter_cls,
        mock_update_team_finding,
        mock_candidates,
        mock_append,
        _mock_coverage,
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
        mock_append.return_value = self.tmp / "canonical.md"
        mock_update_team_finding.side_effect = lambda _program, finding, **_kwargs: dict(finding)

        sync_reports_main("test_program", source_dir=self.source_dir.as_posix())

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
            rc = sync_reports_main(program, storage_root=explicit_root)

        self.assertEqual(rc, 0)
        explicit_prefix = str(explicit_root.resolve(strict=False))
        ledger_path = storage.ledgers_root / "ledger.json"
        self.assertTrue(ledger_path.is_file())
        self.assertTrue(str(ledger_path).startswith(explicit_prefix))
        ledger_payload = json.loads(ledger_path.read_text(encoding="utf-8"))
        self.assertEqual([finding["fid"] for finding in ledger_payload["findings"]], ["D01"])

        self.assertTrue(str(raw_reports.resolve(strict=False)).startswith(explicit_prefix))
        canonical_reports = [
            path
            for path in (storage.reports_root / "findings").glob("**/*.md")
            if "DOM XSS via location hash" in path.read_text(encoding="utf-8")
        ]
        self.assertTrue(canonical_reports)
        self.assertTrue(all(str(path).startswith(explicit_prefix) for path in canonical_reports))
        self.assertFalse(list(storage.reports_root.glob("confirmed/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(storage.reports_root.glob("dormant/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(storage.reports_root.glob("novel/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))

        shared_brain_path = storage.ledgers_root / "shared_brain" / "index.json"
        coverage_path = storage.ledgers_root / "coverage.json"
        self.assertTrue(shared_brain_path.is_file())
        self.assertTrue(coverage_path.is_file())
        self.assertTrue(str(shared_brain_path).startswith(explicit_prefix))
        self.assertTrue(str(coverage_path).startswith(explicit_prefix))
        coverage_payload = json.loads(coverage_path.read_text(encoding="utf-8"))
        coverage_entries = [
            (snapshot_id, snapshot["classes"]["dom-xss"]["files"]["src/app.js"])
            for snapshot_id, snapshot in coverage_payload["snapshots"].items()
            if "dom-xss" in snapshot.get("classes", {})
            and "src/app.js" in snapshot["classes"]["dom-xss"].get("files", {})
        ]
        self.assertEqual(len(coverage_entries), 1)
        coverage_snapshot_id, coverage_entry = coverage_entries[0]
        self.assertEqual(coverage_snapshot_id, get_snapshot_id(target_root))
        self.assertNotEqual(coverage_snapshot_id, get_snapshot_id(raw_reports))
        self.assertEqual(coverage_entry["method"], "sync-reports")
        self.assertEqual(coverage_entry["finding_fids"], ["D01"])

        legacy_ghost_root = home / "Shared" / "bounty_recon" / program / "ghost"
        self.assertFalse(legacy_ghost_root.exists())
        self.assertFalse((home / "Shared" / "binaries" / program).exists())

    @patch("agents.sync_reports.CoverageStore")
    def test_mark_coverage_forwards_explicit_storage_root(self, mock_store_cls):
        store = Mock()
        mock_store_cls.return_value = store
        source_root = self.tmp / "source"
        source_root.mkdir(parents=True)
        storage_root = self.tmp / "explicit-root"
        hunter = SimpleNamespace(
            program="test_program",
            source_root=source_root,
            lane="apk",
            family="binaries",
            storage_root=storage_root,
            shared_brain=SimpleNamespace(files={"src/app.js": {}}),
            snapshot_id="snap-1",
            version_label="v1",
            _coverage_relpath=lambda _file_value: "src/app.js",
        )
        finding = {"class_name": "dom-xss", "run_id": "run-1", "fid": "D01"}
        parsed = SimpleNamespace(finding={"file": "src/app.js"}, source_label="unit-test")

        relpath = _mark_coverage(hunter, finding, parsed)

        self.assertEqual(relpath, "src/app.js")
        mock_store_cls.assert_called_once_with(
            "test_program",
            source_root,
            lane="apk",
            family="binaries",
            root_override=storage_root,
        )
        store.mark_examined.assert_called_once()
        self.assertEqual(store.mark_examined.call_args.kwargs["files"], ["src/app.js"])
        self.assertEqual(store.mark_examined.call_args.kwargs["snapshot_id"], "snap-1")


if __name__ == "__main__":
    unittest.main()
