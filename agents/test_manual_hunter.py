"""Tests for agents.manual_hunter."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from agents.manual_hunter import (
    ManualHunter,
    _build_hunt_context,
    _build_subagent_handoff_bundle,
    main,
)
from agents.shared_brain import build_index, save_index
from agents.storage_resolver import resolve_storage


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

    def test_from_file_ingests_then_dedupes_and_marks_coverage(self) -> None:
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
            rc = main([self.program, "--from-file", str(note_path)])
        self.assertEqual(rc, 0, first_stdout.getvalue())
        self.assertIn("Added finding D01", first_stdout.getvalue())

        ledger_payload = json.loads(self._ledger_path().read_text(encoding="utf-8"))
        self.assertEqual(len(ledger_payload["findings"]), 1)
        self.assertEqual(ledger_payload["findings"][0]["fid"], "D01")
        self.assertEqual(ledger_payload["findings"][0]["class_name"], "native-module-abuse")

        report_files = sorted(self._storage().reports_root.rglob("*.md"))
        self.assertTrue(report_files)
        report_text = "\n".join(path.read_text(encoding="utf-8") for path in report_files)
        self.assertIn("SQLite injection via exposed IPC port", report_text)
        self.assertIn("execSqliteStatement()", report_text)
        self.assertFalse(list(self._storage().reports_root.glob("confirmed/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(self._storage().reports_root.glob("dormant/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))
        self.assertFalse(list(self._storage().reports_root.glob("novel/[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]/index.md")))

        coverage_payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        snapshots = coverage_payload["snapshots"]
        coverage_entries = [
            snapshot["classes"]["native-module-abuse"]["files"][".webpack/renderer/preload.js"]
            for snapshot in snapshots.values()
            if "native-module-abuse" in snapshot.get("classes", {})
            and ".webpack/renderer/preload.js"
            in snapshot["classes"]["native-module-abuse"].get("files", {})
        ]
        self.assertEqual(len(coverage_entries), 1)
        coverage_entry = coverage_entries[0]
        self.assertEqual(coverage_entry["status"], "done")
        self.assertEqual(coverage_entry["method"], "manual-hunter")
        self.assertEqual(coverage_entry["finding_fids"], ["D01"])

        second_stdout = io.StringIO()
        with redirect_stdout(second_stdout):
            rc = main([self.program, "--from-file", str(note_path)])
        self.assertEqual(rc, 1, second_stdout.getvalue())
        self.assertIn("Duplicate: D01 overlaps with SQLite injection via exposed IPC port", second_stdout.getvalue())

        ledger_payload = json.loads(self._ledger_path().read_text(encoding="utf-8"))
        self.assertEqual(len(ledger_payload["findings"]), 1)

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
            patch.object(hunter, "_append_report") as mock_append_report,
            patch.object(hunter, "_mark_coverage") as mock_mark_coverage,
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
        self.assertTrue(mock_update_team_finding.call_args.kwargs["write_report"])
        self.assertTrue(mock_update_team_finding.call_args.kwargs["refresh"])
        mock_append_report.assert_not_called()
        mock_mark_coverage.assert_called_once_with(reserved_finding, parsed)

    def test_source_root_explicit_override_wins_over_shared_brain(self) -> None:
        explicit_root = self.tmp / "explicit-source"
        explicit_root.mkdir(parents=True, exist_ok=True)

        hunter = ManualHunter(self.program, source_root=explicit_root)

        self.assertEqual(hunter.source_root, explicit_root.resolve(strict=False))

    def test_build_hunt_context_uses_shared_brain_target_before_default_source_root(self) -> None:
        fallback_root = self.home / "source" / self.program
        fallback_root.mkdir(parents=True, exist_ok=True)

        context = _build_hunt_context(self.program)

        self.assertIn(f"Target: {self.target_root}", context)
        self.assertNotIn(f"Target: {fallback_root}", context)

    def test_build_hunt_context_falls_back_to_default_source_root_without_shared_brain(self) -> None:
        program = "fallback_only"
        fallback_root = self.home / "source" / program
        fallback_root.mkdir(parents=True, exist_ok=True)

        context = _build_hunt_context(program, storage_root=self.tmp / "fallback-storage")

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

        context = _build_hunt_context(self.program, source_root=self.target_root)
        self.assertIn(f"Program: {self.program}", context)
        self.assertIn(f"Target: {self.target_root}", context)
        self.assertIn("Output: ~/Shared/binaries/notion/apk/reports/raw", context)
        self.assertNotIn("D01: SQLite injection via exposed IPC port", context)
        self.assertIn("## Prior findings lookup:", context)
        self.assertIn("Do not read or summarize the full findings ledger as the opening move.", context)
        self.assertIn("Do not treat a historical confirmed finding as satisfying this hunt", context)
        self.assertIn(".webpack/renderer/preload.js (native-module-abuse) ✅", context)
        self.assertIn("renderer/view.js (dom-xss)", context)
        self.assertIn("updater.ts (exec-sink-reachability)", context)

    def test_build_hunt_context_fresh_mode_rejects_historical_findings_as_success(self) -> None:
        context = _build_hunt_context(self.program, source_root=self.target_root, fresh=True)

        self.assertIn("Fresh context", context)
        self.assertIn("Historical findings are never a success condition", context)
        self.assertNotIn("## Current findings (from ledger):", context)

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
            rc = main([self.program])

        self.assertEqual(rc, 0, stdout.getvalue())
        mock_run_codex_hunt.assert_called_once()
        prompt, workdir = mock_run_codex_hunt.call_args.args
        self.assertIn("## Task:", prompt)
        self.assertEqual(workdir, self.target_root)
        self.assertIn("extra_instructions", mock_run_codex_hunt.call_args.kwargs)
        self.assertIn("/me context handoff bundle", mock_run_codex_hunt.call_args.kwargs["extra_instructions"])
        reports_dir = self._storage().reports_root / "raw"
        mock_sync_reports_main.assert_called_once_with(
            self.program,
            source_dir=str(reports_dir),
            verbose=True,
        )
        self.assertTrue(reports_dir.is_dir())


if __name__ == "__main__":
    unittest.main()
