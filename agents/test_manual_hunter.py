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
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.manual_hunter import ManualHunter, _build_hunt_context, main
from agents.shared_brain import build_index, save_index


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
        save_index(index, self.program)

    def _ledger_path(self) -> Path:
        return (
            self.home
            / "Shared"
            / "bounty_recon"
            / self.program
            / "ghost"
            / "ledger"
            / "findings_ledger.json"
        )

    def _coverage_path(self) -> Path:
        return self.target_root.parent / "ghost" / "coverage.json"

    def _reports_dir(self) -> Path:
        date_folder = self.home / "Shared" / "bounty_recon" / self.program / "ghost" / "reports_source"
        children = [path for path in date_folder.iterdir() if path.is_dir()]
        self.assertTrue(children)
        return children[0]

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
        self.assertEqual(ledger_payload["findings"][0]["vuln_class"], "native-module-abuse")

        reports_dir = self._reports_dir()
        dormant_report = reports_dir / "dormant.md"
        self.assertTrue(dormant_report.exists())
        dormant_text = dormant_report.read_text(encoding="utf-8")
        self.assertIn("SQLite injection via exposed IPC port", dormant_text)
        self.assertIn("execSqliteStatement()", dormant_text)

        coverage_payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        snapshots = coverage_payload["snapshots"]
        self.assertEqual(len(snapshots), 1)
        snapshot = next(iter(snapshots.values()))
        coverage_entry = snapshot["classes"]["native-module-abuse"]["files"][".webpack/renderer/preload.js"]
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
        save_index(build_index(self.target_root, self.program), self.program)

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
        self.assertIn(f"Output: {self.target_root / 'reports'}", context)
        self.assertIn("D01: SQLite injection via exposed IPC port", context)
        self.assertIn(".webpack/renderer/preload.js (native-module-abuse) ✅", context)
        self.assertIn("renderer/view.js (dom-xss)", context)
        self.assertIn("updater.ts (exec-sink-reachability)", context)

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
        mock_sync_reports_main.assert_called_once_with(
            self.program,
            source_dir=str(self.target_root / "reports"),
            verbose=True,
        )
        self.assertTrue((self.target_root / "reports").is_dir())


if __name__ == "__main__":
    unittest.main()
