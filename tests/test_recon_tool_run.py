#!/usr/bin/env python3
"""Tests for agents.recon.tool_run."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import agents.recon.tool_run as M


class ReconToolRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.shared_base = Path(self.tmp.name) / "Shared" / "web_bounty"

    def test_infers_tool_and_captures_stdout_stderr(self):
        result = self.invoke(
            [
                "flourish",
                "--shared-base",
                str(self.shared_base),
                "--run-id",
                "stdout-run",
                "--no-promote",
                "--",
                sys.executable,
                "-c",
                "import sys; print('hello'); print('warn', file=sys.stderr)",
            ]
        )

        self.assertEqual(result, 0)
        run_dir = self.run_dir("flourish", Path(sys.executable).name, "stdout-run")
        self.assertEqual((run_dir / "stdout.txt").read_text(encoding="utf-8"), "hello\n")
        self.assertEqual((run_dir / "stderr.txt").read_text(encoding="utf-8"), "warn\n")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["tool"], Path(sys.executable).name)
        self.assertEqual(manifest["status"], "ok")
        self.assertEqual(manifest["promotion"]["status"], "disabled")

    def test_explicit_tool_override_and_command_generated_file(self):
        result = self.invoke(
            [
                "flourish",
                "--shared-base",
                str(self.shared_base),
                "--tool",
                "custom-tool",
                "--run-id",
                "file-run",
                "--no-promote",
                "--",
                sys.executable,
                "-c",
                "from pathlib import Path; Path('out.txt').write_text('owned file\\n')",
            ]
        )

        self.assertEqual(result, 0)
        run_dir = self.run_dir("flourish", "custom-tool", "file-run")
        self.assertEqual((run_dir / "out.txt").read_text(encoding="utf-8"), "owned file\n")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("out.txt", manifest["generated_files"])

    def test_failed_command_still_writes_manifest_and_outputs(self):
        result = self.invoke(
            [
                "flourish",
                "--shared-base",
                str(self.shared_base),
                "--tool",
                "failing",
                "--run-id",
                "fail-run",
                "--no-promote",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('bad\\n'); raise SystemExit(7)",
            ]
        )

        self.assertEqual(result, 7)
        run_dir = self.run_dir("flourish", "failing", "fail-run")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(manifest["exit_code"], 7)
        self.assertEqual((run_dir / "stderr.txt").read_text(encoding="utf-8"), "bad\n")

    def test_promotes_generated_normalized_outputs_by_default(self):
        result = self.invoke(
            [
                "flourish",
                "--shared-base",
                str(self.shared_base),
                "--tool",
                "producer",
                "--run-id",
                "promote-run",
                "--no-index",
                "--",
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "Path('normalized').mkdir(); "
                    "Path('normalized/urls.txt').write_text('https://example.com/from-tool\\n')"
                ),
            ]
        )

        self.assertEqual(result, 0)
        run_dir = self.run_dir("flourish", "producer", "promote-run")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["promotion"]["status"], "ok")
        self.assertEqual(manifest["promotion"]["mode"], "in-process")
        self.assertIs(manifest["promoted"], True)
        self.assertIn("url", manifest["promoted_counts"])
        self.assertTrue(manifest["promoted_paths_touched"])
        self.assertEqual(
            (
                self.shared_base
                / "flourish"
                / "web"
                / "recon"
                / "aggregated"
                / "urls.txt"
            ).read_text(encoding="utf-8").splitlines(),
            ["https://example.com/from-tool"],
        )

    def test_help_does_not_require_command_separator(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                M.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Run a recon tool", stdout.getvalue())

    def invoke(self, argv: list[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return M.main(argv)

    def run_dir(self, program: str, tool: str, run_id: str) -> Path:
        root = self.shared_base / program / "web" / "recon" / "tools" / tool / "runs"
        matches = list(root.glob(f"*/{run_id}"))
        self.assertEqual(len(matches), 1)
        return matches[0]


if __name__ == "__main__":
    unittest.main()
