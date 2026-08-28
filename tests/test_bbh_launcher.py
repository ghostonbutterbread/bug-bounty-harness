#!/usr/bin/env python3
"""Regression tests for the lane-safe BBH dispatcher."""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bbh.py"
SPEC = importlib.util.spec_from_file_location("bbh_launcher", SCRIPT)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class BbhLauncherTests(unittest.TestCase):
    def test_root_is_the_physical_launcher_checkout(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--root"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT.resolve())

    def test_symlinked_shell_launcher_resolves_its_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            linked = Path(tmp) / "bbh"
            linked.symlink_to(ROOT / "scripts" / "bbh")
            completed = subprocess.run(
                [str(linked), "--root"],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT.resolve())

    def test_registry_paths_are_relative_to_this_checkout(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--print-command", "manual-hunter"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT / "agents" / "manual_hunter.py")

    def test_foreign_harness_root_does_not_change_dispatcher_selection(self) -> None:
        env = {**os.environ, "HARNESS_ROOT": "/definitely/not/the-selected-checkout"}
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--print-command", "recon-bus"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT / "scripts" / "recon_bus.py")

    def test_setup_installs_lane_safe_dispatchers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            env = {
                **os.environ,
                "LOCAL_BIN_DIR": str(bin_dir),
                "HARNESS_ROOT": "/definitely/not/the-selected-checkout",
            }
            completed = subprocess.run(
                ["bash", "-c", 'source "$1"; install_dispatchers', "--", str(ROOT / "setup.sh")],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((bin_dir / "bbh").is_symlink())
            self.assertEqual((bin_dir / "bbh").resolve(), ROOT / "scripts" / "bbh")
            root = subprocess.run(
                [str(bin_dir / "bbh"), "--root"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(root.returncode, 0, root.stderr)
            self.assertEqual(Path(root.stdout.strip()), ROOT.resolve())
            for name in ("tool-run", "recon-bus"):
                content = (bin_dir / name).read_text(encoding="utf-8")
                self.assertIn(str(ROOT / "scripts" / "bbh.py"), content)
                self.assertNotIn("HARNESS_ROOT", content)

    def test_dispatch_replaces_process_with_the_registered_tool(self) -> None:
        with patch.object(M.os, "execvpe") as execute:
            with self.assertRaises(AssertionError):
                M.main(["url-ingest", "next", "demo"])
        execute.assert_called_once_with(
            sys.executable,
            [sys.executable, str(ROOT / "agents" / "url_ingest.py"), "next", "demo"],
            os.environ.copy(),
        )

    def test_unknown_tool_fails_closed(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = M.main(["not-a-tool"])
        self.assertEqual(status, 2)
        self.assertIn("unknown BBH tool", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
