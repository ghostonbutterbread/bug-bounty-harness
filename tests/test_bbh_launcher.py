#!/usr/bin/env python3
"""End-to-end regression tests for the lane-safe BBH dispatcher."""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
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

    def test_symlinked_launcher_resolves_its_source_checkout(self) -> None:
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

    def test_any_repository_relative_python_path_resolves_from_this_checkout(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--print-command", "agents/manual_hunter.py"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT / "agents" / "manual_hunter.py")

    def test_foreign_harness_root_does_not_change_dispatcher_selection(self) -> None:
        env = {**os.environ, "HARNESS_ROOT": "/definitely/not/the-selected-checkout"}
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--print-command", "scripts/recon_bus.py"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(Path(completed.stdout.strip()), ROOT / "scripts" / "recon_bus.py")

    def test_e2e_beta_and_stable_links_execute_their_own_lane_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            env = {**os.environ, "HARNESS_ROOT": "/definitely/not/the-selected-checkout"}
            for lane in ("beta", "stable"):
                checkout = temp / lane
                (checkout / "scripts").mkdir(parents=True)
                (checkout / "agents").mkdir()
                for source in ("bbh", "bbh.py"):
                    shutil.copy2(ROOT / "scripts" / source, checkout / "scripts" / source)
                (checkout / "agents" / "lane_probe.py").write_text(
                    f"print({lane!r})\n", encoding="utf-8"
                )
                venv_python = checkout / ".venv" / "bin" / "python"
                venv_python.parent.mkdir(parents=True)
                venv_python.symlink_to(sys.executable)
                link = temp / f"{lane}-bbh"
                link.symlink_to(checkout / "scripts" / "bbh")
                completed = subprocess.run(
                    [str(link), "agents/lane_probe.py"],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), lane)

    def test_setup_defaults_to_full_initialization(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; load_config(){ :; }; init(){ printf full-init; }; main',
                "--",
                str(ROOT / "setup.sh"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "full-init")

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
            for name, path in (("tool-run", "scripts/tool_run.py"), ("recon-bus", "scripts/recon_bus.py")):
                content = (bin_dir / name).read_text(encoding="utf-8")
                self.assertIn(str(ROOT / "scripts" / "bbh"), content)
                self.assertIn(path, content)
                self.assertNotIn("HARNESS_ROOT", content)

    def test_setup_refuses_to_replace_a_launcher_from_another_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            foreign = Path(tmp) / "stable" / "scripts" / "bbh"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            foreign.chmod(0o755)
            (bin_dir / "bbh").symlink_to(foreign)
            env = {**os.environ, "LOCAL_BIN_DIR": str(bin_dir)}
            completed = subprocess.run(
                ["bash", "-c", 'source "$1"; load_config; install_bbh', "--", str(ROOT / "setup.sh")],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to replace", completed.stderr)
            self.assertEqual((bin_dir / "bbh").resolve(), foreign.resolve())

    def test_absolute_or_escaping_paths_fail_closed(self) -> None:
        for value in ("/tmp/tool.py", "../outside.py"):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = M.main([value])
            self.assertEqual(status, 2)
            self.assertIn("bbh:", stderr.getvalue())

    def test_dispatch_replaces_process_with_the_relative_tool(self) -> None:
        venv_python = ROOT / ".venv" / "bin" / "python"
        with patch.object(M, "runtime_python", return_value=venv_python), patch.object(M.os, "execvpe") as execute:
            with self.assertRaises(AssertionError):
                M.main(["agents/url_ingest.py", "next", "demo"])
        execute.assert_called_once_with(
            str(venv_python),
            [str(venv_python), str(ROOT / "agents" / "url_ingest.py"), "next", "demo"],
            {
                **os.environ,
                "PYTHONPATH": str(ROOT),
            },
        )

    def test_missing_checkout_venv_fails_closed(self) -> None:
        with patch.object(M, "REPO_ROOT", Path(tempfile.mkdtemp())):
            with self.assertRaisesRegex(RuntimeError, "--install-python-deps"):
                M.command_for(Path("tool.py"), [])

    def _drift_warning_checkout(self, manifest_newer: bool) -> Path:
        root = Path(tempfile.mkdtemp())
        venv_lib = root / ".venv" / "lib" / "python3.11" / "site-packages"
        venv_lib.mkdir(parents=True)
        venv_python = root / ".venv" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.write_text("#!/bin/sh\necho '{\"ok\": true}'\nexit 7\n")
        venv_python.chmod(0o755)
        (root / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts" / "bbh.py", root / "scripts" / "bbh.py")
        (root / "tools").mkdir()
        (root / "tools" / "dummy.py").write_text("# dummy dispatched tool\n")
        old = venv_lib.stat().st_mtime - 3600
        new = venv_lib.stat().st_mtime + 3600
        manifest = root / "requirements.txt"
        manifest.write_text("bounty-core @ git+https://example.invalid/bounty-core\n")
        os.utime(manifest, (new, new) if manifest_newer else (old, old))
        return root

    def _dispatch_dummy(self, root: Path, extra_env: dict[str, str] | None = None):
        return subprocess.run(
            [sys.executable, str(root / "scripts" / "bbh.py"), "tools/dummy.py"],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, **(extra_env or {})},
        )

    def test_stale_venv_warns_on_stderr_and_preserves_stdout_and_exit(self) -> None:
        completed = self._dispatch_dummy(self._drift_warning_checkout(manifest_newer=True))
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stdout, '{"ok": true}\n')
        self.assertIn("requirements.txt is newer", completed.stderr)
        self.assertIn("BBH_SKIP_DEP_CHECK=1", completed.stderr)

    def test_fresh_venv_stays_silent(self) -> None:
        completed = self._dispatch_dummy(self._drift_warning_checkout(manifest_newer=False))
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stdout, '{"ok": true}\n')
        self.assertEqual(completed.stderr, "")

    def test_dep_check_suppression_silences_the_warning(self) -> None:
        completed = self._dispatch_dummy(
            self._drift_warning_checkout(manifest_newer=True), extra_env={"BBH_SKIP_DEP_CHECK": "1"}
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stderr, "")

    def test_missing_site_packages_does_not_warn(self) -> None:
        root = self._drift_warning_checkout(manifest_newer=True)
        shutil.rmtree(root / ".venv" / "lib" / "python3.11" / "site-packages")
        completed = self._dispatch_dummy(root)
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
