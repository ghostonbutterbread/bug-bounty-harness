"""Focused tests for the bounty artifact map helper."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.artifacts.map import map_path, normalize_entry, upsert_entry


class BountyArtifactMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_package_and_module_import_paths_share_public_functions(self) -> None:
        new_module = importlib.import_module("agents.artifacts.map")
        package_module = importlib.import_module("agents.artifacts")

        self.assertIs(package_module.map_path, new_module.map_path)

    def test_web_map_path_uses_shared_artifacts_directory(self) -> None:
        path = map_path(self.tmp / "Shared", "demo", "web", "screenshots")

        self.assertEqual(
            path,
            self.tmp / "Shared" / "web_bounty" / "demo" / "web" / "recon" / "artifacts" / "screenshots-map.json",
        )

    def test_upsert_replaces_existing_entry_by_artifact_id(self) -> None:
        shared = self.tmp / "Shared"
        path = map_path(shared, "demo", "web", "screenshots")
        first = normalize_entry(
            {"artifact_id": "admin-root", "stable_root": "/tmp/old"},
            "demo",
            "web",
            "screenshots",
        )
        second = normalize_entry(
            {"artifact_id": "admin-root", "stable_root": "/tmp/new"},
            "demo",
            "web",
            "screenshots",
        )

        upsert_entry(path, first)
        doc = upsert_entry(path, second)

        self.assertEqual(len(doc["entries"]), 1)
        self.assertEqual(doc["entries"][0]["stable_root"], "/tmp/new")
        saved = json.loads(path.read_text())
        self.assertEqual(saved["format"], "bounty-artifact-map-v1")

    def test_check_marks_missing_target_for_regeneration(self) -> None:
        path = map_path(self.tmp / "Shared", "demo", "web", "javascript")
        entry = normalize_entry(
            {
                "artifact_id": "missing-js",
                "target_artifact": str(self.tmp / "missing.js"),
                "stable_root": str(self.tmp / "missing-root"),
            },
            "demo",
            "web",
            "javascript",
        )

        doc = upsert_entry(path, entry, check=True)

        saved = doc["entries"][0]
        self.assertEqual(saved["status"], "regenerate")
        self.assertEqual(saved["health"], "stale_pointer_missing_target")
        self.assertFalse(saved["observed_exists"])

    def test_new_and_legacy_cli_help_smoke(self) -> None:
        commands = [
            [sys.executable, "-m", "agents.artifacts.map", "--help"],
        ]

        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("RuntimeWarning", result.stderr)
                self.assertIn("Upsert/check Shared bounty artifact map entries.", result.stdout)


if __name__ == "__main__":
    unittest.main()
