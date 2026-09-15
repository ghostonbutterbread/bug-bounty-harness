#!/usr/bin/env python3
"""Tests for recon-ry --scope-file derivation from saved program scope."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
AGENT_DIR = PROJECT_ROOT / "agents"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from agents.scope_seed_files import recon_scope_file_lines


class ReconScopeFileLinesTests(unittest.TestCase):
    def test_hosts_wildcards_and_cidrs_pass_through(self):
        lines, deferred = recon_scope_file_lines(
            ["*.example.com", "api.example.net", "10.0.0.0/8", "192.0.2.1"]
        )
        self.assertEqual(lines, ["*.example.com", "api.example.net", "10.0.0.0/8", "192.0.2.1"])
        self.assertEqual(deferred, [])

    def test_root_url_is_reduced_to_its_host(self):
        lines, deferred = recon_scope_file_lines(
            ["https://portal.example.com", "http://legacy.example.com/"]
        )
        self.assertEqual(lines, ["portal.example.com", "legacy.example.com"])
        self.assertEqual(deferred, [])

    def test_path_scoped_url_is_deferred_not_widened_to_its_host(self):
        """A path-scoped asset must not silently authorize its whole host."""
        lines, deferred = recon_scope_file_lines(
            ["https://svc.example.net/api/magpie", "*.example.com"]
        )
        self.assertEqual(lines, ["*.example.com"])
        self.assertNotIn("svc.example.net", lines)
        self.assertEqual(deferred, ["https://svc.example.net/api/magpie"])

    def test_comments_blanks_and_duplicates_are_dropped(self):
        lines, _ = recon_scope_file_lines(
            ["# header", "", "  ", "example.com", "EXAMPLE.com", "example.com  # inline"]
        )
        self.assertEqual(lines, ["example.com"])

    def test_empty_scope_yields_no_lines(self):
        self.assertEqual(recon_scope_file_lines([]), ([], []))


class ReconScopeFileParserCompatibilityTests(unittest.TestCase):
    """The generated file must satisfy recon-ry's own offline scope parser."""

    SCOPE_FILTER = Path.home() / "tools" / "recon-ry-runtime-header" / "scripts" / "scope_filter.py"

    def test_generated_entries_are_accepted_by_recon_ry(self):
        if not self.SCOPE_FILTER.is_file():
            self.skipTest("recon-ry runtime checkout not present")
        import subprocess
        import tempfile

        lines, _ = recon_scope_file_lines(
            ["*.example.com", "api.example.net", "https://portal.example.com", "10.0.0.0/8"]
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("\n".join(lines) + "\n")
            scope_path = handle.name
        try:
            result = subprocess.run(
                [sys.executable, str(self.SCOPE_FILTER), "validate", "--scope-file", scope_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            Path(scope_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
