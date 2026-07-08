#!/usr/bin/env python3
"""Tests for the standalone recon mirror command."""

from __future__ import annotations

import argparse
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.recon import bus
from agents.recon import mirror as M


class ReconMirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original_shared = bus.SHARED_BASE
        self.shared_base = Path(self.tmp.name) / "Shared" / "web_bounty"
        bus.SHARED_BASE = self.shared_base

    def tearDown(self):
        bus.SHARED_BASE = self.original_shared

    def aggregate(self, *parts: str) -> Path:
        return bus.SHARED_BASE / "demo" / "web" / "recon" / "aggregated" / Path(*parts)

    def recon(self, *parts: str) -> Path:
        return bus.SHARED_BASE / "demo" / "web" / "recon" / Path(*parts)

    def write_aggregate(self, name: str, lines: list[str]) -> None:
        path = self.aggregate(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def test_existing_aggregates_copy_to_compatibility_mirrors(self):
        self.write_aggregate("urls.txt", ["https://example.com/a"])
        self.write_aggregate("alive.txt", ["https://example.com/alive"])
        self.write_aggregate("params.txt", ["https://example.com/search?q=1"])
        self.write_aggregate("params_raw.txt", ["https://example.com/search?q=raw"])
        self.write_aggregate("jsfiles.txt", ["https://example.com/app.js"])

        result = M.mirror_aggregates("demo")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            self.recon("urls", "urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/a"],
        )
        self.assertEqual(
            self.recon("urls", "alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/alive"],
        )
        self.assertEqual(
            self.recon("urls", "params.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/search?q=1"],
        )
        self.assertEqual(
            self.recon("params", "params.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/search?q=1"],
        )
        self.assertEqual(
            self.recon("params", "params_raw.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/search?q=raw"],
        )
        self.assertEqual(
            self.recon("js", "js_urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/app.js"],
        )
        self.assertEqual(
            self.recon("js", "jsfiles.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/app.js"],
        )

    def test_missing_aggregates_are_skipped_safely(self):
        self.write_aggregate("urls.txt", ["https://example.com/a"])

        result = M.mirror_aggregates("demo")

        self.assertIn("alive.txt", result["skipped"])
        self.assertIn("params.txt", result["skipped"])
        self.assertIn("params_raw.txt", result["skipped"])
        self.assertIn("jsfiles.txt", result["skipped"])
        self.assertTrue(self.recon("urls", "urls.txt").is_file())
        self.assertFalse(self.recon("urls", "alive.txt").exists())
        self.assertFalse(self.recon("params", "params.txt").exists())
        self.assertFalse(self.recon("js", "jsfiles.txt").exists())

    def test_cli_adapter_honors_shared_base_override(self):
        override = Path(self.tmp.name) / "override"
        source = override / "demo" / "web" / "recon" / "aggregated" / "urls.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("https://override.example/\n", encoding="utf-8")

        result = M.mirror(argparse.Namespace(program="demo", shared_base=str(override)))

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            (override / "demo" / "web" / "recon" / "urls" / "urls.txt")
            .read_text(encoding="utf-8")
            .splitlines(),
            ["https://override.example/"],
        )
        self.assertEqual(bus.SHARED_BASE, self.shared_base)


if __name__ == "__main__":
    unittest.main()
