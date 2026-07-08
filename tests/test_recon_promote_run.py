#!/usr/bin/env python3
"""Tests for agents.recon.promote_run."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import agents.recon.bus as bus
import agents.recon.promote_run as M


def args(run_root: Path, **overrides):
    defaults = {
        "program": "demo",
        "run_root": str(run_root),
        "shared_base": None,
        "no_index": True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class PromoteRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original_shared = bus.SHARED_BASE
        bus.SHARED_BASE = Path(self.tmp.name) / "Shared" / "web_bounty"
        self.run_root = Path(self.tmp.name) / "run"
        self.run_root.mkdir()

    def tearDown(self):
        bus.SHARED_BASE = self.original_shared

    def aggregate(self, *parts: str) -> Path:
        return bus.SHARED_BASE / "demo" / "web" / "recon" / "aggregated" / Path(*parts)

    def write(self, relative: str, lines: list[str]) -> Path:
        path = self.run_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        return path

    def test_promotes_normalized_and_parsed_known_outputs(self):
        self.write("normalized/urls.txt", ["https://example.com/a", "https://example.com/a"])
        self.write("normalized/alive.txt", ["https://example.com/live"])
        self.write("normalized/params_raw.txt", ["https://example.com/search?q=1"])
        self.write("normalized/jsfiles.txt", ["https://example.com/app.js"])
        self.write("normalized/hosts.txt", ["app.example.com"])
        self.write("parsed/dirs.txt", ["/admin"])

        result = M.promote_run(args(self.run_root))

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/live", "https://example.com/a"],
        )
        self.assertEqual(
            self.aggregate("alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/live"],
        )
        self.assertEqual(
            self.aggregate("params_raw.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/search?q=1"],
        )
        self.assertEqual(
            self.aggregate("jsfiles.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/app.js"],
        )
        self.assertEqual(
            self.aggregate("wild.txt").read_text(encoding="utf-8").splitlines(),
            ["app.example.com"],
        )
        self.assertEqual(self.aggregate("dirs.txt").read_text(encoding="utf-8").splitlines(), ["/admin"])

    def test_promotes_manifest_declared_outputs_under_run_root(self):
        declared_url = self.write("custom/url-output.txt", ["https://example.com/from-manifest"])
        declared_js = self.write("custom/js_urls.txt", ["https://example.com/manifest.js"])
        outside = Path(self.tmp.name) / "outside_urls.txt"
        outside.write_text("https://example.com/outside\n", encoding="utf-8")
        (self.run_root / "manifest.json").write_text(
            json.dumps(
                {
                    "outputs": {
                        "urls": str(declared_url.relative_to(self.run_root)),
                        "js": str(declared_js),
                        "outside": str(outside),
                    }
                }
            ),
            encoding="utf-8",
        )

        result = M.promote_run(args(self.run_root))

        self.assertIn("url", result["discovered"])
        self.assertIn("js", result["discovered"])
        self.assertNotIn(str(outside), result["discovered"]["url"])
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/from-manifest"],
        )
        self.assertEqual(
            self.aggregate("jsfiles.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/manifest.js"],
        )

    def test_promotes_plain_params_file(self):
        self.write("normalized/params.txt", ["https://example.com/search?q=1"])

        result = M.promote_run(args(self.run_root))

        self.assertEqual(result["status"], "ok")
        self.assertIn("param", result["discovered"])
        self.assertEqual(
            self.aggregate("params_raw.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/search?q=1"],
        )

    def test_prefers_params_raw_over_derived_params_view(self):
        raw = self.write("normalized/params_raw.txt", ["https://example.com/raw?q=1"])
        view = self.write("normalized/params.txt", ["https://example.com/view?q=1"])

        result = M.promote_run(args(self.run_root))

        self.assertEqual(result["discovered"]["param"], [str(raw)])
        self.assertNotIn(str(view), result["discovered"]["param"])
        self.assertEqual(
            self.aggregate("params_raw.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/raw?q=1"],
        )
        self.assertNotIn(
            "https://example.com/view?q=1",
            self.aggregate("params_raw.txt").read_text(encoding="utf-8").splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
