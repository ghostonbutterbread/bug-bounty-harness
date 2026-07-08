#!/usr/bin/env python3
"""Tests for agents.recon.watch_runs."""

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
import agents.recon.watch_runs as M


def args(root: Path, **overrides):
    defaults = {
        "program": "demo",
        "root": str(root),
        "shared_base": None,
        "dry_run": False,
        "no_index": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ReconWatchRunsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "recon"

    def write_manifest(self, relative: str, payload: dict) -> Path:
        path = self.root / relative / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def read_manifest(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_promotes_completed_manifest_and_preserves_existing_fields(self):
        manifest = self.write_manifest("tool/run-1", {"status": "done", "run_id": "run-1", "tool": "katana"})
        calls = []

        def fake_promote(**kwargs):
            calls.append(kwargs)
            return {
                "status": "ok",
                "counts": {"urls": {"read": 3, "new": 2}},
                "paths_touched": ["/tmp/urls.txt", "/tmp/alive.txt"],
            }

        result = M.watch_runs(
            args(self.root, shared_base=str(Path(self.tmp.name) / "Shared"), no_index=True),
            promote_func=fake_promote,
        )

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["promotable"], 1)
        self.assertEqual(result["promoted"], 1)
        self.assertEqual(calls[0]["program"], "demo")
        self.assertEqual(calls[0]["run_root"], manifest.parent)
        self.assertEqual(calls[0]["shared_base"], Path(self.tmp.name) / "Shared")
        self.assertTrue(calls[0]["no_index"])
        updated = self.read_manifest(manifest)
        self.assertEqual(updated["run_id"], "run-1")
        self.assertEqual(updated["tool"], "katana")
        self.assertTrue(updated["promoted"])
        self.assertRegex(updated["promoted_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(updated["promoted_counts"], {"urls": {"read": 3, "new": 2}})
        self.assertEqual(updated["promoted_paths_touched"], ["/tmp/alive.txt", "/tmp/urls.txt"])

    def test_skips_non_done_already_promoted_and_recon_bus_manifests(self):
        pending = self.write_manifest("tool/pending", {"status": "running"})
        promoted = self.write_manifest("tool/promoted", {"status": "ok", "promoted": True})
        bus_manifest = self.write_manifest("aggregated/runs/recon-bus-run", {"status": "success"})
        calls = []

        result = M.watch_runs(args(self.root), promote_func=lambda **kwargs: calls.append(kwargs) or {})

        self.assertEqual(result["scanned"], 3)
        self.assertEqual(result["promotable"], 0)
        self.assertEqual(result["promoted"], 0)
        self.assertEqual(calls, [])
        self.assertNotIn("promoted_at", self.read_manifest(pending))
        self.assertNotIn("promoted_at", self.read_manifest(promoted))
        self.assertNotIn("promoted_at", self.read_manifest(bus_manifest))

    def test_dry_run_lists_promotable_without_calling_or_writing(self):
        manifest = self.write_manifest("tool/run-1", {"status": "completed"})

        result = M.watch_runs(
            args(self.root, dry_run=True),
            promote_func=lambda **_kwargs: self.fail("promote should not run during dry-run"),
        )

        self.assertEqual(result["promotable"], 1)
        self.assertEqual(result["promoted"], 0)
        self.assertEqual(result["skipped"][0]["reason"], "dry-run")
        self.assertNotIn("promoted", self.read_manifest(manifest))

    def test_promotion_failure_leaves_manifest_unmarked(self):
        manifest = self.write_manifest("tool/run-1", {"status": "success"})

        def fail_promote(**_kwargs):
            raise RuntimeError("promotion exploded")

        result = M.watch_runs(args(self.root), promote_func=fail_promote)

        self.assertEqual(result["promotable"], 1)
        self.assertEqual(result["promoted"], 0)
        self.assertEqual(result["failed"][0]["error"], "promotion exploded")
        self.assertNotIn("promoted", self.read_manifest(manifest))

    def test_default_promoter_calls_real_promote_run_module(self):
        manifest = self.write_manifest("tool/run-1", {"status": "ok"})
        normalized = manifest.parent / "normalized"
        normalized.mkdir()
        (normalized / "urls.txt").write_text("https://example.com/a\n", encoding="utf-8")
        shared_base = Path(self.tmp.name) / "Shared" / "web_bounty"

        result = M.watch_runs(args(self.root, shared_base=str(shared_base), no_index=True))

        self.assertEqual(result["promoted"], 1)
        updated = self.read_manifest(manifest)
        self.assertTrue(updated["promoted"])
        self.assertIn("url", updated["promoted_counts"])
        self.assertTrue(updated["promoted_paths_touched"])
        aggregate = shared_base / "demo" / "web" / "recon" / "aggregated" / "urls.txt"
        self.assertEqual(aggregate.read_text(encoding="utf-8").splitlines(), ["https://example.com/a"])

    def test_invalid_manifest_is_skipped(self):
        path = self.root / "tool" / "bad" / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[1, 2, 3]\n", encoding="utf-8")

        result = M.watch_runs(args(self.root), promote_func=lambda **_kwargs: {})

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["promotable"], 0)
        self.assertIn("invalid-manifest", result["skipped"][0]["reason"])

    def test_cli_wires_watch_runs_subcommand(self):
        parser = bus.build_parser()
        parsed = parser.parse_args(["watch-runs", "demo", "--root", str(self.root), "--dry-run", "--no-index"])

        self.assertEqual(parsed.program, "demo")
        self.assertEqual(parsed.root, str(self.root))
        self.assertTrue(parsed.dry_run)
        self.assertTrue(parsed.no_index)
        self.assertIs(parsed.func, M.watch_runs)


if __name__ == "__main__":
    unittest.main()
