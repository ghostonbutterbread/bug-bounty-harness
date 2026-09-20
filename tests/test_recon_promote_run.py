#!/usr/bin/env python3
"""Tests for agents.recon.promote_run."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        "probe_urls": False,
        "httpx_bin": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class PromoteRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original_shared = bus.SHARED_BASE
        bus.SHARED_BASE = Path(self.tmp.name) / "Shared" / "web_bounty"
        scope = bus.SHARED_BASE.parent / "scopes" / "demo" / "in-scope.txt"
        scope.parent.mkdir(parents=True, exist_ok=True)
        scope.write_text("example.com\n*.example.com\n", encoding="utf-8")
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

    def test_discovery_requires_supported_filenames_not_substrings(self):
        excluded = (
            "wild.txt", "hosts.jsonl", "httpx.jsonl", "httpx_ip_raw.txt",
            "waf_hosts.txt", "unprotected_hosts.txt", "old_urls.txt",
            "urls.txt.bak", "hosts.csv", "transport.log", "report.json",
            "params_notes.txt", "javascript_notes.txt", "directories.json",
        )
        for directory in ("", "normalized", "parsed", "raw", "custom"):
            for name in excluded:
                self.write(f"{directory}/{name}".lstrip("/"), ["app.example.com"])
        (self.run_root / "manifest.json").write_text(
            json.dumps({"outputs": [f"custom/{name}" for name in excluded]}),
            encoding="utf-8",
        )
        self.assertEqual(M.discover_candidate_files(self.run_root), {})

    def test_supported_filename_aliases_remain_classifiable(self):
        supported = {
            "param": ("params_raw.txt", "params.txt"),
            "js": ("jsfiles.txt", "js_urls.txt", "javascript.txt"),
            "alive": ("alive.txt", "httpx.txt", "live.txt"),
            "host": ("hosts.txt", "host.txt", "subdomains.txt", "subdomain.txt"),
            "dir": ("dirs.txt", "directories.txt", "paths.txt"),
            "url": ("urls.txt", "url.txt", "url-output.txt"),
            "port": ("ports.txt", "port.txt", "naabu.txt", "ports.jsonl", "naabu.jsonl"),
        }
        for kind, names in supported.items():
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(M.classify_path(Path(name)), kind)
                    self.assertEqual(M.classify_path(Path(name.upper())), kind)
                    self.assertIsNone(M.classify_path(Path(f"old_{name}")))
                    self.assertIsNone(M.classify_path(Path(f"{name}.bak")))

    def test_existing_ingest_aliases_keep_their_promotion_kinds(self):
        for name, kind in {
            "live-hosts.txt": "alive",
            "url_seed.txt": "url",
            "javascript_urls.txt": "js",
            "all_urls.txt": "url",
        }.items():
            with self.subTest(name=name):
                self.assertEqual(M.classify_path(Path(name)), kind)

    def test_promotion_preserves_scope_store_and_ignores_metadata(self):
        scope_store = self.aggregate("wild.txt")
        scope_store.parent.mkdir(parents=True, exist_ok=True)
        scope_store.write_text("*.example.com\n", encoding="utf-8")
        self.write("wild.txt", ["*.app.example.com"])
        self.write("hosts.txt", ["no-http.example.com"])
        self.write("hosts.jsonl", ['{"host":"metadata.example.com"}'])
        self.write("httpx.jsonl", ['{"url":"https://example.com/metadata"}'])
        for name in ("httpx_ip_raw.txt", "waf_hosts.txt", "unprotected_hosts.txt"):
            self.write(name, ["https://example.com/diagnostic"])
        with patch.object(bus, "run_httpx", side_effect=AssertionError("offline test")):
            result = M.promote_run(args(self.run_root))
        self.assertEqual(set(result["discovered"]), {"host"})
        self.assertEqual(scope_store.read_text(encoding="utf-8"), "*.example.com\n")
        self.assertEqual(self.aggregate("hosts.txt").read_text(encoding="utf-8"), "no-http.example.com\n")
        self.assertFalse(self.aggregate("alive.txt").exists())
        self.assertFalse(self.aggregate("urls.txt").exists())

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
            [
                "https://example.com/live",
                "https://example.com/a",
                "https://example.com/search?q=1",
                "https://example.com/app.js",
            ],
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
            self.aggregate("hosts.txt").read_text(encoding="utf-8").splitlines(),
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
            ["https://example.com/from-manifest", "https://example.com/manifest.js"],
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
    def test_promotes_url_candidates_from_url_param_and_js_with_delta_probe(self):
        self.write("normalized/urls.txt", ["https://example.com/root"])
        self.write("normalized/params_raw.txt", ["https://example.com/search?q=1"])
        self.write("normalized/jsfiles.txt", ["https://example.com/app.js"])
        def fake_httpx(input_path: Path, output_path: Path, *, httpx_bin: str | None = None) -> dict[str, object]:
            lines = M.bus.read_file_lines(input_path)
            M.bus.write_lines(output_path, lines)
            return {"ran": True, "output": str(output_path), "count": len(lines)}

        with patch.object(M.bus, "run_httpx", side_effect=fake_httpx):
            result = M.promote_run(args(self.run_root, probe_urls=True))

        self.assertEqual(result["appends"]["url"]["primary"]["new"], 3)
        self.assertEqual(result["appends"]["url"]["httpx"]["count"], 3)
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/root", "https://example.com/search?q=1", "https://example.com/app.js"],
        )
        self.assertEqual(
            self.aggregate("alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/root", "https://example.com/search?q=1", "https://example.com/app.js"],
        )

    def test_partial_probe_failure_keeps_promotion_retryable(self):
        self.write("normalized/urls.txt", ["https://example.com/retry"])

        with patch.object(
            M.bus,
            "run_httpx",
            return_value={"ran": True, "success": False, "error": "temporary failure", "count": 0},
        ):
            result = M.promote_run(args(self.run_root, probe_urls=True))

        self.assertEqual(result["status"], "partial_promotion_failed")
        self.assertEqual(result["failed_appends"], {"url": "partial_probe_failed"})
        self.assertTrue(self.aggregate("pending_probe.txt").is_file())

    def test_dirs_status_does_not_bypass_non_queue_artifact_exclusions(self):
        status_file = self.write("raw/dirs_status/200.txt", ["https://example.com/admin"])
        for name in (
            "wild.txt", "hosts.jsonl", "httpx.jsonl", "httpx_ip_raw.txt",
            "waf_hosts.txt", "unprotected_hosts.txt",
        ):
            self.write(f"raw/dirs_status/{name}", ["https://example.com/not-a-dir-result"])
        self.assertEqual(M.discover_candidate_files(self.run_root), {"dir": [status_file]})

    def test_promotes_recon_ry_dirs_status_files_as_flat_dir_inventory(self):
        self.write("dirs_status/200.txt", ["https://example.com/admin"])
        self.write("dirs_status/403.txt", ["https://example.com/internal"])

        result = M.promote_run(args(self.run_root))

        self.assertIn("dir", result["discovered"])
        self.assertEqual(
            self.aggregate("dirs.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/admin", "https://example.com/internal"],
        )


if __name__ == "__main__":
    unittest.main()
