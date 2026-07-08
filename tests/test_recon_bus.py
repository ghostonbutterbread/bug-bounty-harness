#!/usr/bin/env python3
"""Tests for agents.recon.bus."""

from __future__ import annotations

import argparse
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import agents.recon.bus as M


def args(**overrides):
    defaults = {
        "program": "demo",
        "kind": "url",
        "value": [],
        "input": [],
        "stdin": False,
        "run_id": "test-run",
        "liveness": "unknown",
        "httpx_bin": None,
        "uro_bin": None,
        "shared_base": None,
        "no_index": True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ReconBusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original_shared = M.SHARED_BASE
        M.SHARED_BASE = Path(self.tmp.name) / "Shared" / "web_bounty"

    def tearDown(self):
        M.SHARED_BASE = self.original_shared

    def aggregate(self, *parts: str) -> Path:
        return M.SHARED_BASE / "demo" / "web" / "recon" / "aggregated" / Path(*parts)

    def recon(self, *parts: str) -> Path:
        return M.SHARED_BASE / "demo" / "web" / "recon" / Path(*parts)

    def test_append_url_records_only_urls_by_default(self):
        result = M.append(
            args(
                value=[
                    "https://example.com/a",
                    "https://example.com/a",
                    "https://example.com/b",
                ]
            )
        )

        self.assertEqual(result["primary"]["new"], 2)
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/a", "https://example.com/b"],
        )
        self.assertFalse(self.aggregate("alive.txt").exists())
        self.assertEqual(
            self.recon("urls", "urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/a", "https://example.com/b"],
        )

    def test_append_known_alive_updates_alive_and_urls(self):
        result = M.append(
            args(
                kind="url",
                liveness="known",
                value=["https://example.com/alive"],
            )
        )

        self.assertEqual(result["primary"]["new"], 1)
        self.assertEqual(result["alive"]["new"], 1)
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/alive"],
        )
        self.assertEqual(
            self.aggregate("alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/alive"],
        )

    def test_kind_alive_updates_alive_and_urls(self):
        result = M.append(args(kind="alive", value=["https://example.com/live"]))

        self.assertEqual(result["primary"]["new"], 1)
        self.assertEqual(result["urls"]["new"], 1)
        self.assertEqual(
            self.aggregate("alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/live"],
        )
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/live"],
        )

    def test_probe_runs_httpx_only_on_new_delta(self):
        M.append(args(value=["https://example.com/already"]))
        fake_httpx = self.make_fake_httpx()

        result = M.append(
            args(
                run_id="probe-run",
                liveness="probe",
                httpx_bin=str(fake_httpx),
                value=[
                    "https://example.com/already",
                    "https://example.com/new",
                ],
            )
        )

        self.assertEqual(result["primary"]["new"], 1)
        self.assertEqual(result["httpx"]["count"], 1)
        self.assertEqual(
            self.aggregate("alive.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/new"],
        )
        delta = self.aggregate("runs", "probe-run", "delta", "urls.txt")
        self.assertEqual(delta.read_text(encoding="utf-8").splitlines(), ["https://example.com/new"])

    def test_param_append_updates_raw_and_regenerates_params(self):
        result = M.append(
            args(
                kind="param",
                value=[
                    "https://example.com/search?b=2&a=1",
                    "https://example.com/search?a=1&b=2",
                ],
            )
        )

        self.assertEqual(result["primary"]["new"], 2)
        self.assertTrue(self.aggregate("params_raw.txt").exists())
        self.assertTrue(self.aggregate("params.txt").exists())
        self.assertEqual(
            self.recon("params", "params_raw.txt").read_text(encoding="utf-8").splitlines(),
            [
                "https://example.com/search?b=2&a=1",
                "https://example.com/search?a=1&b=2",
            ],
        )

    def test_param_regeneration_replaces_existing_params_view(self):
        fake_uro = self.make_fake_uro_appender()
        self.aggregate("params.txt").parent.mkdir(parents=True, exist_ok=True)
        self.aggregate("params.txt").write_text("https://example.com/stale?old=1\n", encoding="utf-8")

        M.append(
            args(
                kind="param",
                uro_bin=str(fake_uro),
                value=["https://example.com/fresh?x=1"],
            )
        )

        self.assertEqual(
            self.aggregate("params.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/fresh?x=1"],
        )

    def test_host_alias_updates_wild_store(self):
        result = M.append(args(kind="host", value=["app.example.com"]))

        self.assertEqual(result["primary"]["new"], 1)
        self.assertEqual(
            self.aggregate("wild.txt").read_text(encoding="utf-8").splitlines(),
            ["app.example.com"],
        )

    def test_non_url_inventory_does_not_update_url_index(self):
        result = M.append(args(kind="dir", value=["/admin"], no_index=False))
        host_result = M.append(args(kind="host", run_id="host-run", value=["app.example.com"], no_index=False))

        self.assertEqual(result["indexed"], [])
        self.assertEqual(host_result["indexed"], [])
        self.assertFalse(self.recon("url_index", "url_index.sqlite").exists())

    def test_url_inventory_updates_url_index(self):
        result = M.append(args(value=["https://example.com/indexed"], no_index=False))

        self.assertEqual(len(result["indexed"]), 1)
        self.assertTrue(self.recon("url_index", "url_index.sqlite").exists())

    def test_stdin_input_appends_values(self):
        with patch.object(sys, "stdin", io.StringIO("https://example.com/stdin\n")):
            result = M.append(args(stdin=True))

        self.assertEqual(result["primary"]["new"], 1)
        self.assertEqual(
            self.aggregate("urls.txt").read_text(encoding="utf-8").splitlines(),
            ["https://example.com/stdin"],
        )

    def test_index_failure_leaves_partial_manifest(self):
        with patch.object(M, "index_delta", side_effect=RuntimeError("sqlite locked")):
            result = M.append(args(run_id="index-failure-run", value=["https://example.com/a"]))

        self.assertEqual(result["status"], "partial_index_failed")
        manifest = self.aggregate("runs", "index-failure-run", "manifest.json")
        self.assertIn('"status": "partial_index_failed"', manifest.read_text(encoding="utf-8"))

    def test_generated_run_ids_are_not_second_granular(self):
        first = M.utc_stamp()
        second = M.utc_stamp()

        self.assertNotEqual(first, second)
        self.assertRegex(first, r"^\d{8}T\d{12}Z$")

    def make_fake_httpx(self) -> Path:
        path = Path(self.tmp.name) / "httpx"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "from pathlib import Path\n"
            "args = sys.argv\n"
            "source = Path(args[args.index('-l') + 1])\n"
            "for line in source.read_text().splitlines():\n"
            "    if line.strip():\n"
            "        print(line.strip())\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | 0o111)
        return path

    def make_fake_uro_appender(self) -> Path:
        path = Path(self.tmp.name) / "uro"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "from pathlib import Path\n"
            "output = Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "with output.open('a', encoding='utf-8') as handle:\n"
            "    for line in sys.stdin:\n"
            "        if line.strip():\n"
            "            handle.write(line.strip() + '\\n')\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | 0o111)
        return path


if __name__ == "__main__":
    unittest.main()
