"""Offline CLI regressions for report source selection."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bounty_core.reports import CATEGORY_STUB_GENERATED_MARKER
from bounty_core.storage import resolve_storage

REPO = Path(__file__).resolve().parent.parent
PROGRAM = "synthetic_program"


class ReportSourceCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.root = self.base / "storage"
        self.source = self.base / "source"
        self.source.mkdir()
        self.home_reports = self.home / "source" / PROGRAM / "reports"
        self.home_reports.mkdir(parents=True)
        self.layout = resolve_storage(PROGRAM, family="binaries", lane="apk", root_override=self.root, create=False)
        self.env = dict(os.environ, HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / "config"),
                        XDG_CACHE_HOME=str(self.home / "cache"), XDG_DATA_HOME=str(self.home / "data"))

    def report(self, path, name):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Title: {name} finding\nType: IDOR\nClass: idor\nSeverity: HIGH\n"
                        f"File: src/{name}.py:1\nDescription: Synthetic {name} finding.\n")

    def run_cli(self, *args):
        result = subprocess.run([sys.executable, str(REPO / "scripts/bbh"), "agents/sync_reports.py", PROGRAM,
                                 "--lane", "apk", "--root", str(self.root),
                                 "--source-root", str(self.source), "-v", *map(str, args)],
                                cwd=REPO, env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def rows(self):
        path = self.layout.ledgers_root / "ledger.json"
        return json.loads(path.read_text())["findings"] if path.exists() else []

    def test_category_link_does_not_shadow_home_source_or_import_evidence(self):
        original = self.home_reports / "original.md"
        self.report(original, "original")
        self.assertIn("Imported: 1 new findings", self.run_cli())
        evidence = Path(self.rows()[0]["evidence_path"])
        links = [p for p in (self.layout.reports_root / "categories").rglob("*.md") if p.is_symlink()]
        self.assertTrue(links)
        self.assertEqual(links[0].resolve(), evidence)
        with evidence.open("a") as stream:
            stream.write("\nFile: src/false_positive.py:7\n")
        original.unlink()
        self.report(self.home_reports / "second.md", "second")
        output = self.run_cli()
        self.assertIn("mode=source_reports", output)
        self.assertIn("Imported: 1 new findings", output)
        self.assertEqual({row["file"] for row in self.rows()}, {"src/original.py", "src/second.py"})

    def test_raw_real_report_has_precedence(self):
        self.report(self.home_reports / "home.md", "home")
        self.report(self.layout.reports_root / "raw" / "raw.md", "raw")
        self.assertIn("mode=canonical_raw", self.run_cli())
        self.assertEqual([row["file"] for row in self.rows()], ["src/raw.py"])

    def test_raw_report_symlink_remains_importable(self):
        target = self.base / "ordinary.md"
        self.report(target, "linked")
        raw = self.layout.reports_root / "raw"
        raw.mkdir(parents=True)
        (raw / "linked.md").symlink_to(target)
        self.assertIn("mode=canonical_raw", self.run_cli())
        self.assertEqual([row["file"] for row in self.rows()], ["src/linked.py"])

    def test_canonical_scan_keeps_real_source_while_skipping_category_link(self):
        target = self.layout.reports_root / "D99" / "EVIDENCE.md"
        self.report(target, "false")
        link = self.layout.reports_root / "categories" / "idor" / "D01.md"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        self.report(self.layout.reports_root / "working.md", "real")
        self.assertIn("mode=canonical_reports files=1", self.run_cli())
        self.assertEqual([row["file"] for row in self.rows()], ["src/real.py"])

    def test_generated_category_stub_does_not_shadow_home(self):
        stub = self.layout.reports_root / "categories" / "idor" / "D01.md"
        stub.parent.mkdir(parents=True)
        stub.write_text(CATEGORY_STUB_GENERATED_MARKER + "\nFile: src/false.py:1\n")
        self.report(self.home_reports / "home.md", "home")
        self.assertIn("mode=source_reports", self.run_cli())
        self.assertEqual([row["file"] for row in self.rows()], ["src/home.py"])

    def test_explicit_external_symlink_remains_importable(self):
        target = self.base / "outside" / "reports" / "D01" / "ordinary.md"
        self.report(target, "external")
        explicit = self.base / "explicit"
        explicit.mkdir()
        (explicit / "link.md").symlink_to(target)
        self.assertIn("mode=override", self.run_cli("--source-dir", explicit))
        self.assertEqual([row["file"] for row in self.rows()], ["src/external.py"])
