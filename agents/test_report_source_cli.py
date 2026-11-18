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

    def run_cli_result(self, *args):
        return subprocess.run([sys.executable, str(REPO / "scripts/bbh"), "agents/sync_reports.py", PROGRAM,
                               "--lane", "apk", "--root", str(self.root),
                               "--source-root", str(self.source), "-v", *map(str, args)],
                              cwd=REPO, env=self.env, text=True, capture_output=True, timeout=30)

    def run_cli(self, *args):
        result = self.run_cli_result(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def tree_snapshot(self, root):
        return {str(p.relative_to(root)): ("link", os.readlink(p)) if p.is_symlink()
                else ("dir",) if p.is_dir() else ("file", p.read_bytes())
                for p in root.rglob("*")}

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

    def test_external_category_symlink_refuses_before_any_mutation_or_fallback(self):
        target = self.base / "outside" / "reports" / "D01" / "original.md"
        self.report(target, "external_category")
        link = self.layout.reports_root / "categories" / "idor" / "original.md"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        self.report(self.home_reports / "home.md", "home")
        before = self.tree_snapshot(self.base)
        result = self.run_cli_result()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(link), result.stderr)
        self.assertIn("--source-dir", result.stderr)
        self.assertEqual(before, self.tree_snapshot(self.base))
        relocated = self.base / "explicit" / "original.md"
        relocated.parent.mkdir()
        link.rename(relocated)
        output = self.run_cli("--source-dir", relocated.parent)
        self.assertIn("Imported: 1 new findings", output)
        self.assertEqual([row["file"] for row in self.rows()], ["src/external_category.py"])
        self.assertTrue(relocated.is_symlink())
        self.assertTrue(target.is_file())

    def test_category_fid_collision_refuses_before_raw_import(self):
        target = self.base / "external.md"
        self.report(target, "external")
        link = self.layout.reports_root / "categories" / "idor" / "D01.md"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        self.report(self.layout.reports_root / "raw" / "new.md", "new")
        before = self.tree_snapshot(self.base)
        result = self.run_cli_result()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(link), result.stderr)
        self.assertEqual(before, self.tree_snapshot(self.base))

    def test_internal_and_dangling_category_symlinks_refuse_without_mutation(self):
        target = self.layout.reports_root / "working.md"
        self.report(target, "internal")
        link = self.layout.reports_root / "categories" / "idor" / "linked.md"
        link.parent.mkdir(parents=True)
        for destination in (target, self.base / "missing.md"):
            with self.subTest(destination=destination):
                link.symlink_to(os.path.relpath(destination, link.parent))
                before = self.tree_snapshot(self.base)
                result = self.run_cli_result()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(str(link), result.stderr)
                self.assertEqual(before, self.tree_snapshot(self.base))
                link.unlink()

    def test_explicit_source_does_not_bypass_destination_conflict(self):
        target = self.base / "original.md"
        self.report(target, "external_category")
        link = self.layout.reports_root / "categories" / "idor" / "original.md"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        explicit = self.base / "explicit"
        self.report(explicit / "other.md", "other")
        before = self.tree_snapshot(self.base)
        result = self.run_cli_result("--source-dir", explicit)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(link), result.stderr)
        self.assertEqual(before, self.tree_snapshot(self.base))

    def test_category_symlink_to_real_internal_source_is_not_navigation(self):
        from agents.report_paths import discover_report_files

        target = self.layout.reports_root / "working.md"
        self.report(target, "internal")
        link = self.layout.reports_root / "categories" / "idor" / "linked.md"
        link.parent.mkdir(parents=True)
        link.symlink_to(os.path.relpath(target, link.parent))
        self.assertEqual(set(discover_report_files(self.layout.reports_root, skip_category_links=True)),
                         {link, target})

    def test_generated_category_stub_does_not_shadow_home(self):
        stub = self.layout.reports_root / "categories" / "idor" / "D01.md"
        stub.parent.mkdir(parents=True)
        stub.write_text(CATEGORY_STUB_GENERATED_MARKER + "\nFile: src/false.py:1\n")
        self.report(self.home_reports / "home.md", "home")
        self.assertIn("mode=source_reports", self.run_cli())
        self.assertEqual([row["file"] for row in self.rows()], ["src/home.py"])

    def test_explicit_alias_of_canonical_root_skips_navigation_links(self):
        original = self.home_reports / "original.md"
        self.report(original, "original")
        self.run_cli()
        evidence = Path(self.rows()[0]["evidence_path"])
        with evidence.open("a") as stream:
            stream.write("\nFile: src/false_positive.py:7\n")
        self.report(self.layout.reports_root / "working.md", "real")
        alias = self.base / "reports_alias"
        alias.symlink_to(self.layout.reports_root, target_is_directory=True)
        output = self.run_cli("--source-dir", alias)
        self.assertIn("mode=override files=1", output)
        self.assertEqual({row["file"] for row in self.rows()}, {"src/original.py", "src/real.py"})

    def test_explicit_external_symlink_remains_importable(self):
        target = self.base / "outside" / "reports" / "D01" / "ordinary.md"
        self.report(target, "external")
        explicit = self.base / "explicit"
        explicit.mkdir()
        (explicit / "link.md").symlink_to(target)
        self.assertIn("mode=override", self.run_cli("--source-dir", explicit))
        self.assertEqual([row["file"] for row in self.rows()], ["src/external.py"])
