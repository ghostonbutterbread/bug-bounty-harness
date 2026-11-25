"""Write hot path: lazy snapshot identity, manifest cache, legacy relative packet pointers."""

from __future__ import annotations

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agents import snapshot_identity as snap
from agents.ledger_report_dirs import repair_report_dirs
from agents.manual_hunter import main
from bounty_core.storage import resolve_storage

PROGRAM = "fictional-hot-path"


def _forbidden(*_args, **_kwargs):
    raise AssertionError("snapshot identity must not be computed on this path")


class _LaneCase(unittest.TestCase):
    """A synthetic binaries/apk lane under an explicit --root, like the Bounty Board's writer call."""

    def setUp(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.tmp = Path(tempdir.name)
        self.root = self.tmp / "data"
        self.source = self.tmp / "extracted"
        (self.source / "smali").mkdir(parents=True)
        for index in range(5):
            (self.source / "smali" / f"C{index}.smali").write_text(f".class C{index}\n", encoding="utf-8")
        env = patch.dict(os.environ, {"HOME": str(self.tmp / "home"), "XDG_CACHE_HOME": str(self.tmp / "cache")})
        env.start()
        self.addCleanup(env.stop)
        # A temp dir may sit inside some git checkout; the binaries lane case is a non-git root.
        no_git = patch.object(snap, "_git_head", return_value=None)
        no_git.start()
        self.addCleanup(no_git.stop)

    def base_args(self, *extra: str) -> list[str]:
        return [PROGRAM, "--family", "binaries", "--lane", "apk", "--root", str(self.root), *extra]

    def run_main(self, *extra: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(self.base_args(*extra))
        return rc, out.getvalue(), err.getvalue()

    def layout(self):
        return resolve_storage(PROGRAM, family="binaries", lane="apk", root_override=self.root, create=False)

    def ledger_file(self) -> Path:
        return self.layout().ledgers_root / "ledger.json"

    def findings(self) -> list[dict]:
        return json.loads(self.ledger_file().read_text(encoding="utf-8"))["findings"]

    def add_finding(self, title: str, line: int) -> str:
        note = self.tmp / f"note-{line}.md"
        note.write_text(
            f"Title: {title}\nClass: idor\nFile: smali/C1.smali:{line}\n"
            "Description: Owned synthetic fixture.\n",
            encoding="utf-8",
        )
        rc, out, err = self.run_main("--source-root", str(self.source), "--from-file", str(note))
        self.assertEqual(rc, 0, out + err)
        return self.findings()[-1]["fid"]

    def edit(self, fid: str, patch_body: dict) -> tuple[int, str, str]:
        patch_file = self.tmp / "patch.json"
        patch_file.write_text(json.dumps(patch_body), encoding="utf-8")
        # The Bounty Board's exact argument order.
        return self.run_main("--edit-finding", fid, "--patch-file", str(patch_file))

    def rewrite_ledger(self, mutate) -> None:
        payload = json.loads(self.ledger_file().read_text(encoding="utf-8"))
        mutate(payload["findings"])
        self.ledger_file().write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class LazySnapshotIdentityTests(_LaneCase):
    def test_new_finding_is_stamped_with_the_unchanged_identity(self) -> None:
        fid = self.add_finding("Stamped finding", 3)
        expected = snap._manifest_hash(self.source.resolve())
        self.assertEqual(expected, snap.get_snapshot_identity(self.source)["snapshot_id"])
        finding = next(item for item in self.findings() if item["fid"] == fid)
        self.assertEqual(finding["first_snapshot"], expected)
        self.assertEqual(finding["sightings"][0]["snapshot_id"], expected)

    def test_metadata_actions_never_compute_the_identity(self) -> None:
        fid = self.add_finding("Metadata target", 4)
        with patch("agents.manual_hunter.get_snapshot_identity", side_effect=_forbidden), \
                patch.object(snap, "_manifest_hash", side_effect=_forbidden), \
                patch.object(snap, "_manifest_entries", side_effect=_forbidden), \
                patch("bounty_core.ledger.get_snapshot_identity", side_effect=_forbidden):
            rc, out, err = self.edit(fid, {"status": "triaged", "severity": "P3"})
            self.assertEqual(rc, 0, out + err)
            rc, out, err = self.run_main("--source-root", str(self.source), "--edit-finding", fid,
                                         "--patch-file", str(self.tmp / "patch.json"))
            self.assertEqual(rc, 0, out + err)
            rc, out, err = self.run_main("--source-root", str(self.source), "--set-submission", fid,
                                         "--submission-state", "submitted")
            self.assertEqual(rc, 0, out + err)
            self.assertIn(f"Submission updated: {fid} -> submitted", out)
            rc, out, err = self.run_main("--repair-report-dirs")
            self.assertEqual(rc, 0, out + err)
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as help_exit:
                main(["--help"])
            self.assertEqual(help_exit.exception.code, 0)
        finding = next(item for item in self.findings() if item["fid"] == fid)
        self.assertEqual(finding["status"], "triaged")
        self.assertEqual(finding["current"]["status"], "triaged")
        self.assertEqual(finding["submission"]["state"], "submitted")

    def test_identity_resolved_once_before_the_ledger_lock(self) -> None:
        from agents.manual_hunter import ManualHunter, parse_finding_text

        hunter = ManualHunter(PROGRAM, family="binaries", lane="apk", source_root=self.source, storage_root=self.root)
        self.assertFalse(hunter.ledger.snapshot_loaded)
        calls = []
        real = snap.get_snapshot_identity

        def counting(*args, **kwargs):
            calls.append(args)
            return real(*args, **kwargs)

        with patch("agents.manual_hunter.get_snapshot_identity", side_effect=counting):
            for line in (7, 8):
                note = parse_finding_text(f"Title: Once {line}\nClass: idor\nFile: smali/C2.smali:{line}\n"
                                          "Description: Owned synthetic fixture.\n", source_label="t",
                                          family="binaries", lane="apk")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(hunter.ingest(note), 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(hunter.ledger.snapshot_loaded)
        self.assertEqual(hunter.ledger.snapshot_id, snap._manifest_hash(self.source.resolve()))


class ManifestCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.tmp = Path(tempdir.name)
        self.tree = self.tmp / "tree"
        (self.tree / "a").mkdir(parents=True)
        (self.tree / "a" / "one.txt").write_text("one", encoding="utf-8")
        (self.tree / "two.bin").write_bytes(b"\x00\x01")
        self.cache = self.tmp / "cache"

    def cached(self) -> str:
        return snap.cached_manifest_hash(self.tree, self.cache)

    def assert_recomputed(self) -> None:
        with patch.object(snap, "_manifest_hash", wraps=snap._manifest_hash) as spy:
            self.assertEqual(self.cached(), snap._manifest_hash(self.tree.resolve()))
        self.assertGreaterEqual(spy.call_count, 1)

    def test_cached_value_equals_uncached_and_skips_content_reads(self) -> None:
        self.assertEqual(self.cached(), snap._manifest_hash(self.tree.resolve()))
        identity = snap.get_snapshot_identity(self.tree, manifest_cache_dir=self.cache)
        self.assertEqual(set(identity), {"version_label", "build_id", "git_head", "manifest_hash", "platform",
                                         "arch", "channel", "snapshot_id"})

    def test_cache_hit_reads_no_file_contents(self) -> None:
        expected = self.cached()
        with patch.object(snap, "_manifest_hash", side_effect=_forbidden):
            self.assertEqual(self.cached(), expected)

    def test_content_change_invalidates(self) -> None:
        self.cached()
        (self.tree / "a" / "one.txt").write_text("changed", encoding="utf-8")
        self.assert_recomputed()

    def test_same_size_rewrite_with_new_mtime_invalidates(self) -> None:
        self.cached()
        target = self.tree / "a" / "one.txt"
        stat = target.stat()
        target.write_text("ONE", encoding="utf-8")
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        self.assert_recomputed()

    def test_same_size_rewrite_with_restored_mtime_invalidates(self) -> None:
        self.cached()
        target = self.tree / "a" / "one.txt"
        stat = target.stat()
        time.sleep(0.02)  # ctime granularity
        target.write_text("ONE", encoding="utf-8")
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual(target.stat().st_mtime_ns, stat.st_mtime_ns)
        self.assert_recomputed()

    def test_cache_prunes_old_and_excess_entries(self) -> None:
        self.cache.mkdir(parents=True)
        old = self.cache / ("0" * 64 + ".json")
        old.write_text("{}", encoding="utf-8")
        past = time.time() - snap.MANIFEST_CACHE_MAX_AGE_SECONDS - 60
        os.utime(old, (past, past))
        foreign = self.cache / "settings.json"
        foreign.write_text("{}", encoding="utf-8")
        os.utime(foreign, (past, past))
        with patch.object(snap, "MANIFEST_CACHE_MAX_ENTRIES", 3):
            for index in range(5):
                (self.cache / f"{index:064d}.json").write_text("{}", encoding="utf-8")
                os.utime(self.cache / f"{index:064d}.json", (time.time() - 100 + index, time.time() - 100 + index))
            self.cached()
        remaining = sorted(path.name for path in self.cache.glob("*.json") if path.name != "settings.json")
        self.assertNotIn(old.name, remaining)
        self.assertEqual(len(remaining), 3)
        self.assertTrue((self.cache / "settings.json").exists())  # foreign files are never pruned
        self.assertIn(snap._cache_file(self.cache, self.tree.resolve()).name, remaining)

    def test_rename_and_new_file_invalidate(self) -> None:
        self.cached()
        (self.tree / "two.bin").rename(self.tree / "three.bin")
        self.assert_recomputed()
        (self.tree / "four.txt").write_text("4", encoding="utf-8")
        self.assert_recomputed()

    def test_corrupt_or_foreign_cache_is_ignored(self) -> None:
        self.cached()
        (cache_file,) = self.cache.glob("*.json")
        cache_file.write_text("{not json", encoding="utf-8")
        self.assert_recomputed()
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        cache_file.write_text(json.dumps({**payload, "root": "/elsewhere"}), encoding="utf-8")
        self.assert_recomputed()

    def test_unwritable_cache_still_returns_the_hash(self) -> None:
        blocker = self.tmp / "blocker"
        blocker.write_text("file, not a directory", encoding="utf-8")
        self.assertEqual(snap.cached_manifest_hash(self.tree, blocker / "cache"), snap._manifest_hash(self.tree.resolve()))


class RelativeReportDirTests(_LaneCase):
    def setUp(self) -> None:
        super().setUp()
        self.d1 = self.add_finding("First fixture", 10)
        self.d2 = self.add_finding("Second fixture", 11)
        self.canonical = {item["fid"]: item["report_dir"] for item in self.findings()}
        self.lane_root = self.layout().lane_root

    def make_relative(self, fid: str, value: str | None = None, *, evidence: bool = True) -> None:
        def mutate(findings):
            for item in findings:
                if item["fid"] == fid:
                    absolute = Path(item["report_dir"])
                    item["report_dir"] = value if value is not None else absolute.relative_to(self.lane_root).as_posix()
                    if evidence:
                        item["evidence_path"] = (absolute / "EVIDENCE.md").relative_to(self.lane_root).as_posix()
        self.rewrite_ledger(mutate)

    def test_relative_report_dir_record_no_longer_blocks_lane_edits(self) -> None:
        self.make_relative(self.d1)
        # Base behaviour: Bounty Core refuses the whole lane.
        from bounty_core.ledger import patch_finding_by_fid as core_patch
        with self.assertRaisesRegex(ValueError, "exact-FID packet"):
            core_patch(PROGRAM, self.d2, {"status": "triaged"}, family="binaries", lane="apk",
                       root_override=self.root, refresh=True)
        rc, out, err = self.edit(self.d2, {"status": "triaged"})
        self.assertEqual(rc, 0, out + err)
        self.assertIn("normalized 2 legacy packet pointer(s)", err)
        by_fid = {item["fid"]: item for item in self.findings()}
        self.assertEqual(by_fid[self.d1]["report_dir"], self.canonical[self.d1])
        self.assertEqual(by_fid[self.d1]["evidence_path"], str(Path(self.canonical[self.d1]) / "EVIDENCE.md"))
        self.assertEqual(by_fid[self.d2]["status"], "triaged")
        # The record itself is editable too, and set-submission works.
        rc, out, err = self.edit(self.d1, {"status": "triaged"})
        self.assertEqual(rc, 0, out + err)
        self.make_relative(self.d1, evidence=False)
        rc, out, err = self.run_main("--set-submission", self.d1, "--submission-state", "dropped")
        self.assertEqual(rc, 0, out + err)

    def test_bare_fid_relative_to_reports_root_is_accepted(self) -> None:
        name = Path(self.canonical[self.d1]).name
        self.make_relative(self.d1, name, evidence=False)
        rc, out, err = self.edit(self.d2, {"status": "triaged"})
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.findings()[0]["report_dir"], self.canonical[self.d1])

    def test_unsafe_relative_values_still_fail_closed(self) -> None:
        other = Path(self.canonical[self.d2]).name
        for value in (f"../apk/reports/{Path(self.canonical[self.d1]).name}", f"reports/{other}", "reports/raw",
                      "reports", f"recon/{Path(self.canonical[self.d1]).name}"):
            with self.subTest(value=value):
                self.make_relative(self.d1, value, evidence=False)
                before = self.ledger_file().read_bytes()
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                    main(self.base_args("--edit-finding", self.d2, "--patch-file", str(self._patch())))
                self.assertEqual(self.ledger_file().read_bytes(), before)

    def _patch(self) -> Path:
        path = self.tmp / "status.json"
        path.write_text(json.dumps({"status": "triaged"}), encoding="utf-8")
        return path

    def test_repair_dry_run_lists_without_writing_then_apply_rewrites(self) -> None:
        self.make_relative(self.d1)
        before = self.ledger_file().read_bytes()
        rc, out, _ = self.run_main("--repair-report-dirs")
        self.assertEqual(rc, 2)
        self.assertIn(f"Would repair: {self.d1} report_dir: reports/", out)
        self.assertIn(f"Would repair: {self.d1} evidence_path: reports/", out)
        self.assertIn("2 repairable, 0 need manual review; nothing written", out)
        self.assertEqual(self.ledger_file().read_bytes(), before)
        rc, out, _ = self.run_main("--repair-report-dirs", "--dry-run")
        self.assertEqual((rc, self.ledger_file().read_bytes()), (2, before))

        rc, out, _ = self.run_main("--repair-report-dirs", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Repaired: {self.d1} report_dir", out)
        by_fid = {item["fid"]: item for item in self.findings()}
        self.assertEqual(by_fid[self.d1]["report_dir"], self.canonical[self.d1])
        self.assertEqual(by_fid[self.d2]["report_dir"], self.canonical[self.d2])
        rc, out, _ = self.run_main("--repair-report-dirs")
        self.assertEqual(rc, 0)
        self.assertIn("No relative or non-canonical packet pointers.", out)

    def test_repair_leaves_unsafe_values_for_manual_review(self) -> None:
        self.make_relative(self.d1, "../escape", evidence=False)
        rc, out, _ = self.run_main("--repair-report-dirs", "--apply")
        self.assertEqual(rc, 2)
        self.assertIn(f"Manual review: {self.d1} report_dir: ../escape", out)
        self.assertIn("0 repairable, 1 need manual review; nothing written", out)
        self.assertEqual(self.findings()[0]["report_dir"], "../escape")

    def test_repair_refuses_malformed_ledger_and_missing_lane(self) -> None:
        self.ledger_file().write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "malformed"):
            repair_report_dirs(PROGRAM, family="binaries", lane="apk", root_override=self.root, apply=True)
        self.assertEqual(self.ledger_file().read_text(encoding="utf-8"), "{broken")
        rc, _, err = self.run_main("--repair-report-dirs", "--apply")
        self.assertEqual(rc, 1, err)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([PROGRAM, "--family", "binaries", "--lane", "exe", "--root", str(self.root),
                       "--repair-report-dirs"])
        self.assertEqual(rc, 1)

    def test_file_pointer_into_another_findings_packet_is_left_for_review(self) -> None:
        other = Path(self.canonical[self.d2])
        def mutate(findings):
            for item in findings:
                if item["fid"] == self.d1:
                    item["evidence_path"] = (other / "EVIDENCE.md").relative_to(self.lane_root).as_posix()
        self.rewrite_ledger(mutate)
        stored = (other / "EVIDENCE.md").relative_to(self.lane_root).as_posix()
        rc, out, _ = self.run_main("--repair-report-dirs", "--apply")
        self.assertEqual(rc, 2, out)
        self.assertIn(f"Manual review: {self.d1} evidence_path: {stored}", out)
        self.assertNotIn("Repaired", out)
        self.assertEqual({item["fid"]: item for item in self.findings()}[self.d1]["evidence_path"], stored)

    def test_apply_and_dry_run_require_repair_mode(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(self.base_args("--apply", "--set-submission", self.d1))

    def test_delete_of_another_finding_carries_canonical_pointers(self) -> None:
        rc, out, err = self.edit(self.d1, {"status": "archive"})
        self.assertEqual(rc, 0, out + err)
        self.make_relative(self.d2)  # D01 is deletable; D02 (highest FID) stays
        rc, out, err = self.run_main("--delete-finding", self.d1)
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("Warning", err)
        (remaining,) = self.findings()
        self.assertEqual(remaining["report_dir"], self.canonical[self.d2])

if __name__ == "__main__":
    unittest.main()
