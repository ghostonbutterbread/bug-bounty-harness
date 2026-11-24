"""Archived-finding delete, tombstone, resurrection guard, and restore (synthetic storage only)."""

from __future__ import annotations

import fcntl
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bounty_core.ledger import patch_finding_by_fid  # noqa: E402
from bounty_core.reports import render_finding_report  # noqa: E402
from bounty_core.storage import resolve_storage  # noqa: E402

from agents import me_ledger  # noqa: E402
from agents.ledger import create_team_ledger_from_storage, update_team_finding  # noqa: E402
from agents.ledger_tombstones import (  # noqa: E402
    CorruptTombstoneLogError,
    LedgerDeleteError,
    MalformedLedgerError,
    delete_finding_by_fid,
)
from agents.manual_hunter import main  # noqa: E402

PROGRAM = "synthetic_delete"
FAMILY = "binaries"
LANE = "apk"


class LedgerDeleteFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "storage"
        self.layout = resolve_storage(PROGRAM, family=FAMILY, lane=LANE, root_override=self.root, create=False)
        self.base = [PROGRAM, "--family", FAMILY, "--lane", LANE, "--root", str(self.root),
                     "--source-root", str(self.tmp)]
        for index, title in enumerate(("Placeholder alpha", "Placeholder beta", "Kept gamma"), start=1):
            self.assertEqual(self._ingest(title, f"src/file{index}.js:{index}"), 0)

    # -- helpers -----------------------------------------------------------

    def _run(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*self.base, *args])
        return code, out.getvalue(), err.getvalue()

    def _ingest(self, title: str, file_ref: str) -> int:
        note = self.tmp / f"{title.replace(' ', '_')}.md"
        note.write_text(f"Title: {title}\nClass: native-module-abuse\nFile: {file_ref}\n"
                        "Description: Synthetic observation.\n", encoding="utf-8")
        return self._run("--from-file", str(note))[0]

    @property
    def ledger(self) -> Path:
        return self.layout.ledgers_root / "ledger.json"

    @property
    def tombstone(self) -> Path:
        return self.layout.ledgers_root / "deleted-findings.jsonl"

    def _findings(self) -> dict[str, dict]:
        return {row["fid"]: row for row in json.loads(self.ledger.read_text(encoding="utf-8"))["findings"]}

    def _archive(self, fid: str) -> None:
        patch = self.tmp / f"archive-{fid}.json"
        patch.write_text('{"status":"archive"}', encoding="utf-8")
        self.assertEqual(self._run("--edit-finding", fid, "--patch-file", str(patch))[0], 0)

    def _write_generated_report(self, fid: str) -> Path:
        row = self._findings()[fid]
        report = Path(row["report_dir"]) / "REPORT.md"
        report.write_text(render_finding_report(row), encoding="utf-8")
        return report

    # -- CLI contract ------------------------------------------------------

    def test_help_advertises_delete_and_restore(self) -> None:
        result = subprocess.run([sys.executable, "-m", "agents.manual_hunter", "--help"], cwd=REPO_ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--delete-finding FID", result.stdout)
        self.assertIn("--restore-finding FID", result.stdout)

    def test_delete_refused_unless_archived(self) -> None:
        before = self.ledger.read_bytes()
        code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 1)
        self.assertIn("not 'archive'", err)
        self.assertEqual(out, "")
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(self.tombstone.exists())
        # current.status alone does not override a non-archive top-level status.
        patch_finding_by_fid(PROGRAM, "D01", {"current": {"status": "archive"}}, family=FAMILY, lane=LANE,
                             root_override=self.root)
        self.assertEqual(self._run("--delete-finding", "D01")[0], 1)

    def test_unknown_fid_is_a_clear_error(self) -> None:
        before = self.ledger.read_bytes()
        code, _out, err = self._run("--delete-finding", "D99")
        self.assertEqual(code, 1)
        self.assertIn("no finding found for fid D99", err)
        self.assertEqual(self.ledger.read_bytes(), before)
        code, _out, err = self._run("--restore-finding", "D99")
        self.assertEqual(code, 1)
        self.assertIn("no tombstoned finding", err)

    def test_highest_fid_is_refused_to_prevent_reuse(self) -> None:
        self._archive("D03")
        code, _out, err = self._run("--delete-finding", "D03")
        self.assertEqual(code, 1)
        self.assertIn("highest FID", err)
        self.assertIn("D03", self._findings())

    def test_malformed_ledger_fails_closed(self) -> None:
        self.ledger.write_text('{"findings": [ {"fid": "D01", ', encoding="utf-8")
        before = self.ledger.read_bytes()
        code, _out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 1)
        self.assertIn("malformed", err)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(self.tombstone.exists())
        with self.assertRaises(MalformedLedgerError):
            delete_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)

    # -- successful delete -------------------------------------------------

    def test_delete_removes_only_that_finding_tombstones_and_retires_generated_files(self) -> None:
        self._archive("D01")
        self._archive("D02")
        before = self._findings()
        packet1 = Path(before["D01"]["report_dir"])
        report1 = self._write_generated_report("D01")
        evidence1 = packet1 / "EVIDENCE.md"
        poc1 = packet1 / "poc.py"
        poc1.write_text("# operator-authored PoC\n", encoding="utf-8")
        outside = self.tmp / "outside.md"
        outside.write_text("must survive", encoding="utf-8")
        (packet1 / "escape.md").symlink_to(outside)
        category_index = self.layout.reports_root / "categories" / "native-module-abuse" / "index.md"
        self.assertIn("Placeholder alpha", category_index.read_text(encoding="utf-8"))

        code, out, err = self._run("--delete-finding", "D01", "--actor", "board:synthetic")
        self.assertEqual(code, 0, err)
        self.assertIn("Finding deleted: D01", out)
        self.assertIn(f"Tombstone: {self.tombstone}", out)

        after = self._findings()
        self.assertEqual(sorted(after), ["D02", "D03"])
        self.assertEqual(after["D02"], before["D02"])
        self.assertEqual(after["D03"], before["D03"])

        lines = self.tombstone.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual(event["event"], "deleted")
        self.assertEqual(event["fid"], "D01")
        self.assertEqual(event["deleted_by"], "board:synthetic")
        self.assertEqual(event["ledger_path"], str(self.ledger))
        self.assertRegex(event["deleted_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(event["record"], before["D01"])
        self.assertEqual(stat.S_IMODE(self.tombstone.stat().st_mode), 0o600)

        retired = {Path(item["from"]): Path(item["to"]) for item in event["artifacts"]["retired"]}
        self.assertEqual(set(retired), {report1, evidence1})
        for source, target in retired.items():
            self.assertFalse(source.exists())
            self.assertTrue(target.is_file())
            self.assertTrue(str(target).startswith(str(self.layout.ledgers_root / "_deleted" / "D01")))
            self.assertIn(f"Retired: {source} -> {target}", out)
        kept = {Path(item["path"]): item["reason"] for item in event["artifacts"]["kept"]}
        self.assertEqual(kept[poc1], "not BBH-generated")
        self.assertEqual(kept[packet1 / "escape.md"], "symlink (not followed)")
        self.assertIn(f"Kept (not BBH-generated): {poc1}", out)
        self.assertTrue(poc1.is_file())
        self.assertEqual(outside.read_text(encoding="utf-8"), "must survive")

        # Derived views are refreshed like any other ledger write.
        self.assertNotIn("Placeholder alpha", category_index.read_text(encoding="utf-8"))
        self.assertFalse((category_index.parent / "D01.md").exists())
        by_status = self.layout.ledgers_root / "indexes" / "by_status" / "archive.json"
        self.assertEqual([row["fid"] for row in json.loads(by_status.read_text(encoding="utf-8"))], ["D02"])

    def test_human_edited_artifacts_are_left_and_listed(self) -> None:
        self._archive("D02")
        packet = Path(self._findings()["D02"]["report_dir"])
        report = self._write_generated_report("D02")
        report.write_text(report.read_text(encoding="utf-8") + "\nReviewer note.\n", encoding="utf-8")
        evidence = packet / "EVIDENCE.md"
        evidence.write_text(evidence.read_text(encoding="utf-8") + "\nVerified detail.\n", encoding="utf-8")
        code, out, _err = self._run("--delete-finding", "D02")
        self.assertEqual(code, 0)
        self.assertIn(f"Kept (generated report edited (checksum mismatch)): {report}", out)
        self.assertIn(f"Kept (evidence edited after creation): {evidence}", out)
        self.assertNotIn("Retired:", out)
        self.assertIn("Reviewer note.", report.read_text(encoding="utf-8"))
        self.assertIn("Verified detail.", evidence.read_text(encoding="utf-8"))
        event = json.loads(self.tombstone.read_text(encoding="utf-8"))
        self.assertEqual(event["deleted_by"], "manual_hunter")
        self.assertEqual(event["artifacts"]["retired"], [])

    # -- concurrency -------------------------------------------------------

    def test_delete_waits_for_lock_and_keeps_concurrent_edit(self) -> None:
        self._archive("D01")
        lock_path = self.layout.ledgers_root / "ledger.lock"
        errors: list[BaseException] = []

        def run_delete() -> None:
            try:
                delete_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        with lock_path.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            worker = threading.Thread(target=run_delete)
            worker.start()
            time.sleep(0.3)
            self.assertTrue(worker.is_alive(), "delete must wait for the ledger lock")
            # A writer that owns the lock commits an edit to another finding.
            payload = json.loads(self.ledger.read_text(encoding="utf-8"))
            for row in payload["findings"]:
                if row["fid"] == "D02":
                    row["description"] = "edited while delete waited"
            self.ledger.write_text(json.dumps(payload), encoding="utf-8")
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        worker.join(timeout=30)
        self.assertFalse(errors, errors)
        findings = self._findings()
        self.assertNotIn("D01", findings)
        self.assertEqual(findings["D02"]["description"], "edited while delete waited")

    def test_concurrent_patches_and_delete_lose_no_update(self) -> None:
        self._archive("D01")
        errors: list[BaseException] = []

        def patcher(fid: str, count: int) -> None:
            try:
                for index in range(count):
                    patch_finding_by_fid(PROGRAM, fid, {f"review_note_{index}": f"{fid}-{index}"},
                                         family=FAMILY, lane=LANE, root_override=self.root)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        def deleter() -> None:
            time.sleep(0.05)  # land the delete while the patchers are mid-stream
            try:
                delete_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=patcher, args=(fid, 15)) for fid in ("D02", "D03")]
        threads.append(threading.Thread(target=deleter))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertFalse(errors, errors)
        findings = self._findings()
        self.assertEqual(sorted(findings), ["D02", "D03"])
        for fid in ("D02", "D03"):
            for index in range(15):
                self.assertEqual(findings[fid][f"review_note_{index}"], f"{fid}-{index}")

    # -- resurrection guards -----------------------------------------------

    def _delete_d01(self) -> dict:
        self._archive("D01")
        record = self._findings()["D01"]
        self.assertEqual(self._run("--delete-finding", "D01")[0], 0)
        return record

    def test_manual_reingest_of_deleted_identity_is_skipped(self) -> None:
        self._delete_d01()
        before = self.ledger.read_bytes()
        note = self.tmp / "Placeholder_alpha.md"
        code, out, err = self._run("--from-file", str(note), "--link-duplicate-comment")
        self.assertEqual(code, 1)
        self.assertIn("Skipped tombstoned finding D01", err)
        self.assertIn("Skipped: D01 was deleted", out)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse((self.layout.ledgers_root / "manual_comments.jsonl").exists())

    def test_new_finding_after_delete_does_not_reuse_deleted_fid(self) -> None:
        self._archive("D02")
        self.assertEqual(self._run("--delete-finding", "D02")[0], 0)
        self.assertEqual(self._ingest("Fresh delta", "src/fresh.js:9"), 0)
        self.assertEqual(sorted(self._findings()), ["D01", "D03", "D04"])

    def test_team_check_batch_and_update_paths_skip_tombstones(self) -> None:
        record = self._delete_d01()
        before = self.ledger.read_bytes()
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        candidate = {k: record[k] for k in ("file", "line", "class_name", "type")}
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(ledger.check(dict(candidate))[:2], (True, "D01"))
            dup, fid, finding = ledger.import_finding({"fid": "D01", "file": "other.js", "line": 1,
                                                       "class_name": "xss", "type": "xss"})
            self.assertEqual((dup, fid, finding["tombstoned"]), (True, "D01", True))
            results = ledger.reserve_batch([dict(candidate), {"file": "new.js", "line": 2,
                                                              "class_name": "xss", "type": "xss"}])
            updated = ledger.update({**candidate, "fid": "D01"})
            self.assertTrue(updated["tombstoned"])
            # report_checker / promotion fallback: patch misses, ledger_add must not re-create.
            reinserted = update_team_finding(PROGRAM, {"fid": "D01", "title": "again"}, family=FAMILY,
                                             lane=LANE, root_override=self.root)
        self.assertEqual(results[0][:2], (True, "D01"))
        self.assertFalse(results[1][0])
        self.assertTrue(reinserted["tombstoned"])
        self.assertIn("Skipped tombstoned finding D01", err.getvalue())
        findings = self._findings()
        self.assertNotIn("D01", findings)
        self.assertEqual(sorted(findings), ["D02", "D03", "D04"])  # only the genuinely new batch item
        self.assertNotEqual(self.ledger.read_bytes(), before)

    def test_sync_reports_style_import_by_old_fid_is_skipped(self) -> None:
        self._delete_d01()
        before = self.ledger.read_bytes()
        hunter_ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp,
                                                        agent="sync-reports")
        with redirect_stderr(io.StringIO()):
            dup, fid, finding = hunter_ledger.import_finding(
                {"fid": "D01", "title": "Renamed in leftover report", "file": "src/moved.js", "line": 4,
                 "class_name": "native-module-abuse"}, packet_mode="evidence_only")
        self.assertTrue(dup and finding.get("tombstoned"))
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_me_ledger_add_of_deleted_identity_is_skipped(self) -> None:
        args = Namespace(program=PROGRAM, family=FAMILY, lane=LANE, root_override=str(self.root),
                         version_label=None, type="synthetic-type", class_name="ssrf", file="src/me.js",
                         severity="LOW", agent="me", fid_prefix="D", scoring_authority="",
                         severity_rationale="", program_constraint="")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(me_ledger.cmd_add(args), 0)
        self.assertEqual(self._ingest("Newest epsilon", "src/newest.js:1"), 0)  # D05 keeps D04 deletable
        self._archive("D04")
        self.assertEqual(self._run("--delete-finding", "D04")[0], 0)
        before = self.ledger.read_bytes()
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(me_ledger.cmd_add(args), 1)
        self.assertIn("Skipped tombstoned finding D04", err.getvalue())
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_file_and_class_only_candidate_is_skipped(self) -> None:
        record = self._delete_d01()
        before = self.ledger.read_bytes()
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        loose = {"file": record["file"], "class_name": record["class_name"]}
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ledger.import_finding(dict(loose))[:2], (True, "D01"))
            self.assertEqual(ledger.check(dict(loose))[:2], (True, "D01"))
            self.assertEqual(ledger.reserve_batch([dict(loose)])[0][:2], (True, "D01"))
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_corrupt_or_symlinked_tombstone_log_fails_closed(self) -> None:
        self._delete_d01()
        with self.tombstone.open("ab") as handle:
            handle.write(b'{"fid": "D02", "event": "dele')
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        with self.assertRaises(CorruptTombstoneLogError):
            ledger.import_finding({"fid": "D01", "file": "x.js", "line": 1, "class_name": "xss", "type": "xss"})
        self._archive("D02")
        code, _out, err = self._run("--delete-finding", "D02")
        self.assertEqual(code, 1)
        self.assertIn("tombstone log line 2 is unreadable", err)
        self.assertIn("D02", self._findings())
        real = self.tmp / "elsewhere.jsonl"
        real.write_text("", encoding="utf-8")
        self.tombstone.unlink()
        self.tombstone.symlink_to(real)
        with self.assertRaises(CorruptTombstoneLogError):
            ledger.check({"file": "y.js", "line": 1, "class_name": "xss", "type": "xss"})
        self.assertEqual(self._run("--delete-finding", "D02")[0], 1)
        self.assertEqual(real.read_text(encoding="utf-8"), "")
        self.assertIn("D02", self._findings())

    def test_symlinked_retire_area_is_refused_without_moving_files(self) -> None:
        self._archive("D01")
        report = self._write_generated_report("D01")
        outside = self.tmp / "outside-retire"
        outside.mkdir()
        (self.layout.ledgers_root / "_deleted").symlink_to(outside)
        before = self.ledger.read_bytes()
        code, _out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 1)
        self.assertIn("symlinked directory", err)
        self.assertTrue(report.is_file())
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(self.tombstone.exists())

    def test_report_pointer_into_another_packet_is_kept(self) -> None:
        self._archive("D01")
        other_report = self._write_generated_report("D02")
        payload = json.loads(self.ledger.read_text(encoding="utf-8"))
        for row in payload["findings"]:
            if row["fid"] == "D01":
                row["report_path"] = str(other_report)  # legacy/hand-edited mis-pointer
        self.ledger.write_text(json.dumps(payload), encoding="utf-8")
        code, out, _err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0)
        self.assertTrue(other_report.is_file())
        self.assertIn(f"Kept (report_path not owned by this FID): {other_report}", out)

    def test_legacy_lifecycle_report_is_retired(self) -> None:
        self._archive("D01")
        row = self._findings()["D01"]
        legacy = self.layout.reports_root / "findings" / "active" / "D01 - Placeholder alpha.md"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(render_finding_report(row), encoding="utf-8")
        code, out, _err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0)
        self.assertFalse(legacy.exists())
        self.assertIn(f"Retired: {legacy} -> ", out)

    # -- restore -----------------------------------------------------------

    def test_restore_reinserts_record_and_files(self) -> None:
        self._archive("D01")
        report = self._write_generated_report("D01")
        report_text = report.read_text(encoding="utf-8")
        record = self._findings()["D01"]
        self.assertEqual(self._run("--delete-finding", "D01")[0], 0)
        self.assertFalse(report.exists())

        code, out, err = self._run("--restore-finding", "D01", "--actor", "operator")
        self.assertEqual(code, 0, err)
        self.assertIn("Finding restored: D01", out)
        self.assertIn(f"Restored file: {report}", out)
        self.assertEqual(self._findings()["D01"], record)
        self.assertEqual(report.read_text(encoding="utf-8"), report_text)
        events = [json.loads(line) for line in self.tombstone.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["event"] for e in events], ["deleted", "restored"])
        self.assertEqual(events[1]["restored_by"], "operator")

        # Restored identity is live again: a re-ingest is an ordinary duplicate.
        code, out, _err = self._run("--from-file", str(self.tmp / "Placeholder_alpha.md"))
        self.assertEqual(code, 1)
        self.assertIn("Duplicate: D01", out)
        # Second restore has nothing to restore; FID now exists.
        code, _out, err = self._run("--restore-finding", "D01")
        self.assertEqual(code, 1)
        self.assertIn("no tombstoned finding", err)

    def test_restore_refresh_failure_reports_partial_after_commit(self) -> None:
        self._delete_d01()
        from unittest.mock import patch as mock_patch
        with mock_patch("agents.ledger_tombstones.refresh_report_indexes", side_effect=ValueError("bad packet")):
            code, out, err = self._run("--restore-finding", "D01")
        self.assertEqual(code, 3)
        self.assertIn("Finding restored: D01", out)
        self.assertIn("navigation refresh failed after restore", err)
        self.assertIn("D01", self._findings())

    def test_restore_rolls_back_when_ledger_write_fails(self) -> None:
        self._archive("D01")
        report = self._write_generated_report("D01")
        self.assertEqual(self._run("--delete-finding", "D01")[0], 0)
        before = self.ledger.read_bytes()
        events_before = self.tombstone.read_text(encoding="utf-8")
        from unittest.mock import patch as mock_patch
        with mock_patch("agents.ledger_tombstones._write_json_atomic", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                from agents.ledger_tombstones import restore_finding_by_fid
                restore_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual(self.tombstone.read_text(encoding="utf-8"), events_before)
        self.assertFalse(report.exists())
        self.assertEqual(self._run("--restore-finding", "D01")[0], 0)
        self.assertTrue(report.is_file())

    def test_restore_refused_when_fid_exists(self) -> None:
        self._delete_d01()
        payload = json.loads(self.ledger.read_text(encoding="utf-8"))
        payload["findings"].append({**payload["findings"][0], "fid": "D01", "file": "src/other.js"})
        self.ledger.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(LedgerDeleteError, "exists"):
            from agents.ledger_tombstones import restore_finding_by_fid
            restore_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)


if __name__ == "__main__":
    unittest.main()
