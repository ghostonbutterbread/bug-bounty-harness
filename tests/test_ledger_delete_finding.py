"""Permanent archived-finding delete, minimal tombstone, and resurrection guard (synthetic storage only)."""

from __future__ import annotations

import fcntl
import io
import json
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

    def test_help_advertises_delete_only(self) -> None:
        result = subprocess.run([sys.executable, "-m", "agents.manual_hunter", "--help"], cwd=REPO_ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--delete-finding FID", result.stdout)
        self.assertNotIn("--restore-finding", result.stdout)  # archive is the recoverable state

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

    def test_delete_removes_only_that_finding_tombstones_and_deletes_generated_files(self) -> None:
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
        # Minimal tombstone: no recoverable copy of the finding.
        self.assertEqual(set(event), {"schema", "event", "fid", "identity_key", "deleted_at", "deleted_by"})
        self.assertEqual(event["event"], "deleted")
        self.assertEqual(event["fid"], "D01")
        self.assertEqual(event["deleted_by"], "board:synthetic")
        self.assertEqual(event["identity_key"], ["src/file1.js", 1, "native-module-abuse", "placeholder alpha"])
        self.assertRegex(event["deleted_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertNotIn("Synthetic observation", lines[0])
        self.assertEqual(stat.S_IMODE(self.tombstone.stat().st_mode), 0o600)

        for path in (report1, evidence1):
            self.assertFalse(path.exists())
            self.assertIn(f"Deleted file: {path}", out)
        self.assertFalse((self.layout.ledgers_root / "_deleted").exists())
        self.assertIn(f"Kept (not BBH-generated): {poc1}", out)
        self.assertIn(f"Kept (symlink (not followed)): {packet1 / 'escape.md'}", out)
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
        self.assertNotIn("Deleted file:", out)
        self.assertIn("Reviewer note.", report.read_text(encoding="utf-8"))
        self.assertIn("Verified detail.", evidence.read_text(encoding="utf-8"))
        event = json.loads(self.tombstone.read_text(encoding="utf-8"))
        self.assertEqual(event["deleted_by"], "manual_hunter")

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
        self.assertIn("Skipped: D01 was permanently deleted", out)
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
            handle.write(b'{"fid": "D02", "event": "dele\n')  # damaged *committed* line
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

    def test_symlinked_packet_directory_is_not_followed(self) -> None:
        self._archive("D01")
        packet = Path(self._findings()["D01"]["report_dir"])
        report = self._write_generated_report("D01")
        outside = self.tmp / "outside-packet"
        packet.rename(outside)
        packet.symlink_to(outside)
        code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Deleted file:", out)
        self.assertTrue((outside / report.name).is_file())
        self.assertTrue((outside / "EVIDENCE.md").is_file())

    def test_ledger_write_failure_aborts_without_touching_files(self) -> None:
        self._archive("D01")
        report = self._write_generated_report("D01")
        before = self.ledger.read_bytes()
        from unittest.mock import patch as mock_patch
        with mock_patch("agents.ledger_tombstones._write_json_atomic", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(LedgerDeleteError, "failed before commit: OSError: disk full"):
                delete_finding_by_fid(PROGRAM, "D01", family=FAMILY, lane=LANE, root_override=self.root)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertTrue(report.is_file())
        events = [json.loads(line)["event"] for line in self.tombstone.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events, ["deleted", "delete_aborted"])
        # The aborted delete does not block the still-live finding, and a retry succeeds.
        self.assertEqual(self._ingest("Placeholder alpha", "src/file1.js:1"), 1)  # ordinary duplicate
        self.assertEqual(self._run("--delete-finding", "D01")[0], 0)
        self.assertFalse(report.exists())

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

    def test_legacy_lifecycle_report_is_deleted(self) -> None:
        self._archive("D01")
        row = self._findings()["D01"]
        legacy = self.layout.reports_root / "findings" / "active" / "D01 - Placeholder alpha.md"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(render_finding_report(row), encoding="utf-8")
        code, out, _err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0)
        self.assertFalse(legacy.exists())
        self.assertIn(f"Deleted file: {legacy}", out)


    # -- review round 2 regressions ----------------------------------------

    def test_delete_scrubs_finding_rows_from_lane_sidecars(self) -> None:
        dup = self.tmp / "dup.md"
        dup.write_text("Title: Placeholder alpha\nClass: native-module-abuse\nFile: src/file1.js:1\n"
                       "Description: ZQXSECRET duplicate note.\n", encoding="utf-8")
        self.assertEqual(self._run("--from-file", str(dup), "--link-duplicate-comment")[0], 1)
        comments = self.layout.ledgers_root / "manual_comments.jsonl"
        with comments.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"fid": "D02", "raw_note": "keep me"}) + "\n")
        stream = self.layout.ledgers_root / "findings.jsonl"
        stream.write_text(json.dumps({"event": "finding_seen", "finding": {"fid": "D01", "title": "ZQXSECRET"}}) + "\n"
                          + json.dumps({"fid": "D01", "description": "ZQXSECRET raw"}) + "\n"
                          + json.dumps({"fid": "D03", "description": "other"}) + "\n", encoding="utf-8")
        comments.chmod(0o640)
        self._archive("D01")
        code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0, err)
        self.assertIn(f"Removed 1 row(s) for D01: {comments}", out)
        self.assertIn(f"Removed 2 row(s) for D01: {stream}", out)
        for path in (comments, stream):
            self.assertNotIn("ZQXSECRET", path.read_text(encoding="utf-8"))
        self.assertEqual([json.loads(line)["fid"] for line in comments.read_text().splitlines()], ["D02"])
        self.assertEqual([json.loads(line)["fid"] for line in stream.read_text().splitlines()], ["D03"])
        self.assertEqual(stat.S_IMODE(comments.stat().st_mode), 0o640)

    def test_malformed_or_symlinked_sidecar_refuses_before_commit(self) -> None:
        self._archive("D01")
        comments = self.layout.ledgers_root / "manual_comments.jsonl"
        # An unterminated partial tail is an append in flight: kept, not fatal.
        comments.write_text('{"fid": "D02", "raw_note": "x"}\n{"fid": "D0', encoding="utf-8")
        from agents.ledger_tombstones import _plan_sidecar_scrub
        self.assertEqual(_plan_sidecar_scrub(self.layout, "D01"), [])
        # A damaged committed line refuses the delete before anything changes.
        comments.write_text('{"fid": "D01", "raw_note": "x"}\n{"fid": "D0\n{"fid": "D02"}\n', encoding="utf-8")
        before = self.ledger.read_bytes()
        code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 1)
        self.assertIn("manual_comments.jsonl line 2 is unreadable", err)
        self.assertEqual(out, "")
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(self.tombstone.exists())
        outside = self.tmp / "outside-comments.jsonl"
        outside.write_text('{"fid": "D01"}\n', encoding="utf-8")
        comments.unlink()
        comments.symlink_to(outside)
        self.assertEqual(self._run("--delete-finding", "D01")[0], 1)
        self.assertEqual(outside.read_text(encoding="utf-8"), '{"fid": "D01"}\n')
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_comment_append_waits_for_ledger_lock(self) -> None:
        from agents.manual_hunter import DuplicateCommentStore
        store = DuplicateCommentStore(PROGRAM, family=FAMILY, lane=LANE, root_override=self.root)
        done = threading.Event()
        lock_path = self.layout.ledgers_root / "ledger.lock"
        with lock_path.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            worker = threading.Thread(target=lambda: (store.append(fid="D02", source_label="t", source_path=None,
                                                                    raw_text="note", parsed_finding={}), done.set()))
            worker.start()
            time.sleep(0.3)
            self.assertFalse(done.is_set(), "comment append must wait for the ledger lock")
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        worker.join(timeout=10)
        self.assertTrue(done.is_set())

    def test_unterminated_tombstone_tail_is_ignored_and_trimmed(self) -> None:
        self._delete_d01()
        with self.tombstone.open("ab") as handle:
            handle.write(b'{"schema": "bbh-deleted-finding/2", "event": "del')
        # The committed D01 tombstone still blocks; unrelated ingest works.
        code, _out, err = self._run("--from-file", str(self.tmp / "Placeholder_alpha.md"))
        self.assertEqual(code, 1)
        self.assertIn("Skipped tombstoned finding D01", err)
        self.assertEqual(self._ingest("Unrelated delta", "src/delta.js:4"), 0)
        self._archive("D02")
        self.assertEqual(self._run("--delete-finding", "D02")[0], 0)
        lines = self.tombstone.read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(line)["fid"] for line in lines], ["D01", "D02"])
        # A damaged committed line still fails closed.
        self.tombstone.write_text("not json\n" + self.tombstone.read_text(encoding="utf-8"), encoding="utf-8")
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        with self.assertRaises(CorruptTombstoneLogError):
            ledger.check({"file": "z.js", "line": 1, "class_name": "xss", "type": "xss"})

    def test_leftover_tombstone_for_live_fid_does_not_block_updates(self) -> None:
        row = self._findings()["D01"]
        from agents.ledger_tombstones import identity_key
        self.tombstone.write_text(json.dumps({"schema": "bbh-deleted-finding/2", "event": "deleted", "fid": "D01",
                                              "identity_key": identity_key(row)}) + "\n", encoding="utf-8")
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        err = io.StringIO()
        with redirect_stderr(err):
            updated = ledger.update({**row, "severity": "HIGH"})
            checked = ledger.check(dict(row))
        self.assertFalse(updated.get("tombstoned"))
        self.assertFalse(checked[2].get("tombstoned"))
        self.assertEqual(self._findings()["D01"]["severity"], "HIGH")
        self.assertNotIn("Skipped tombstoned", err.getvalue())

    def test_post_commit_failure_exits_3_with_warning(self) -> None:
        self._archive("D01")
        from unittest.mock import patch as mock_patch
        self._write_generated_report("D01")
        with mock_patch("agents.ledger_tombstones._refresh_and_persist", side_effect=RuntimeError("boom")), \
                mock_patch("agents.ledger_tombstones._still_safe_to_unlink", side_effect=PermissionError("denied")):
            code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 3)
        self.assertIn("Finding deleted: D01", out)
        self.assertIn("Warning: navigation refresh failed after delete: RuntimeError: boom", err)
        self.assertIn("Warning: could not delete generated file", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("D01", self._findings())

    def test_pre_commit_failure_is_a_clean_refusal(self) -> None:
        self._archive("D01")
        before = self.ledger.read_bytes()
        from unittest.mock import patch as mock_patch
        with mock_patch("agents.ledger_tombstones.classify_artifacts", side_effect=OSError("io error")):
            code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("[manual_hunter] delete of D01 failed before commit: OSError"))
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(self.tombstone.exists())

    def test_unreadable_evidence_is_kept_not_fatal(self) -> None:
        self._archive("D01")
        evidence = Path(self._findings()["D01"]["report_dir"]) / "EVIDENCE.md"
        evidence.chmod(0)
        self.addCleanup(evidence.chmod, 0o600)
        code, out, _err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0)
        self.assertIn(f"Kept (unreadable (PermissionError); left in place): {evidence}", out)

    def test_missing_lane_is_refused_without_creating_anything(self) -> None:
        web_lane = self.root / FAMILY / PROGRAM / "web"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([PROGRAM, "--family", FAMILY, "--lane", "web", "--root", str(self.root), "--delete-finding", "D01"])
        self.assertEqual(code, 1)
        self.assertIn("lane has no ledger", err.getvalue())
        self.assertFalse(web_lane.exists())

    def test_actor_without_delete_is_a_usage_error(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            main([*self.base, "--actor", "x"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--actor is only valid with --delete-finding", err.getvalue())

    def test_loose_identity_match_only_where_bounty_core_uses_it(self) -> None:
        record = self._delete_d01()
        loose = {"file": record["file"], "class_name": record["class_name"]}
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        with redirect_stderr(io.StringIO()):
            self.assertTrue(ledger.check(dict(loose))[2].get("tombstoned"))  # ledger_check matches (file, class)
            updated = ledger.update(dict(loose))  # ledger_add matches the full key only
        self.assertFalse(updated.get("tombstoned"))
        added = update_team_finding(PROGRAM, {"fid": "D09", **loose}, family=FAMILY, lane=LANE, root_override=self.root)
        self.assertFalse(added.get("tombstoned"))


    # -- review round 3 regressions ----------------------------------------

    def test_unicode_line_separators_in_type_and_actor_do_not_corrupt_log(self) -> None:
        for fid, separator in (("D01", "\u2028"), ("D02", "\u0085")):
            patch = self.tmp / f"type-{fid}.json"
            patch.write_text(json.dumps({"type": f"sep{separator}type", "status": "archive"}), encoding="utf-8")
            self.assertEqual(self._run("--edit-finding", fid, "--patch-file", str(patch))[0], 0)
            code, _out, err = self._run("--delete-finding", fid, "--actor", f"board{separator}x")
            self.assertEqual(code, 0, err)
        raw = self.tombstone.read_bytes()
        raw.decode("ascii")  # ASCII-only events
        self.assertEqual(raw.count(b"\n"), 2)
        events = [json.loads(line) for line in raw.split(b"\n") if line]
        self.assertEqual([e["deleted_by"] for e in events], ["board\u2028x", "board\u0085x"])
        self.assertEqual(events[0]["identity_key"][3], "sep\u2028type")
        # A following ingest and a second delete still work in this lane.
        self.assertEqual(self._ingest("After separators", "src/after.js:7"), 0)
        self.assertEqual(self._ingest("Newest", "src/newest.js:8"), 0)
        self._archive("D04")
        self.assertEqual(self._run("--delete-finding", "D04")[0], 0)
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ledger.check({"file": "src/file1.js", "line": 1, "class_name": "native-module-abuse",
                                           "type": "sep\u2028type"})[:2], (True, "D01"))

    def test_sidecar_rows_with_raw_separators_are_preserved_byte_for_byte(self) -> None:
        stream = self.layout.ledgers_root / "findings.jsonl"
        other = json.dumps({"fid": "D02", "note": "keep\u2028me\u0085too"}, ensure_ascii=False).encode("utf-8")
        mine = json.dumps({"fid": "D01", "note": "drop\u2029me"}, ensure_ascii=False).encode("utf-8")
        stream.write_bytes(other + b"\n" + mine + b"\n" + other + b"\n")
        self._archive("D01")
        code, out, err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0, err)
        self.assertIn(f"Removed 1 row(s) for D01: {stream}", out)
        self.assertEqual(stream.read_bytes(), other + b"\n" + other + b"\n")

    def test_lockless_findings_append_during_delete_survives(self) -> None:
        stream = self.layout.ledgers_root / "findings.jsonl"
        stream.write_text(json.dumps({"event": "finding_seen", "finding": {"fid": "D01", "title": "x"}}) + "\n",
                          encoding="utf-8")
        self._archive("D01")
        import agents.ledger_tombstones as lt
        from unittest.mock import patch as mock_patch
        original = lt.classify_artifacts

        def racing(layout, finding):  # Bounty Core add_finding appends outside the lock
            with stream.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"event": "finding_seen", "finding": {"fid": "D02", "title": "CONCURRENT"}}) + "\n")
            return original(layout, finding)

        with mock_patch("agents.ledger_tombstones.classify_artifacts", side_effect=racing):
            self.assertEqual(self._run("--delete-finding", "D01")[0], 0)
        rows = [json.loads(line) for line in stream.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["finding"]["title"] for row in rows], ["CONCURRENT"])

    def test_finding_updated_rows_keyed_by_identity_are_removed(self) -> None:
        stream = self.layout.ledgers_root / "findings.jsonl"
        identity = f"harness-fid:{PROGRAM}:{FAMILY}:{LANE}:D01"
        stream.write_text(json.dumps({"event": "finding_updated", "identity": identity,
                                      "patch": {"description": "ZQXTEXT"}, "before": {"description": "old ZQXTEXT"}})
                          + "\n" + json.dumps({"event": "finding_updated", "identity": identity[:-1] + "2"}) + "\n",
                          encoding="utf-8")
        self._archive("D01")
        code, out, _err = self._run("--delete-finding", "D01")
        self.assertEqual(code, 0)
        self.assertIn(f"Removed 1 row(s) for D01: {stream}", out)
        self.assertNotIn("ZQXTEXT", stream.read_text(encoding="utf-8"))
        self.assertIn(identity[:-1] + "2", stream.read_text(encoding="utf-8"))

    def test_complete_tombstone_tail_without_newline_is_committed_and_terminated(self) -> None:
        self._delete_d01()
        data = self.tombstone.read_bytes()
        self.tombstone.write_bytes(data.rstrip(b"\n"))  # newline lost, event complete
        ledger = create_team_ledger_from_storage(PROGRAM, storage=self.layout, target_root=self.tmp, agent="team")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ledger.import_finding({"fid": "D01", "file": "q.js", "line": 1,
                                                    "class_name": "xss", "type": "xss"})[:2], (True, "D01"))
        self._archive("D02")
        self.assertEqual(self._run("--delete-finding", "D02")[0], 0)
        lines = self.tombstone.read_bytes().split(b"\n")
        self.assertEqual([json.loads(line)["fid"] for line in lines if line], ["D01", "D02"])
        self.assertTrue(self.tombstone.read_bytes().endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
