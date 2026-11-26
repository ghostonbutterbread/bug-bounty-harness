"""Failed-review output goes to the log folder, not the ledger; repair of existing ledgers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.base_team import review_logs
from agents.base_team import review as review_module
from agents.base_team.review import review_single_finding, stage2_ghost_review, stage2_review
from agents.base_team.review_logs import (
    ENTRY_CAP,
    SUMMARY_CAP,
    finding_log_id,
    log_root,
    sanitize_component,
    write_log,
)
from agents import ledger_review_errors
from agents.ledger_review_errors import CompactAborted, compact_review_errors
from agents.test_ledger_write_hot_path import PROGRAM, _LaneCase

HUGE = 3 * 1024 * 1024  # several MB of Codex-style session output


def _codex_blob(size: int = HUGE) -> str:
    line = '{"type":"exec","command":"rg -n token src/","stdout":"src/a.py:1: token = x; y"}\n'
    return (line * (size // len(line) + 1))[:size]


class _TempLogDir(unittest.TestCase):
    def setUp(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.tmp = Path(tempdir.name)
        self.logs = self.tmp / "logs"
        env = patch.dict(os.environ, {"BBH_LOG_DIR": str(self.logs), "HOME": str(self.tmp / "home")})
        env.start()
        self.addCleanup(env.stop)


class LogRootTests(unittest.TestCase):
    def test_env_override_then_xdg_then_home_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"BBH_LOG_DIR": f"{tmp}/x", "XDG_STATE_HOME": f"{tmp}/s", "HOME": f"{tmp}/h"}):
                self.assertEqual(log_root(), Path(f"{tmp}/x"))
            with patch.dict(os.environ, {"XDG_STATE_HOME": f"{tmp}/s", "HOME": f"{tmp}/h"}):
                os.environ.pop("BBH_LOG_DIR", None)
                self.assertEqual(log_root(), Path(f"{tmp}/s/bug_bounty_harness/logs"))
            with patch.dict(os.environ, {"HOME": f"{tmp}/h"}):
                os.environ.pop("BBH_LOG_DIR", None)
                os.environ.pop("XDG_STATE_HOME", None)
                self.assertEqual(log_root(), Path(f"{tmp}/h/.local/state/bug_bounty_harness/logs"))

    def test_sanitize_components(self) -> None:
        self.assertEqual(sanitize_component("F/0001"), "F_0001")
        self.assertEqual(sanitize_component(".."), "unknown")
        self.assertEqual(sanitize_component("../../etc"), "_.._etc")
        self.assertEqual(sanitize_component(".hidden"), "hidden")
        self.assertEqual(sanitize_component(""), "unknown")
        self.assertEqual(sanitize_component(None), "unknown")
        for value in ("a/b", "..", ".x", "", "/abs", "x\x00y"):
            out = sanitize_component(value)
            self.assertNotIn("/", out)
            self.assertFalse(out.startswith("."))
            self.assertNotIn(out, ("", ".", ".."))

    def test_finding_log_id_preference(self) -> None:
        self.assertEqual(finding_log_id({"fid": "F1", "harness_fid": "H1"}), "F1")
        self.assertEqual(finding_log_id({"harness_fid": "H/1"}), "H_1")
        hashed = finding_log_id({"title": "Some title"})
        self.assertTrue(hashed.startswith("h") and len(hashed) == 13)
        self.assertEqual(finding_log_id({}), "unknown")


class WriteLogTests(_TempLogDir):
    def test_modes_layout_and_no_overwrite(self) -> None:
        first = write_log("one", category="review", program="../prog", lane=".apk", name="F/1")
        second = write_log("two", category="review", program="../prog", lane=".apk", name="F/1")
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, self.logs / "review" / "_prog" / "apk")
        self.assertRegex(first.name, r"^F_1-\d{8}T\d{6}Z-[0-9a-f]{6}\.log$")
        self.assertEqual((first.read_text(), second.read_text()), ("one", "two"))
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
        for directory in (self.logs, self.logs / "review", first.parent.parent, first.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700, directory)
        self.assertEqual([p for p in first.parent.iterdir() if p.name.startswith(".")], [])

    def test_name_collision_retries_instead_of_overwriting(self) -> None:
        fixed = "F1-20260101T000000Z-aaaaaa.log"
        directory = self.logs / "review" / "p" / "l"
        directory.mkdir(parents=True)
        (directory / fixed).write_text("keep")
        tokens = iter(["aaaaaa", "bbbbbb"])
        with patch.object(review_logs, "_utc_stamp", return_value="20260101T000000Z"), \
                patch.object(review_logs.secrets, "token_hex", side_effect=lambda _n: next(tokens)):
            path = write_log("new", category="review", program="p", lane="l", name="F1")
        self.assertEqual((directory / fixed).read_text(), "keep")
        self.assertEqual(path.name, "F1-20260101T000000Z-bbbbbb.log")


def _review(finding, run_review_cli, **kwargs):
    return review_single_finding(
        finding, Path("/nonexistent"),
        build_review_prompt=lambda _f, _p: "prompt",
        run_review_cli=run_review_cli,
        extract_json_object=json.loads,
        normalize_review_tier=lambda v: str(v or "INCONCLUSIVE").upper(),
        review_timeout=1,
        **kwargs,
    )


class ReviewWriterTests(_TempLogDir):
    def failing(self, blobs: dict[str, str]):
        def run(cli, _prompt, timeout):
            raise RuntimeError(blobs[cli])
        return run

    def test_huge_codex_error_is_logged_and_capped(self) -> None:
        blob = _codex_blob()
        reviewed = _review({"fid": "F0007", "title": "t"}, self.failing({"claude": "claude exited 1: usage limit", "codex": blob}),
                           program="prog", lane="web")
        self.assertEqual(reviewed["review_tier"], "INCONCLUSIVE")
        error = reviewed["review_error"]
        self.assertLessEqual(len(error), SUMMARY_CAP)
        self.assertTrue(error.startswith("claude: claude exited 1"))
        self.assertIn("; codex: ", error)
        log = Path(reviewed["review_log"])
        self.assertTrue(error.endswith(f" (full log: {log})"))
        self.assertEqual(log.parent, self.logs / "review" / "prog" / "web")
        self.assertTrue(log.name.startswith("F0007-"))
        self.assertEqual(log.read_text(encoding="utf-8"), f"claude: claude exited 1: usage limit; codex: {blob}")

    def test_both_long_errors_keep_both_prefixes(self) -> None:
        reviewed = _review({"fid": "F1"}, self.failing({"claude": "c" * 5000, "codex": "x" * 5000}))
        claude_part, codex_part = reviewed["review_error"].split("; codex: ", 1)
        self.assertTrue(claude_part.startswith("claude: "))
        self.assertLessEqual(len(claude_part), ENTRY_CAP)
        self.assertLessEqual(len(reviewed["review_error"]), SUMMARY_CAP)
        # Program/lane fall back to "unknown" when neither caller nor finding gives them.
        self.assertEqual(Path(reviewed["review_log"]).parent, self.logs / "review" / "unknown" / "unknown")

    def test_unwritable_log_dir_still_returns_inconclusive(self) -> None:
        self.logs.write_text("not a directory")  # any write below it fails
        reviewed = _review({"fid": "F1", "review_log": "/stale.log"}, self.failing({"claude": "boom", "codex": _codex_blob(100_000)}))
        self.assertEqual(reviewed["review_tier"], "INCONCLUSIVE")
        self.assertIn(" (full log not saved: ", reviewed["review_error"])
        self.assertLessEqual(len(reviewed["review_error"]), SUMMARY_CAP)
        self.assertNotIn("review_log", reviewed)

    def test_successful_review_writes_no_log(self) -> None:
        out = json.dumps({"tier": "DORMANT", "safety_assumption": "a"})
        reviewed = _review({"fid": "F1"}, lambda *_a, **_k: out)
        self.assertNotIn("review_error", reviewed)
        self.assertFalse(self.logs.exists())

    def test_stage2_exception_path_and_last_error_are_capped(self) -> None:
        blob = _codex_blob()
        last: list[str | None] = []

        def explode(_finding, _path):
            raise RuntimeError(blob)

        _, dormant, _ = stage2_review(
            [{"fid": "F9"}], Path("/nonexistent"),
            review_single_finding=explode,
            normalize_review_tier=lambda v: str(v or "INCONCLUSIVE").upper(),
            set_last_review_error=last.append,
            program="prog", lane="api",
        )
        reviewed = dormant[0]
        self.assertEqual(reviewed["review_tier"], "INCONCLUSIVE")
        self.assertLessEqual(len(reviewed["review_error"]), SUMMARY_CAP)
        self.assertEqual(Path(reviewed["review_log"]).read_text(encoding="utf-8"), blob)
        self.assertEqual(last, [None, reviewed["review_error"]])
        self.assertLessEqual(len(last[-1]), SUMMARY_CAP)

    def test_ghost_review_default_reviewer_logs_under_program_and_lane(self) -> None:
        def fail(cli, _prompt, _timeout, *, workdir):
            raise RuntimeError(f"{cli} broke " + "z" * 10_000)

        with patch.object(review_module, "run_review_cli", side_effect=fail):
            _, dormant, _ = stage2_ghost_review(
                [{"fid": "F3", "severity": "high", "description": "d", "type": "idor", "file": "a.py:1"}],
                self.tmp, "prog", "web", write_reports=False,
            )
        reviewed = dormant[0]
        self.assertLessEqual(len(reviewed["review_error"]), SUMMARY_CAP)
        self.assertEqual(Path(reviewed["review_log"]).parent, self.logs / "review" / "prog" / "web")


class CompactReviewErrorsTests(_LaneCase):
    def setUp(self) -> None:
        super().setUp()
        self.logs = self.tmp / "logs"
        env = patch.dict(os.environ, {"BBH_LOG_DIR": str(self.logs)})
        env.start()
        self.addCleanup(env.stop)
        self.big = self.add_finding("Big one", 10)
        self.small = self.add_finding("Small one", 11)
        self.clean = self.add_finding("Clean one", 12)
        self.blob = "claude: Claude review failed: exit 1; codex: " + _codex_blob(1_000_000)

        def mutate(findings):
            for item in findings:
                if item["fid"] == self.big:
                    item["review_error"] = self.blob
                    item["review_tier"] = "INCONCLUSIVE"
                elif item["fid"] == self.small:
                    item["review_error"] = "claude: short failure"
        self.rewrite_ledger(mutate)

    def test_dry_run_reports_counts_and_writes_nothing(self) -> None:
        before = self.ledger_file().read_bytes()
        for extra in ((), ("--dry-run",)):
            rc, out, err = self.run_main("--compact-review-errors", *extra)
            self.assertEqual(rc, 0, out + err)
            self.assertIn(f"Would compact: {self.big} ({len(self.blob)} bytes)", out)
            self.assertIn(f"[dry-run] 1 finding(s), {len(self.blob)} bytes moved to logs; ledger {len(before)} -> ", out)
            self.assertIn("nothing written", out)
            self.assertNotIn(PROGRAM, out)
        self.assertEqual(self.ledger_file().read_bytes(), before)
        self.assertFalse(self.logs.exists())

    def test_apply_moves_only_oversized_values_and_second_apply_is_noop(self) -> None:
        before = {item["fid"]: item for item in self.findings()}
        dry = compact_review_errors(PROGRAM, family="binaries", lane="apk", root_override=self.root)
        with patch.object(ledger_review_errors, "_write_json_atomic", wraps=ledger_review_errors._write_json_atomic) as writer:
            rc, out, err = self.run_main("--compact-review-errors", "--apply")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(writer.call_count, 1)
        after = {item["fid"]: item for item in self.findings()}
        big = after[self.big]
        log = Path(big["review_log"])
        self.assertIn(f"Compacted: {self.big} ({len(self.blob)} bytes) -> {log}", out)
        self.assertIn("ledger rewritten", out)
        self.assertEqual(log.parent, self.logs / "review" / PROGRAM / "apk")
        self.assertTrue(log.name.startswith(f"{self.big}-compacted-"))
        self.assertEqual(hashlib.sha256(log.read_bytes()).hexdigest(), hashlib.sha256(self.blob.encode()).hexdigest())
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertLessEqual(len(big["review_error"]), SUMMARY_CAP)
        self.assertTrue(big["review_error"].startswith("claude: Claude review failed: exit 1; codex: "))
        self.assertTrue(big["review_error"].endswith(f" (full log: {log})"))
        self.assertEqual(big["review_tier"], "INCONCLUSIVE")
        # Every other field of every finding is unchanged.
        for fid, item in before.items():
            strip = lambda d: {k: v for k, v in d.items() if k not in ("review_error", "review_log")}
            self.assertEqual(strip(after[fid]), strip(item), fid)
        self.assertEqual(after[self.small]["review_error"], "claude: short failure")
        self.assertNotIn("review_log", after[self.small])
        self.assertNotIn("review_error", after[self.clean])
        actual_size = self.ledger_file().stat().st_size
        self.assertLess(actual_size, 100_000)
        self.assertLess(abs(dry.ledger_bytes_after - actual_size), 400)  # estimate is close

        snapshot = self.ledger_file().read_bytes()
        rc, out, _ = self.run_main("--compact-review-errors", "--apply")
        self.assertEqual(rc, 0)
        self.assertIn("No oversized review_error values; nothing to do", out)
        self.assertEqual(self.ledger_file().read_bytes(), snapshot)
        self.assertEqual(len(list(log.parent.iterdir())), 1)

    def test_concurrent_ledger_change_aborts_without_writing(self) -> None:
        real_write_log = ledger_review_errors.write_log

        def write_then_tamper(*args, **kwargs):
            path = real_write_log(*args, **kwargs)
            # A writer that ignores the lock changes the ledger mid-run.
            payload = json.loads(self.ledger_file().read_text(encoding="utf-8"))
            payload["findings"][-1]["title"] = "changed elsewhere"
            self.ledger_file().write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            return path

        with patch.object(ledger_review_errors, "write_log", side_effect=write_then_tamper):
            rc, out, err = self.run_main("--compact-review-errors", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertIn("ledger changed", err)
        tampered = self.findings()
        self.assertEqual(tampered[-1]["title"], "changed elsewhere")
        self.assertEqual(next(f for f in tampered if f["fid"] == self.big)["review_error"], self.blob)
        self.assertEqual(list((self.logs / "review" / PROGRAM / "apk").iterdir()), [])  # run's logs removed

    def test_log_write_or_verify_failure_writes_nothing(self) -> None:
        before = self.ledger_file().read_bytes()
        with patch.object(ledger_review_errors, "write_log", side_effect=OSError("disk full")):
            rc, _, err = self.run_main("--compact-review-errors", "--apply")
        self.assertEqual(rc, 1)
        self.assertIn("log write failed", err)
        self.assertEqual(self.ledger_file().read_bytes(), before)

        def short_write(text, **kwargs):
            return write_log(text[:-1], **kwargs)

        with patch.object(ledger_review_errors, "write_log", side_effect=short_write):
            with self.assertRaisesRegex(CompactAborted, "log verify failed"):
                compact_review_errors(PROGRAM, family="binaries", lane="apk", root_override=self.root, apply=True)
        self.assertEqual(self.ledger_file().read_bytes(), before)

    def test_flags_validation(self) -> None:
        with self.assertRaises(SystemExit):
            self.run_main("--apply")  # --apply alone is refused
        rc, _, err = self.run_main_lane("exe", "--compact-review-errors")
        self.assertEqual(rc, 1, err)

    def run_main_lane(self, lane: str, *extra: str):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from agents.manual_hunter import main
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([PROGRAM, "--family", "binaries", "--lane", lane, "--root", str(self.root), *extra])
        return rc, out.getvalue(), err.getvalue()


if __name__ == "__main__":
    unittest.main()
