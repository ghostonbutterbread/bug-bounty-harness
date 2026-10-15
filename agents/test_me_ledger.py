"""Tests for agents.me_ledger CLI ledger adapter usage."""

from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agents import ledger as ledger_adapter  # noqa: E402
from agents import me_ledger  # noqa: E402


class MeLedgerCliAdapterTests(unittest.TestCase):
    def test_ledger_functions_are_imported_from_harness_adapter(self) -> None:
        self.assertIs(me_ledger.ledger_add, ledger_adapter.ledger_add)
        self.assertIs(me_ledger.ledger_check, ledger_adapter.ledger_check)
        self.assertIs(me_ledger.ledger_get, ledger_adapter.ledger_get)
        self.assertIs(me_ledger.ledger_list, ledger_adapter.ledger_list)
        self.assertIs(me_ledger.ledger_path, ledger_adapter.ledger_path)

    @patch("agents.me_ledger.ledger_get")
    @patch("agents.me_ledger.ledger_check")
    def test_cmd_check_uses_adapter_functions_with_lane_and_family(
        self,
        mock_check,
        mock_get,
    ) -> None:
        finding = {
            "fid": "D03",
            "class_name": "native-module-abuse",
            "file": "src/preload.js",
            "sightings": [{"snapshot_id": "snap-1"}],
        }
        mock_check.return_value = (True, "D03")
        mock_get.return_value = finding
        args = argparse.Namespace(
            program="notion",
            file="./src\\preload.js",
            class_name=" Native-Module-Abuse ",
            lane="web",
            family="web_bounty",
            root_override="/tmp/me-root",
            snapshot=None,
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = me_ledger.cmd_check(args)

        self.assertEqual(rc, 0)
        mock_check.assert_called_once_with(
            "notion",
            "src/preload.js",
            "native-module-abuse",
            lane="web",
            family="web_bounty",
            root_override="/tmp/me-root",
        )
        mock_get.assert_called_once_with(
            "notion",
            "D03",
            lane="web",
            family="web_bounty",
            root_override="/tmp/me-root",
        )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload,
            {
                "exists": True,
                "fid": "D03",
                "finding": finding,
            },
        )

    @patch("agents.me_ledger._default_run_id", return_value="run-1")
    @patch(
        "agents.me_ledger._resolve_snapshot",
        return_value={"snapshot_id": "snap-1", "version_label": "v2.2.0"},
    )
    @patch("agents.me_ledger.ledger_get")
    @patch("agents.me_ledger.ledger_add")
    @patch("agents.me_ledger.update_team_finding")
    def test_cmd_add_uses_adapter_functions_with_lane_and_family(
        self,
        mock_update,
        mock_add,
        mock_get,
        _mock_resolve_snapshot,
        _mock_default_run_id,
    ) -> None:
        entry = {
            "fid": "B07",
            "type": "SQLite IPC",
            "class_name": "native-module-abuse",
            "file": "src/preload.js",
            "severity": "HIGH",
        }
        mock_add.return_value = (True, "B07")
        mock_get.return_value = entry
        args = argparse.Namespace(
            program="notion",
            type="SQLite IPC",
            class_name=" Native-Module-Abuse ",
            file="./src\\preload.js",
            severity=" high ",
            scoring_authority="Bugcrowd VRT",
            severity_rationale="Confirmed session cookie theft via stored XSS on /settings.",
            program_constraint="",
            agent="unit-agent",
            fid_prefix="B",
            version_label="v2.2.0",
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = me_ledger.cmd_add(args)

        self.assertEqual(rc, 0)
        mock_add.assert_called_once_with(
            "notion",
            {
                "type": "SQLite IPC",
                "class_name": "native-module-abuse",
                "file": "src/preload.js",
                "severity": "HIGH",
                "review_tier": "PENDING_REVIEW",
                "status": "active",
                "agent": "unit-agent",
                "fid_prefix": "B",
                "scoring_authority": "Bugcrowd VRT",
                "severity_rationale": "Confirmed session cookie theft via stored XSS on /settings.",
            },
            "snap-1",
            "v2.2.0",
            "run-1",
            "unit-agent",
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
        )
        mock_update.assert_called_once_with(
            "notion", {"fid": "B07"}, family="binaries", lane="exe",
            root_override="/tmp/me-root", write_report=False, refresh=True,
        )
        mock_get.assert_called_once_with(
            "notion",
            "B07",
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
        )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["added"], True)
        self.assertEqual(payload["duplicate"], False)
        self.assertEqual(payload["snapshot_id"], "snap-1")
        self.assertEqual(payload["version_label"], "v2.2.0")
        self.assertEqual(payload["finding"], entry)

    @patch("agents.me_ledger.ledger_path", return_value=Path("/tmp/test-ledger.json"))
    @patch("agents.me_ledger.ledger_list")
    def test_cmd_list_uses_adapter_functions_with_lane_and_family(
        self,
        mock_list,
        mock_path,
    ) -> None:
        findings = [{"fid": "D01", "class_name": "dom-xss"}]
        mock_list.return_value = findings
        args = argparse.Namespace(
            program="My Program",
            snapshot="snap-1",
            version_label="v2.2.0",
            lane="api",
            family="web_bounty",
            root_override="/tmp/me-root",
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = me_ledger.cmd_list(args)

        self.assertEqual(rc, 0)
        mock_list.assert_called_once_with(
            "My Program",
            snapshot_id="snap-1",
            version_label="v2.2.0",
            lane="api",
            family="web_bounty",
            root_override="/tmp/me-root",
        )
        mock_path.assert_called_once_with(
            "My Program",
            lane="api",
            family="web_bounty",
            root_override="/tmp/me-root",
        )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload,
            {
                "program": "My_Program",
                "ledger_path": "/tmp/test-ledger.json",
                "findings": findings,
            },
        )

    @patch("agents.me_ledger.ledger_path", return_value=Path("/tmp/test-ledger.json"))
    @patch("agents.me_ledger.ledger_list")
    def test_cmd_list_hides_closed_findings_unless_requested(self, mock_list, _mock_path) -> None:
        findings = [
            {"fid": "D01", "status": "active"},
            {"fid": "D02", "status": "confirmed"},
            {"fid": "D03", "submission": {"state": "submitted"}},
            {"fid": "D04", "submission": {"state": "dropped", "result": "duplicate"}},
            {"fid": "D05", "submission": {"state": "not_submitted", "result": "duplicate"}},
        ]
        mock_list.return_value = findings
        args = argparse.Namespace(
            program="demo", snapshot=None, version_label=None, lane="web", family="web_bounty", root_override="/tmp/me-root"
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(me_ledger.cmd_list(args), 0)
        self.assertEqual([item["fid"] for item in json.loads(stdout.getvalue())["findings"]], ["D01"])

        args.include_closed = True
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(me_ledger.cmd_list(args), 0)
        self.assertEqual([item["fid"] for item in json.loads(stdout.getvalue())["findings"]], ["D01", "D02", "D03", "D04", "D05"])

    @patch("agents.me_ledger.ledger_get")
    def test_get_by_fid_returns_exact_closed_finding_without_listing(self, mock_get) -> None:
        finding = {"fid": "D05", "submission": {"state": "not_submitted", "result": "duplicate"}}
        mock_get.return_value = finding
        args = me_ledger.build_parser().parse_args([
            "get", "--program", "demo", "--family", "web_bounty", "--lane", "web", "--fid", "D05"
        ])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(args.func(args), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"exists": True, "fid": "D05", "finding": finding})
        mock_get.assert_called_once_with("demo", "D05", lane="web", family="web_bounty", root_override=None)

    @patch("agents.me_ledger.ledger_get", return_value=None)
    def test_get_by_fid_reports_missing(self, mock_get) -> None:
        args = me_ledger.build_parser().parse_args([
            "get", "--program", "demo", "--family", "web_bounty", "--lane", "web", "--fid", "D99"
        ])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(args.func(args), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"exists": False, "fid": "D99", "finding": None})
        mock_get.assert_called_once()

    @patch("agents.me_ledger.ledger_list")
    def test_prior_work_returns_only_exact_pair_dispositions(self, mock_list) -> None:
        mock_list.return_value = [
            {"fid": "D01", "file": "src/flow.js", "class_name": "idor", "review_tier": "CONFIRMED",
             "description": "private proof"},
            {"fid": "D02", "file": "src/flow.js", "class_name": "idor", "submission": {"state": "submitted",
             "report": "H1-123", "result": "duplicate"}, "poc": "private payload"},
            {"fid": "D03", "file": "src/flow.js", "class_name": "idor", "status": "active"},
            {"fid": "D04", "file": "src/flow.js", "class_name": "xss", "submission": {"state": "submitted"}},
            {"fid": "D05", "file": "src/other.js", "class_name": "idor", "status": "confirmed"},
            {"fid": "D06", "file": "src/flow.js", "class_name": "idor", "current": {"review_tier": "CONFIRMED"}},
            {"fid": "D07", "file": "src/flow.js", "class_name": "idor", "submission": {"result": "duplicate"}},
        ]
        args = me_ledger.build_parser().parse_args([
            "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
            "--root", "/tmp/me-root", "--file", "./src\\flow.js", "--class-name", " IDOR ",
        ])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(args.func(args), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {
            "program": "demo", "file": "src/flow.js", "class_name": "idor", "known_prior_work": True,
            "confirmed": True, "submitted": True, "duplicate": True,
        })
        mock_list.assert_called_once_with("demo", lane="web", family="web_bounty", root_override="/tmp/me-root")

    @patch("agents.me_ledger.ledger_list", return_value=[])
    def test_prior_work_miss_is_not_claimed_as_global_novelty(self, mock_list) -> None:
        args = me_ledger.build_parser().parse_args([
            "prior-work", "--program", "demo", "--file", "src/flow.js", "--class-name", "idor",
        ])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(args.func(args), 0)
        response = json.loads(stdout.getvalue())
        self.assertEqual(response["known_prior_work"], False)
        self.assertEqual((response["confirmed"], response["submitted"], response["duplicate"]), (False, False, False))
        mock_list.assert_called_once()

    def test_prior_work_reads_canonical_ledger_without_report_content(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            is_new, fid = ledger_adapter.ledger_add(
                "demo", {
                    "file": "src/flow.js", "class_name": "idor", "type": "cross-account object read",
                    "review_tier": "CONFIRMED", "submission": {"state": "submitted", "report": "H1-123"},
                    "description": "private proof must not enter the prior-work response",
                }, "snapshot-1", "v1", "run-1", "test-agent",
                lane="web", family="web_bounty", root_override=root,
            )
            self.assertTrue(is_new)
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--root", root, "--file", "src/flow.js", "--class-name", "idor",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            response = json.loads(stdout.getvalue())
            self.assertEqual(response, {
                "program": "demo", "file": "src/flow.js", "class_name": "idor",
                "known_prior_work": True, "confirmed": True, "submitted": True, "duplicate": False,
            })
            self.assertNotIn(fid, stdout.getvalue())
            self.assertNotIn("private proof", stdout.getvalue())
            self.assertNotIn("H1-123", stdout.getvalue())

            _, normalized_fid = ledger_adapter.ledger_add(
                "demo", {
                    "file": "src/render.js", "class_name": "dom_xss", "type": "stored render",
                    "review_tier": "CONFIRMED",
                }, "snapshot-1", "v1", "run-2", "test-agent",
                lane="web", family="web_bounty", root_override=root,
            )
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--root", root, "--file", "src/render.js", "--class-name", "dom_xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            self.assertEqual(json.loads(stdout.getvalue()), {
                "program": "demo", "file": "src/render.js", "class_name": "dom-xss",
                "known_prior_work": True, "confirmed": True, "submitted": False, "duplicate": False,
            })
            self.assertNotIn(normalized_fid, stdout.getvalue())

    def test_prior_work_recovers_legacy_web_label_from_one_evidenced_route(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            is_new, fid = ledger_adapter.ledger_add(
                "demo", {
                    "file": "Next.js", "asset": "Next.js", "class_name": "dom-xss",
                    "description": (
                        "## Summary\n"
                        "`https://auth.example.test/im-logged-in` is a Next.js bridge page. "
                        "Login at https://auth.example.test/ and return to "
                        "https://auth.example.test/im-logged-in?code=x. Private proof."
                    ),
                    "impact": "`https://auth.example.test/im-logged-in` is affected",
                    "review_tier": "CONFIRMED", "status": "confirmed",
                    "submission": {"state": "submitted", "result": "duplicate"},
                }, "snapshot-1", "v1", "run-1", "test-agent",
                lane="web", family="web_bounty", root_override=root,
            )
            self.assertTrue(is_new)

            def lookup(file_name: str, lane: str = "web") -> dict:
                args = me_ledger.build_parser().parse_args([
                    "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", lane,
                    "--root", root, "--file", file_name, "--class-name", "dom_xss",
                ])
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    self.assertEqual(args.func(args), 0)
                self.assertNotIn(fid, stdout.getvalue())
                self.assertNotIn("Private proof", stdout.getvalue())
                return json.loads(stdout.getvalue())

            match = lookup("https://AUTH.example.test/im-logged-in?code=other")
            self.assertEqual((match["known_prior_work"], match["confirmed"], match["submitted"], match["duplicate"]),
                             (True, True, True, True))
            self.assertFalse(lookup("https://auth.example.test/im-logged-in-other")["known_prior_work"])
            self.assertFalse(lookup("https://auth.example.test/other")["known_prior_work"])
            self.assertFalse(lookup("https://other.example.test/im-logged-in")["known_prior_work"])
            self.assertFalse(lookup("https://auth.example.test/im-logged-in", lane="api")["known_prior_work"])

    def test_ambiguous_legacy_routes_report_incomplete_without_false_positive(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "Framework", "class_name": "dom-xss", "review_tier": "CONFIRMED",
            "description": "Affected at https://auth.example.test/one.\nAffected at https://auth.example.test/two.",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://auth.example.test/one", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["known_prior_work"])
            self.assertTrue(result["identity_incomplete"])

    def test_explicit_source_file_is_not_replaced_by_incidental_url(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "src/app.js", "class_name": "dom-xss", "review_tier": "CONFIRMED",
            "description": "Further context at https://auth.example.test/other",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://auth.example.test/other", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["known_prior_work"])
            self.assertNotIn("identity_incomplete", result)

    def test_legacy_prose_does_not_claim_incidental_documentation_route(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "App.js", "class_name": "dom-xss", "review_tier": "CONFIRMED",
            "description": "App.js sink; see documentation at `https://docs.example.test/guide`",
        }, {
            "file": "Next.js", "class_name": "dom-xss", "review_tier": "CONFIRMED",
            "description": "Affected root `https://auth.example.test/` is a Next.js page. See `https://docs.example.test/guide`",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://docs.example.test/guide", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            self.assertFalse(json.loads(stdout.getvalue())["known_prior_work"])

    def test_ordinary_affected_route_prose_is_recovered(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "Next.js", "class_name": "dom-xss", "status": "confirmed",
            "description": "Confirmed DOM-XSS at https://auth.example.test/im-logged-in.",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://auth.example.test/im-logged-in", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            self.assertTrue(json.loads(stdout.getvalue())["known_prior_work"])

    def test_negated_route_claim_does_not_stop_work(self) -> None:
        for description in (
            "Confirmed not affected at https://docs.example.test/guide. The page uses Next.js.",
            "Confirmed DOM-XSS at https://docs.example.test/guide is not affected. The vulnerable route was not identified.",
            "## Summary\n`https://docs.example.test/guide` is not affected. It uses Next.js.",
            "## Summary\n`https://docs.example.test/guide` is a Next.js documentation page; the affected route was not identified.",
            "## Summary\nhttps://docs.example.test/guide is a Next.js documentation page; the affected route was not identified.",
        ):
            with self.subTest(description=description), patch("agents.me_ledger.ledger_list", return_value=[{
                "file": "Next.js", "class_name": "dom-xss", "status": "confirmed",
                "description": description,
            }]):
                args = me_ledger.build_parser().parse_args([
                    "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                    "--file", "https://docs.example.test/guide", "--class-name", "dom-xss",
                ])
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    self.assertEqual(args.func(args), 0)
                self.assertFalse(json.loads(stdout.getvalue())["known_prior_work"])

    def test_explicit_web_route_does_not_strip_valid_trailing_path_period(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "https://auth.example.test/path.", "class_name": "dom-xss", "status": "confirmed",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://auth.example.test/path", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            self.assertFalse(json.loads(stdout.getvalue())["known_prior_work"])

    def test_legacy_summary_route_preserves_valid_trailing_period(self) -> None:
        with patch("agents.me_ledger.ledger_list", return_value=[{
            "file": "Framework", "class_name": "dom-xss", "status": "confirmed",
            "description": "## Summary\n`https://auth.example.test/path.` is a Framework page.",
        }]):
            args = me_ledger.build_parser().parse_args([
                "prior-work", "--program", "demo", "--family", "web_bounty", "--lane", "web",
                "--file", "https://auth.example.test/path.", "--class-name", "dom-xss",
            ])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(args.func(args), 0)
            self.assertTrue(json.loads(stdout.getvalue())["known_prior_work"])

    @patch("agents.me_ledger._default_run_id", return_value="run-1")
    @patch(
        "agents.me_ledger._resolve_snapshot",
        return_value={"snapshot_id": "snap-1", "version_label": "v2.2.0"},
    )
    @patch("agents.me_ledger._load_shared_brain_candidates", return_value={"dom-xss": ["src/preload.js"]})
    @patch("agents.me_ledger.CoverageStore")
    def test_cmd_cover_uses_explicit_root_for_coverage_store(
        self,
        mock_store_cls,
        _mock_candidates,
        _mock_resolve_snapshot,
        _mock_default_run_id,
    ) -> None:
        mock_store = mock_store_cls.return_value
        mock_store.path = Path("/tmp/me-root/coverage.json")
        mock_store.get_unexplored.return_value = []
        args = argparse.Namespace(
            program="notion",
            file="./src\\preload.js",
            class_name=" Dom-Xss ",
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
            version_label="v2.2.0",
            agent="unit-agent",
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = me_ledger.cmd_cover(args)

        self.assertEqual(rc, 0)
        mock_store_cls.assert_called_once_with(
            "notion",
            unittest.mock.ANY,
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
        )
        mock_store.mark_examined.assert_called_once_with(
            vuln_class="dom-xss",
            files=["src/preload.js"],
            method="unit-agent",
            status="done",
            run_id="run-1",
            snapshot_id="snap-1",
            version_label="v2.2.0",
        )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["coverage_path"], "/tmp/me-root/coverage.json")

    def test_unexplored_ignores_legacy_auto_marks_but_keeps_explicit_review(self) -> None:
        candidates = {"dom-xss": ["src/manual.js", "src/synced.js", "src/reviewed.js"]}
        coverage = {"snapshots": {
            "snap-1": {"classes": {"dom-xss": {"files": {
                "src/manual.js": {"method": "manual-hunter", "status": "done"},
                "src/synced.js": {"method": "sync-reports", "status": "done"},
                "./src\\reviewed.js": {"method": "manual-review", "status": "done"},
            }}}},
        }}
        args = argparse.Namespace(
            program="demo", class_name="dom-xss", version_label=None,
            lane="apk", family="binaries", root_override=None,
        )
        stdout = io.StringIO()
        with patch("agents.me_ledger._load_shared_brain_candidates", return_value=candidates), \
             patch("agents.me_ledger._load_coverage_payload", return_value=coverage), \
             patch("agents.me_ledger._resolve_snapshot", return_value={"snapshot_id": "snap-1"}), \
             redirect_stdout(stdout):
            self.assertEqual(me_ledger.cmd_unexplored(args), 0)
        result = json.loads(stdout.getvalue())["classes"]["dom-xss"]
        self.assertEqual(result["candidate_count"], 3)
        self.assertEqual(result["examined_count"], 1)
        self.assertEqual(result["unexplored_count"], 2)
        self.assertEqual(result["unexplored"], ["src/manual.js", "src/synced.js"])

    def test_unexplored_cli_parses_version_and_root_for_handler(self) -> None:
        args = me_ledger.build_parser().parse_args(
            ["unexplored", "--program", "demo", "--class", "dom-xss", "--version", "v1", "--root", "/tmp/me-ledger-test"]
        )
        stdout = io.StringIO()
        with patch("agents.me_ledger._load_shared_brain_candidates", return_value={"dom-xss": []}), \
             patch("agents.me_ledger._load_coverage_payload", return_value={}), \
             patch("agents.me_ledger._resolve_snapshot", return_value={"snapshot_id": "snap-1"}) as snapshot, \
             redirect_stdout(stdout):
            self.assertEqual(args.func(args), 0)
        self.assertEqual(args.root_override, "/tmp/me-ledger-test")
        snapshot.assert_called_once_with(
            "demo", "v1", lane="apk", family="binaries", root_override="/tmp/me-ledger-test"
        )

    def test_build_parser_cover_accepts_root_override(self) -> None:
        args = me_ledger.build_parser().parse_args(
            [
                "cover",
                "--program",
                "notion",
                "--file",
                "src/preload.js",
                "--class-name",
                "dom-xss",
                "--root",
                "/tmp/me-root",
            ]
        )

        self.assertEqual(args.root_override, "/tmp/me-root")

    def test_build_parser_add_accepts_scoring_fields(self) -> None:
        args = me_ledger.build_parser().parse_args(
            [
                "add",
                "--program",
                "notion",
                "--file",
                "src/preload.js",
                "--class-name",
                "dom-xss",
                "--type",
                "DOM XSS",
                "--severity",
                "HIGH",
                "--scoring-authority",
                "Bugcrowd VRT",
                "--severity-rationale",
                "Demonstrated admin session theft.",
                "--program-constraint",
                "Program caps XSS at High without account takeover proof.",
            ]
        )

        self.assertEqual(args.scoring_authority, "Bugcrowd VRT")
        self.assertEqual(args.severity_rationale, "Demonstrated admin session theft.")
        self.assertEqual(args.program_constraint, "Program caps XSS at High without account takeover proof.")

    def test_cmd_add_normalizes_severity_aliases(self) -> None:
        """Severity enters the ledger through bounty_core normalization so agents can
        say P1/P2/P3 or lowercase names and the stored value lands as the canonical
        CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN enum."""
        cases = {
            "P1": "CRITICAL",
            "p2": "HIGH",
            "P3": "MEDIUM",
            "P4": "LOW",
            "critical": "CRITICAL",
            "HIGH": "HIGH",
            "bogus-severity": "UNKNOWN",
            "": "UNKNOWN",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                with patch("agents.me_ledger.ledger_get") as mock_get, patch(
                    "agents.me_ledger.update_team_finding"
                ), patch(
                    "agents.me_ledger.ledger_add", return_value=(True, "D09")
                ) as mock_add, patch(
                    "agents.me_ledger._default_run_id", return_value="run-1"
                ), patch(
                    "agents.me_ledger._resolve_snapshot",
                    return_value={"snapshot_id": "snap-1", "version_label": ""},
                ):
                    mock_get.return_value = {"fid": "D09"}
                    args = argparse.Namespace(
                        program="notion",
                        type="XSS",
                        class_name="dom-xss",
                        file="src/x.js",
                        severity=raw,
                        scoring_authority="",
                        severity_rationale="",
                        program_constraint="",
                        agent="unit-agent",
                        fid_prefix="D",
                        version_label=None,
                        lane="web",
                        family="web_bounty",
                        root_override="/tmp/me-root",
                    )
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        self.assertEqual(me_ledger.cmd_add(args), 0)
                self.assertEqual(mock_add.call_args[0][1]["severity"], expected)


if __name__ == "__main__":
    unittest.main()
