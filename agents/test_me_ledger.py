"""Tests for agents.me_ledger CLI ledger adapter usage."""

from __future__ import annotations

import argparse
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

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
    def test_cmd_add_uses_adapter_functions_with_lane_and_family(
        self,
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
            },
            "snap-1",
            "v2.2.0",
            "run-1",
            "unit-agent",
            lane="exe",
            family="binaries",
            root_override="/tmp/me-root",
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


if __name__ == "__main__":
    unittest.main()
