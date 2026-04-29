"""Focused tests for APK deep-dive orchestration."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import apk_deep_dive  # noqa: E402


class ApkDeepDiveLedgerPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_new_raw_finding_uses_check_reservation_then_team_adapter(self) -> None:
        raw_finding = {
            "type": "exported-provider-file-read",
            "title": "Exported provider exposes private files",
            "file": "smali/com/example/Provider.smali",
            "severity": "HIGH",
        }
        reserved_finding = {
            **raw_finding,
            "fid": "D01",
            "snapshot_id": "snap-1",
            "version_label": "1.2.3",
            "run_id": "run-1",
        }
        root_override = self.tmp / "storage-root"
        ledger = Mock()
        ledger.check.return_value = (False, "D01", reserved_finding)
        ledger.snapshot_id = "snap-1"
        ledger.version_label = "1.2.3"
        ledger.run_id = "run-1"
        ledger.family = "binaries"
        ledger.lane = "apk"
        ledger.root_override = root_override
        registry = Mock()

        parent = Mock()
        parent.attach_mock(ledger.check, "check")

        with (
            patch.object(apk_deep_dive, "update_team_finding", return_value=reserved_finding) as update_mock,
            patch("bounty_core.ledger.add_finding") as add_finding_mock,
        ):
            parent.attach_mock(update_mock, "update_team_finding")
            count = apk_deep_dive._persist_pass2_findings(
                [raw_finding],
                ledger=ledger,
                registry=registry,
                program="Example_Program",
            )

        self.assertEqual(count, 1)
        expected_calls = [
            call.check(raw_finding),
            call.update_team_finding(
                "Example_Program",
                reserved_finding,
                snapshot_id="snap-1",
                version_label="1.2.3",
                run_id="run-1",
                agent="deep-dive",
                family="binaries",
                lane="apk",
                root_override=root_override,
                write_report=False,
                refresh=False,
                update_current=False,
                update_sighting=False,
            ),
        ]
        self.assertEqual(parent.mock_calls[:2], expected_calls)
        ledger.update.assert_not_called()
        add_finding_mock.assert_not_called()
        registry.record_progressive_finding.assert_called_once_with(raw_finding, requested_by="deep_dive")
        self.assertNotIn("fid", raw_finding)


if __name__ == "__main__":
    unittest.main()
