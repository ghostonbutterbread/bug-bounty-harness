"""Regression: report_checker accepts EXCEPTIONAL severity (P0 rollout).

report_checker.py had its own severity validation that silently degraded
EXCEPTIONAL findings to UNKNOWN in the report view layer.
"""

from __future__ import annotations

import sys
import unittest

sys.path.insert(0, "/home/ryushe/projects/bbh-feat-exceptional-rollout")

from agents.report_checker import FindingRecord, _normalize_severity  # noqa: E402


class ReportCheckerExceptionalSeverityTests(unittest.TestCase):
    def test_normalize_severity_accepts_exceptional(self) -> None:
        self.assertEqual(_normalize_severity("EXCEPTIONAL"), "EXCEPTIONAL")
        self.assertEqual(_normalize_severity("exceptional"), "EXCEPTIONAL")
        self.assertEqual(_normalize_severity("P0"), "EXCEPTIONAL")
        self.assertEqual(_normalize_severity("CRITICAL"), "CRITICAL")
        self.assertEqual(_normalize_severity("bogus"), "UNKNOWN")

    def test_finding_record_preserves_exceptional_severity(self) -> None:
        record = FindingRecord.from_dict({"fid": "D01", "severity": "EXCEPTIONAL", "title": "x"})
        self.assertEqual(record.severity, "EXCEPTIONAL")

    def test_exceptional_sorts_above_critical(self) -> None:
        from agents.report_checker import SEVERITY_ORDER

        self.assertGreater(SEVERITY_ORDER["EXCEPTIONAL"], SEVERITY_ORDER["CRITICAL"])


if __name__ == "__main__":
    unittest.main()
