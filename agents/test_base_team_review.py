"""Focused tests for shared BaseTeam review orchestration."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.base_team.reports import write_report_indexes  # noqa: E402
from agents.base_team.review import _render_dormant_report, stage2_ghost_review  # noqa: E402


class BaseTeamReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.target = self.tmp / "target"
        self.target.mkdir()

    def _finding(self, **overrides: Any) -> dict[str, Any]:
        finding = {
            "agent": "dom-xss",
            "category": "class",
            "class_name": "dom-xss",
            "type": "hash reaches html sink",
            "file": "src/main.js",
            "line": 42,
            "description": "User-controlled hash reaches an HTML interpretation sink.",
            "severity": "HIGH",
            "source": "location.hash",
            "sink": "innerHTML",
        }
        finding.update(overrides)
        return finding

    def test_semantic_duplicate_replaces_first_copy_when_later_copy_has_fid(self) -> None:
        reviewed_inputs: list[dict[str, Any]] = []

        def review_single(finding: dict[str, Any], _target: Path) -> dict[str, Any]:
            reviewed_inputs.append(dict(finding))
            return {
                **finding,
                "review_tier": "CONFIRMED",
                "tier": "CONFIRMED",
                "review_notes": "Confirmed for duplicate replacement regression.",
            }

        first_without_fid = self._finding(copy_id="first-without-fid")
        later_with_fid = self._finding(copy_id="later-with-fid", fid="D01")

        confirmed, dormant, novel = stage2_ghost_review(
            [first_without_fid, later_with_fid],
            self.target,
            "Example Program",
            "0day_team",
            output_root=self.tmp / "out",
            review_single=review_single,
            max_workers=1,
            write_reports=False,
        )

        self.assertEqual(len(reviewed_inputs), 1)
        self.assertEqual(reviewed_inputs[0]["copy_id"], "later-with-fid")
        self.assertEqual(reviewed_inputs[0]["fid"], "D01")
        self.assertEqual([finding["fid"] for finding in confirmed], ["D01"])
        self.assertEqual(confirmed[0]["copy_id"], "later-with-fid")
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [])

    def test_empty_report_indexes_do_not_create_dated_bucket_dirs(self) -> None:
        storage = SimpleNamespace(reports_root=self.tmp / "reports")

        paths = write_report_indexes(
            storage,
            confirmed=[],
            dormant=[],
            novel=[],
            render_confirmed=lambda _rows: "confirmed",
            render_dormant=lambda _rows: "dormant",
            render_novel=lambda _rows: "novel",
        )

        self.assertEqual(paths, (None, None, None))
        self.assertFalse((storage.reports_root / "confirmed").exists())
        self.assertFalse((storage.reports_root / "dormant").exists())
        self.assertFalse((storage.reports_root / "novel").exists())

    def test_write_report_indexes_creates_canonical_reports_before_daily_links(self) -> None:
        storage = SimpleNamespace(reports_root=self.tmp / "reports")
        finding = self._finding(
            fid="D01",
            title="DOM XSS via hash",
            vulnerability_name="DOM XSS via hash",
            status="confirmed",
            review_tier="CONFIRMED",
        )

        confirmed_path, dormant_path, novel_path = write_report_indexes(
            storage,
            confirmed=[finding],
            dormant=[],
            novel=[],
            render_confirmed=lambda _rows: "confirmed body",
            render_dormant=lambda _rows: "dormant body",
            render_novel=lambda _rows: "novel body",
        )

        canonical = storage.reports_root / "findings" / "confirmed" / "D01 - HIGH - DOM XSS via hash.md"
        self.assertTrue(canonical.is_file())
        self.assertEqual(finding["report_path"], str(canonical))
        self.assertIsNotNone(confirmed_path)
        self.assertIn(
            "[[D01 - HIGH - DOM XSS via hash|D01]]",
            confirmed_path.read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(dormant_path)
        self.assertTrue(dormant_path.is_file())
        self.assertIsNotNone(novel_path)
        self.assertTrue(novel_path.is_file())

    def test_report_renderer_groups_findings_by_surface_category(self) -> None:
        renderer = self._finding(
            review_tier="DORMANT_ACTIVE",
            type="raw main world host RPC bridge exposed to renderer scripts",
            vulnerability_name="Raw Main World Host RPC Bridge Exposed to Renderer Scripts",
        )
        protocol = self._finding(
            review_tier="DORMANT_ACTIVE",
            class_name="external-protocol-abuse",
            type="openExternal accepts attacker-controlled deeplink",
            vulnerability_name="External Protocol Abuse",
            source="deeplink callback",
            sink="shell.openExternal",
        )

        report = _render_dormant_report([renderer, protocol])

        self.assertIn("## Category: Renderer / Privileged Bridge", report)
        self.assertIn("## Category: External Protocol Abuse", report)
        self.assertIn("**Category:** Renderer / Privileged Bridge", report)
        self.assertIn("## [DORMANT_ACTIVE] Raw Main World Host RPC Bridge Exposed to Renderer Scripts", report)


if __name__ == "__main__":
    unittest.main()
