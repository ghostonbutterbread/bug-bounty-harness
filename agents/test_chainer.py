"""Focused tests for chainer storage routing."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import chainer  # noqa: E402
from agents.storage_resolver import resolve_family_lane, resolve_storage  # noqa: E402


class ChainerStorageRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.program = "example-program"

    def test_default_output_dir_uses_canonical_reports_storage(self) -> None:
        explicit_root = self.tmp / "storage"
        family, lane = resolve_family_lane(hunt_type="0day_team")
        storage = resolve_storage(
            self.program,
            family=family,
            lane=lane,
            root_override=explicit_root,
            create=True,
        )

        output_dir = chainer._default_output_dir(self.program, "source", str(explicit_root))

        self.assertEqual(output_dir, storage.reports_root / "chained")

    def test_default_status_report_paths_use_canonical_with_legacy_read_fallback(self) -> None:
        explicit_root = self.tmp / "storage"
        family, lane = resolve_family_lane(hunt_type="0day_team")
        storage = resolve_storage(
            self.program,
            family=family,
            lane=lane,
            root_override=explicit_root,
            create=True,
        )
        dormant_path = storage.reports_root / "dormant" / "2026-04-28" / "index.md"
        dormant_path.parent.mkdir(parents=True, exist_ok=True)
        dormant_path.write_text("# Dormant\n\n## [DORMANT] Requires prior XSS\n", encoding="utf-8")

        resolved_dormant, resolved_novel = chainer._default_status_report_paths(
            self.program,
            "source",
            str(explicit_root),
        )

        self.assertEqual(resolved_dormant, dormant_path)
        self.assertIsNone(resolved_novel)


if __name__ == "__main__":
    unittest.main()
