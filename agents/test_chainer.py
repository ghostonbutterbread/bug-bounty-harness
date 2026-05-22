"""Focused tests for chainer storage routing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agents import chainer
from agents.report_paths import status_report_path_for_read
from agents.storage_resolver import resolve_family_lane, resolve_storage


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

    def test_default_status_report_paths_prefer_new_daily_layout(self) -> None:
        explicit_root = self.tmp / "storage"
        family, lane = resolve_family_lane(hunt_type="0day_team")
        storage = resolve_storage(
            self.program,
            family=family,
            lane=lane,
            root_override=explicit_root,
            create=True,
        )
        legacy_path = storage.reports_root / "dormant" / "2026-04-28" / "index.md"
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_path.write_text("# Dormant\n\n## [DORMANT] Legacy\n", encoding="utf-8")
        daily_path = storage.reports_root / "daily" / "06-13-2026" / "dormant.md"
        daily_path.parent.mkdir(parents=True, exist_ok=True)
        daily_path.write_text("<!-- generated: bounty-core-report-navigation -->\n# Dormant\n", encoding="utf-8")

        resolved_dormant, _resolved_novel = chainer._default_status_report_paths(
            self.program,
            "source",
            str(explicit_root),
        )

        self.assertEqual(resolved_dormant, daily_path)

    def test_status_report_paths_prefer_global_lifecycle_index_over_daily_and_legacy(self) -> None:
        explicit_root = self.tmp / "storage"
        family, lane = resolve_family_lane(hunt_type="0day_team")
        storage = resolve_storage(
            self.program,
            family=family,
            lane=lane,
            root_override=explicit_root,
            create=True,
        )
        legacy_path = storage.reports_root / "dormant" / "2026-04-28" / "index.md"
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_path.write_text("# Dormant\n\n## [DORMANT] Legacy\n", encoding="utf-8")
        daily_path = storage.reports_root / "daily" / "06-13-2026" / "dormant.md"
        daily_path.parent.mkdir(parents=True, exist_ok=True)
        daily_path.write_text("<!-- generated: bounty-core-report-navigation -->\n# Daily Dormant\n", encoding="utf-8")
        global_path = storage.reports_root / "dormant.md"
        global_path.write_text("<!-- generated: bounty-core-report-navigation -->\n# Dormant\n", encoding="utf-8")

        resolved = status_report_path_for_read(storage.reports_root, "dormant", "dormant.md")

        self.assertEqual(resolved, global_path)

    def test_dormant_loader_follows_daily_links_to_canonical_findings(self) -> None:
        reports_root = self.tmp / "reports"
        finding_path = reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge requires prior XSS.md"
        finding_path.parent.mkdir(parents=True, exist_ok=True)
        finding_path.write_text(
            "# Renderer bridge requires prior XSS\n\n"
            "- **FID:** D01\n"
            "- **Type:** renderer bridge\n"
            "- **Review Tier:** DORMANT_ACTIVE\n"
            "- **Class:** renderer-bridge\n"
            "- **File:** src/main.js\n\n"
            "## Summary\n\n"
            "Renderer input can reach a privileged bridge once script execution exists.\n\n"
            "## Source -> Sink\n\n"
            "Source: location.hash\n"
            "Trust boundary: renderer to main\n"
            "Flow: hash to bridge call\n"
            "Sink: host.rpc\n\n"
            "## Blocking / Chain Requirements\n\n"
            "Blocked reason: Needs prior renderer script execution.\n"
            "Chain requirements: Chain with XSS.\n\n"
            "## Impact\n\n"
            "Privileged action.\n\n"
            "## Remediation\n\n"
            "Validate bridge callers.\n",
            encoding="utf-8",
        )
        dormant_path = reports_root / "daily" / "06-13-2026" / "dormant.md"
        dormant_path.parent.mkdir(parents=True, exist_ok=True)
        dormant_path.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n"
            "# Dormant Findings - 06-13-2026\n\n"
            "| FID | Title |\n"
            "|---|---|\n"
            "| [D01](<../../findings/dormant/D01%20-%20HIGH%20-%20Renderer%20bridge%20requires%20prior%20XSS.md>) | Renderer bridge requires prior XSS |\n",
            encoding="utf-8",
        )

        findings = chainer._load_dormant_findings(dormant_path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fid, "D01")
        self.assertEqual(findings[0].title, "Renderer bridge requires prior XSS")
        self.assertEqual(findings[0].source, "location.hash")

    def test_dormant_loader_follows_global_links_to_lifecycle_findings(self) -> None:
        reports_root = self.tmp / "reports"
        finding_path = reports_root / "findings" / "dormant" / "D02 - MEDIUM - Global renderer bridge.md"
        finding_path.parent.mkdir(parents=True, exist_ok=True)
        finding_path.write_text(
            "# Global renderer bridge\n\n"
            "- **FID:** D02\n"
            "- **Class:** renderer-bridge\n"
            "- **File:** src/preload.js\n\n"
            "## Summary\n\n"
            "Bridge can be reached after a separate renderer primitive.\n\n"
            "## Source -> Sink\n\n"
            "Source: postMessage\n"
            "Sink: ipcRenderer.invoke\n\n"
            "## Blocking / Chain Requirements\n\n"
            "Blocked reason: Needs prior message injection.\n"
            "Chain requirements: Chain with renderer control.\n",
            encoding="utf-8",
        )
        dormant_path = reports_root / "dormant.md"
        dormant_path.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n"
            "# Dormant Findings\n\n"
            "- [D02](<findings/dormant/D02%20-%20MEDIUM%20-%20Global%20renderer%20bridge.md>) - Global renderer bridge\n",
            encoding="utf-8",
        )

        findings = chainer._load_dormant_findings(dormant_path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fid, "D02")
        self.assertEqual(findings[0].title, "Global renderer bridge")
        self.assertEqual(findings[0].sink, "ipcRenderer.invoke")

    def test_dormant_loader_accepts_dormant_subtiers_and_category_headers(self) -> None:
        dormant_path = self.tmp / "reports" / "dormant" / "05-05-2026" / "index.md"
        dormant_path.parent.mkdir(parents=True, exist_ok=True)
        dormant_path.write_text(
            "# Dormant Findings\n\n"
            "## Category: Renderer / Privileged Bridge\n"
            "Findings: 1\n\n"
            "## [DORMANT_ACTIVE] Renderer bridge requires prior XSS\n"
            "**Class:** renderer-bridge\n"
            "**File:** src/main.js\n\n"
            "### Why It's Dangerous\n"
            "Renderer input can reach a privileged bridge.\n\n"
            "### Source -> Sink\n"
            "Source: location.hash\n"
            "Sink: host.rpc\n\n"
            "### Why It's Blocked Right Now\n"
            "Needs prior renderer script execution.\n\n"
            "### What's Needed to Exploit\n"
            "Chain with XSS.\n",
            encoding="utf-8",
        )

        findings = chainer._load_dormant_findings(dormant_path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Renderer bridge requires prior XSS")
        self.assertEqual(findings[0].vuln_class, "renderer-bridge")

    def test_explicit_exe_lane_output_dir_uses_binary_reports(self) -> None:
        explicit_root = self.tmp / "storage"
        storage = resolve_storage(
            self.program,
            family="binaries",
            lane="exe",
            root_override=explicit_root,
            create=True,
        )

        output_dir = chainer._default_output_dir(
            self.program,
            "source",
            str(explicit_root),
            family="binaries",
            lane="exe",
        )

        self.assertEqual(output_dir, storage.reports_root / "chained")

    def test_source_default_does_not_infer_lane_from_source_path(self) -> None:
        explicit_root = self.tmp / "storage"
        source_path = explicit_root / "binaries" / self.program / "apk" / "input" / "example.apk"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("placeholder\n", encoding="utf-8")
        family, lane = resolve_family_lane(hunt_type="0day_team")
        storage = resolve_storage(
            self.program,
            family=family,
            lane=lane,
            root_override=explicit_root,
            create=True,
        )

        output_dir = chainer._default_output_dir(
            self.program,
            "source",
            str(explicit_root),
            target_path=source_path,
        )

        self.assertEqual(output_dir, storage.reports_root / "chained")

    def test_source_with_explicit_identity_hint_can_use_source_path_lane(self) -> None:
        explicit_root = self.tmp / "storage"
        source_path = explicit_root / "binaries" / self.program / "apk" / "input" / "example.apk"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("placeholder\n", encoding="utf-8")
        storage = resolve_storage(
            self.program,
            family="binaries",
            lane="apk",
            root_override=explicit_root,
            create=True,
        )

        output_dir = chainer._default_output_dir(
            self.program,
            "source",
            str(explicit_root),
            family="binaries",
            target_path=source_path,
        )

        self.assertEqual(output_dir, storage.reports_root / "chained")

    def test_target_kind_api_routes_status_reads_to_api_lane(self) -> None:
        explicit_root = self.tmp / "storage"
        storage = resolve_storage(
            self.program,
            family="web_bounty",
            lane="api",
            root_override=explicit_root,
            create=True,
        )
        novel_path = storage.reports_root / "novel" / "2026-04-29" / "index.md"
        novel_path.parent.mkdir(parents=True, exist_ok=True)
        novel_path.write_text("# Novel\n\n## [CONFIRMED] API issue\n", encoding="utf-8")

        resolved_dormant, resolved_novel = chainer._default_status_report_paths(
            self.program,
            "source",
            str(explicit_root),
            target_kind="api",
        )

        if resolved_dormant is not None:
            self.assertTrue(str(resolved_dormant).startswith(str(storage.reports_root)))
        self.assertEqual(resolved_novel, novel_path)

    def test_hunt_type_apk_routes_output_to_apk_lane(self) -> None:
        explicit_root = self.tmp / "storage"
        storage = resolve_storage(
            self.program,
            family="binaries",
            lane="apk",
            root_override=explicit_root,
            create=True,
        )

        output_dir = chainer._default_output_dir(self.program, "apk", str(explicit_root))

        self.assertEqual(output_dir, storage.reports_root / "chained")


if __name__ == "__main__":
    unittest.main()
