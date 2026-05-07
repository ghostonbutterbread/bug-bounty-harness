"""Unit tests for agents.report_checker storage root handling."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import report_checker  # noqa: E402
from agents.shared_brain import RepoIndex, save_index  # noqa: E402
from agents.storage_resolver import resolve_storage  # noqa: E402
from bounty_core import ledger as core_ledger  # noqa: E402


def _finding(fid: str, title: str, file_value: str = "src/app.js") -> dict[str, object]:
    return {
        "fid": fid,
        "title": title,
        "type": title,
        "vuln_class": "dom-xss",
        "class_name": "dom-xss",
        "category": "class",
        "status": "pending-review",
        "chain_status": "unchained",
        "file": file_value,
        "line": 1,
        "severity": "HIGH",
        "description": "Attacker controlled input reaches a browser DOM sink.",
        "context": "The source path is wired into the renderer flow.",
        "source": "location.hash",
        "trust_boundary": "URL input to renderer",
        "flow_path": "location.hash -> render -> sink",
        "sink": "innerHTML",
        "exploitability": "A user can open a crafted URL.",
        "discovered_date": "2026-04-28",
        "last_seen": "2026-04-28",
        "agent": "unit-test",
    }


def _markdown(title: str) -> str:
    return "\n".join(
        [
            f"# {title}",
            "Class: dom-xss",
            "Severity: HIGH",
            "File: src/app.js:1",
            "Source: location.hash",
            "Trust Boundary: URL input to renderer",
            "Flow: location.hash -> render -> sink",
            "Sink: innerHTML",
            "### Description",
            "Attacker controlled input reaches a browser DOM sink.",
        ]
    ) + "\n"


def _canonical_markdown(fid: str, title: str, file_value: str = "src/app.js:1") -> str:
    return "\n".join(
        [
            "<!-- generated: bounty-core-finding-report -->",
            f"# {title}",
            "",
            f"- **FID:** {fid}",
            "- **Type:** DOM XSS",
            "- **Status:** dormant",
            "- **Review Tier:** DORMANT_ACTIVE",
            "- **Category:** Renderer / Privileged Bridge",
            "- **Severity:** HIGH",
            "- **Class:** dom-xss",
            f"- **File:** {file_value}",
            "",
            "## Summary",
            "",
            "Attacker controlled input reaches a browser DOM sink.",
            "",
            "## Source -> Sink",
            "",
            "Source: location.hash",
            "Trust boundary: URL input to renderer",
            "Flow: location.hash -> render -> sink",
            "Sink: innerHTML",
            "",
            "## Blocking / Chain Requirements",
            "",
            "Blocked reason: Needs a reachable renderer entry point.",
            "Chain requirements: Chain with a navigation primitive.",
        ]
    ) + "\n"


class ReportCheckerRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.program = "explicit_program"

        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

    def _storage(self, *, root_override: str | Path | None = None):
        return resolve_storage(
            self.program,
            family="binaries",
            lane="apk",
            root_override=root_override,
            create=False,
        )

    def _legacy_reports_root(self) -> Path:
        return self.home / "Shared" / "bounty_recon" / self.program / "ghost" / "reports_source"

    def test_load_ledger_findings_reads_explicit_root_over_default_home(self) -> None:
        default_storage = self._storage()
        explicit_root = self.tmp / "explicit-root"
        explicit_storage = self._storage(root_override=explicit_root)

        default_storage.ledgers_root.mkdir(parents=True, exist_ok=True)
        explicit_storage.ledgers_root.mkdir(parents=True, exist_ok=True)
        (default_storage.ledgers_root / "ledger.json").write_text(
            json.dumps({"findings": [_finding("D99", "Default HOME finding")]}) + "\n",
            encoding="utf-8",
        )
        (explicit_storage.ledgers_root / "ledger.json").write_text(
            json.dumps({"findings": [_finding("D01", "Explicit root finding")]}) + "\n",
            encoding="utf-8",
        )

        findings = report_checker._load_ledger_findings(
            self.program,
            "source",
            root_override=explicit_root,
        )

        self.assertEqual([finding.fid for finding in findings], ["D01"])
        self.assertEqual(findings[0].title, "Explicit root finding")

    def test_load_markdown_findings_prefers_explicit_root_before_legacy_fallback(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        explicit_storage = self._storage(root_override=explicit_root)
        explicit_report = explicit_storage.reports_root / "confirmed" / "index.md"
        explicit_report.parent.mkdir(parents=True, exist_ok=True)
        explicit_report.write_text(_markdown("Explicit markdown finding"), encoding="utf-8")

        legacy_reports = (
            self.home
            / "Shared"
            / "bounty_recon"
            / self.program
            / "ghost"
            / "reports_source"
        )
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.md").write_text(
            _markdown("Legacy markdown finding"),
            encoding="utf-8",
        )

        explicit_findings = report_checker._load_markdown_findings(
            self.program,
            "source",
            root_override=explicit_root,
        )
        default_findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in explicit_findings], ["Explicit markdown finding"])
        self.assertEqual([finding.title for finding in default_findings], ["Legacy markdown finding"])

    def test_load_markdown_findings_with_empty_explicit_root_does_not_read_legacy(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        legacy_reports = (
            self.home
            / "Shared"
            / "bounty_recon"
            / self.program
            / "ghost"
            / "reports_source"
        )
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.md").write_text(
            _markdown("Legacy markdown finding"),
            encoding="utf-8",
        )

        explicit_findings = report_checker._load_markdown_findings(
            self.program,
            "source",
            root_override=explicit_root,
        )
        default_findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual(explicit_findings, [])
        self.assertEqual([finding.title for finding in default_findings], ["Legacy markdown finding"])

    def test_legacy_status_without_markdown_extension_does_not_load(self) -> None:
        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.txt").write_text(
            _markdown("Legacy text extension finding"),
            encoding="utf-8",
        )
        (legacy_reports / "confirmed_foo").write_text(
            _markdown("Legacy no extension finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual(findings, [])

    def test_legacy_status_with_markdown_extension_still_loads(self) -> None:
        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.md").write_text(
            _markdown("Legacy markdown extension finding"),
            encoding="utf-8",
        )
        (legacy_reports / "confirmed_2026-04-29.txt").write_text(
            _markdown("Newer text extension finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Legacy markdown extension finding"])

    def test_default_fallback_uses_legacy_when_canonical_has_no_readable_status_reports(self) -> None:
        default_storage = self._storage()
        non_status_report = default_storage.reports_root / "confirmed" / "random.md"
        non_status_report.parent.mkdir(parents=True, exist_ok=True)
        non_status_report.write_text(_markdown("Canonical non-status markdown"), encoding="utf-8")

        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.md").write_text(
            _markdown("Legacy fallback finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Legacy fallback finding"])

    def test_empty_explicit_root_never_falls_back_to_legacy_status_reports(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed_2026-04-28.md").write_text(
            _markdown("Legacy fallback finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(
            self.program,
            "source",
            root_override=explicit_root,
        )

        self.assertEqual(findings, [])

    def test_arbitrary_canonical_markdown_does_not_suppress_legacy_fallback(self) -> None:
        default_storage = self._storage()
        arbitrary_report = default_storage.reports_root / "confirmed" / "random.md"
        arbitrary_report.parent.mkdir(parents=True, exist_ok=True)
        arbitrary_report.write_text(_markdown("Canonical arbitrary markdown"), encoding="utf-8")

        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed.md").write_text(
            _markdown("Legacy readable finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Legacy readable finding"])

    def test_arbitrary_canonical_markdown_with_explicit_root_does_not_read_legacy(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        explicit_storage = self._storage(root_override=explicit_root)
        arbitrary_report = explicit_storage.reports_root / "confirmed" / "random.md"
        arbitrary_report.parent.mkdir(parents=True, exist_ok=True)
        arbitrary_report.write_text(_markdown("Explicit arbitrary markdown"), encoding="utf-8")

        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed.md").write_text(
            _markdown("Legacy readable finding"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(
            self.program,
            "source",
            root_override=explicit_root,
        )

        self.assertEqual(findings, [])

    def test_seeded_canonical_status_index_does_not_suppress_legacy_fallback(self) -> None:
        default_storage = self._storage()
        seeded_index = default_storage.reports_root / "confirmed" / "dom-xss" / "index.md"
        seeded_index.parent.mkdir(parents=True, exist_ok=True)
        seeded_index.write_text("# Confirmed DOM-XSS\n", encoding="utf-8")

        legacy_reports = self._legacy_reports_root()
        legacy_reports.mkdir(parents=True, exist_ok=True)
        (legacy_reports / "confirmed.md").write_text(
            _markdown("Legacy after seeded index"),
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Legacy after seeded index"])

    def test_canonical_dated_status_index_counts_as_readable(self) -> None:
        default_storage = self._storage()
        dated_index = default_storage.reports_root / "confirmed" / "2026-04-28" / "index.md"
        dated_index.parent.mkdir(parents=True, exist_ok=True)
        dated_index.write_text(_markdown("Canonical dated finding"), encoding="utf-8")

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Canonical dated finding"])

    def test_canonical_non_date_status_index_remains_readable_for_compatibility(self) -> None:
        default_storage = self._storage()
        compatibility_index = default_storage.reports_root / "confirmed" / "manual-run" / "index.md"
        compatibility_index.parent.mkdir(parents=True, exist_ok=True)
        compatibility_index.write_text(_markdown("Canonical non-date finding"), encoding="utf-8")

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual([finding.title for finding in findings], ["Canonical non-date finding"])

    def test_load_markdown_findings_follows_global_generated_links_to_canonical_bodies(self) -> None:
        default_storage = self._storage()
        canonical = (
            default_storage.reports_root
            / "findings"
            / "dormant"
            / "D01 - HIGH - Renderer bridge requires prior XSS.md"
        )
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_text(
            _canonical_markdown("D01", "Renderer bridge requires prior XSS"),
            encoding="utf-8",
        )
        global_index = default_storage.reports_root / "dormant.md"
        global_index.parent.mkdir(parents=True, exist_ok=True)
        global_index.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n"
            "# Dormant Findings\n\n"
            "- [D01](<findings/dormant/D01%20-%20HIGH%20-%20Renderer%20bridge%20requires%20prior%20XSS.md>)"
            " - Renderer bridge requires prior XSS\n",
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fid, "D01")
        self.assertEqual(findings[0].title, "Renderer bridge requires prior XSS")
        self.assertEqual(findings[0].source, "location.hash")

    def test_load_markdown_findings_follows_daily_generated_links_to_canonical_bodies(self) -> None:
        default_storage = self._storage()
        canonical = default_storage.reports_root / "findings" / "dormant" / "D02 - HIGH - Daily body.md"
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_text(_canonical_markdown("D02", "Daily body"), encoding="utf-8")
        daily_index = default_storage.reports_root / "daily" / "05-06-2026" / "dormant.md"
        daily_index.parent.mkdir(parents=True, exist_ok=True)
        daily_index.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n"
            "# Dormant Findings - 05-06-2026\n\n"
            "| FID | Title |\n"
            "|---|---|\n"
            "| [D02](<../../findings/dormant/D02%20-%20HIGH%20-%20Daily%20body.md>) | Daily body |\n",
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fid, "D02")
        self.assertEqual(findings[0].title, "Daily body")

    def test_generated_status_without_links_is_not_parsed_as_fake_finding(self) -> None:
        default_storage = self._storage()
        generated_index = default_storage.reports_root / "dormant.md"
        generated_index.parent.mkdir(parents=True, exist_ok=True)
        generated_index.write_text(
            "<!-- generated: bounty-core-report-navigation -->\n# Dormant Findings\n\nCount: 0\n",
            encoding="utf-8",
        )

        findings = report_checker._load_markdown_findings(self.program, "source")

        self.assertEqual(findings, [])

    def test_source_root_candidates_explicit_override_wins(self) -> None:
        explicit_root = self.tmp / "explicit-source"
        shared_root = self.tmp / "shared-source"
        fallback_root = self.home / "source" / self.program
        for path in (explicit_root, shared_root, fallback_root):
            path.mkdir(parents=True, exist_ok=True)
        save_index(
            RepoIndex(
                target_root=str(shared_root),
                target_id="target-shared",
                generated_at="2026-04-28T12:00:00Z",
                git_head="shared-head",
                manifest_hash="shared-manifest",
                files={},
            ),
            self.program,
            family="binaries",
            lane="apk",
        )

        candidates = report_checker._source_root_candidates(
            self.program,
            str(explicit_root),
            hunt_type="source",
            family="binaries",
            lane="apk",
        )

        self.assertEqual(candidates[0], explicit_root.resolve(strict=False))

    def test_source_root_candidates_shared_brain_wins_over_home_source_fallback(self) -> None:
        shared_root = self.tmp / "shared-source"
        fallback_root = self.home / "source" / self.program
        for path in (shared_root, fallback_root):
            path.mkdir(parents=True, exist_ok=True)
        save_index(
            RepoIndex(
                target_root=str(shared_root),
                target_id="target-shared",
                generated_at="2026-04-28T12:00:00Z",
                git_head="shared-head",
                manifest_hash="shared-manifest",
                files={},
            ),
            self.program,
            family="binaries",
            lane="apk",
        )

        candidates = report_checker._source_root_candidates(
            self.program,
            None,
            hunt_type="source",
            family="binaries",
            lane="apk",
        )

        self.assertEqual(candidates[0], shared_root.resolve(strict=False))

    def test_source_root_candidates_fallback_still_works_without_shared_brain(self) -> None:
        fallback_root = self.home / "source" / self.program
        fallback_root.mkdir(parents=True, exist_ok=True)

        candidates = report_checker._source_root_candidates(
            self.program,
            None,
            hunt_type="source",
            family="binaries",
            lane="apk",
        )

        self.assertEqual(candidates[0], fallback_root.resolve(strict=False))

    def test_main_root_reads_explicit_findings_and_writes_validation_to_explicit_root(self) -> None:
        default_storage = self._storage()
        explicit_root = self.tmp / "explicit-root"
        explicit_storage = self._storage(root_override=explicit_root)
        default_ledger = default_storage.ledgers_root / "ledger.json"
        explicit_ledger = explicit_storage.ledgers_root / "ledger.json"

        default_storage.ledgers_root.mkdir(parents=True, exist_ok=True)
        explicit_storage.ledgers_root.mkdir(parents=True, exist_ok=True)
        (default_storage.ledgers_root / "findings.jsonl").write_text(
            json.dumps(_finding("D99", "Default HOME finding")) + "\n",
            encoding="utf-8",
        )
        (explicit_storage.ledgers_root / "findings.jsonl").write_text(
            json.dumps(_finding("D01", "Explicit root finding")) + "\n",
            encoding="utf-8",
        )

        codex_payload = {
            "finding_id": "D01",
            "validation": {
                "performed": True,
                "function_name_correct": True,
                "flow_correct": True,
                "severity_justified": True,
                "blocked_reason_accurate": True,
                "confidence": "HIGH",
                "corrections": [],
                "evidence": ["unit evidence"],
            },
            "expansion": {"performed": False},
            "confidence": "HIGH",
            "further_investigation": [],
            "suggested_finding_updates": {},
        }
        with patch.object(report_checker, "_run_codex_check") as run_codex:
            run_codex.return_value = (codex_payload, explicit_root / "codex-output.txt")
            rc = report_checker.main(
                [
                    self.program,
                    "--root",
                    str(explicit_root),
                    "--finding",
                    "D01",
                    "--validate-only",
                ]
            )

        self.assertEqual(rc, 0)
        run_codex.assert_called_once()
        validation_reports = sorted(explicit_storage.reports_root.glob("validation_*.json"))
        self.assertEqual(len(validation_reports), 1)
        payload = json.loads(validation_reports[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["findings"][0]["fid"], "D01")
        self.assertFalse(list(default_storage.reports_root.glob("validation_*.json")))
        self.assertFalse(default_ledger.exists())
        self.assertTrue(explicit_ledger.exists())
        ledger_payload = json.loads(explicit_ledger.read_text(encoding="utf-8"))
        self.assertEqual([finding["fid"] for finding in ledger_payload["findings"]], ["D01"])

    def test_main_validation_updates_existing_fid_without_rewriting_sightings(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        explicit_storage = self._storage(root_override=explicit_root)
        explicit_ledger = explicit_storage.ledgers_root / "ledger.json"
        explicit_storage.ledgers_root.mkdir(parents=True, exist_ok=True)
        (explicit_storage.ledgers_root / "findings.jsonl").write_text(
            json.dumps(_finding("D01", "Explicit root finding")) + "\n",
            encoding="utf-8",
        )
        explicit_ledger.write_text(
            json.dumps(
                {
                    "version": 2,
                    "program": self.program,
                    "updated_at": "2026-04-28T00:00:00Z",
                    "findings": [
                        {
                            **_finding("D01", "Explicit root finding"),
                            "type": "Explicit root finding",
                            "class_name": "dom-xss",
                            "first_seen": "2026-04-27T10:00:00Z",
                            "first_snapshot": "snap-a",
                            "last_seen": "2026-04-28T10:00:00Z",
                            "last_snapshot": "snap-b",
                            "sighting_count": 2,
                            "sightings": [
                                {
                                    "snapshot_id": "snap-a",
                                    "version_label": "v1",
                                    "run_id": "run-a",
                                    "seen_at": "2026-04-27T10:00:00Z",
                                    "status": "active",
                                    "review_tier": "CONFIRMED",
                                    "agent": "unit-test",
                                    "source_artifact": {"path": "artifacts/a.json"},
                                },
                                {
                                    "snapshot_id": "snap-b",
                                    "version_label": "v2",
                                    "run_id": "run-b",
                                    "seen_at": "2026-04-28T10:00:00Z",
                                    "status": "active",
                                    "review_tier": "CONFIRMED",
                                    "agent": "unit-test",
                                },
                            ],
                            "current": {
                                "review_tier": "CONFIRMED",
                                "status": "active",
                                "version_label": "v2",
                            },
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        codex_payload = {
            "finding_id": "D01",
            "validation": {
                "performed": True,
                "function_name_correct": True,
                "flow_correct": True,
                "severity_justified": True,
                "blocked_reason_accurate": True,
                "confidence": "HIGH",
                "corrections": [],
                "evidence": ["unit evidence"],
            },
            "expansion": {"performed": False},
            "confidence": "HIGH",
            "further_investigation": [],
            "suggested_finding_updates": {
                "title": "Corrected explicit finding",
                "file": "src/corrected.js",
                "line": 7,
                "severity": "CRITICAL",
            },
        }
        with (
            patch.object(report_checker, "_run_codex_check") as run_codex,
            patch.object(
                core_ledger,
                "write_finding_report",
                wraps=core_ledger.write_finding_report,
            ) as write_report,
            patch.object(
                core_ledger,
                "refresh_indexes",
                wraps=core_ledger.refresh_indexes,
            ) as refresh_indexes,
            patch.object(
                core_ledger,
                "refresh_report_indexes",
                wraps=core_ledger.refresh_report_indexes,
            ) as refresh_report_indexes,
        ):
            run_codex.return_value = (codex_payload, explicit_root / "codex-output.txt")
            rc = report_checker.main(
                [
                    self.program,
                    "--root",
                    str(explicit_root),
                    "--finding",
                    "D01",
                    "--validate-only",
                ]
            )

        self.assertEqual(rc, 0)
        write_report.assert_not_called()
        refresh_indexes.assert_not_called()
        refresh_report_indexes.assert_not_called()
        ledger_payload = json.loads(explicit_ledger.read_text(encoding="utf-8"))
        self.assertEqual(len(ledger_payload["findings"]), 1)
        stored = ledger_payload["findings"][0]
        self.assertEqual(stored["fid"], "D01")
        self.assertEqual(stored["title"], "Corrected explicit finding")
        self.assertEqual(stored["file"], "src/corrected.js")
        self.assertEqual(stored["line"], 7)
        self.assertEqual(stored["severity"], "CRITICAL")
        self.assertEqual(stored["status"], "validated-confirmed")
        self.assertEqual(stored["first_snapshot"], "snap-a")
        self.assertEqual(stored["last_snapshot"], "snap-b")
        self.assertEqual(stored["sighting_count"], 2)
        self.assertEqual([item["snapshot_id"] for item in stored["sightings"]], ["snap-a", "snap-b"])
        self.assertEqual(stored["sightings"][0]["source_artifact"]["path"], "artifacts/a.json")
        self.assertEqual(stored["current"]["review_tier"], "CONFIRMED")
        self.assertNotIn("report_path", stored)
        raw_lines = (explicit_storage.ledgers_root / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(raw_lines), 1)
        self.assertNotIn("event", json.loads(raw_lines[0]))


if __name__ == "__main__":
    unittest.main()
