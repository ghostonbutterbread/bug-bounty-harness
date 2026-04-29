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


if __name__ == "__main__":
    unittest.main()
