"""Tests for snapshot identity and the version-aware ledger."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.ledger import update_team_finding
from agents.ledger_v2 import VersionedFindingsLedger, ledger_add, ledger_get, ledger_list, ledger_path
from agents.apk_prefingerprint import _select_apk_candidate
from agents.snapshot_identity import get_snapshot_identity, get_snapshot_id, is_same_snapshot
from agents.storage_resolver import infer_family_from_lane, resolve_storage

ensure_bounty_core_importable()
from bounty_core.ledger import ledger_add as core_ledger_add
from bounty_core.ledger import ledger_list as core_ledger_list
from bounty_core.ledger import list_findings as core_list_findings


_CONCURRENT_ADD_SCRIPT = textwrap.dedent(
    """
    import os

    import sys

    home = sys.argv[1]
    program = sys.argv[2]
    relpath = sys.argv[3]
    class_name = sys.argv[4]
    snapshot_id = sys.argv[5]
    run_id = sys.argv[6]

    os.environ["HOME"] = home

    from agents.ledger_v2 import ledger_add

    ledger_add(
        program,
        {
            "type": "Concurrent finding",
            "class_name": class_name,
            "file": relpath,
            "severity": "HIGH",
        },
        snapshot_id,
        "v2.2.0",
        run_id,
        "concurrent-writer",
    )
    """
)


class SnapshotIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def _init_git_repo(self, target: Path) -> str:
        subprocess.run(["git", "init"], cwd=target, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
        (target / "app.js").write_text("console.log('ok');\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.js"], cwd=target, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=target, check=True, capture_output=True, text=True)
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_snapshot_identity_git_vs_non_git_and_version_override(self) -> None:
        git_target = self.tmp / "git-target"
        git_target.mkdir()
        expected_head = self._init_git_repo(git_target)

        identity = get_snapshot_identity(git_target, version_label="2.2.0-beta.3")
        self.assertEqual(identity["git_head"], expected_head)
        self.assertIsNone(identity["manifest_hash"])
        self.assertEqual(identity["snapshot_id"], expected_head)
        self.assertEqual(identity["version_label"], "2.2.0-beta.3")
        self.assertEqual(identity["channel"], "beta")
        self.assertTrue(is_same_snapshot(git_target, expected_head))

        non_git_target = self.tmp / "non-git-target"
        non_git_target.mkdir()
        (non_git_target / "a.txt").write_text("alpha\n", encoding="utf-8")
        (non_git_target / "nested").mkdir()
        (non_git_target / "nested" / "b.txt").write_text("bravo\n", encoding="utf-8")

        with patch.dict(os.environ, {"SNAPSHOT_VERSION": "9.9.9-dev.1"}, clear=False):
            non_git_identity = get_snapshot_identity(non_git_target)

        self.assertIsNone(non_git_identity["git_head"])
        self.assertEqual(len(non_git_identity["manifest_hash"]), 64)
        self.assertEqual(non_git_identity["snapshot_id"], non_git_identity["manifest_hash"])
        self.assertEqual(non_git_identity["version_label"], "9.9.9-dev.1")
        self.assertEqual(non_git_identity["channel"], "dev")
        self.assertEqual(get_snapshot_id(non_git_target), non_git_identity["manifest_hash"])

    def test_snapshot_identity_changes_when_non_git_file_contents_change_without_size_change(self) -> None:
        first_target = self.tmp / "first-target"
        second_target = self.tmp / "second-target"
        first_target.mkdir()
        second_target.mkdir()
        (first_target / "same.txt").write_text("alpha\n", encoding="utf-8")
        (second_target / "same.txt").write_text("bravo\n", encoding="utf-8")

        first_identity = get_snapshot_identity(first_target)
        second_identity = get_snapshot_identity(second_target)

        self.assertIsNone(first_identity["git_head"])
        self.assertIsNone(second_identity["git_head"])
        self.assertEqual((first_target / "same.txt").stat().st_size, (second_target / "same.txt").stat().st_size)
        self.assertNotEqual(first_identity["manifest_hash"], second_identity["manifest_hash"])
        self.assertNotEqual(first_identity["snapshot_id"], second_identity["snapshot_id"])


class LedgerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)
        self.program = "notion"

    def _read_payload(self) -> dict:
        return json.loads(ledger_path(self.program).read_text(encoding="utf-8"))

    def test_ledger_add_new_and_duplicate_across_snapshots(self) -> None:
        finding = {
            "type": "SQLite IPC",
            "class_name": "native-module-abuse",
            "file": "preload.js",
            "line": 142,
            "severity": "CRITICAL",
            "review_tier": "CONFIRMED",
            "seen_at": "2026-04-07T18:00:00Z",
        }

        is_new, fid = ledger_add(
            self.program,
            dict(finding),
            "snap-a",
            "v2.1.4",
            "20260407T180000Z",
            "zero-day-team",
        )
        self.assertTrue(is_new)
        self.assertEqual(fid, "D01")

        same_snapshot_new, same_snapshot_fid = ledger_add(
            self.program,
            dict(finding),
            "snap-a",
            "v2.1.4",
            "20260407T180000Z",
            "zero-day-team",
        )
        self.assertFalse(same_snapshot_new)
        self.assertEqual(same_snapshot_fid, "D01")

        other_snapshot_new, other_snapshot_fid = ledger_add(
            self.program,
            {
                **finding,
                "seen_at": "2026-04-08T09:00:00Z",
            },
            "snap-b",
            "v2.2.0",
            "20260408T090000Z",
            "zero-day-team",
        )
        self.assertFalse(other_snapshot_new)
        self.assertEqual(other_snapshot_fid, "D01")

        entry = ledger_get(self.program, "D01")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["first_snapshot"], "snap-a")
        self.assertEqual(entry["last_snapshot"], "snap-b")
        self.assertEqual(entry["first_seen"], "2026-04-07T18:00:00Z")
        self.assertEqual(entry["last_seen"], "2026-04-08T09:00:00Z")
        self.assertEqual(len(entry["sightings"]), 2)
        self.assertEqual(entry["sightings"][0]["snapshot_id"], "snap-a")
        self.assertEqual(entry["sightings"][1]["snapshot_id"], "snap-b")
        self.assertEqual(entry["current"]["version_label"], "v2.2.0")

    def test_ledger_list_prioritizes_current_snapshot(self) -> None:
        old_only = {
            "type": "Historical bug",
            "class_name": "dom-xss",
            "file": "renderer/history.js",
            "severity": "HIGH",
        }
        current = {
            "type": "Current bug",
            "class_name": "ssrf",
            "file": "main/fetcher.js",
            "severity": "HIGH",
        }

        ledger_add(self.program, old_only, "snap-old", "v2.1.0", "20260401T010000Z", "agent-a")
        ledger_add(self.program, current, "snap-current", "v2.2.0", "20260407T180000Z", "agent-b")

        findings = ledger_list(self.program, snapshot_id="snap-current", version_label="v2.2.0")
        self.assertEqual([item["fid"] for item in findings], ["D02", "D01"])
        self.assertEqual(findings[0]["sightings"][0]["snapshot_id"], "snap-current")
        self.assertEqual(findings[1]["sightings"][0]["snapshot_id"], "snap-old")

    def test_migrates_legacy_ledger_format(self) -> None:
        legacy_payload = {
            "version": 1,
            "program": self.program,
            "findings": [
                {
                    "fid": "D01",
                    "type": "Legacy finding",
                    "class_name": "ipc-trust-boundary",
                    "file": "preload.js",
                    "severity": "HIGH",
                    "review_tier": "CONFIRMED",
                    "added_at": "2026-04-01T00:00:00Z",
                    "agent": "legacy-agent",
                }
            ],
        }
        path = ledger_path(self.program)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(legacy_payload, indent=2) + "\n", encoding="utf-8")

        is_new, fid = ledger_add(
            self.program,
            {
                "type": "Fresh finding",
                "class_name": "ssrf",
                "file": "network/client.js",
                "severity": "MEDIUM",
            },
            "snap-new",
            "v2.2.0",
            "20260407T180000Z",
            "zero-day-team",
        )
        self.assertTrue(is_new)
        self.assertEqual(fid, "D02")

        payload = self._read_payload()
        self.assertEqual(payload["version"], 2)
        self.assertEqual(len(payload["findings"]), 2)
        migrated = payload["findings"][0]
        self.assertEqual(migrated["fid"], "D01")
        self.assertEqual(migrated["first_snapshot"], "legacy")
        self.assertEqual(migrated["sightings"][0]["review_tier"], "CONFIRMED")

    def test_dedupe_normalizes_underscore_and_dash_class_names(self) -> None:
        first = {
            "type": "Websocket auth bypass",
            "class_name": "canva-websocket-auth_bypass",
            "file": "relative/path.smali",
            "severity": "HIGH",
        }
        second = {
            "type": "Websocket auth bypass",
            "class_name": "canva-websocket-auth-bypass",
            "file": "relative/path.smali",
            "severity": "HIGH",
        }

        is_new, fid = ledger_add(self.program, first, "snap-a", "v1", "20260407T180000Z", "agent-a")
        self.assertTrue(is_new)
        self.assertEqual(fid, "D01")

        is_new_again, fid_again = ledger_add(self.program, second, "snap-b", "v2", "20260408T180000Z", "agent-b")
        self.assertFalse(is_new_again)
        self.assertEqual(fid_again, "D01")

        payload = self._read_payload()
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["class_name"], "canva-websocket-auth-bypass")
        self.assertEqual(len(payload["findings"][0]["sightings"]), 2)

    def test_versioned_update_persists_core_identity_without_losing_snapshot_metadata(self) -> None:
        ledger = VersionedFindingsLedger(
            self.program,
            target_root=self.tmp,
            snapshot_identity={"snapshot_id": "snap-reviewed", "version_label": "v9.0.0"},
            run_id="20260428T010203Z",
            agent="manual-hunter",
            lane="apk",
            family="binaries",
        )

        finding = ledger.update(
            {
                "type": "Reviewed IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
                "review_tier": "CONFIRMED",
                "status": "confirmed",
            }
        )

        self.assertEqual(finding["fid"], "D01")
        self.assertEqual(finding["first_snapshot"], "snap-reviewed")
        self.assertEqual(finding["last_snapshot"], "snap-reviewed")
        self.assertEqual(finding["current"]["version_label"], "v9.0.0")
        self.assertEqual(len(finding["sightings"]), 1)
        self.assertEqual(finding["identity"], "harness-fid:notion:binaries:apk:D01")
        self.assertEqual(finding["harness_fid"], "D01")

        core_findings = core_list_findings(self.program, family="binaries", lane="apk")
        self.assertEqual(len(core_findings), 1)
        self.assertEqual(core_findings[0]["fid"], "D01")
        self.assertEqual(core_findings[0]["identity"], "harness-fid:notion:binaries:apk:D01")

        updated = ledger.update({**finding, "severity": "CRITICAL"})
        self.assertEqual(updated["fid"], "D01")
        self.assertEqual(updated["severity"], "CRITICAL")
        self.assertEqual(len(core_list_findings(self.program, family="binaries", lane="apk")), 1)

    def test_versioned_update_with_root_override_uses_explicit_canonical_root(self) -> None:
        explicit_root = self.tmp / "canonical-storage"
        default_path = ledger_path(self.program, lane="apk", family="binaries")
        explicit_path = ledger_path(
            self.program,
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )
        ledger = VersionedFindingsLedger(
            self.program,
            target_root=self.tmp,
            snapshot_identity={"snapshot_id": "snap-explicit", "version_label": "v9.1.0"},
            run_id="20260428T020304Z",
            agent="manual-hunter",
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )

        finding = ledger.update(
            {
                "type": "Explicit root issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/explicit.js",
                "severity": "HIGH",
                "review_tier": "CONFIRMED",
                "status": "confirmed",
            }
        )

        self.assertEqual(ledger.path, explicit_path)
        self.assertEqual(finding["fid"], "D01")
        self.assertTrue(explicit_path.exists())
        self.assertFalse(default_path.exists())
        self.assertEqual(
            len(core_list_findings(self.program, family="binaries", lane="apk", root_override=explicit_root)),
            1,
        )
        self.assertEqual(len(core_list_findings(self.program, family="binaries", lane="apk")), 0)

    def test_harness_and_core_apis_share_one_explicit_ledger_root(self) -> None:
        explicit_root = self.tmp / "shared-storage"
        path = ledger_path(self.program, lane="apk", family="binaries", root_override=explicit_root)

        harness_new, harness_fid = ledger_add(
            self.program,
            {
                "type": "Harness-added IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
            },
            "snap-harness",
            "v1.0.0",
            "run-harness",
            "harness-wrapper",
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )
        self.assertTrue(harness_new)
        self.assertEqual(harness_fid, "D01")

        core_seen = core_ledger_list(self.program, family="binaries", lane="apk", root_override=explicit_root)
        self.assertEqual([item["fid"] for item in core_seen], ["D01"])

        core_new, core_fid = core_ledger_add(
            self.program,
            {
                "type": "Core-added IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 88,
                "severity": "HIGH",
            },
            "snap-core",
            "v1.1.0",
            "run-core",
            "core-api",
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )
        self.assertTrue(core_new)
        self.assertEqual(core_fid, "D02")

        harness_seen = ledger_list(self.program, family="binaries", lane="apk", root_override=explicit_root)
        self.assertEqual({item["fid"] for item in harness_seen}, {"D01", "D02"})
        self.assertTrue(path.exists())
        self.assertFalse(ledger_path(self.program, lane="apk", family="binaries").exists())

    def test_update_team_finding_patches_reviewer_identity_changes_by_fid(self) -> None:
        explicit_root = self.tmp / "reviewed-storage"
        is_new, fid = ledger_add(
            self.program,
            {
                "type": "Initial IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
                "review_tier": "DORMANT_HYPOTHETICAL",
            },
            "snap-a",
            "v1.0.0",
            "run-a",
            "zero-day-team",
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )
        self.assertTrue(is_new)
        self.assertEqual(fid, "D01")

        updated = update_team_finding(
            self.program,
            {
                "fid": "D01",
                "type": "Reviewed corrected issue",
                "title": "Reviewed corrected issue",
                "class_name": "native-module-abuse",
                "file": "src/corrected.js",
                "line": 7,
                "severity": "CRITICAL",
                "review_tier": "CONFIRMED",
                "status": "confirmed",
            },
            snapshot_id="snap-a",
            version_label="v1.0.0",
            run_id="run-review",
            agent="zero-day-team",
            lane="apk",
            family="binaries",
            root_override=explicit_root,
        )

        self.assertEqual(updated["fid"], "D01")
        self.assertEqual(updated["type"], "Reviewed corrected issue")
        self.assertEqual(updated["class_name"], "native-module-abuse")
        self.assertEqual(updated["file"], "src/corrected.js")
        self.assertEqual(updated["line"], 7)
        findings = ledger_list(self.program, family="binaries", lane="apk", root_override=explicit_root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fid"], "D01")
        self.assertEqual(findings[0]["title"], "Reviewed corrected issue")
        self.assertFalse(list((explicit_root / "binaries" / self.program / "apk" / "reports").glob("**/*.md")))

    def test_versioned_update_preserves_unknown_top_level_metadata(self) -> None:
        path = ledger_path(self.program, lane="apk", family="binaries")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "program": self.program,
                    "updated_at": "2026-04-28T00:00:00Z",
                    "coverage": {"src/preload.js": {"ipc-trust-boundary": True}},
                    "custom_metadata": {"owner": "compat"},
                    "findings": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        ledger = VersionedFindingsLedger(
            self.program,
            target_root=self.tmp,
            snapshot_identity={"snapshot_id": "snap-metadata", "version_label": "v9.2.0"},
            run_id="20260428T030405Z",
            agent="manual-hunter",
            lane="apk",
            family="binaries",
        )

        ledger.update(
            {
                "type": "Metadata preserving issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "severity": "HIGH",
                "review_tier": "CONFIRMED",
                "status": "confirmed",
            }
        )

        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["coverage"], {"src/preload.js": {"ipc-trust-boundary": True}})
        self.assertEqual(payload["custom_metadata"], {"owner": "compat"})
        self.assertEqual(len(payload["findings"]), 1)

    def test_storage_resolver_facade_matches_core_custom_lane_and_binary_roots(self) -> None:
        with self.assertRaises(ValueError):
            infer_family_from_lane("mobile-research")

        custom_layout = resolve_storage(
            self.program,
            family="binaries",
            lane="mobile-research",
            root_override=self.tmp / "storage",
            create=False,
        )
        self.assertEqual(custom_layout.family, "binaries")
        self.assertEqual(custom_layout.lane, "mobile-research")

        layout = resolve_storage(
            self.program,
            family="binaries",
            lane="apk",
            root_override=self.tmp / "storage",
            create=True,
        )

        self.assertEqual(layout.family, "binaries")
        self.assertEqual(layout.lane, "apk")
        self.assertEqual(layout.recon_root, layout.lane_root / "recon")
        self.assertEqual(layout.input_root, layout.lane_root / "input")
        self.assertTrue((layout.recon_root / "artifacts").is_dir())
        self.assertTrue((layout.input_root / "original").is_dir())

    def test_file_locking_under_concurrent_writes(self) -> None:
        processes: list[subprocess.Popen[str]] = []
        for index in range(8):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _CONCURRENT_ADD_SCRIPT,
                    str(self.home),
                    self.program,
                    f"src/file_{index}.js",
                    "dom-xss",
                    "snap-concurrent",
                    f"20260407T18000{index}Z",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(process)

        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            if process.returncode != 0:
                self.fail(
                    f"concurrent writer failed: rc={process.returncode} stderr={stderr} stdout={stdout}"
                )

        payload = self._read_payload()
        self.assertEqual(payload["version"], 2)
        self.assertEqual(len(payload["findings"]), 8)
        self.assertEqual({item["fid"] for item in payload["findings"]}, {f"D0{index + 1}" for index in range(8)})


class ApkCandidateSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_prefers_bundle_base_apk_when_no_top_level_apk_exists(self) -> None:
        bundle = self.tmp / "Canva_2.356.0_apkcombo.com"
        bundle.mkdir()
        (bundle / "config.x86_64.apk").write_text("x", encoding="utf-8")
        (bundle / "config.xxhdpi.apk").write_text("x", encoding="utf-8")
        (bundle / "com.canva.editor.apk").write_text("x", encoding="utf-8")

        selected, debug_rows, selected_bundle = _select_apk_candidate(self.tmp, "canva")
        self.assertEqual(selected.name, "com.canva.editor.apk")
        self.assertEqual(selected_bundle, bundle)
        self.assertTrue(any(row.get("source") == "bundle_dir" for row in debug_rows))

    def test_prefers_top_level_apk_when_present(self) -> None:
        (self.tmp / "com.canva.editor.apk").write_text("x", encoding="utf-8")
        bundle = self.tmp / "Canva_2.355.0_apkcombo.com"
        bundle.mkdir()
        (bundle / "config.x86_64.apk").write_text("x", encoding="utf-8")
        (bundle / "com.canva.editor.apk").write_text("x", encoding="utf-8")

        selected, debug_rows, selected_bundle = _select_apk_candidate(self.tmp, "canva")
        self.assertEqual(selected, self.tmp / "com.canva.editor.apk")
        self.assertIsNone(selected_bundle)
        self.assertTrue(all(row.get("source") == "top_level" for row in debug_rows))


if __name__ == "__main__":
    unittest.main()
