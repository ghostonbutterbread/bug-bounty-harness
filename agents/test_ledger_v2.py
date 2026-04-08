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

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.ledger_v2 import ledger_add, ledger_get, ledger_list, ledger_path
from agents.snapshot_identity import get_snapshot_identity, get_snapshot_id, is_same_snapshot


_CONCURRENT_ADD_SCRIPT = textwrap.dedent(
    """
    import os
    import sys
    from pathlib import Path

    project_root = Path(sys.argv[1])
    home = sys.argv[2]
    program = sys.argv[3]
    relpath = sys.argv[4]
    class_name = sys.argv[5]
    snapshot_id = sys.argv[6]
    run_id = sys.argv[7]

    os.environ["HOME"] = home
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

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

    def test_file_locking_under_concurrent_writes(self) -> None:
        processes: list[subprocess.Popen[str]] = []
        for index in range(8):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _CONCURRENT_ADD_SCRIPT,
                    str(_project_root),
                    str(self.home),
                    self.program,
                    f"src/file_{index}.js",
                    "dom-xss",
                    "snap-concurrent",
                    f"20260407T18000{index}Z",
                ],
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


if __name__ == "__main__":
    unittest.main()
