"""Unit tests for agents.coverage_store."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.coverage_store import CoverageStore  # noqa: E402


_CONCURRENT_MARK_SCRIPT = """
import os
import sys
from pathlib import Path

project_root = Path(sys.argv[1])
home = sys.argv[2]
program = sys.argv[3]
target_dir = Path(sys.argv[4])
vuln_class = sys.argv[5]
relpath = sys.argv[6]

os.environ["HOME"] = home
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from agents.coverage_store import CoverageStore

store = CoverageStore(program, target_dir)
store.mark_examined(
    vuln_class=vuln_class,
    files=[relpath],
    method="sub-agent",
    status="done",
    run_id=relpath.replace("/", "_"),
)
"""


def _brain_file(sha1: str, *, class_scores: dict[str, int] | None = None) -> dict[str, object]:
    return {
        "lang": "javascript",
        "size": 123,
        "mtime_ns": 1,
        "sha1": sha1,
        "roles": [],
        "signals": {
            "entries": [],
            "trust_boundaries": [],
            "sinks": [],
            "class_scores": class_scores or {"dom-xss": 1},
        },
    }


class CoverageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.workspace = self.tmp / "workspace"
        self.target_dir = self.workspace / "source"
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.program = "notion"

        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

    def _shared_brain_path(self) -> Path:
        return (
            self.home
            / "Shared"
            / "bounty_recon"
            / self.program
            / "ghost"
            / "shared_brain"
            / "index.json"
        )

    def _coverage_path(self) -> Path:
        return self.target_dir.parent / "ghost" / "coverage.json"

    def _write_shared_brain(
        self,
        *,
        git_head: str | None = "abc123",
        manifest_hash: str = "manifest-1",
        files: dict[str, dict[str, object]] | None = None,
    ) -> None:
        path = self._shared_brain_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "target_root": str(self.target_dir),
            "target_id": "target-123",
            "generated_at": "2026-04-06T20:00:00Z",
            "git_head": git_head,
            "manifest_hash": manifest_hash,
            "frameworks": [],
            "files": files or {},
            "inventories": {},
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_mark_and_retrieve(self) -> None:
        self._write_shared_brain(
            files={
                "src/a.js": _brain_file("sha-a"),
                "src/b.js": _brain_file("sha-b"),
            }
        )

        store = CoverageStore(self.program, self.target_dir)
        store.mark_examined(
            vuln_class="dom-xss",
            files=["src/a.js", "src/b.js"],
            method="agent-static",
            status="done",
            run_id="20260406T201100Z",
            finding_fids=["C004"],
            notes="Bridge reviewed; no unsafe HTML sink",
        )

        coverage = store.get_coverage("dom-xss")
        self.assertEqual(set(coverage), {"src/a.js", "src/b.js"})
        self.assertEqual(coverage["src/a.js"]["sha1"], "sha-a")
        self.assertEqual(coverage["src/a.js"]["status"], "done")
        self.assertEqual(coverage["src/a.js"]["method"], "agent-static")
        self.assertEqual(coverage["src/a.js"]["run_id"], "20260406T201100Z")
        self.assertEqual(coverage["src/a.js"]["finding_fids"], ["C004"])
        self.assertEqual(
            coverage["src/a.js"]["notes"], "Bridge reviewed; no unsafe HTML sink"
        )

    def test_sha1_invalidation(self) -> None:
        self._write_shared_brain(files={"src/a.js": _brain_file("sha-old")})
        store = CoverageStore(self.program, self.target_dir)
        store.mark_examined("dom-xss", ["src/a.js"], method="agent-static")

        self._write_shared_brain(
            git_head="abc123",
            manifest_hash="manifest-2",
            files={"src/a.js": _brain_file("sha-new")},
        )
        reloaded = CoverageStore(self.program, self.target_dir)

        self.assertEqual(reloaded.get_coverage("dom-xss"), {})
        self.assertEqual(reloaded.get_unexplored("dom-xss", ["src/a.js"]), ["src/a.js"])

    def test_status_values(self) -> None:
        self._write_shared_brain(
            files={
                "src/done.js": _brain_file("sha-done"),
                "src/partial.js": _brain_file("sha-partial"),
                "src/error.js": _brain_file("sha-error"),
                "src/skip.js": _brain_file("sha-skip"),
            }
        )
        store = CoverageStore(self.program, self.target_dir)

        store.mark_examined("dom-xss", ["src/done.js"], method="agent-static", status="done")
        store.mark_examined("dom-xss", ["src/partial.js"], method="agent-static", status="partial")
        store.mark_examined("dom-xss", ["src/error.js"], method="agent-static", status="error")
        store.mark_examined("dom-xss", ["src/skip.js"], method="manual", status="manual-skip")

        coverage = store.get_coverage("dom-xss")
        self.assertEqual(coverage["src/done.js"]["status"], "done")
        self.assertEqual(coverage["src/partial.js"]["status"], "partial")
        self.assertEqual(coverage["src/error.js"]["status"], "error")
        self.assertEqual(coverage["src/skip.js"]["status"], "manual-skip")

    def test_unexplored_derived(self) -> None:
        self._write_shared_brain(
            files={
                "src/done.js": _brain_file("sha-done"),
                "src/partial.js": _brain_file("sha-partial"),
                "src/error.js": _brain_file("sha-error"),
                "src/new.js": _brain_file("sha-new"),
            }
        )
        store = CoverageStore(self.program, self.target_dir)
        store.mark_examined("dom-xss", ["src/done.js"], method="agent-static", status="done")
        store.mark_examined("dom-xss", ["src/partial.js"], method="agent-static", status="partial")
        store.mark_examined("dom-xss", ["src/error.js"], method="agent-static", status="error")

        unexplored = store.get_unexplored(
            "dom-xss",
            ["src/done.js", "src/partial.js", "src/error.js", "src/new.js"],
        )
        self.assertEqual(unexplored, ["src/error.js", "src/new.js"])

        payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        self.assertNotIn("unexplored", payload)
        snapshot = payload["snapshots"][store.get_snapshot_id()]
        self.assertNotIn("unexplored", snapshot["classes"]["dom-xss"])

    def test_findings_fids_optional(self) -> None:
        self._write_shared_brain(files={"src/a.js": _brain_file("sha-a")})
        store = CoverageStore(self.program, self.target_dir)
        store.mark_examined("dom-xss", ["src/a.js"], method="agent-static")

        coverage = store.get_coverage("dom-xss")
        self.assertNotIn("finding_fids", coverage["src/a.js"])

        payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        snapshot = payload["snapshots"][store.get_snapshot_id()]
        entry = snapshot["classes"]["dom-xss"]["files"]["src/a.js"]
        self.assertNotIn("finding_fids", entry)

    def test_atomic_write(self) -> None:
        files = {
            f"src/file_{index}.js": _brain_file(f"sha-{index}")
            for index in range(8)
        }
        self._write_shared_brain(files=files)

        processes: list[subprocess.Popen[str]] = []
        for relpath in files:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _CONCURRENT_MARK_SCRIPT,
                    str(_project_root),
                    str(self.home),
                    self.program,
                    str(self.target_dir),
                    "dom-xss",
                    relpath,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(process)

        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            if process.returncode != 0:
                self.fail(f"concurrent writer failed: rc={process.returncode} stderr={stderr} stdout={stdout}")

        payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        snapshot = payload["snapshots"]["abc123"]
        stored = snapshot["classes"]["dom-xss"]["files"]
        self.assertEqual(set(stored), set(files))

        store = CoverageStore(self.program, self.target_dir)
        self.assertEqual(set(store.get_coverage("dom-xss")), set(files))

    def test_snapshot_id_git_head_priority(self) -> None:
        self._write_shared_brain(
            git_head="git-head-123",
            manifest_hash="manifest-xyz",
            files={"src/a.js": _brain_file("sha-a")},
        )
        store = CoverageStore(self.program, self.target_dir)

        self.assertEqual(store.get_snapshot_id(), "git-head-123")

        payload = json.loads(self._coverage_path().read_text(encoding="utf-8"))
        self.assertEqual(payload["target_id"], "git-head-123")
        self.assertIn("git-head-123", payload["snapshots"])


if __name__ == "__main__":
    unittest.main()
