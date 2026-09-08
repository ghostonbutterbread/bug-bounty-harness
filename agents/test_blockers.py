from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "agents" / "blockers.py"


def run_cli(tmp_path: Path, *args: str) -> dict:
    env = os.environ.copy()
    core_source = env.get("BOUNTY_CORE_TEST_SOURCE")
    if core_source:
        env["PYTHONPATH"] = core_source
    result = subprocess.run([sys.executable, str(CLI), "--root", str(tmp_path), *args], cwd=ROOT, capture_output=True, text=True, env=env, check=True)
    return json.loads(result.stdout)


def record_external_blocker(tmp_path: Path, *, run_id: str = "run-1", blocker_key: str = "human-verification") -> dict:
    return run_cli(
        tmp_path, "record", "--program", "ad-signal", "--producer", "access-control", "--run-id", run_id,
        "--subject", "https://ads.example.test/campaigns", "--test-scope", "access-control:horizontal:campaign",
        "--blocker-key", blocker_key, "--blocker-type", "auth-state",
        "--reason", "normal setup completed but human-only identity verification is pending", "--unblock-condition", "Ryushe completes identity verification",
        "--remediation-evidence", "attempt: owned signup and normal setup completed; verification prompt requires human action",
        "--account-ref", "green", "--account-ref", "magenta", "--fixture", "campaign",
    )


def test_check_finds_known_external_blocker_and_preserves_its_next_action(tmp_path):
    record_external_blocker(tmp_path)
    checked = run_cli(
        tmp_path, "check", "--program", "ad-signal", "--subject", "https://ads.example.test/campaigns",
        "--test-scope", "access-control:horizontal:campaign", "--blocker-key", "human-verification",
    )

    assert checked["known_blocker"] is True
    assert checked["blockers"][0]["unblock_condition"] == "Ryushe completes identity verification"
    assert "known blocker is not permission to stop" in checked["remediation_first"]
    assert "If the prerequisite remains outside" in checked["next_action"]


def test_open_blocker_requires_remediation_evidence(tmp_path):
    result = subprocess.run(
        [
            sys.executable, str(CLI), "--root", str(tmp_path), "record", "--program", "ad-signal",
            "--producer", "access-control", "--run-id", "run-1", "--subject", "https://ads.example.test/campaigns",
            "--test-scope", "access-control:horizontal:campaign", "--blocker-key", "human-verification",
            "--blocker-type", "auth-state", "--reason", "human verification pending",
            "--unblock-condition", "Ryushe completes identity verification",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": os.environ.get("BOUNTY_CORE_TEST_SOURCE", "")},
    )
    assert result.returncode != 0
    assert "remediation-evidence" in result.stderr


def test_completion_brief_lists_only_open_blockers_from_that_run(tmp_path):
    record_external_blocker(tmp_path, run_id="run-current")
    record_external_blocker(tmp_path, run_id="run-other", blocker_key="other-fixture")
    brief = run_cli(tmp_path, "brief", "--program", "ad-signal", "--run-id", "run-current")

    assert brief["open_blocker_count"] == 1
    assert brief["what_happened"] == "The run completed with 1 external blocker(s) left open."
    assert brief["next_to_push"] == ["Ryushe completes identity verification"]
    assert brief["open_blockers"][0]["blocker_key"] == "human-verification"


def test_resolved_event_removes_open_blocker_from_check_and_brief(tmp_path):
    record_external_blocker(tmp_path, run_id="run-current")
    resolved = run_cli(
        tmp_path, "record", "--program", "ad-signal", "--producer", "access-control", "--run-id", "run-resolution",
        "--subject", "https://ads.example.test/campaigns", "--test-scope", "access-control:horizontal:campaign",
        "--blocker-key", "human-verification", "--blocker-type", "auth-state", "--state", "resolved",
        "--reason", "normal owned fixture verified after human setup",
    )
    assert resolved["lifecycle"] == "resolved"

    checked = run_cli(
        tmp_path, "check", "--program", "ad-signal", "--subject", "https://ads.example.test/campaigns",
        "--test-scope", "access-control:horizontal:campaign", "--blocker-key", "human-verification",
    )
    brief = run_cli(tmp_path, "brief", "--program", "ad-signal", "--run-id", "run-current")
    assert checked["known_blocker"] is False
    assert brief["open_blocker_count"] == 0


def test_blocker_cli_has_no_coverage_gate(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), "query", "--program", "ad-signal", "--intent", "coverage"],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": os.environ.get("BOUNTY_CORE_TEST_SOURCE", "")},
    )
    assert result.returncode != 0
    assert "coverage" in result.stderr


def test_check_does_not_require_or_create_a_blocker(tmp_path):
    checked = run_cli(
        tmp_path, "check", "--program", "ad-signal", "--subject", "https://ads.example.test/campaigns",
        "--test-scope", "access-control:horizontal:campaign",
    )

    assert checked == {
        "known_blocker": False, "blockers": [],
        "remediation_first": "First determine whether this agent can now clear the prerequisite through normal authorized work, including permitted signup/free-trial enrollment, owned-account or fixture creation, feature setup, or bounded login recovery. If it can, perform that work and freshly verify the flow; a known blocker is not permission to stop.",
        "next_action": "No known external blocker matches this scope. Continue normal work; record one only after feasible authorized remediation is exhausted and the remaining action is outside the agent's authority.",
    }
