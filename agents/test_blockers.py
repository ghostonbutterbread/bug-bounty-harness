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
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT, capture_output=True, text=True, env=env, check=True,
    )
    return json.loads(result.stdout)


def test_blocker_cli_records_and_exposes_a_coverage_gate(tmp_path):
    recorded = run_cli(
        tmp_path, "record", "--program", "ad-signal", "--producer", "access-control",
        "--subject", "https://ads.example.test/campaigns", "--test-scope", "access-control:horizontal:campaign",
        "--blocker-key", "ads-campaign-fixture:green-magenta", "--blocker-type", "owned-fixture",
        "--reason", "selected accounts have no owned campaign", "--unblock-condition", "create one campaign per account",
        "--account-ref", "green", "--account-ref", "magenta", "--fixture", "campaign",
    )
    gate = run_cli(
        tmp_path, "query", "--program", "ad-signal", "--intent", "coverage",
        "--subject", "https://ads.example.test/campaigns", "--test-scope", "access-control:horizontal:campaign",
    )

    assert recorded["blocker_id"].startswith("B-")
    assert gate["coverage_state"] == "blocked"
    assert gate["blockers"][0]["blocker_key"] == "ads-campaign-fixture:green-magenta"


def test_coverage_query_requires_the_subject_and_test_scope(tmp_path):
    env = os.environ.copy()
    if env.get("BOUNTY_CORE_TEST_SOURCE"):
        env["PYTHONPATH"] = env["BOUNTY_CORE_TEST_SOURCE"]
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), "query", "--program", "ad-signal", "--intent", "coverage"],
        cwd=ROOT, capture_output=True, text=True, env=env,
    )

    assert result.returncode != 0
    assert "--subject and --test-scope" in result.stderr
