from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "agents" / "hypothesis_ledger.py"


def run_cli(tmp_path: Path, *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ""},
        check=True,
    )
    return json.loads(result.stdout)


def test_cli_captures_private_hypothesis_and_exposes_only_owner_view(tmp_path):
    created = run_cli(
        tmp_path,
        "create", "demo",
        "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Signed URL export worker", "--surface", "export",
        "--url", "https://app.example/export", "--tag", "worker", "--tag", "pdf",
    )

    owner_view = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")
    other_view = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-b", "--run-id", "run-b")
    checkpoint = run_cli(tmp_path, "continuation", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")

    assert owner_view["hypotheses"][0]["id"] == created["id"]
    assert other_view == {"hypotheses": []}
    assert checkpoint == {"private_unresolved_count": 1, "active_count": 0, "surface": "export"}


def test_cli_can_transition_an_owned_hypothesis_to_active(tmp_path):
    created = run_cli(
        tmp_path, "create", "demo", "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Signed URL export worker", "--surface", "export",
    )

    active = run_cli(
        tmp_path, "transition", "demo", created["id"], "--agent-id", "agent-a", "--run-id", "run-a", "--status", "active",
    )
    checkpoint = run_cli(tmp_path, "continuation", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")

    assert active["status"] == "active"
    assert checkpoint == {"private_unresolved_count": 1, "active_count": 1, "surface": "export"}


def test_cli_lead_followup_returns_released_context_without_broadening_list(tmp_path):
    created = run_cli(
        tmp_path, "create", "demo", "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Export worker authorization seam", "--surface", "export",
        "--lead-id", "lead-export-worker",
    )

    released = run_cli(
        tmp_path, "release", "demo", created["id"],
        "--agent-id", "agent-a", "--run-id", "run-a",
    )
    ordinary_list = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-b", "--run-id", "run-b")
    followup = run_cli(
        tmp_path, "lead-followup", "demo", "--agent-id", "agent-b", "--run-id", "run-b",
        "--lead-id", "lead-export-worker",
    )

    assert released["context_state"] == "released"
    assert ordinary_list == {"hypotheses": []}
    assert [item["id"] for item in followup["hypotheses"]] == [created["id"]]
    assert followup["hypotheses"][0]["visibility"] == "released"
