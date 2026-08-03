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
