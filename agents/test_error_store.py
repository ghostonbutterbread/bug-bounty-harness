from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "agents" / "error_store.py"


def run_cli(tmp_path: Path, *args: str) -> dict:
    core_source = os.environ.get("BOUNTY_CORE_TEST_SOURCE")
    assert core_source, "BOUNTY_CORE_TEST_SOURCE must name the Core source under test"
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": core_source},
        check=True,
    )
    return json.loads(result.stdout)


def test_record_and_dedupe_query_use_the_core_error_store(tmp_path):
    recorded = run_cli(
        tmp_path,
        "--family", "web_bounty", "--lane", "web",
        "record", "--program", "ticket-signal", "--producer", "error-intelligence",
        "--subject", "https://tickets.example.test/api/tickets/1",
        "--reason", "unexpected parser failure", "--layer", "application",
        "--channel", "http", "--status-or-event", "500",
        "--fingerprint", "json-parser-type-error", "--trigger-family", "type",
        "--input-location", "body.ticket_id",
    )
    dedupe = run_cli(
        tmp_path, "--family", "web_bounty", "--lane", "web",
        "query", "--program", "ticket-signal", "--intent", "dedupe",
        "--fingerprint", "json-parser-type-error",
        "--subject", "https://tickets.example.test/api/tickets/1",
    )

    assert recorded["error_id"].startswith("E-")
    assert dedupe["intent"] == "dedupe"
    assert dedupe["events"][0]["error_id"] == recorded["error_id"]
    assert dedupe["fingerprints"][0]["count"] == 1
