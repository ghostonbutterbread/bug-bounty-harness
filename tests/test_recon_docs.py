from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.recon_docs import normalized_record


def test_normalized_record_preserves_source_context_and_rejects_non_http() -> None:
    record = normalized_record(
        {"url": "https://developers.example.com/webhooks", "kind": "webhook", "signals": ["Webhook", "integration"], "use_cases": "events, delivery"},
        source_path="/tmp/docs.jsonl",
    )

    assert record is not None
    assert record["kind"] == "webhook"
    assert record["signals"] == ["integration", "webhook"]
    assert record["source_status"] == "collected-unverified"
    assert normalized_record({"url": "file:///tmp/private"}, source_path="fixture") is None


def test_recon_docs_cli_writes_offline_source_artifact(tmp_path: Path) -> None:
    source = tmp_path / "docs.jsonl"
    source.write_text(
        "\n".join(
            [
                json.dumps({"url": "https://docs.example.com/api", "kind": "api", "signals": ["rest", "token"]}),
                json.dumps({"url": "https://docs.example.com/api", "kind": "api", "signals": ["rest"]}),
                json.dumps({"url": "not-a-url"}),
            ]
        ) + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "agents/recon_docs.py", "demo", "--target", "example.com", "--input", str(source), "--root", str(tmp_path / "shared"), "--run-id", "docs", "--json"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=True,
    )
    manifest = json.loads(result.stdout)
    output = Path(manifest["run_dir"]) / "parsed" / "developer_docs.jsonl"

    assert manifest["tool"] == "recon-docs"
    assert manifest["counts"]["document_sources"] == 1
    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["promotion"] == "candidate-for-program-docs"
