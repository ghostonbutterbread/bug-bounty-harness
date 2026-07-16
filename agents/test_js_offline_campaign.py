from __future__ import annotations

import json
from pathlib import Path

from agents import js_offline_campaign as C
from agents.brainstorm_spec import parse_brainstorm_spec


def _write_js_run(tmp_path: Path) -> Path:
    root = tmp_path / "js-run"
    packets = root / "packets"
    packets.mkdir(parents=True)
    packet_path = packets / "abcd-001.md"
    packet_path.write_text(
        "# JS Deep Review Packet\n\nfetch('/api/billing/invoices/:invoice_id');\n",
        encoding="utf-8",
    )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "program": "demo",
                "run_id": "js-demo-unit",
                "target_host": "example.com",
                "scope_hosts": ["example.com"],
                "js_downloaded": 1,
                "packets": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "metadata.jsonl").write_text(
        json.dumps(
            {
                "url": "https://static.example.com/app.js",
                "sha256": "abcd",
                "flow_hints": ["payment", "object_ids", "graphql"],
                "sources": ["location"],
                "sinks": ["request", "dom_write"],
                "graphql_operations": ["UpdateInvoice"],
                "hidden_state_hints": ["__NEXT_DATA__"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "packets.jsonl").write_text(
        json.dumps(
            {
                "url": "https://static.example.com/app.js",
                "sha256": "abcd",
                "chunk_index": 0,
                "chunk_count": 1,
                "packet_path": str(packet_path),
                "byte_start": 0,
                "byte_end": 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return root


def test_prepare_builds_valid_offline_campaign(tmp_path: Path) -> None:
    js_run = _write_js_run(tmp_path)
    campaign_root = tmp_path / "campaign"

    rc = C.main(
        [
            "prepare",
            "--js-run-root",
            str(js_run),
            "--campaign-root",
            str(campaign_root),
            "--mode",
            "deep",
        ]
    )

    assert rc == 0
    manifest = json.loads((campaign_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["execution_mode"] == "offline"
    assert manifest["live_requests_allowed"] is False
    assert manifest["agent_granularity"] == "category"
    assert manifest["packet_count"] == 1
    assert manifest["runtime_handoff"] == "none"
    assert "zero_day_command" not in manifest
    assert manifest["mapstore_candidates"].endswith("mapstore_candidates.jsonl")
    assert manifest["mapstore_candidate_schema"].endswith("mapstore_candidate_schema.json")
    assert (campaign_root / "offline_target" / "index.json").exists()
    assert (campaign_root / "mapstore_candidates.jsonl").exists()
    schema = json.loads((campaign_root / "mapstore_candidate_schema.json").read_text(encoding="utf-8"))
    assert schema["schema"] == "js-offline-mapstore-candidate.v1"
    assert "dedupe_hint" in schema["required_fields"]
    assert list((campaign_root / "offline_target" / "packets").glob("*.md"))

    spec_path = campaign_root / "brainstorm" / "spec.md"
    spec_text = spec_path.read_text(encoding="utf-8")
    assert "new-to-current-index" in spec_text
    assert "mapstore_candidates.jsonl" in spec_text
    assert "do not overclaim global novelty" in spec_text

    spec = parse_brainstorm_spec(spec_path)
    assert spec.metadata["Execution mode"] == "offline"
    assert spec.metadata["Live requests allowed"] == "false"
    assert spec.metadata["Target kind"] == "web-js"
    assert spec.metadata["Agent granularity"] == "category"
    assert spec.metadata["MapStore candidates path"] == str(campaign_root / "mapstore_candidates.jsonl")
    agent_keys = [agent for hyp in spec.hypotheses for agent in hyp.suggested_agents]
    assert "js-general-map" in agent_keys
    assert "js-client-side-trust" in agent_keys
    assert "js-api-request-contracts" in agent_keys
    assert "js-anomaly-hunter" in agent_keys
    assert "js-dom-xss" not in agent_keys


def test_look_mode_adds_signal_triggered_lanes(tmp_path: Path) -> None:
    js_run = _write_js_run(tmp_path)
    campaign_root = tmp_path / "campaign"

    assert (
        C.main(
            [
                "prepare",
                "--js-run-root",
                str(js_run),
                "--campaign-root",
                str(campaign_root),
                "--mode",
                "look",
            ]
        )
        == 0
    )

    spec = parse_brainstorm_spec(campaign_root / "brainstorm" / "spec.md")
    agent_keys = [agent for hyp in spec.hypotheses for agent in hyp.suggested_agents]
    assert "js-commerce-feature-logic" in agent_keys
    assert "js-api-request-contracts" in agent_keys
    assert "js-anomaly-hunter" in agent_keys


def test_lens_granularity_preserves_legacy_narrow_lanes(tmp_path: Path) -> None:
    js_run = _write_js_run(tmp_path)
    campaign_root = tmp_path / "campaign"

    assert (
        C.main(
            [
                "prepare",
                "--js-run-root",
                str(js_run),
                "--campaign-root",
                str(campaign_root),
                "--mode",
                "look",
                "--granularity",
                "lens",
            ]
        )
        == 0
    )

    manifest = json.loads((campaign_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["agent_granularity"] == "lens"
    spec = parse_brainstorm_spec(campaign_root / "brainstorm" / "spec.md")
    agent_keys = [agent for hyp in spec.hypotheses for agent in hyp.suggested_agents]
    assert "js-payment" in agent_keys
    assert "js-graphql" in agent_keys
    assert "js-dom-xss" in agent_keys


def test_run_prints_non_executable_review_handoff(tmp_path: Path, capsys) -> None:
    js_run = _write_js_run(tmp_path)
    campaign_root = tmp_path / "campaign"
    assert C.main(["prepare", "--js-run-root", str(js_run), "--campaign-root", str(campaign_root)]) == 0

    assert C.main(["run", "--campaign-root", str(campaign_root)]) == 0
    output = capsys.readouterr().out
    assert '"runtime_handoff": "none"' in output
    assert "zero_day_team.py" not in output


def test_run_execute_is_rejected_until_zero_day_runner_enforces_offline_mode(tmp_path: Path) -> None:
    js_run = _write_js_run(tmp_path)
    campaign_root = tmp_path / "campaign"
    assert C.main(["prepare", "--js-run-root", str(js_run), "--campaign-root", str(campaign_root)]) == 0

    try:
        C.main(["run", "--campaign-root", str(campaign_root), "--execute"])
    except SystemExit as exc:
        assert "disconnected from zero_day_team" in str(exc)
    else:
        raise AssertionError("offline JS campaigns must not execute a mutable generated command")


def test_dry_run_previews_flow_without_durable_campaign(tmp_path: Path, capsys) -> None:
    js_run = _write_js_run(tmp_path)

    assert C.main(["dry-run", "--js-run-root", str(js_run), "--mode", "deep"]) == 0

    output = capsys.readouterr().out
    summary = json.loads(output)
    assert summary["dry_run"] is True
    assert summary["runtime_handoff"] == "none"
    assert summary["live_requests_allowed"] is False
    assert summary["durable_aftermath"] is False
    assert summary["campaign_root"] == "(temporary; removed after dry run)"
    assert summary["packet_count"] == 1
    assert "js-general-map" in summary["lanes"]
    assert "js-anomaly-hunter" in summary["lanes"]
    assert summary["always_on_anomaly_hunter"] is True
