from __future__ import annotations

import json
from pathlib import Path

from agents import js_team as T


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


def test_dry_run_defaults_to_planner_then_waits_for_follow_up_selection(tmp_path: Path, capsys) -> None:
    js_run = _write_js_run(tmp_path)

    assert T.main(["dry-run", "--js-run-root", str(js_run), "--mode", "deep"]) == 0

    plan = json.loads(capsys.readouterr().out)
    assert plan["schema"] == "js-team-staged-plan.v1"
    assert plan["live_requests_allowed"] is False
    assert plan["stage_order"] == ["planner", "follow-up"]
    assert plan["stages"]["planner"]["lanes"] == ["general-map", "anomaly-hunter"]
    assert plan["stages"]["follow-up"]["lanes"] == []
    assert plan["stages"]["follow-up"]["selection_mode"] == "waiting-for-mapper-output"
    planner_commands = plan["stages"]["planner"]["commands"]
    assert [item["hypothesis_id"] for item in planner_commands] == ["H001", "H008"]
    assert all("--brainstorm-hypothesis" in item["command"] for item in planner_commands)
    assert plan["campaign_root"] == "(temporary; removed after dry run)"
    assert not (js_run / "offline_campaign").exists()


def test_run_with_explicit_follow_up_lanes_writes_staged_plan(tmp_path: Path, capsys) -> None:
    js_run = _write_js_run(tmp_path)

    assert (
        T.main(
            [
                "run",
                "--js-run-root",
                str(js_run),
                "--follow-up-lane",
                "api-request-contracts,commerce-feature-logic",
            ]
        )
        == 0
    )

    plan = json.loads(capsys.readouterr().out)
    assert plan["stages"]["follow-up"]["selection_mode"] == "explicit"
    assert plan["stages"]["follow-up"]["lanes"] == ["api-request-contracts", "commerce-feature-logic"]
    assert [item["hypothesis_id"] for item in plan["stages"]["follow-up"]["commands"]] == ["H004", "H006"]
    plan_path = js_run / "offline_campaign" / "js_team_plan.json"
    assert plan_path.exists()
    saved = json.loads(plan_path.read_text(encoding="utf-8"))
    assert saved["stages"]["follow-up"]["lanes"] == ["api-request-contracts", "commerce-feature-logic"]


def test_auto_follow_up_from_signals_is_deterministic(tmp_path: Path, capsys) -> None:
    js_run = _write_js_run(tmp_path)

    assert T.main(["dry-run", "--js-run-root", str(js_run), "--auto-follow-up-from-signals"]) == 0

    plan = json.loads(capsys.readouterr().out)
    assert plan["stages"]["follow-up"]["selection_mode"] == "auto-signals"
    assert "auth-account-tenant" in plan["stages"]["follow-up"]["lanes"]
    assert "commerce-feature-logic" in plan["stages"]["follow-up"]["lanes"]
    assert "api-request-contracts" in plan["stages"]["follow-up"]["lanes"]


def test_execute_all_is_rejected_to_preserve_the_human_review_gate(tmp_path: Path, monkeypatch) -> None:
    js_run = _write_js_run(tmp_path)
    monkeypatch.setattr(T, "_execute_stage", lambda *_args: (_ for _ in ()).throw(AssertionError("must not execute")))

    try:
        T.main(["run", "--js-run-root", str(js_run), "--stage", "all", "--execute"])
    except SystemExit as exc:
        assert "execute planner and follow-up stages separately" in str(exc)
    else:
        raise AssertionError("--execute --stage all must require an explicit stage boundary")
