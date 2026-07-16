from __future__ import annotations

import json
from pathlib import Path

import pytest


def _campaign(tmp_path: Path) -> Path:
    root = tmp_path / "offline_campaign"
    (root / "offline_target" / "packets").mkdir(parents=True)
    (root / "offline_target" / "packets" / "packet.md").write_text("fetch('/api/invoices')\n", encoding="utf-8")
    (root / "brainstorm").mkdir()
    (root / "brainstorm" / "spec.md").write_text("# local JS review\n", encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "js-offline-campaign.v1",
                "program": "demo",
                "brainstorm_spec": str(root / "brainstorm" / "spec.md"),
                "offline_target": str(root / "offline_target"),
                "runtime_handoff": "none",
                "lanes": [{"key": "general-map"}, {"key": "anomaly-hunter"}, {"key": "api-request-contracts"}],
            }
        ),
        encoding="utf-8",
    )
    return root


def test_worker_command_uses_only_file_toolset_and_local_paths(tmp_path: Path) -> None:
    from agents import js_offline_team as T

    root = _campaign(tmp_path)
    command = T.worker_command(root, "general-map", "H001")

    assert command[:4] == ["hermes", "chat", "-q", "--toolsets"]
    assert command[4] == "file"
    prompt = command[-1]
    assert str(root / "offline_target") in prompt
    assert "Do not make network requests" in prompt
    assert "web" not in command[4]
    assert "terminal" not in command[4]


def test_planner_execution_writes_reports_and_blocks_follow_up_without_approval(tmp_path: Path) -> None:
    from agents import js_offline_team as T

    root = _campaign(tmp_path)
    received: list[list[str]] = []

    def fake_runner(command: list[str], **_kwargs: object) -> T.WorkerResult:
        received.append(command)
        return T.WorkerResult(returncode=0, stdout="local report", stderr="")

    result = T.run_stage(root, stage="planner", runner=fake_runner)
    assert result["status"] == "completed"
    assert [item["lane"] for item in result["workers"]] == ["general-map", "anomaly-hunter"]
    assert len(received) == 2
    assert (root / "reviews" / "planner" / "general-map.md").read_text(encoding="utf-8") == "local report\n"

    with pytest.raises(SystemExit, match="approval"):
        T.run_stage(root, stage="follow-up", lanes=["api-request-contracts"], runner=fake_runner)


def test_follow_up_requires_matching_persisted_approval(tmp_path: Path) -> None:
    from agents import js_offline_team as T

    root = _campaign(tmp_path)

    def fake_runner(_command: list[str], **_kwargs: object) -> T.WorkerResult:
        return T.WorkerResult(returncode=0, stdout="review", stderr="")

    T.run_stage(root, stage="planner", runner=fake_runner)
    approval = T.approve_follow_up(root, ["api-request-contracts"])
    assert approval["approved_lanes"] == ["api-request-contracts"]

    result = T.run_stage(root, stage="follow-up", lanes=["api-request-contracts"], runner=fake_runner)
    assert result["status"] == "completed"
    assert (root / "reviews" / "follow-up" / "api-request-contracts.md").exists()
