"""Read-only Coverage uptake checks: missing inventory is never a negative verdict."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.coverage_watch import watch_lane
from agents.surface_coverage import SurfaceCoverageStore

CLI = Path(__file__).with_name("coverage.py")


def stream(root: Path, run_id: str, rows: list[dict]) -> Path:
    path = root / "web_bounty" / "sample" / "web" / "attempts" / "_runs" / run_id / "attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_missing_coverage_is_gap_not_review_and_watch_is_read_only(tmp_path: Path) -> None:
    path = stream(tmp_path, "worker-1", [{"attempt_id": "A-1", "target": "https://private.example/?secret=x"}])
    before = path.read_bytes()
    result = watch_lane("sample", family="web_bounty", lane="web", root=tmp_path, attempt_run_id="worker-1")
    assert result["coverage"]["state"] == "missing"
    assert result["runs"][0]["signal"] == "needs_reconciliation"
    assert result["runs"][0]["attempt_rows"] == 1
    assert "private.example" not in json.dumps(result)
    assert not (tmp_path / "web_bounty" / "sample" / "web" / "ledgers" / "surface_coverage.sqlite").exists()
    assert path.read_bytes() == before


def test_linked_run_and_unlinked_sibling_are_distinct(tmp_path: Path) -> None:
    stream(tmp_path, "worker-1", [{"attempt_id": "A-1"}])
    stream(tmp_path, "worker-2", [{"attempt_id": "A-2"}])
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path)
    surface = store.discover(kind="route", host="app.example", surface_key="GET /preview",
                             input_key="comment", consumer="preview", source_ref="recon/preview.jsonl",
                             run_id="mapper-1", class_name="xss")
    store.assess(surface, class_name="xss", status="in_progress", expected_fingerprint="",
                 reason="browser consumer open", evidence_refs=["attempt:worker-1:A-1"])
    result = watch_lane("sample", family="web_bounty", lane="web", root=tmp_path)
    assert result["coverage"]["questions"] == 1
    assert result["coverage"]["history_events"] == 1
    assert {row["run_id"]: row["signal"] for row in result["runs"]} == {
        "worker-1": "linked", "worker-2": "needs_reconciliation"}
    assert result["runs"][0]["linked_events"] in (0, 1)


def test_invalid_or_incomplete_run_is_not_reported_as_unlinked(tmp_path: Path) -> None:
    path = stream(tmp_path, "worker-1", [{"attempt_id": "A-1"}, {"attempt_id": "A-2"}])
    path.write_text(path.read_text() + "{not-json}\n", encoding="utf-8")
    result = watch_lane("sample", family="web_bounty", lane="web", root=tmp_path,
                        attempt_run_id="worker-1", max_attempt_rows=2)
    assert result["runs"][0]["signal"] == "incomplete"
    assert result["runs"][0]["truncated"] is True
    with pytest.raises(ValueError, match="run_id"):
        watch_lane("sample", family="web_bounty", lane="web", root=tmp_path, attempt_run_id="../other")


def test_source_pointers_are_availability_not_review(tmp_path: Path) -> None:
    lane = tmp_path / "web_bounty" / "sample" / "web"
    (lane / "recon" / "aggregated").mkdir(parents=True)
    (lane / "recon" / "aggregated" / "jsfiles.txt").write_text("https://app.example/a.js\n")
    result = watch_lane("sample", family="web_bounty", lane="web", root=tmp_path)
    assert result["sources"]["js_aggregate"]["available"] is True
    assert result["coverage"]["state"] == "missing"
    assert result["sources"]["js_aggregate"]["reviewed"] is False


def test_cli_watch_requires_explicit_lane_and_has_no_write_side_effect(tmp_path: Path) -> None:
    base = [sys.executable, str(CLI), "watch", "--program", "sample", "--root", str(tmp_path)]
    bad = subprocess.run(base, capture_output=True, text=True)
    assert bad.returncode != 0
    assert "--family" in bad.stderr and "--lane" in bad.stderr
    good = subprocess.run(base + ["--family", "web_bounty", "--lane", "web"],
                          capture_output=True, text=True, check=True)
    assert json.loads(good.stdout)["coverage"]["state"] == "missing"
    assert not (tmp_path / "web_bounty" / "sample" / "web").exists()
