from __future__ import annotations

import json
from pathlib import Path

from agents.hunt_pipeline.appmap_loader import load_appmap_run


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def test_appmap_loader_prefers_neutral_surfaces_and_marks_candidates_legacy(tmp_path: Path) -> None:
    run = tmp_path / "appmap" / "run-1"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text('{"run_id":"run-1","hunting_policy_id":"electron-application-first-loose"}\n', encoding="utf-8")
    (run / "target_profile.json").write_text('{"target_kind":"electron"}\n', encoding="utf-8")
    _write_jsonl(run / "surfaces.jsonl", [{"id": "S0001", "kind": "ipc", "file": "src/main.js"}])
    _write_jsonl(run / "flows.jsonl", [{"id": "F0001", "source_id": "S0001"}])
    _write_jsonl(run / "candidates.jsonl", [{"id": "C0001", "surface_id": "S0001"}])
    _write_jsonl(run / "rejected_candidates.jsonl", [{"id": "R0001", "candidate_id": "C0001"}])

    normalized = load_appmap_run(run)

    assert normalized.counts() == {
        "surfaces": 1,
        "flows": 1,
        "legacy_candidates": 1,
        "legacy_rejected_candidates": 1,
    }
    assert normalized.surfaces[0]["kind"] == "ipc"
    assert normalized.legacy_policy_shaped is True
    assert normalized.legacy_candidates[0]["pipeline_context"]["neutral_truth"] is False
    assert normalized.legacy_candidates[0]["pipeline_context"]["legacy_compatibility_context"] is True
