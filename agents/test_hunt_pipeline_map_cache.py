from __future__ import annotations

import json
from pathlib import Path

from agents.hunt_pipeline.map_cache import (
    DEFAULT_STALE_AFTER_DAYS,
    build_map_cache_metadata,
    ensure_map_cache_metadata,
    find_latest_prior_map,
    resolve_appmap_run,
    write_map_diff,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _write_appmap_run(root: Path, *, target_path: Path, mapped_at: str, surfaces: list[dict], run_id: str = "run-1") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "created_at": mapped_at, "target_path": str(target_path), "target_kind": "electron"}) + "\n",
        encoding="utf-8",
    )
    (root / "target_profile.json").write_text(
        json.dumps({"program": "demo", "target_kind": "electron", "target_path": str(target_path)}) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(root / "surfaces.jsonl", surfaces)
    _write_jsonl(root / "flows.jsonl", [])
    return root


def _write_plan(root: Path, *, target_path: Path, appmap_root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    metadata = ensure_map_cache_metadata(appmap_root, target_path=target_path)
    payload = {
        "program": "demo",
        "target_path": str(target_path),
        "appmap_source": {
            "mode": "generated-neutral",
            "run_root": str(appmap_root),
            "map_cache_metadata": metadata,
        },
    }
    plan_path = root / "pipeline_plan.json"
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan_path


def test_resolve_appmap_run_reuses_fresh_matching_prior_map(tmp_path: Path) -> None:
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    prior_output = tmp_path / "hunt_pipeline_out" / "run-old"
    prior_appmap = _write_appmap_run(
        prior_output / "appmap" / "run-old",
        target_path=target,
        mapped_at="2099-05-15T22:00:00Z",
        surfaces=[{"id": "S1", "kind": "ipc", "file": "src/main.js", "line": 10}],
        run_id="run-old",
    )
    _write_plan(prior_output, target_path=target, appmap_root=prior_appmap)

    resolution = resolve_appmap_run(
        appmap_run=None,
        program="demo",
        target_path=target,
        target_kind="electron",
        output_root=tmp_path / "hunt_pipeline_out" / "run-new",
        run_id="run-new",
        cache_search_root=tmp_path / "hunt_pipeline_out",
    )

    assert resolution.source_mode == "reused-cache"
    assert resolution.decision.action == "reuse"
    assert resolution.decision.reason == "reused prior fresh map"
    assert resolution.appmap_root == prior_appmap


def test_resolve_appmap_run_remaps_when_target_fingerprint_changes(tmp_path: Path) -> None:
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    prior_output = tmp_path / "hunt_pipeline_out" / "run-old"
    prior_appmap = _write_appmap_run(
        prior_output / "appmap" / "run-old",
        target_path=target,
        mapped_at="2099-05-15T22:00:00Z",
        surfaces=[{"id": "S1", "kind": "ipc", "file": "src/main.js", "line": 10}],
        run_id="run-old",
    )
    _write_plan(prior_output, target_path=target, appmap_root=prior_appmap)
    target.write_text("console.log('v2')\n", encoding="utf-8")

    resolution = resolve_appmap_run(
        appmap_run=None,
        program="demo",
        target_path=target,
        target_kind="electron",
        output_root=tmp_path / "hunt_pipeline_out" / "run-new",
        run_id="run-new",
        cache_search_root=tmp_path / "hunt_pipeline_out",
    )

    assert resolution.source_mode == "generated-neutral"
    assert resolution.decision.action == "remap"
    assert resolution.decision.app_version_changed is True
    assert resolution.decision.reason == "target fingerprint changed"


def test_resolve_appmap_run_remaps_when_stale(tmp_path: Path) -> None:
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    prior_output = tmp_path / "hunt_pipeline_out" / "run-old"
    prior_appmap = _write_appmap_run(
        prior_output / "appmap" / "run-old",
        target_path=target,
        mapped_at="2000-05-15T22:00:00Z",
        surfaces=[{"id": "S1", "kind": "ipc", "file": "src/main.js", "line": 10}],
        run_id="run-old",
    )
    metadata = build_map_cache_metadata(
        prior_appmap,
        target_path=target,
        target_kind="electron",
        program="demo",
        stale_after_days=DEFAULT_STALE_AFTER_DAYS,
        mapped_at="2000-05-15T22:00:00Z",
    )
    (prior_appmap / "map_cache.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_plan(prior_output, target_path=target, appmap_root=prior_appmap)

    resolution = resolve_appmap_run(
        appmap_run=None,
        program="demo",
        target_path=target,
        target_kind="electron",
        output_root=tmp_path / "hunt_pipeline_out" / "run-new",
        run_id="run-new",
        cache_search_root=tmp_path / "hunt_pipeline_out",
    )

    assert resolution.decision.action == "remap"
    assert resolution.decision.stale is True
    assert resolution.decision.reason == "stale map"


def test_write_map_diff_reports_new_changed_removed_surfaces(tmp_path: Path) -> None:
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    previous_root = _write_appmap_run(
        tmp_path / "previous",
        target_path=target,
        mapped_at="2099-05-15T22:00:00Z",
        surfaces=[
            {"id": "S1", "kind": "ipc", "file": "src/main.js", "line": 10, "snippet": "old"},
            {"id": "S2", "kind": "rendering", "file": "src/view.js", "line": 20},
        ],
    )
    current_root = _write_appmap_run(
        tmp_path / "current",
        target_path=target,
        mapped_at="2099-05-15T23:00:00Z",
        surfaces=[
            {"id": "SX", "kind": "ipc", "file": "src/main.js", "line": 10, "snippet": "new"},
            {"id": "S3", "kind": "storage", "file": "src/store.js", "line": 30},
        ],
        run_id="run-2",
    )

    diff_path = write_map_diff(
        previous_appmap_root=previous_root,
        current_appmap_root=current_root,
        output_path=tmp_path / "map_diff.json",
        previous_metadata=ensure_map_cache_metadata(previous_root, target_path=target),
        current_metadata=ensure_map_cache_metadata(current_root, target_path=target),
    )
    payload = json.loads(diff_path.read_text(encoding="utf-8"))

    assert payload["counts"] == {"new": 1, "changed": 1, "removed": 1, "unchanged": 0}
    assert payload["new_surfaces"][0]["kind"] == "storage"
    assert payload["changed_surfaces"][0]["identity"].startswith("ipc|src/main.js|10")
    assert payload["removed_surfaces"][0]["kind"] == "rendering"


def test_find_latest_prior_map_ignores_current_output_root(tmp_path: Path) -> None:
    target = tmp_path / "target.js"
    target.write_text("console.log('v1')\n", encoding="utf-8")
    old_output = tmp_path / "hunt_pipeline_out" / "run-old"
    new_output = tmp_path / "hunt_pipeline_out" / "run-new"
    old_appmap = _write_appmap_run(old_output / "appmap" / "run-old", target_path=target, mapped_at="2099-05-15T22:00:00Z", surfaces=[])
    new_appmap = _write_appmap_run(new_output / "appmap" / "run-new", target_path=target, mapped_at="2099-05-15T23:00:00Z", surfaces=[], run_id="run-new")
    _write_plan(old_output, target_path=target, appmap_root=old_appmap)
    _write_plan(new_output, target_path=target, appmap_root=new_appmap)

    prior = find_latest_prior_map(tmp_path / "hunt_pipeline_out", target_path=target, exclude_output_root=new_output)

    assert prior is not None
    assert prior["output_root"] == old_output
