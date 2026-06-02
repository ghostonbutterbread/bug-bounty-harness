from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agents.recon.surface_map import (
    EvidenceSource,
    ReconSurfaceMap,
    SurfaceMapConfig,
    default_input_paths,
    ingest_asset_graph,
    ingest_asset_graph_record,
    ingest_local_path,
    make_surface_id,
    run_surface_map,
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_asset_graph_ingestion_preserves_scope_and_full_url(tmp_path: Path) -> None:
    asset_graph = tmp_path / "asset_graph.jsonl"
    asset_graph.write_text(
        json.dumps(
            {
                "kind": "url",
                "value": "https://api.example.com/login",
                "normalized_value": "https://api.example.com/login",
                "scope_status": "in-scope",
                "graph_id": "url:https://api.example.com/login",
                "sources": [{"name": "fixture"}],
                "labels": ["auth"],
                "edges": [],
                "metadata": {"source": "asset-intel"},
                "confidence": 0.9,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    surface_map = ReconSurfaceMap("demo", "example.com")
    stats = type(
        "Stats",
        (),
        {"files_seen": 0, "files_parsed": 0, "files_skipped": 0, "asset_graph_records_seen": 0},
    )()

    ingest_asset_graph(asset_graph, surface_map, stats)
    records = surface_map.sorted_records()

    assert len(records) == 1
    assert records[0].family == "auth-session-flow"
    assert records[0].entry_vector == "https://api.example.com/login"
    assert records[0].scope_status == "in-scope"
    assert records[0].metadata["asset_graph_key"] == {
        "kind": "url",
        "normalized_value": "https://api.example.com/login",
    }


def test_url_family_inference_for_surface_categories() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")
    source = EvidenceSource(name="urls.txt")

    cases = {
        "https://app.example.com/graphql": "graphql-rpc-operation",
        "https://app.example.com/users/avatar": "media-avatar-profile",
        "https://app.example.com/webhooks/import?url=https://example.net/feed": "url-fetch-import-webhook",
        "https://app.example.com/billing/gift-card/redeem": "payment-gift-card-promo",
        "https://cdn.example.com/static/app.js": "cdn-static-js-asset",
        "https://app.example.com/admin/impersonate": "admin-support-impersonation",
    }
    for url, expected_family in cases.items():
        record = surface_map.add_observation(url, source=source)
        assert record is not None
        assert record.family == expected_family


def test_malformed_placeholder_observation_does_not_crash() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")
    record = surface_map.add_observation(
        "[signed-media-url]",
        source=EvidenceSource(name="probe.json"),
        labels=["media"],
    )

    assert record is not None
    assert record.entry_vector == "[signed-media-url]"
    assert record.family == "media-avatar-profile"


def test_dedupe_and_stable_surface_ids_merge_sources() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")
    first = surface_map.add_observation(
        "HTTPS://App.Example.com/login#frag",
        source=EvidenceSource(name="urls.txt"),
    )
    second = surface_map.add_observation(
        "https://app.example.com/login",
        source=EvidenceSource(name="alive.txt"),
    )

    assert first is second
    assert first is not None
    assert first.surface_id == make_surface_id("auth-session-flow", "auth-flow", "https://app.example.com/login")
    assert sorted(source.name for source in first.sources) == ["alive.txt", "urls.txt"]


def test_http_method_is_preserved_in_operation_identity() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")
    source = EvidenceSource(name="routes.jsonl")

    get_record = surface_map.add_observation("/api/users/123", source=source, method="GET")
    delete_record = surface_map.add_observation("/api/users/123", source=source, method="DELETE")

    assert get_record is not None
    assert delete_record is not None
    assert get_record is not delete_record
    assert get_record.http_method == "GET"
    assert delete_record.http_method == "DELETE"
    assert get_record.surface_id != delete_record.surface_id


def test_malformed_asset_graph_record_is_defensive() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")

    record = ingest_asset_graph_record(
        {
            "kind": "url",
            "normalized_value": "https://app.example.com/search",
            "scope_status": "trusted-in-scope",
            "confidence": "high",
        },
        surface_map,
        EvidenceSource(name="asset_graph.jsonl"),
    )

    assert record is not None
    assert record.scope_status == "unknown"
    assert record.confidence == 0.65


def test_off_target_asset_graph_in_scope_claim_is_downgraded() -> None:
    surface_map = ReconSurfaceMap("demo", "example.com")

    record = ingest_asset_graph_record(
        {
            "kind": "url",
            "normalized_value": "https://other.test/admin",
            "scope_status": "in-scope",
        },
        surface_map,
        EvidenceSource(name="asset_graph.jsonl"),
    )

    assert record is not None
    assert record.scope_status == "needs-human-review"
    assert record.metadata["asset_scope_status"] == "in-scope"
    assert "scope_downgrade_reason" in record.metadata


def test_root_override_isolates_surface_default_input_discovery(tmp_path: Path) -> None:
    config = SurfaceMapConfig(program="demo", target="example.com", root=tmp_path / "shared")

    paths = default_input_paths(config)

    assert paths
    assert all(str(path).startswith(str(tmp_path / "shared")) for path in paths)


def test_local_text_json_and_output_artifacts(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "urls.txt").write_text(
        "https://app.example.com/search?q=test\nhttps://app.example.com/api/users/123\n",
        encoding="utf-8",
    )
    (input_dir / "routes.jsonl").write_text(
        json.dumps({"method": "POST", "path": "/api/files/upload"}) + "\n",
        encoding="utf-8",
    )

    surface_map = ReconSurfaceMap("demo", "example.com")
    stats = type(
        "Stats",
        (),
        {"files_seen": 0, "files_parsed": 0, "files_skipped": 0, "local_records_seen": 0},
    )()
    ingest_local_path(input_dir, surface_map, stats)
    families = {record.family for record in surface_map.sorted_records()}

    assert "search-filter-query" in families
    assert "account-tenant-object" in families
    assert "file-upload-ingestion" in families

    manifest_path = run_surface_map(
        SurfaceMapConfig(
            program="demo",
            target="example.com",
            root=tmp_path / "shared",
            input_paths=[input_dir],
            run_id="surface-run",
            offline=True,
        )
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["tool"] == "surface-map"
    assert manifest["counts"]["promoted_findings"] == 0
    assert manifest_path.parent == (
        tmp_path
        / "shared"
        / "web_bounty"
        / "demo"
        / "web"
        / "recon"
        / "surface-map"
        / "example.com"
        / "runs"
        / manifest["date"]
        / "surface-run"
    )
    records = read_jsonl(manifest_path.parent / "surface_map.jsonl")
    assert records
    assert (manifest_path.parent / "surface_map.md").exists()
    assert all(record["entry_vector"].startswith("https://") for record in records)


def test_cli_wrapper_json_output_with_asset_graph(tmp_path: Path) -> None:
    asset_graph = tmp_path / "asset_graph.jsonl"
    asset_graph.write_text(
        json.dumps(
            {
                "kind": "url",
                "value": "https://app.example.com/api/search?q=a",
                "normalized_value": "https://app.example.com/api/search?q=a",
                "scope_status": "needs-human-review",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cmd = [
        sys.executable,
        "agents/recon_surface_map.py",
        "demo",
        "--target",
        "example.com",
        "--offline",
        "--root",
        str(tmp_path / "shared"),
        "--asset-graph",
        str(asset_graph),
        "--run-id",
        "cli-run",
        "--json",
    ]

    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=True)
    manifest = json.loads(result.stdout)

    assert manifest["run_id"] == "cli-run"
    assert manifest["counts"]["promoted_findings"] == 0
    records = read_jsonl(Path(manifest["run_dir"], "surface_map.jsonl"))
    assert records[0]["family"] == "search-filter-query"
    assert records[0]["entry_vector"] == "https://app.example.com/api/search?q=a"
