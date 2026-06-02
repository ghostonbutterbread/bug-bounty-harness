from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agents.recon.asset_intelligence import (
    AssetIntelligenceConfig,
    AssetIntelligenceGraph,
    EvidenceSource,
    default_input_paths,
    ingest_local_path,
    record_from_value,
    run_asset_intelligence,
)


def test_record_normalization_keeps_full_urls() -> None:
    record = record_from_value(
        "HTTPS://Api.Example.COM/login?q=1#frag",
        source=EvidenceSource(name="fixture"),
    )

    assert record is not None
    assert record.kind == "url"
    assert record.value == "HTTPS://Api.Example.COM/login?q=1#frag"
    assert record.normalized_value == "https://api.example.com/login?q=1"


def test_dedupe_merges_sources_and_scope_status() -> None:
    graph = AssetIntelligenceGraph("demo", "example.com")
    graph.add_scope_pattern("*.example.com", in_scope=True)
    first = graph.add_value("https://api.example.com/login", source=EvidenceSource(name="urls.txt"))
    second = graph.add_value("https://api.example.com/login", source=EvidenceSource(name="alive.txt"))

    assert first is second
    assert first is not None
    assert first.scope_status == "in-scope"
    assert sorted(source.name for source in first.sources) == ["alive.txt", "urls.txt"]


def test_scope_status_labels_unknown_related_and_out_of_scope() -> None:
    graph = AssetIntelligenceGraph("demo", "example.com")
    graph.add_scope_pattern("*.example.com", in_scope=True)
    graph.add_scope_pattern("blocked.example.com", in_scope=False)

    in_scope = graph.add_value("https://api.example.com", source=EvidenceSource(name="fixture"))
    blocked = graph.add_value("https://blocked.example.com", source=EvidenceSource(name="fixture"))
    related = graph.add_value("https://cdn.example.com", source=EvidenceSource(name="fixture"))
    unknown = graph.add_value("https://other.test", source=EvidenceSource(name="fixture"))

    assert in_scope is not None and in_scope.scope_status == "in-scope"
    assert blocked is not None and blocked.scope_status == "out-of-scope"
    assert related is not None and related.scope_status == "in-scope"
    assert unknown is not None and unknown.scope_status == "unknown"


def test_related_target_without_scope_needs_human_review() -> None:
    graph = AssetIntelligenceGraph("demo", "example.com")

    record = graph.add_value("https://cdn.example.com", source=EvidenceSource(name="fixture"))

    assert record is not None
    assert record.scope_status == "needs-human-review"


def test_local_artifact_parsing_text_json_and_jsonl(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "in-scope.txt").write_text("*.example.com\n", encoding="utf-8")
    (root / "urls.txt").write_text("https://api.example.com/login\n", encoding="utf-8")
    (root / "assets.json").write_text(
        json.dumps({"out_of_scope": ["blocked.example.com"], "ips": ["203.0.113.10"]}),
        encoding="utf-8",
    )
    (root / "records.jsonl").write_text(
        json.dumps({"domain": "blocked.example.com"}) + "\n",
        encoding="utf-8",
    )

    graph = AssetIntelligenceGraph("demo", "example.com")
    stats = type("Stats", (), {"files_seen": 0, "files_parsed": 0, "files_skipped": 0, "local_records_seen": 0})()
    ingest_local_path(root, graph, stats)
    records = {record.normalized_value: record for record in graph.sorted_records()}

    assert "https://api.example.com/login" in records
    assert records["https://api.example.com/login"].scope_status == "in-scope"
    assert records["blocked.example.com"].scope_status == "out-of-scope"
    assert records["203.0.113.10"].kind == "ip"
    assert stats.files_parsed == 4


def test_discovered_domains_file_does_not_promote_scope(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "domains.txt").write_text("related.example.com\n", encoding="utf-8")

    graph = AssetIntelligenceGraph("demo", "example.com")
    stats = type("Stats", (), {"files_seen": 0, "files_parsed": 0, "files_skipped": 0, "local_records_seen": 0})()
    ingest_local_path(root, graph, stats)
    records = {record.normalized_value: record for record in graph.sorted_records()}

    assert records["related.example.com"].scope_status == "needs-human-review"


def test_root_override_isolates_default_input_discovery(tmp_path: Path) -> None:
    config = AssetIntelligenceConfig(program="demo", target="example.com", root=tmp_path / "shared")

    paths = default_input_paths(config)

    assert paths
    assert all(str(path).startswith(str(tmp_path / "shared")) for path in paths)


def test_out_of_scope_cidr_classifies_provider_style_ip() -> None:
    graph = AssetIntelligenceGraph("demo", "example.com")
    graph.add_scope_pattern("203.0.113.0/24", in_scope=False)

    record = graph.add_value(
        "203.0.113.10",
        source=EvidenceSource(name="dns-stdlib", source_type="passive-network"),
        kind_hint="ip",
    )

    assert record is not None
    assert record.scope_status == "out-of-scope"


def test_offline_cli_writes_canonical_outputs(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "in-scope.txt").write_text("*.example.com\n", encoding="utf-8")
    (input_dir / "alive.txt").write_text("https://api.example.com/login\n", encoding="utf-8")

    manifest_path = run_asset_intelligence(
        AssetIntelligenceConfig(
            program="demo",
            target="example.com",
            root=tmp_path / "shared",
            input_paths=[input_dir],
            run_id="test-run",
            offline=True,
        )
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["tool"] == "asset-intel"
    assert manifest["counts"]["promoted_findings"] == 0
    assert manifest_path.parent == (
        tmp_path
        / "shared"
        / "web_bounty"
        / "demo"
        / "web"
        / "recon"
        / "asset-intel"
        / "example.com"
        / "runs"
        / manifest["date"]
        / "test-run"
    )
    assert (manifest_path.parent / "asset_graph.jsonl").exists()
    assert (manifest_path.parent / "asset_graph.md").exists()


def test_cli_wrapper_json_output(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "urls.txt").write_text("https://app.example.com/\n", encoding="utf-8")
    cmd = [
        sys.executable,
        "agents/recon_asset_intel.py",
        "demo",
        "--target",
        "example.com",
        "--offline",
        "--root",
        str(tmp_path / "shared"),
        "--input",
        str(input_dir),
        "--run-id",
        "cli-run",
        "--json",
    ]

    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=True)
    manifest = json.loads(result.stdout)

    assert manifest["run_id"] == "cli-run"
    assert manifest["allow_network"] is False
    assert Path(manifest["run_dir"], "asset_graph.jsonl").exists()
