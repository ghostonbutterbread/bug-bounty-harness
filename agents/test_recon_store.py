from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import agents.recon_store as R
import agents.url_ingest as U


def test_looks_urlish_accepts_urls_and_hosts_only():
    assert R.looks_urlish("https://app.example.com/path?q=1")
    assert R.looks_urlish("api.example.com")
    assert not R.looks_urlish("user_id")
    assert not R.looks_urlish("https://example.com/a b")


def test_url_ingest_normalizes_bare_host_and_path():
    assert U.normalize_url("api.example.com") == "https://api.example.com"
    assert U.normalize_url("api.example.com/v1?q=1") == "https://api.example.com/v1?q=1"
    assert U.parse_host_from_url("api.example.com/v1?q=1") == "api.example.com"
    assert U.parse_path_from_url("api.example.com/v1?q=1") == "/v1"


def test_record_recon_artifacts_preserves_raw_and_indexes_urlish(tmp_path: Path):
    source = tmp_path / "alive.txt"
    source.write_text(
        "https://app.example.com/search?q=test\n"
        "api.example.com\n"
        "not a url\n",
        encoding="utf-8",
    )
    params = tmp_path / "params.txt"
    params.write_text("q\nuser_id\n", encoding="utf-8")

    shared = tmp_path / "Shared" / "web_bounty"
    with patch.object(U, "SHARED_BASE", shared), patch.object(R.url_ingest, "SHARED_BASE", shared):
        manifest = R.record_recon_artifacts(
            program="demo",
            target="example.com",
            tool="fixture-recon",
            source_paths=[source, params],
            root_override=tmp_path / "Shared",
            run_id="run1",
            scope_filter="off",
        )

    payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
    assert payload["counts"]["url_indexed_artifacts"] == 1
    assert payload["url_index_summary"]["total_urls"] == 2
    assert any(path.endswith("/raw/alive.txt") for path in payload["raw_files"])
    assert any(path.endswith("/raw/params.txt") for path in payload["raw_files"])
    assert any(path.endswith("/parsed/alive.txt") for path in payload["parsed_files"])

    db_path = shared / "demo" / "web" / "recon" / "url_index" / "url_index.sqlite"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT canonical_url FROM urls ORDER BY canonical_url").fetchall()
    assert [row[0] for row in rows] == [
        "https://api.example.com",
        "https://app.example.com/search?q=test",
    ]


def test_record_recon_artifacts_indexes_params_txt_urls(tmp_path: Path):
    params = tmp_path / "params.txt"
    params.write_text(
        "https://app.example.com/search?q=test\n"
        "https://app.example.com/search?q=test\n"
        "not_a_url\n",
        encoding="utf-8",
    )

    shared = tmp_path / "Shared" / "web_bounty"
    with patch.object(U, "SHARED_BASE", shared), patch.object(R.url_ingest, "SHARED_BASE", shared):
        manifest = R.record_recon_artifacts(
            program="demo-params",
            target="example.com",
            tool="param-recon",
            source_paths=[params],
            root_override=tmp_path / "Shared",
            run_id="params-run1",
            scope_filter="off",
        )

    payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
    assert payload["counts"]["url_indexed_artifacts"] == 1
    assert any(path.endswith("/parsed/params.txt") for path in payload["parsed_files"])

    db_path = shared / "demo-params" / "web" / "recon" / "url_index" / "url_index.sqlite"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT canonical_url FROM urls ORDER BY canonical_url").fetchall()
    assert [row[0] for row in rows] == ["https://app.example.com/search?q=test"]


def test_record_recon_artifacts_indexes_subdomain_outputs(tmp_path: Path):
    all_subs = tmp_path / "all_subs.txt"
    all_subs.write_text("api.example.com\nwww.example.com\n", encoding="utf-8")
    alive_subs = tmp_path / "alive_subs.txt"
    alive_subs.write_text("www.example.com\n", encoding="utf-8")
    dead_subs = tmp_path / "dead_subs.txt"
    dead_subs.write_text("old.example.com\n", encoding="utf-8")

    shared = tmp_path / "Shared" / "web_bounty"
    with patch.object(U, "SHARED_BASE", shared), patch.object(R.url_ingest, "SHARED_BASE", shared):
        manifest = R.record_recon_artifacts(
            program="demo-subdomains",
            target="example.com",
            tool="subdomain-agent",
            source_paths=[all_subs, alive_subs, dead_subs],
            root_override=tmp_path / "Shared",
            run_id="sub-run1",
            scope_filter="off",
        )

    payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
    assert payload["counts"]["url_indexed_artifacts"] == 2
    assert payload["url_index_summary"]["total_urls"] == 2


def test_append_deduped_lines_preserves_unique_current_view(tmp_path: Path):
    path = tmp_path / "aggregated" / "urls.txt"
    first = R.append_deduped_lines(path, ["https://api.example.com/a", "https://api.example.com/a", ""])
    second = R.append_deduped_lines(path, ["https://api.example.com/a", "https://api.example.com/b"])

    assert first == {"read": 2, "new": 1}
    assert second == {"read": 2, "new": 1}
    assert path.read_text(encoding="utf-8").splitlines() == [
        "https://api.example.com/a",
        "https://api.example.com/b",
    ]


def test_append_deduped_jsonl_uses_stable_keys(tmp_path: Path):
    path = tmp_path / "fuzz" / "status_leads.jsonl"
    first = R.append_deduped_jsonl(
        path,
        [
            {"url": "https://api.example.com/admin", "status": 403, "run_id": "run1"},
            {"url": "https://api.example.com/admin", "status": 403, "run_id": "run1-duplicate"},
        ],
        key_fields=("url", "status"),
    )
    second = R.append_deduped_jsonl(
        path,
        [
            {"url": "https://api.example.com/admin", "status": 403, "run_id": "run2"},
            {"url": "https://api.example.com/admin", "status": 405, "run_id": "run2"},
        ],
        key_fields=("url", "status"),
    )

    rows = [__import__("json").loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert first == {"read": 2, "new": 1}
    assert second == {"read": 2, "new": 1}
    assert [(row["url"], row["status"]) for row in rows] == [
        ("https://api.example.com/admin", 403),
        ("https://api.example.com/admin", 405),
    ]
