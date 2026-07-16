from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import json
import sqlite3
from argparse import Namespace

from agents import js_analyzer as J


def test_default_inventory_paths_use_mounted_bounty_program_js_root():
    root, library, integrations, summary = J.resolve_inventory_paths(Namespace(program="demo", config=None, output_root=None, library_root=None, integration_index_root=None), "run-1")

    assert root == Path("/mnt/bounty/demo/web/recon/js/run-1")
    assert library == Path("/mnt/bounty/demo/web/recon/js/_library")
    assert integrations == Path("/mnt/bounty/demo/web/intel/integrations")
    assert summary["program_root"] == "/mnt/bounty/demo"


def test_extract_signals_finds_endpoints_params_and_sinks():
    text = """
    const url = "/api/v1/login?return_to=/home";
    fetch(url, {body: JSON.stringify({user_id: localStorage.uid})});
    document.querySelector('#out').innerHTML = location.hash;
    //# sourceMappingURL=app.js.map
    """
    signals = J.extract_signals(text, "https://app.example.com/static/app.js")

    assert "https://app.example.com/api/v1/login?return_to=/home" in signals["endpoints"]
    assert "return_to" in signals["params"]
    assert signals["source_map"] == "https://app.example.com/static/app.js.map"
    assert "storage" in signals["sources"]
    assert "location" in signals["sources"]
    assert "request" in signals["sinks"]
    assert "dom_write" in signals["sinks"]
    assert "auth" in signals["flow_hints"]
    assert "user_id" in signals["interesting_keys"]


def test_extract_signals_splits_in_scope_and_external_endpoints():
    text = """
    const internal = "https://static.canva.com/app.js";
    const route = "/api/apps/install?appId=abc";
    const external = "https://slack.com/apps/A06GQJFDUP9";
    """
    signals = J.extract_signals(text, "https://www.canva.com/apps", ["canva.com"])

    assert "https://static.canva.com/app.js" in signals["in_scope_endpoints"]
    assert "https://www.canva.com/api/apps/install?appId=abc" in signals["in_scope_endpoints"]
    assert "https://slack.com/apps/A06GQJFDUP9" in signals["external_endpoints"]


def test_extract_signals_uses_target_host_url_as_scope_hint():
    text = """
    const cdn = "https://assets.canva-apps.com/app.js";
    const api = "https://api.canva.com/v1/designs";
    const third = "https://slack.com/apps/A06GQJFDUP9";
    """
    signals = J.extract_signals(
        text,
        "https://www.canva.com/apps",
        ["canva.com"],
    )

    assert "https://assets.canva-apps.com/app.js" in signals["external_endpoints"]
    assert "https://api.canva.com/v1/designs" in signals["in_scope_endpoints"]
    assert "https://slack.com/apps/A06GQJFDUP9" in signals["external_endpoints"]


def test_external_url_classification_and_policy():
    assert J.classify_external_url("https://slack.com/apps/A06GQJFDUP9") == "integration_reference"
    assert J.classify_external_url("https://docs.example.com/help/canva") == "public_reference"
    assert J.classify_external_url("https://cdn.example.com/file?token=abc") == "possible_sensitive_reference"
    assert J.external_action_policy("integration_reference") == "context-only-find-scoped-integration-flow"
    assert "open_public_page_read_only" in J.allowed_context_actions("integration_reference")
    assert "do_not_open_without_approval" in J.allowed_context_actions("possible_sensitive_reference")


def test_extract_signals_prioritizes_flow_and_route_hints():
    text = """
    mutation UpdateInvoice($invoiceId: ID!) { updateInvoice(id: $invoiceId) { id } }
    const route = { path: "/api/billing/invoices/:invoice_id/refund" };
    const payload = { tenant_id: tenantId, redirect_uri: nextUrl, featureFlag: "new_checkout" };
    imagePreview({ remoteUrl: image_url, importPath: file_path });
    """
    signals = J.extract_signals(text, "https://app.example.com/static/billing.js")

    assert "UpdateInvoice" in signals["graphql_operations"]
    assert "/api/billing/invoices/:invoice_id/refund" in signals["route_hints"]
    assert "invoice_id" in signals["interesting_keys"]
    assert "tenant_id" in signals["interesting_keys"]
    assert "redirect_uri" in signals["interesting_keys"]
    assert "payment" in signals["flow_hints"]
    assert "access_control" in signals["flow_hints"]
    assert "server_fetch" in signals["flow_hints"]


def test_extract_signals_finds_hidden_bootstrap_state_hints():
    text = """
    const csrf = document.querySelector('input[type="hidden"][name="csrf_token"]');
    const orgId = document.body.dataset.orgId;
    const boot = JSON.parse(document.getElementById('__NEXT_DATA__').textContent);
    window.__INITIAL_STATE__ = { featureFlag: 'new_editor' };
    """
    signals = J.extract_signals(text, "https://app.example.com/static/app.js")

    hints = set(signals["hidden_state_hints"])
    assert "querySelector(" in hints
    assert "dataset" in hints
    assert "document.getElementById" in hints
    assert "__NEXT_DATA__" in hints
    assert "__INITIAL_STATE__" in hints


def test_extract_signals_ignores_malformed_urlish_strings():
    signals = J.extract_signals(
        'const noisy = "https://[not-an-ipv6]/bad"; const ok = "/api/v1/me?user_id=1";',
        "https://app.example.com/static/app.js",
    )

    assert "https://app.example.com/api/v1/me?user_id=1" in signals["endpoints"]
    assert "user_id" in signals["params"]


def test_inventory_writes_metadata_and_packets(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    provenance_file = tmp_path / "provenance-input.jsonl"
    provenance_file.write_text(json.dumps({
        "js_url": "https://app.example.com/static/app.js",
        "source": "unit-proxy",
        "page_url": "https://app.example.com/login",
        "page_context": "login/auth",
        "proxy_request_id": "req-1",
        "initiator": "script",
        "referrer": "https://app.example.com/login",
        "status": 200,
        "content_type": "application/javascript",
        "related_requests": ["req-2"],
    }) + "\n", encoding="utf-8")
    output_root = tmp_path / "out"
    library_root = tmp_path / "library"

    def fake_get(url: str, timeout: int = 20):
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; const external='https://slack.com/apps/A06GQJFDUP9'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    with patch.object(J, "http_get", side_effect=fake_get):
        rc = J.main([
            "inventory",
            "demo",
            "--input",
            str(input_file),
            "--target-host",
            "example.com",
            "--output-root",
            str(output_root),
            "--library-root",
            str(library_root),
            "--run-id",
            "unit",
            "--integration-index-root",
            str(tmp_path / "integrations"),
            "--provenance-input",
            str(provenance_file),
            "--chunk-size",
            "30",
            "--chunk-overlap",
            "5",
        ])

    assert rc == 0
    assert (output_root / "manifest.json").exists()
    metadata_text = (output_root / "metadata.jsonl").read_text(encoding="utf-8")
    metadata_rows = [json.loads(line) for line in metadata_text.splitlines()]
    assert metadata_rows[0]["url"] == "https://app.example.com/static/app.js"
    assert "https://app.example.com/api/auth/login?next=/dashboard" in metadata_text
    assert metadata_rows[0]["metadata_schema_version"] == 2
    assert metadata_rows[0]["provenance"]["page_urls"] == ["https://app.example.com/login"]
    assert metadata_rows[0]["provenance"]["proxy_request_ids"] == ["req-1"]
    assert metadata_rows[0]["artifact_links"]["packets"]
    assert (library_root / "metadata.jsonl").exists()
    external_rows = (output_root / "external_integrations.jsonl").read_text(encoding="utf-8")
    assert "https://slack.com/apps/A06GQJFDUP9" in external_rows
    assert "open_public_page_read_only" in external_rows
    provenance_rows = (output_root / "js_provenance.jsonl").read_text(encoding="utf-8")
    assert "unit-proxy" in provenance_rows
    assert "https://app.example.com/login" in provenance_rows
    assert "req-1" in provenance_rows
    assert "application/javascript" in provenance_rows
    assert (library_root / "provenance.jsonl").exists()
    assert (library_root / "js_info.sqlite").exists()
    with sqlite3.connect(library_root / "js_info.sqlite") as db:
        count = db.execute(
            "SELECT count(*) FROM js_provenance WHERE js_url = ? AND page_context = ?",
            ("https://app.example.com/static/app.js", "login/auth"),
        ).fetchone()[0]
        file_count = db.execute(
            "SELECT count(*) FROM js_files WHERE latest_run_id = ? AND target_host = ?",
            ("unit", "example.com"),
        ).fetchone()[0]
        alias_count = db.execute(
            "SELECT count(*) FROM js_url_aliases WHERE js_url = ?",
            ("https://app.example.com/static/app.js",),
        ).fetchone()[0]
        artifact_count = db.execute(
            "SELECT count(*) FROM js_artifacts WHERE artifact_type = 'packet'",
        ).fetchone()[0]
        observation_count = db.execute("SELECT count(*) FROM js_observations").fetchone()[0]
    assert count == 1
    assert file_count == 1
    assert alias_count == 1
    assert artifact_count > 0
    assert observation_count == 0
    host_index = json.loads((tmp_path / "integrations" / "external_hosts.json").read_text(encoding="utf-8"))
    assert any(host["host"] == "slack.com" for host in host_index["hosts"])
    packets = list((output_root / "packets").glob("*.md"))
    assert packets
    packet = packets[0].read_text(encoding="utf-8")
    assert "JS Deep Review Packet" in packet
    assert "Nearby In-Scope Extracted Endpoints" in packet
    assert "Trace:" in packet
    assert "Hidden/bootstrap state hints" in packet


def test_inventory_reuses_ledger_download_and_chunk_set(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    args = [
        "inventory",
        "demo",
        "--input",
        str(input_file),
        "--target-host",
        "example.com",
        "--library-root",
        str(library_root),
        "--chunk-size",
        "30",
        "--chunk-overlap",
        "5",
    ]
    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main(args + ["--output-root", str(tmp_path / "run1"), "--run-id", "unit1"]) == 0
        assert J.main(args + ["--output-root", str(tmp_path / "run2"), "--run-id", "unit2"]) == 0

    assert calls["count"] == 1
    ledger = J.load_ledger(library_root / "ledger.json")
    sha = J.ledger_lookup_url(ledger, "https://app.example.com/static/app.js")
    assert sha
    assert (library_root / "downloads" / f"{sha}.js").exists()
    metadata = (tmp_path / "run2" / "metadata.jsonl").read_text(encoding="utf-8")
    assert '"reused_download": true' in metadata
    assert '"reused_chunks": true' in metadata


def test_inventory_can_skip_cached_url_processing(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    args = [
        "inventory",
        "demo",
        "--input",
        str(input_file),
        "--target-host",
        "example.com",
        "--library-root",
        str(library_root),
        "--chunk-size",
        "30",
        "--chunk-overlap",
        "5",
    ]
    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main(args + ["--output-root", str(tmp_path / "run1"), "--run-id", "unit1"]) == 0
        assert J.main(args + [
            "--output-root",
            str(tmp_path / "run2"),
            "--run-id",
            "unit2",
            "--skip-cached-processing",
        ]) == 0

    assert calls["count"] == 1
    manifest = json.loads((tmp_path / "run2" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["js_urls_seen"] == 1
    assert manifest["cached_urls_skipped"] == 1
    assert manifest["js_downloaded"] == 0
    assert manifest["packets"] == 0
    assert (tmp_path / "run2" / "metadata.jsonl").read_text(encoding="utf-8") == ""
    assert not list((tmp_path / "run2" / "packets").glob("*.md"))


def test_inventory_uses_configured_program_roots(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://static.example.com/static/app.js\n", encoding="utf-8")
    config_path = tmp_path / "js_analyzer.json"
    configured_program_root = tmp_path / "bounty" / "canva"
    config_path.write_text(json.dumps({
        "programs": {
            "canva": {
                "program_root": str(configured_program_root)
            }
        }
    }) + "\n", encoding="utf-8")

    def fake_get(url: str, timeout: int = 20):
        return (b"fetch('/api/config?design_id=1')", 200, "application/javascript")

    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main([
            "inventory",
            "canva",
            "--input",
            str(input_file),
            "--target-host",
            "example.com",
            "--config",
            str(config_path),
            "--run-id",
            "configured-unit",
        ]) == 0

    js_root = configured_program_root / "web" / "recon" / "js"
    run_root = js_root / "configured-unit"
    library_root = js_root / "_library"
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["root"] == str(run_root)
    assert manifest["config"]["program_root"] == str(configured_program_root)
    assert manifest["outputs"]["library"] == str(library_root)
    assert (library_root / "ledger.json").exists()


def test_inventory_target_host_accepts_url_and_keeps_external_artifacts(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://static.example.com/static/app.js\n", encoding="utf-8")
    output_root = tmp_path / "out"
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (b"fetch('https://api.example.com/v1/me')", 200, "application/javascript")

    with patch.object(J, "http_get", side_effect=fake_get):
        rc = J.main([
            "inventory",
            "demo",
            "--input",
            str(input_file),
            "--target-host",
            "https://example.com/dashboard",
            "--output-root",
            str(output_root),
            "--library-root",
            str(library_root),
            "--run-id",
            "scope-unit",
        ])

    assert rc == 0
    assert calls["count"] == 1
    metadata = [json.loads(line) for line in (output_root / "metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert metadata[0]["url"] == "https://static.example.com/static/app.js"
    assert metadata[0]["target_host"] == "example.com"
    assert "https://api.example.com/v1/me" in metadata[0]["in_scope_endpoints"]


def test_observe_appends_observations_jsonl_and_sqlite_rows(tmp_path: Path):
    library_root = tmp_path / "library"
    observations_input = tmp_path / "observations.jsonl"
    observations_input.write_text(json.dumps({
        "sha256": "abc123",
        "js_url": "https://static.example.com/app.js",
        "packet_path": "/tmp/packet.md",
        "lens": "access-control",
        "run_id": "worker-run",
        "agent_id": "agent-1",
        "title": "Potential owner id request field",
        "summary": "Worker saw owner_id flow into a request body but did not prove controllability.",
        "confidence": "medium",
        "evidence": ["owner_id", "fetch('/api/projects')"],
        "next_action": "Compare owned-account request contract.",
    }) + "\n", encoding="utf-8")

    rc = J.main([
        "observe",
        "demo",
        "--input",
        str(observations_input),
        "--library-root",
        str(library_root),
    ])

    assert rc == 0
    assert (library_root / "observations.jsonl").exists()
    with sqlite3.connect(library_root / "js_info.sqlite") as db:
        row = db.execute(
            "SELECT lens, run_id, title, evidence_json FROM js_observations WHERE sha256 = ?",
            ("abc123",),
        ).fetchone()
    assert row[0] == "access-control"
    assert row[1] == "worker-run"
    assert row[2] == "Potential owner id request field"
    assert "owner_id" in row[3]
