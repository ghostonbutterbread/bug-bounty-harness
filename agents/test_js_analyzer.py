from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import json
import sqlite3

from agents import js_analyzer as J


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
    signals = J.extract_signals(text, "https://www.canva.com/apps", "canva.com")

    assert "https://static.canva.com/app.js" in signals["in_scope_endpoints"]
    assert "https://www.canva.com/api/apps/install?appId=abc" in signals["in_scope_endpoints"]
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
    metadata = (output_root / "metadata.jsonl").read_text(encoding="utf-8")
    assert "https://app.example.com/static/app.js" in metadata
    assert "https://app.example.com/api/auth/login?next=/dashboard" in metadata
    external_rows = (output_root / "external_integrations.jsonl").read_text(encoding="utf-8")
    assert "https://slack.com/apps/A06GQJFDUP9" in external_rows
    assert "open_public_page_read_only" in external_rows
    provenance_rows = (output_root / "js_provenance.jsonl").read_text(encoding="utf-8")
    assert "unit-proxy" in provenance_rows
    assert "https://app.example.com/login" in provenance_rows
    assert "req-1" in provenance_rows
    assert "application/javascript" in provenance_rows
    assert (library_root / "provenance.jsonl").exists()
    assert (library_root / "js_provenance.sqlite").exists()
    with sqlite3.connect(library_root / "js_provenance.sqlite") as db:
        count = db.execute(
            "SELECT count(*) FROM js_provenance WHERE js_url = ? AND page_context = ?",
            ("https://app.example.com/static/app.js", "login/auth"),
        ).fetchone()[0]
    assert count == 1
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
