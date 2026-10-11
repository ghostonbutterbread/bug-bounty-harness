"""Named input sites must survive the JS inventory's persisted handoff, not only extract_signals."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from agents import js_analyzer as J


def test_inventory_persists_named_input_and_pairs_review_sites(tmp_path: Path):
    source = tmp_path / "urls.txt"
    source.write_text("https://app.example.com/app.js\n")
    body = b"const q = searchParams.get('giftMessage'); node.innerHTML = q;"
    with patch.object(J, "http_get", return_value=(body, 200, "application/javascript")):
        assert J.main(["inventory", "demo", "--input", str(source), "--target-host", "example.com",
                       "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "lib"),
                       "--integration-index-root", str(tmp_path / "integrations")]) == 0
    metadata = J.read_jsonl(tmp_path / "out" / "metadata.jsonl")[0]
    assert any(site["name"] == "giftMessage" for site in metadata["source_sites"])
    assert metadata["signal_counts"]["source_sites"] >= 1
    assert metadata["sink_sites"]
    packet = Path(metadata["packet_paths"][0]).read_text()
    assert "giftMessage" in packet and "Individual XSS Sink Review Sites" in packet
    assert "not proven" in packet.lower() or "not a proven" in packet.lower()
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["source_site_hits"] >= 1


def test_source_map_module_exposes_named_input_with_bundle_provenance(tmp_path: Path):
    source = tmp_path / "urls.txt"
    source.write_text("https://app.example.com/app.js\n")
    body = b"//# sourceMappingURL=app.js.map\n"
    mapped = json.dumps({"version": 3, "sources": ["src/page.ts"],
                         "sourcesContent": ["const q = searchParams.get('invoiceTitle'); el.innerHTML = q;"]}).encode()
    with patch.object(J, "http_get", return_value=(body, 200, "application/javascript")), \
         patch.object(J, "http_get_limited", return_value=(mapped, 200, "application/json", False)):
        assert J.main(["inventory", "demo", "--input", str(source), "--target-host", "example.com",
                       "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "lib"),
                       "--integration-index-root", str(tmp_path / "integrations")]) == 0
    row = J.read_jsonl(tmp_path / "out" / "source_map_modules.jsonl")[0]
    assert row["bundle_url"] == "https://app.example.com/app.js"
    assert any(site["name"] == "invoiceTitle" for site in row["source_sites"])
    assert "invoiceTitle" in Path(row["packet_paths"][0]).read_text()
