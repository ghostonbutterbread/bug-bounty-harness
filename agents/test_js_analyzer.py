from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

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


def test_inventory_writes_metadata_and_packets(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    output_root = tmp_path / "out"

    def fake_get(url: str, timeout: int = 20):
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; fetch(endpoint);",
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
            "--run-id",
            "unit",
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
    packets = list((output_root / "packets").glob("*.md"))
    assert packets
    assert "JS Deep Review Packet" in packets[0].read_text(encoding="utf-8")


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
