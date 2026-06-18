from __future__ import annotations

import json
import subprocess
import sys
import threading
import importlib.util
import argparse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


SCRIPT = Path(__file__).with_name("xss_canary_mapper.py")


def load_module():
    spec = importlib.util.spec_from_file_location("xss_canary_mapper", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_mapper(*args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def run_mapper_raw(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        capture_output=True,
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_plan_parses_url_params_and_writes_mutated_requests(tmp_path: Path) -> None:
    input_path = tmp_path / "urls.txt"
    input_path.write_text(
        "https://example.test/search?q=hat&session_token=secret&sort=asc\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"

    summary = run_mapper("plan", "--input", str(input_path), "--out-dir", str(out_dir), "--run-id", "unit")

    assert summary["sources"] == 2
    sources = read_jsonl(out_dir / "sources.jsonl")
    assert {source["field"] for source in sources} == {"q", "sort"}
    assert all(source["canary"].startswith("GHOST_XSS_unit_") for source in sources)

    planned = read_jsonl(out_dir / "planned_requests.jsonl")
    q_request = next(record for record in planned if record["field"] == "q")
    assert q_request["status"] == "ready"
    assert q_request["sensitive_replay_required"] is True
    assert "session_token=REDACTED" in q_request["mutated_url"]
    assert all("session_token=secret" not in json.dumps(record) for record in sources + planned)
    assert any(source["url_redacted"] for source in sources)
    private_replay = read_jsonl(out_dir / "private_replay_requests.jsonl")
    assert any("session_token=secret" in record["mutated_url"] for record in private_replay)
    assert oct((out_dir / "private_replay_requests.jsonl").stat().st_mode & 0o777) == "0o600"


def test_map_finds_multiple_contexts_and_writes_packets(tmp_path: Path) -> None:
    input_path = tmp_path / "sources.jsonl"
    input_path.write_text(
        json.dumps({"url": "https://example.test/search?q=hat", "param": "q"}) + "\n"
        + json.dumps({"url": "https://example.test/profile", "method": "POST", "json_fields": {"name": "Ada"}})
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"

    plan = run_mapper("plan", "--input", str(input_path), "--out-dir", str(out_dir), "--run-id", "unit")
    assert plan["sources"] == 2
    sources = read_jsonl(out_dir / "sources.jsonl")
    by_field = {source["field"]: source for source in sources}

    response_path = tmp_path / "responses.jsonl"
    response_path.write_text(
        json.dumps(
            {
                "url": "https://example.test/search?q=...",
                "body": f"<h1>{by_field['q']['canary']}</h1>",
            }
        )
        + "\n"
        + json.dumps(
            {
                "url": "https://example.test/account",
                "body": f"<input value=\"{by_field['name']['canary']}\">",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    summary = run_mapper(
        "scan",
        "--sources",
        str(out_dir / "sources.jsonl"),
        "--response",
        str(response_path),
        "--out-dir",
        str(out_dir),
    )

    assert summary["sinks"] == 2
    sinks = read_jsonl(out_dir / "sinks.jsonl")
    assert {sink["context"] for sink in sinks} == {"html_text", "quoted_attribute"}
    edges = read_jsonl(out_dir / "edges.jsonl")
    assert {edge["recommended_lane"] for edge in edges} == {
        "reflected-xss",
        "stored-or-reflected-xss",
    }
    packets = list((out_dir / "agent_packets").glob("*.md"))
    assert len(packets) == 2
    assert "Next Agent Task" in packets[0].read_text(encoding="utf-8")


def test_script_context_routes_to_dom_lane(tmp_path: Path) -> None:
    source_path = tmp_path / "source.json"
    source_path.write_text(
        json.dumps({"url": "https://example.test/app?state=x", "param": "state"}),
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    run_mapper("plan", "--input", str(source_path), "--out-dir", str(out_dir), "--run-id", "unit")
    source = read_jsonl(out_dir / "sources.jsonl")[0]

    response_path = tmp_path / "app.html"
    response_path.write_text(
        f"<script>window.boot = \"{source['canary']}\";</script>",
        encoding="utf-8",
    )
    run_mapper(
        "scan",
        "--sources",
        str(out_dir / "sources.jsonl"),
        "--response",
        str(response_path),
        "--out-dir",
        str(out_dir),
    )

    edge = read_jsonl(out_dir / "edges.jsonl")[0]
    sink = read_jsonl(out_dir / "sinks.jsonl")[0]
    assert sink["context"] == "inline_javascript_string"
    assert edge["recommended_lane"] == "dom-xss"


def test_tool_style_records_extract_nested_urls_and_params(tmp_path: Path) -> None:
    input_path = tmp_path / "dalfox.jsonl"
    input_path.write_text(
        json.dumps(
            {
                "scanner": "dalfox",
                "data": {
                    "url": "https://example.test/products?category=shoes",
                    "param": "category",
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "request": {"endpoint": "https://example.test/app?view=home"},
                "parameters": ["view", "csrf_token"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"

    summary = run_mapper("plan", "--input", str(input_path), "--out-dir", str(out_dir), "--run-id", "unit")

    assert summary["sources"] == 2
    sources = read_jsonl(out_dir / "sources.jsonl")
    assert {source["field"] for source in sources} == {"category", "view"}


def test_fetch_requires_scope_or_allow_host_for_live_default(tmp_path: Path) -> None:
    planned = tmp_path / "planned_requests.jsonl"
    planned.write_text(
        json.dumps(
            {
                "source_id": "src",
                "run_id": "unit",
                "method": "GET",
                "url": "https://example.test/?q=x",
                "mutated_url": "https://example.test/?q=GHOST_XSS_unit_src",
                "vector": "query",
                "field": "q",
                "canary": "GHOST_XSS_unit_src",
                "status": "ready",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_mapper_raw("fetch", "--planned", str(planned), "--out-dir", str(tmp_path / "out"))

    assert result.returncode != 0
    assert "requires --program saved scope or at least one --allow-host" in result.stderr


def test_fetch_stores_only_canary_snippets_from_live_response(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            query = parse_qs(urlsplit(self.path).query)
            canary = query.get("q", [""])[0]
            body = f"<html><body>SECRET-ACCOUNT-DATA{'A' * 2000}<h1>{canary}</h1></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        source = tmp_path / "urls.txt"
        source.write_text(f"http://127.0.0.1:{port}/search?q=seed\n", encoding="utf-8")
        out_dir = tmp_path / "out"
        run_mapper("plan", "--input", str(source), "--out-dir", str(out_dir), "--run-id", "unit")

        result = run_mapper(
            "fetch",
            "--planned",
            str(out_dir / "planned_requests.jsonl"),
            "--out-dir",
            str(out_dir),
            "--allow-host",
            "127.0.0.1",
            "--max-requests",
            "1",
            "--rate-delay",
            "0",
        )

        assert result["responses"] == 1
        response = read_jsonl(out_dir / "responses.jsonl")[0]
        assert "GHOST_XSS_unit_" in response["body"]
        assert "SECRET-ACCOUNT-DATA" not in response["body"]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_fetch_does_not_follow_cross_host_redirect(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://example.org/offsite")
            self.end_headers()

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        source = tmp_path / "urls.txt"
        source.write_text(f"http://127.0.0.1:{port}/redirect?q=seed\n", encoding="utf-8")
        out_dir = tmp_path / "out"
        run_mapper("plan", "--input", str(source), "--out-dir", str(out_dir), "--run-id", "unit")

        run_mapper(
            "fetch",
            "--planned",
            str(out_dir / "planned_requests.jsonl"),
            "--out-dir",
            str(out_dir),
            "--allow-host",
            "127.0.0.1",
            "--max-requests",
            "1",
            "--rate-delay",
            "0",
        )

        response = read_jsonl(out_dir / "responses.jsonl")[0]
        assert response["status_code"] == 302
        assert response["url"].startswith(f"http://127.0.0.1:{port}/redirect")
        assert "example.org" not in response["url"]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_fetch_blocked_hosts_count_against_max_requests(tmp_path: Path) -> None:
    planned = tmp_path / "planned_requests.jsonl"
    rows = []
    for index in range(3):
        rows.append(
            {
                "source_id": f"src{index}",
                "run_id": "unit",
                "method": "GET",
                "url": f"https://blocked{index}.test/?q=x",
                "mutated_url": f"https://blocked{index}.test/?q=GHOST_XSS_unit_src{index}",
                "vector": "query",
                "field": "q",
                "canary": f"GHOST_XSS_unit_src{index}",
                "status": "ready",
            }
        )
    planned.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    run_mapper(
        "fetch",
        "--planned",
        str(planned),
        "--out-dir",
        str(out_dir),
        "--allow-host",
        "allowed.test",
        "--max-requests",
        "1",
        "--rate-delay",
        "0",
    )

    responses = read_jsonl(out_dir / "responses.jsonl")
    assert len(responses) == 1
    assert responses[0]["blocked_reason"] == "host_not_allowlisted"


def test_rate_delay_reads_saved_program_policy(tmp_path: Path, monkeypatch) -> None:
    module = load_module()
    scope_dir = tmp_path / "Shared" / "scopes" / "demo"
    scope_dir.mkdir(parents=True)
    (scope_dir / "rules-of-engagement.json").write_text(
        json.dumps({"rate_delay_seconds": 1.25}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    args = argparse.Namespace(rate_delay=None, program="demo")

    assert module.effective_rate_delay(args) == 1.25


def test_sensitive_replay_requires_explicit_flag_but_keeps_private_artifact(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            query = parse_qs(urlsplit(self.path).query)
            canary = query.get("q", [""])[0]
            assert query.get("session_token") == ["secret"]
            body = f"<p>{canary}</p>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        source = tmp_path / "urls.txt"
        source.write_text(
            f"http://127.0.0.1:{port}/search?q=seed&session_token=secret\n",
            encoding="utf-8",
        )
        out_dir = tmp_path / "out"
        run_mapper("plan", "--input", str(source), "--out-dir", str(out_dir), "--run-id", "unit")

        run_mapper(
            "fetch",
            "--planned",
            str(out_dir / "planned_requests.jsonl"),
            "--out-dir",
            str(out_dir),
            "--allow-host",
            "127.0.0.1",
            "--max-requests",
            "1",
            "--rate-delay",
            "0",
        )
        blocked = read_jsonl(out_dir / "responses.jsonl")[0]
        assert blocked["blocked_reason"] == "sensitive_replay_requires_explicit_flag"
        assert "session_token=secret" not in json.dumps(blocked)

        result = run_mapper(
            "fetch",
            "--planned",
            str(out_dir / "planned_requests.jsonl"),
            "--out-dir",
            str(out_dir),
            "--allow-host",
            "127.0.0.1",
            "--allow-sensitive-replay",
            "--max-requests",
            "1",
            "--rate-delay",
            "0",
        )
        assert result["responses"] == 1
        response = read_jsonl(out_dir / "responses.jsonl")[0]
        assert "GHOST_XSS_unit_" in response["body"]
        assert "session_token=secret" not in json.dumps(response)
    finally:
        server.shutdown()
        thread.join(timeout=2)
