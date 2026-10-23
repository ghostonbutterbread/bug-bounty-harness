from __future__ import annotations

import io
import urllib.error

from agents import autonomous_recon
from agents.autonomous_recon import ReconResult, _extract_forms, phase_analyze


def test_extract_forms_scopes_inputs_per_form() -> None:
    result = ReconResult(
        program="demo",
        target="https://example.com",
        target_host="example.com",
    )

    _extract_forms(
        """
        <html>
          <form action="/login">
            <input name="username" />
            <input name="password" />
          </form>
          <form action="/search">
            <input name="q" />
          </form>
        </html>
        """,
        "https://example.com/account",
        result,
    )

    assert result.forms == [
        {
            "action": "https://example.com/login",
            "inputs": ["username", "password"],
        },
        {
            "action": "https://example.com/search",
            "inputs": ["q"],
        },
    ]


def test_phase_analyze_fetches_only_same_host_js(monkeypatch) -> None:
    fetched: list[str] = []

    def fake_http_get(url: str, timeout: int = 10):
        fetched.append(url)
        return b"const endpoint = '/api/demo';", {}

    monkeypatch.setattr(autonomous_recon, "_http_get", fake_http_get)
    monkeypatch.setattr(autonomous_recon, "INTERESTING_PATHS", [])

    result = ReconResult(
        program="demo",
        target="https://example.com",
        target_host="example.com",
    )
    result.js_files = [
        "https://cdn.thirdparty.example/app.js",
        "https://example.com/static/app.js",
    ]

    phase_analyze(result)

    assert fetched == ["https://example.com/static/app.js"]
    assert result.api_endpoints == ["https://example.com/api/demo"]


def test_http_get_returns_http_error_body(monkeypatch) -> None:
    def fake_urlopen(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://example.com",
            403,
            "Forbidden",
            {"Server": "cloudflare"},
            io.BytesIO(b"cf-ray challenge body"),
        )

    monkeypatch.setattr(autonomous_recon.urllib.request, "urlopen", fake_urlopen)

    body, headers = autonomous_recon._http_get("https://example.com")

    assert body == b"cf-ray challenge body"
    assert headers["Server"] == "cloudflare"


def test_js_analysis_processes_all_scoped_files_and_reports_failures(monkeypatch) -> None:
    fetched = []
    def fake_get(url, timeout=10):
        fetched.append((url, timeout))
        return (b"", {}) if url.endswith("/20.js") else (b"const api='/api/ok';", {})
    monkeypatch.setattr(autonomous_recon, "_http_get", fake_get)
    monkeypatch.setattr(autonomous_recon, "INTERESTING_PATHS", [])
    result = ReconResult("demo", "https://example.com", "example.com")
    result.js_files = [f"https://example.com/{i}.js" for i in range(100)] + ["https://other.example/x.js"]
    phase_analyze(result)
    assert len(fetched) == 100
    assert {timeout for _, timeout in fetched} == {10}
    assert (result.js_files_scoped, result.js_files_attempted, result.js_files_failed, result.analysis_status) == (100, 100, 1, "partial")
    assert result.api_endpoints == ["https://example.com/api/ok"]


def test_crawl_checkpoint_resumes_frontier_and_retryable_failures(monkeypatch, tmp_path) -> None:
    import sys
    import json
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "CRAWL_PAGE_BUDGET", 2)
    calls = []
    def fake_get(url, timeout=10):
        calls.append((url, timeout))
        if url.endswith("/retry") and calls.count((url, 10)) == 1:
            return b"", {}
        path = url.rsplit("/", 1)[-1]
        if path == "example.com":
            return b'<a href="/a">a</a><a href="/retry">retry</a><script src="/a.js"></script>', {}
        if path == "a":
            return b'<a href="/deep">deep</a><a href="https://outside.example/no">outside</a>', {}
        return b"ok", {}
    monkeypatch.setattr(autonomous_recon, "_http_get", fake_get)
    scope = type("Scope", (), {"is_in_scope": lambda self, u: "outside" not in u})()
    result = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result, scope)
    assert result.crawl_status == "paused"
    assert result.crawl_pages_pending == 2
    checkpoint = autonomous_recon._output_dir(result) / "crawl_checkpoint.json"
    assert checkpoint.exists()
    result2 = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result2, scope)
    assert result2.crawl_status == "paused"  # /retry has not yet succeeded
    assert json.loads(checkpoint.read_text())["retryable_failed"] == ["https://example.com/retry"]
    result3 = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result3, scope)
    assert result3.crawl_status == "complete"
    assert result3.crawl_pages_pending == 0
    assert result3.crawl_pages_attempted == 4
    assert "https://example.com/deep" in result3.urls
    assert "https://example.com/a.js" in result3.js_files
    assert not checkpoint.exists()
    assert all(timeout == 10 for _, timeout in calls)


def test_output_floor_prevents_write(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(autonomous_recon.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 4 * 1024 ** 3})())
    result = ReconResult("demo", "https://example.com", "example.com")
    import pytest
    with pytest.raises(OSError, match="below 5 GiB"):
        autonomous_recon.phase_crawl(result)
    assert not (autonomous_recon._output_dir(result) / "crawl_checkpoint.json").exists()


def test_frontier_limit_pauses_without_publishing(monkeypatch, tmp_path) -> None:
    import sys
    import json
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "CRAWL_URL_LIMIT", 2)
    monkeypatch.setattr(autonomous_recon, "_http_get", lambda url, timeout=10: (b'<a href="/one">1</a><a href="/two">2</a>', {}))
    published = []
    monkeypatch.setattr(autonomous_recon, "record_recon_artifacts", lambda **kw: published.append(kw))
    result = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result)
    assert result.crawl_status == "paused"
    assert result.crawl_frontier_overflow > 0
    result.analysis_status = "pending_crawl"
    out = autonomous_recon.phase_organize(result)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["crawl_status"] == "paused"
    assert summary["crawl_frontier_overflow"] > 0
    assert "https://example.com/two" in (out / "crawl_overflow.txt").read_text().splitlines()
    assert published == []


def test_changed_scope_blocks_checkpoint_replay(monkeypatch, tmp_path) -> None:
    import pytest
    import sys
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "CRAWL_PAGE_BUDGET", 1)
    monkeypatch.setattr(autonomous_recon, "_http_get", lambda url, timeout=10: (b'<a href="/next">next</a>', {}))
    result = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result)
    scope = type("Scope", (), {"is_in_scope": lambda self, url: not url.endswith("/next")})()
    with pytest.raises(ValueError, match="no longer authorized"):
        autonomous_recon.phase_crawl(ReconResult("demo", "https://example.com", "example.com"), scope)
