from __future__ import annotations

import io
import urllib.error
import pytest

from agents import autonomous_recon
from agents.autonomous_recon import ReconResult, _extract_forms, phase_analyze

@pytest.fixture(autouse=True)
def isolated_recon(monkeypatch, tmp_path):
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(autonomous_recon, "_g_scope", None)
    monkeypatch.setattr(autonomous_recon, "_g_target_host", "example.com")
    monkeypatch.setattr(autonomous_recon, "_g_result", None)
    monkeypatch.setattr(autonomous_recon, "_g_limiter", None)


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

    monkeypatch.setattr(autonomous_recon, "_open_scoped", fake_urlopen)

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
    def fake_get(url, timeout=10, *, effective_url=None):
        calls.append((url, timeout))
        if effective_url is not None:
            effective_url.append(url)
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
    assert checkpoint.exists()  # retained until analysis and publication succeed
    assert all(timeout == 10 for _, timeout in calls)


def test_output_floor_prevents_write(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(autonomous_recon.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 4 * 1024 ** 3})())
    result = ReconResult("demo", "https://example.com", "example.com")
    import pytest
    autonomous_recon.phase_crawl(result)
    assert result.crawl_status == "paused"
    assert "below 5 GiB" in result.pause_reason
    assert (autonomous_recon._output_dir(result) / "crawl_checkpoint.json").exists()


def test_frontier_limit_pauses_without_publishing(monkeypatch, tmp_path) -> None:
    import sys
    import json
    monkeypatch.setattr(autonomous_recon.Path, "home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "CRAWL_URL_LIMIT", 2)
    def get(url, timeout=10, *, effective_url=None):
        if effective_url is not None: effective_url.append(url)
        return b'<a href="/one">1</a><a href="/two">2</a>', {}
    monkeypatch.setattr(autonomous_recon, "_http_get", get)
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
    def get(url, timeout=10, *, effective_url=None):
        if effective_url is not None: effective_url.append(url)
        return b'<a href="/next">next</a>', {}
    monkeypatch.setattr(autonomous_recon, "_http_get", get)
    result = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(result)
    scope = type("Scope", (), {"is_in_scope": lambda self, url: not url.endswith("/next")})()
    with pytest.raises(ValueError, match="no longer authorized"):
        autonomous_recon.phase_crawl(ReconResult("demo", "https://example.com", "example.com"), scope)


def test_restored_js_scope_rejected_before_network(monkeypatch, tmp_path):
    import json
    monkeypatch.setitem(__import__("sys").modules, "playwright.sync_api", None)
    result = ReconResult("demo", "https://example.com", "example.com")
    path = autonomous_recon._output_dir(result) / "crawl_checkpoint.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(dict(program="demo", target=result.target, pending=[],
        visited=[result.target], urls=[], params=[], js_files=["https://example.com/private.js"], forms=[])))
    scope = type("Scope", (), {"is_in_scope": lambda self, u: "/private" not in u})()
    with pytest.raises(ValueError, match="no longer authorized"):
        autonomous_recon.phase_crawl(result, scope)


def test_urllib_redirect_hops_validate_scope_and_rate(monkeypatch):
    class Limiter:
        calls = 0
        def wait(self):
            self.calls += 1
    limiter = Limiter()
    monkeypatch.setattr(autonomous_recon, "_g_limiter", limiter)
    monkeypatch.setattr(autonomous_recon, "_g_scope", type("S", (), {
        "is_in_scope": lambda self, u: "/private" not in u})())
    handler = autonomous_recon._ScopedRedirect()
    req = autonomous_recon.urllib.request.Request("https://example.com/start")
    assert handler.redirect_request(req, None, 302, "", {}, "/next").full_url == "https://example.com/next"
    assert limiter.calls == 1
    for destination in ("/private/secret", "https://outside.example/x", "file:///etc/passwd"):
        with pytest.raises(ValueError, match="outside saved scope"):
            handler.redirect_request(req, None, 302, "", {}, destination)
    assert limiter.calls == 1


def test_urllib_local_redirect_fixture_blocks_excluded_hop_and_rates_allowed(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path in ("/out-redirect", "/in-redirect"):
                self.send_response(302)
                self.send_header("Location", "/private-redirect" if self.path == "/out-redirect" else "/allowed")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"allowed")
        def log_message(self, format, *args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr(autonomous_recon, "_g_target_host", origin.removeprefix("http://"))
        monkeypatch.setattr(autonomous_recon, "_g_scope", type("Scope", (), {
            "is_in_scope": lambda self, url: "/private" not in url})())
        class Limiter:
            calls = 0
            def wait(self): self.calls += 1
        limiter = Limiter()
        monkeypatch.setattr(autonomous_recon, "_g_limiter", limiter)
        assert autonomous_recon._http_get(origin + "/out-redirect")[0] == b""
        assert hits == ["/out-redirect"]
        assert limiter.calls == 1
        assert autonomous_recon._http_get(origin + "/in-redirect")[0] == b"allowed"
        assert hits == ["/out-redirect", "/in-redirect", "/allowed"]
        assert limiter.calls == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_crawl_resolves_relative_links_against_scoped_redirect_destination(monkeypatch):
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/old/start":
                self.send_response(302)
                self.send_header("Location", "/new/index")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<a href="detail">detail</a>' if self.path == "/new/index" else b"ok")
        def log_message(self, format, *args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr(autonomous_recon, "_g_target_host", origin.removeprefix("http://"))
        monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
        monkeypatch.setattr(autonomous_recon, "CRAWL_PAGE_BUDGET", 2)
        class Limiter:
            calls = 0
            def wait(self): self.calls += 1
        limiter = Limiter()
        monkeypatch.setattr(autonomous_recon, "_g_limiter", limiter)
        scope = type("Scope", (), {"is_in_scope": lambda self, u: u.startswith(origin) and "/private" not in u})()
        result = ReconResult("demo", origin + "/old/start", origin.removeprefix("http://"))
        autonomous_recon.phase_crawl(result, scope)
        assert result.crawl_status == "complete"
        assert origin + "/new/detail" in result.urls
        assert origin + "/old/detail" not in result.urls
        assert hits == ["/old/start", "/new/index", "/new/detail"]
        assert limiter.calls == len(hits)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_analyze_filters_extracted_paths_by_saved_scope_and_checkpoint(monkeypatch):
    monkeypatch.setattr(autonomous_recon, "INTERESTING_PATHS", [])
    fetched = []
    def get(url, timeout=10):
        fetched.append(url)
        return b"const paths=['/api/private', 'https://example.com/allowed/api/public'];", {}
    monkeypatch.setattr(autonomous_recon, "_http_get", get)
    scope = type("Scope", (), {"is_in_scope": lambda self, u: u.startswith("https://example.com/allowed/")})()
    result = ReconResult("demo", "https://example.com/allowed/", "example.com")
    result.js_files = ["https://example.com/allowed/app.js"]
    phase_analyze(result, scope)
    assert fetched == result.js_files
    assert result.api_endpoints == ["https://example.com/allowed/api/public"]
    resumed = ReconResult("demo", result.target, result.target_host)
    resumed.js_files = result.js_files
    phase_analyze(resumed, scope)
    assert fetched == result.js_files
    assert resumed.api_endpoints == result.api_endpoints


def test_crawl_missing_effective_url_is_retryable_not_complete(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "_http_get", lambda url, timeout=10, *, effective_url=None: (b'<a href="detail">x</a>', {}))
    result = ReconResult("demo", "https://example.com/old/start", "example.com")
    autonomous_recon.phase_crawl(result)
    assert result.crawl_status == "paused"
    assert result.crawl_pages_pending == 1
    assert result.urls == []
    assert any("effective URL" in error for error in result.errors)


def test_browser_route_blocks_redirects_and_subrequests_and_retries(monkeypatch):
    import sys, types
    calls = []
    class Route:
        def __init__(self, url): self.request = types.SimpleNamespace(url=url, is_navigation_request=lambda: url == "https://example.com")
        def abort(self): calls.append((self.request.url, "abort"))
        def fetch(self, *, max_redirects):
            assert max_redirects == 0
            calls.append((self.request.url, "fetch"))
            return types.SimpleNamespace(status=200, headers={})
        def fulfill(self, *, response): calls.append((self.request.url, "fulfill"))
    class Page:
        url = "https://example.com"
        def on(self, *_): pass
        def goto(self, url, **_):
            context.route_handler(Route(url))
            context.route_handler(Route("https://example.com/allowed.js"))
            context.route_handler(Route("https://example.com/private.js"))
            context.route_handler(Route("https://outside.example/redirect"))
            if len([x for x in calls if x == (url, "fulfill")]) == 1:
                raise RuntimeError("navigation interrupted")
            self.url = url
        def wait_for_timeout(self, *_): pass
        def content(self): return "ok"
        def eval_on_selector_all(self, *_): return []
    class Context:
        def route(self, pattern, handler): self.route_handler = handler
        def route_web_socket(self, pattern, handler): self.ws_handler = handler
        def new_page(self): return Page()
    context = Context()
    class Browser:
        def new_context(self, **kwargs):
            assert kwargs["service_workers"] == "block"
            return context
        def close(self): pass
    class PW:
        chromium = types.SimpleNamespace(launch=lambda **_: Browser())
    class Manager:
        def __enter__(self): return PW()
        def __exit__(self, *_): pass
    monkeypatch.setitem(sys.modules, "playwright.sync_api", types.SimpleNamespace(sync_playwright=lambda: Manager()))
    monkeypatch.setattr(autonomous_recon, "CRAWL_PAGE_BUDGET", 1)
    scope = type("Scope", (), {"is_in_scope": lambda self, u: "/private" not in u})()
    first = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(first, scope)
    assert first.crawl_status == "paused"
    second = ReconResult("demo", "https://example.com", "example.com")
    autonomous_recon.phase_crawl(second, scope)
    assert second.crawl_status == "complete"
    assert ("https://example.com/private.js", "abort") in calls
    assert ("https://outside.example/redirect", "abort") in calls
    assert ("https://example.com/allowed.js", "fulfill") in calls
    class WS:
        def __init__(self, url): self.url = url
        def close(self): calls.append((self.url, "close"))
        def connect_to_server(self): calls.append((self.url, "connect"))
    context.ws_handler(WS("wss://outside.example/stream"))
    context.ws_handler(WS("wss://example.com/private/socket"))
    context.ws_handler(WS("wss://example.com/allowed"))
    assert ("wss://outside.example/stream", "close") in calls
    assert ("wss://example.com/private/socket", "close") in calls
    assert ("wss://example.com/allowed", "connect") in calls

def test_browser_redirects_pause_excluded_hop_and_urllib_resumes_allowed_navigation(monkeypatch):
    import sys, types, json
    calls = []
    class Route:
        def __init__(self, url):
            self.request = types.SimpleNamespace(url=url, is_navigation_request=lambda: url.endswith("/start"))
        def fetch(self, *, max_redirects):
            assert max_redirects == 0
            calls.append(("fetch", self.request.url))
            location = "/allowed" if self.request.url.endswith("/start") else "/private-redirect"
            return types.SimpleNamespace(status=302, headers={"location": location})
        def abort(self): calls.append(("abort", self.request.url))
        def fulfill(self, **_): pytest.fail("redirect fulfilled to Chromium")
    class Page:
        url = "https://example.com/start"
        def on(self, *_): pass
        def goto(self, url, **_):
            context.handler(Route(url))
            if url.endswith("/start"):
                raise RuntimeError("navigation aborted")
            context.handler(Route("https://example.com/script.js"))
        def wait_for_timeout(self, *_): pass
        def content(self): return "ok"
        def eval_on_selector_all(self, *_): return []
    class Context:
        def route(self, _, handler): self.handler = handler
        def route_web_socket(self, *_): pass
        def new_page(self): return Page()
    context = Context()
    class Browser:
        def new_context(self, **_): return context
        def close(self): pass
    class Manager:
        def __enter__(self): return types.SimpleNamespace(chromium=types.SimpleNamespace(launch=lambda **_: Browser()))
        def __exit__(self, *_): pass
    monkeypatch.setitem(sys.modules, "playwright.sync_api", types.SimpleNamespace(sync_playwright=lambda: Manager()))
    monkeypatch.setattr(autonomous_recon, "CRAWL_PAGE_BUDGET", 2)
    scope = type("Scope", (), {"is_in_scope": lambda self, u: "/private" not in u})()
    def get(url, timeout=10, *, effective_url=None):
        if effective_url is not None: effective_url.append("https://example.com/new/index")
        return b'<a href="detail">next</a>', {}
    monkeypatch.setattr(autonomous_recon, "_http_get", get)
    result = ReconResult("demo", "https://example.com/start", "example.com")
    autonomous_recon.phase_crawl(result, scope)
    assert result.crawl_status == "paused"
    assert ("fetch", "https://example.com/start") in calls
    assert ("abort", "https://example.com/start") in calls
    assert ("abort", "https://example.com/script.js") in calls
    assert ("fetch", "https://example.com/private-redirect") not in calls
    assert "https://example.com/new/detail" in json.loads((autonomous_recon._output_dir(result) / "crawl_checkpoint.json").read_text())["retryable_failed"]
    assert "https://example.com/old/detail" not in result.urls
    assert any("Browser redirect not followed" in error for error in result.errors)


def test_analysis_resume_and_publication_checkpoint(monkeypatch):
    result = ReconResult("demo", "https://example.com", "example.com")
    result.js_files = ["https://example.com/1.js", "https://example.com/2.js"]
    monkeypatch.setattr(autonomous_recon, "INTERESTING_PATHS", [])
    calls = []
    def get(url, timeout=10):
        calls.append(url)
        if url.endswith("2.js") and calls.count(url) == 1:
            raise KeyboardInterrupt
        return b"const api='/api/ok';", {}
    monkeypatch.setattr(autonomous_recon, "_http_get", get)
    with pytest.raises(KeyboardInterrupt):
        phase_analyze(result)
    assert (autonomous_recon._output_dir(result) / "analysis_checkpoint.json").exists()
    resumed = ReconResult("demo", "https://example.com", "example.com")
    resumed.js_files = result.js_files
    phase_analyze(resumed)
    assert calls.count("https://example.com/1.js") == 1
    assert resumed.js_files_attempted == 2
    resumed.crawl_status = "complete"
    monkeypatch.setattr(autonomous_recon, "record_recon_artifacts", lambda **_: (_ for _ in ()).throw(RuntimeError("publish failed")))
    with pytest.raises(RuntimeError, match="publish failed"):
        autonomous_recon.phase_organize(resumed)
    assert (autonomous_recon._output_dir(resumed) / "analysis_checkpoint.json").exists()
    monkeypatch.setattr(autonomous_recon, "record_recon_artifacts", lambda **_: "manifest.json")
    autonomous_recon.phase_organize(resumed)
    assert not (autonomous_recon._output_dir(resumed) / "analysis_checkpoint.json").exists()


def test_publication_resume_skips_existing_manifest(monkeypatch, tmp_path):
    import json
    result = ReconResult("demo", "https://example.com", "example.com")
    result.run_id = "same-run"
    result.crawl_status = result.analysis_status = "complete"
    out = autonomous_recon._output_dir(result)
    out.mkdir(parents=True)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    (out / "summary.json").write_text(json.dumps({"run_id": "same-run", "canonical_manifest": str(manifest)}))
    monkeypatch.setattr(autonomous_recon, "record_recon_artifacts", lambda **_: pytest.fail("duplicate promotion"))
    autonomous_recon.phase_organize(result)
    assert json.loads((out / "summary.json").read_text())["canonical_manifest"] == str(manifest)


def test_partial_exit_and_timed_out_discovery(monkeypatch):
    import subprocess, sys
    result = ReconResult("demo", "https://example.com", "example.com")
    monkeypatch.setattr(autonomous_recon, "_g_result", result)
    monkeypatch.setattr(autonomous_recon.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired("nmap", 90)))
    assert autonomous_recon._run_cmd(["nmap"], timeout=90) == ""
    assert result.discovery_status == "partial"
    assert not autonomous_recon.recon_complete(result)
    monkeypatch.setattr(autonomous_recon, "run_recon", lambda **_: result)
    monkeypatch.setattr(sys, "argv", ["autonomous_recon.py", "--target", "example.com"])
    with pytest.raises(SystemExit) as exc:
        autonomous_recon.main()
    assert exc.value.code == 2


def test_disk_floor_run_writes_durable_partial_summary(monkeypatch):
    import json, sys
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    monkeypatch.setattr(autonomous_recon, "ScopeValidator", lambda _: type("Scope", (), {"is_in_scope": lambda self, url: True})())
    monkeypatch.setattr(autonomous_recon, "phase_discover", lambda _: None)
    monkeypatch.setattr(autonomous_recon, "record_recon_artifacts", lambda **_: pytest.fail("published partial run"))
    monkeypatch.setattr(autonomous_recon.shutil, "disk_usage", lambda _: type("U", (), {"free": 4 * 1024 ** 3})())
    result = autonomous_recon.run_recon("demo", "https://example.com")
    out = autonomous_recon._output_dir(result)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["crawl_status"] == "paused"
    assert "below 5 GiB" in summary["pause_reason"]
    assert summary["crawl_checkpoint"] == str(out / "crawl_checkpoint.json")
    assert json.loads((out / "crawl_checkpoint.json").read_text())["pending"] == [result.target]
    assert not (out / "urls.txt").exists()
