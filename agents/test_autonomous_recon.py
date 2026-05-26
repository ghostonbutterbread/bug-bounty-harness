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
