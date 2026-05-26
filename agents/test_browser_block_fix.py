from __future__ import annotations

from agents.browser_block_fix import BrowserBlockFix


def test_cloudflare_success_header_is_not_a_block() -> None:
    bbf = BrowserBlockFix("https://example.com")

    blocked, waf_name = bbf.is_blocked(
        {
            "status": 200,
            "headers": {"cf-ray": "abc123"},
            "content": "OK",
        }
    )

    assert blocked is False
    assert waf_name is None


def test_cloudflare_block_status_with_header_is_a_block() -> None:
    bbf = BrowserBlockFix("https://example.com")

    blocked, waf_name = bbf.is_blocked(
        {
            "status": 403,
            "headers": {"cf-ray": "abc123"},
            "content": "Forbidden",
        }
    )

    assert blocked is True
    assert waf_name == "Cloudflare"


def test_post_browser_fallback_preserves_headers(monkeypatch) -> None:
    bbf = BrowserBlockFix("https://example.com")
    captured = {}

    def fake_curl_post(path, data=None, json=None, headers=None):
        return {
            "status": 403,
            "headers": {"cf-ray": "abc123"},
            "content": "Forbidden",
        }

    def fake_spawn_browser():
        captured["spawned"] = True

    def fake_browser_post(path, data=None, json=None, headers=None):
        captured["headers"] = headers
        return {"status": 200, "headers": {}, "content": "OK"}

    monkeypatch.setattr(bbf, "curl_post", fake_curl_post)
    monkeypatch.setattr(bbf, "spawn_browser", fake_spawn_browser)
    monkeypatch.setattr(bbf, "browser_post", fake_browser_post)

    response = bbf.post("/login", data={"u": "a"}, headers={"Authorization": "Bearer token"})

    assert response["status"] == 200
    assert captured["spawned"] is True
    assert captured["headers"] == {"Authorization": "Bearer token"}
