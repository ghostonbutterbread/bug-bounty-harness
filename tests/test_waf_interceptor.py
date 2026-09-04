#!/usr/bin/env python3
"""Regression coverage for evidence-gated WAF retry strategies."""

from __future__ import annotations

import asyncio
import importlib.util
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "agents" / "waf_interceptor.py"
SPEC = importlib.util.spec_from_file_location("waf_interceptor", SCRIPT)
assert SPEC and SPEC.loader
WAF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WAF)


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers: dict[str, str] = {}


AKAMAI_BLOCK = FakeResponse(403, "AkamaiGHost Access Denied")
CLEAN_RESPONSE = FakeResponse(200, "ok")


class WAFInterceptorTests(unittest.TestCase):
    def test_akamai_retries_android_chrome_after_desktop_chrome(self) -> None:
        retries = WAF.WAF_BYPASSES["Akamai"]
        user_agents = [entry["headers"]["User-Agent"] for entry in retries if "headers" in entry and "User-Agent" in entry["headers"]]
        self.assertEqual(user_agents[:2], [WAF._CHROME_UA, WAF._ANDROID_CHROME_UA])

    def test_sync_akamai_block_can_recover_with_android_chrome_retry(self) -> None:
        interceptor = WAF.WAFInterceptor("https://example.test", verbose=False)
        calls: list[dict[str, Any]] = []
        responses = iter([AKAMAI_BLOCK, AKAMAI_BLOCK, CLEAN_RESPONSE])

        def request(method: str, url: str, **kwargs: Any) -> FakeResponse:
            calls.append(kwargs)
            return next(responses)

        interceptor._sync_request = request
        with patch.object(WAF.time, "sleep"):
            response = interceptor.get("/protected")

        self.assertIs(response, CLEAN_RESPONSE)
        self.assertEqual(calls[1]["headers"]["User-Agent"], WAF._CHROME_UA)
        self.assertEqual(calls[2]["headers"]["User-Agent"], WAF._ANDROID_CHROME_UA)
        self.assertEqual(interceptor._stats["bypass_success"], 1)

    def test_async_akamai_block_can_recover_with_android_chrome_retry(self) -> None:
        interceptor = WAF.WAFInterceptor("https://example.test", verbose=False)
        responses = iter([AKAMAI_BLOCK, AKAMAI_BLOCK, CLEAN_RESPONSE])

        class Client:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            async def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
                self.calls.append(kwargs)
                return next(responses)

        client = Client()
        with patch.object(WAF.asyncio, "sleep", new=AsyncMock()):
            response = asyncio.run(interceptor.aget("/protected", client=client))

        self.assertIs(response, CLEAN_RESPONSE)
        self.assertEqual(client.calls[1]["headers"]["User-Agent"], WAF._CHROME_UA)
        self.assertEqual(client.calls[2]["headers"]["User-Agent"], WAF._ANDROID_CHROME_UA)
        self.assertEqual(interceptor._stats["bypass_success"], 1)

    def test_wrap_async_retries_original_path_and_query_with_mobile_ua(self) -> None:
        interceptor = WAF.WAFInterceptor("https://example.test", verbose=False)
        responses = iter([AKAMAI_BLOCK, CLEAN_RESPONSE])

        class Client:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, dict[str, Any]]] = []

            async def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
                self.calls.append((method, url, kwargs))
                return next(responses)

        client = Client()
        blocked_url = "https://example.test/protected?mode=test"
        with patch.object(WAF.asyncio, "sleep", new=AsyncMock()):
            response = asyncio.run(interceptor.wrap_async(client, "GET", blocked_url, AKAMAI_BLOCK))

        self.assertIs(response, CLEAN_RESPONSE)
        self.assertEqual([call[1] for call in client.calls], [blocked_url, blocked_url])
        self.assertEqual(client.calls[0][2]["headers"]["User-Agent"], WAF._CHROME_UA)
        self.assertEqual(client.calls[1][2]["headers"]["User-Agent"], WAF._ANDROID_CHROME_UA)
        self.assertEqual(interceptor._stats["bypass_success"], 1)


if __name__ == "__main__":
    unittest.main()
