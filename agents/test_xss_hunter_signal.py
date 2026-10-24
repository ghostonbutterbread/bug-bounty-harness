"""Offline signal tests: reflected text is not proof of execution."""

import httpx

from agents.context_detector import ContextType
from agents.xss_hunter import XSSHunter


def test_escaped_html_payload_is_not_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<p>baseline</p>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<p>&lt;img src=x onerror=alert(1)&gt;</p>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.reflected
        assert result.context == ContextType.HTML_BODY
        assert not result.likely_executable
        assert not hunter._is_finding(result)
    finally:
        hunter.close()


def test_absent_payload_cannot_be_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<p>baseline</p>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<p>nothing</p>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert not result.reflected
        assert not result.likely_executable
    finally:
        hunter.close()


def test_escaped_tag_in_attribute_is_not_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<input value='baseline'>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<input value='&lt;img src=x onerror=alert(1)&gt;'>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.HTML_ATTRIBUTE
        assert not result.likely_executable
    finally:
        hunter.close()
