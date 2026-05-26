from __future__ import annotations

import httpx

from agents.context_detector import ContextDetector, ContextType


def _response(text: str) -> httpx.Response:
    return httpx.Response(200, text=text)


def test_script_reflection_is_detected_before_html_attribute_context() -> None:
    detector = ContextDetector()

    context = detector.detect(
        _response(""),
        _response("<script>var x='PAYLOAD'</script>"),
        "PAYLOAD",
    )

    assert context.reflected is True
    assert context.type == ContextType.JS_STRING


def test_attribute_reflection_still_detects_attribute_context() -> None:
    detector = ContextDetector()

    context = detector.detect(
        _response(""),
        _response('<a href="/search?q=PAYLOAD">link</a>'),
        "PAYLOAD",
    )

    assert context.reflected is True
    assert context.type == ContextType.URL_PARAM
