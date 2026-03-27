"""Detect reflection context for XSS payloads."""

from __future__ import annotations

from dataclasses import dataclass
import html
import re
from urllib.parse import quote, quote_plus

import httpx


class ContextType:
    HTML_BODY = "HTML_BODY"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    HTML_COMMENT = "HTML_COMMENT"
    JS_STRING = "JS_STRING"
    JS_TEMPLATE = "JS_TEMPLATE"
    URL_PARAM = "URL_PARAM"
    STYLESHEET = "STYLESHEET"
    NO_REFLECTION = "NO_REFLECTION"


@dataclass
class InjectionContext:
    type: str
    reflected_fragment: str = ""
    surrounding_text: str = ""
    confidence: float = 0.0
    location_hint: str = ""
    reflected: bool = False


class ContextDetector:
    """Detects injection context from reflection response."""

    def detect(
        self,
        original_response: httpx.Response,
        payload_response: httpx.Response,
        payload: str,
    ) -> InjectionContext:
        """Analyze where the payload was reflected."""
        response_text = payload_response.text or ""
        match_value, start_index = self._find_reflection(response_text, payload)
        if start_index < 0:
            return InjectionContext(type=ContextType.NO_REFLECTION, confidence=1.0)

        surrounding = self._snippet(response_text, start_index, len(match_value))
        location_hint = f"offset:{start_index}"

        if self._inside_html_comment(response_text, start_index):
            return InjectionContext(
                type=ContextType.HTML_COMMENT,
                reflected_fragment=match_value,
                surrounding_text=surrounding,
                confidence=0.92,
                location_hint=location_hint,
                reflected=True,
            )

        if self._inside_tag(response_text, start_index, match_value):
            if self._is_url_attribute(response_text, start_index, match_value):
                context_type = ContextType.URL_PARAM
            else:
                context_type = ContextType.HTML_ATTRIBUTE
            return InjectionContext(
                type=context_type,
                reflected_fragment=match_value,
                surrounding_text=surrounding,
                confidence=0.9,
                location_hint=location_hint,
                reflected=True,
            )

        if self._inside_script(response_text, start_index):
            script_context = self._detect_script_subcontext(response_text, start_index)
            return InjectionContext(
                type=script_context,
                reflected_fragment=match_value,
                surrounding_text=surrounding,
                confidence=0.88,
                location_hint=location_hint,
                reflected=True,
            )

        if self._inside_style(response_text, start_index):
            return InjectionContext(
                type=ContextType.STYLESHEET,
                reflected_fragment=match_value,
                surrounding_text=surrounding,
                confidence=0.86,
                location_hint=location_hint,
                reflected=True,
            )

        return InjectionContext(
            type=ContextType.HTML_BODY,
            reflected_fragment=match_value,
            surrounding_text=surrounding,
            confidence=0.75,
            location_hint=location_hint,
            reflected=True,
        )

    def _find_reflection(self, response_text: str, payload: str) -> tuple[str, int]:
        candidates = [
            payload,
            html.escape(payload),
            html.escape(payload, quote=True),
            quote(payload, safe=""),
            quote_plus(payload, safe=""),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            index = response_text.find(candidate)
            if index >= 0:
                return candidate, index
        return "", -1

    def _snippet(self, text: str, start: int, length: int, radius: int = 80) -> str:
        left = max(0, start - radius)
        right = min(len(text), start + length + radius)
        return text[left:right].replace("\n", "\\n")

    def _inside_html_comment(self, text: str, start: int) -> bool:
        comment_open = text.rfind("<!--", 0, start)
        comment_close = text.rfind("-->", 0, start)
        comment_end = text.find("-->", start)
        return comment_open > comment_close and comment_end != -1

    def _inside_style(self, text: str, start: int) -> bool:
        style_open = text.lower().rfind("<style", 0, start)
        style_close = text.lower().rfind("</style", 0, start)
        style_end = text.lower().find("</style", start)
        return style_open > style_close and style_end != -1

    def _inside_script(self, text: str, start: int) -> bool:
        lower = text.lower()
        script_open = lower.rfind("<script", 0, start)
        script_close = lower.rfind("</script", 0, start)
        script_end = lower.find("</script", start)
        return script_open > script_close and script_end != -1

    def _inside_tag(self, text: str, start: int, match_value: str) -> bool:
        left = text.rfind("<", 0, start)
        right = text.find(">", start + len(match_value))
        if left == -1 or right == -1 or right - left > 400:
            return False
        if text[left:right].find("\n") != -1:
            return False
        return start < right

    def _is_url_attribute(self, text: str, start: int, match_value: str) -> bool:
        left = text.rfind("<", 0, start)
        right = text.find(">", start + len(match_value))
        if left == -1 or right == -1:
            return False
        tag_chunk = text[left:right + 1]
        return bool(
            re.search(
                r"""(?:href|src|action|formaction|data|poster)\s*=\s*(['"])[^'"]*"""
                + re.escape(match_value)
                + r"""[^'"]*\1""",
                tag_chunk,
                re.IGNORECASE | re.DOTALL,
            )
        )

    def _detect_script_subcontext(self, text: str, start: int) -> str:
        script_open = text.lower().rfind("<script", 0, start)
        open_end = text.find(">", script_open)
        script_prefix = text[open_end + 1:start]

        if self._in_unclosed_literal(script_prefix, "`"):
            return ContextType.JS_TEMPLATE
        if self._in_unclosed_literal(script_prefix, "'") or self._in_unclosed_literal(script_prefix, '"'):
            return ContextType.JS_STRING
        return ContextType.JS_STRING

    def _in_unclosed_literal(self, prefix: str, quote_char: str) -> bool:
        escaped = False
        count = 0
        for char in prefix:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote_char:
                count += 1
        return count % 2 == 1
