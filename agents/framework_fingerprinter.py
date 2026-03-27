"""Frontend framework fingerprinting for XSS targeting."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

import httpx


@dataclass
class FrameworkInfo:
    name: str
    version: str = ""
    protections: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    score: int = 0


class FrameworkFingerprinter:
    """Identifies frontend frameworks from response signatures."""

    SIGNATURES = {
        "angular": [
            ("ng-app", 4),
            ("angular.js", 3),
            ("angular.min.js", 3),
            ("_ngcontent", 4),
            ("angularjs", 2),
            ("[ng-style]", 2),
            ("[innerhtml]", 3),
            ("ng-version", 3),
            ("ng-bind-html", 4),
        ],
        "react": [
            ("__react", 4),
            ("data-reactroot", 4),
            ("_reactrootcontainer", 4),
            ("react-", 2),
            ("dangerouslysetinnerhtml", 4),
            ("__next", 2),
        ],
        "vue": [
            ("__vue__", 4),
            ("v-if", 2),
            ("v-for", 2),
            ("vue-app", 3),
            ("data-v-", 4),
            ("v-html", 4),
        ],
        "jquery": [
            ("jquery", 4),
            ("$(", 1),
            (".html(", 3),
            (".append(", 2),
            (".after(", 2),
            (".before(", 2),
        ],
        "prototype": [
            ("prototype", 4),
            ("$$(", 3),
            ("$f(", 2),
        ],
        "dojo": [
            ("dojox", 4),
            ("dijit", 4),
            ("dojo/", 3),
        ],
        "server-side": [
            ("__viewstate", 4),
            ("__requestverificationtoken", 4),
            (".jsp", 2),
            (".aspx", 2),
            ("asp.net", 2),
        ],
    }

    PROTECTIONS = {
        "angular": [
            "DOMSanitizer / template sanitization",
            "Angular HTML binding restrictions",
        ],
        "react": [
            "React escapes text nodes by default",
            "dangerouslySetInnerHTML is explicit",
        ],
        "vue": [
            "Vue escapes interpolated HTML by default",
            "v-html bypasses auto escaping",
        ],
        "jquery": [
            "No built-in sanitization for html()/append()",
        ],
        "prototype": [
            "No built-in sanitization for DOM insertion helpers",
        ],
        "dojo": [
            "Widget templating may escape some contexts",
        ],
        "vanilla": [
            "No framework-level sanitization detected",
        ],
        "server-side": [
            "Server templating may HTML-encode output",
        ],
    }

    COMMON_SINKS = {
        "angular": ["ng-bind-html", "[innerHTML]", "bypassSecurityTrustHtml"],
        "react": ["dangerouslySetInnerHTML", "render", "hydrateRoot"],
        "vue": ["v-html", "render", "innerHTML"],
        "jquery": [".html()", ".append()", ".after()", ".before()"],
        "prototype": ["update()", "insert()"],
        "dojo": ["dojo.html.set", "innerHTML"],
        "vanilla": ["innerHTML", "outerHTML", "document.write"],
        "server-side": ["template render", "server-rendered reflection"],
    }

    def fingerprint(self, response: httpx.Response) -> FrameworkInfo:
        """Detect framework, version hints, and known protections."""
        text = response.text or ""
        lower = text.lower()
        headers = " ".join(f"{key}: {value}" for key, value in response.headers.items()).lower()
        combined = f"{lower}\n{headers}"

        candidates: list[FrameworkInfo] = []
        for name, signatures in self.SIGNATURES.items():
            score = 0
            evidence: list[str] = []
            for signature, weight in signatures:
                if signature in combined:
                    score += weight
                    evidence.append(signature)
            if score:
                candidates.append(
                    FrameworkInfo(
                        name=name,
                        version=self._detect_version(name, combined),
                        protections=list(self.PROTECTIONS.get(name, [])),
                        sinks=list(self.COMMON_SINKS.get(name, [])),
                        evidence=evidence,
                        score=score,
                    )
                )

        if not candidates:
            return FrameworkInfo(
                name="vanilla",
                version=self._detect_version("vanilla", combined),
                protections=list(self.PROTECTIONS["vanilla"]),
                sinks=list(self.COMMON_SINKS["vanilla"]),
                evidence=self._vanilla_evidence(combined),
                score=1,
            )

        best = max(candidates, key=lambda item: item.score)
        csp = response.headers.get("content-security-policy")
        if csp:
            best.protections.append("CSP present")
            best.evidence.append("content-security-policy")
        return best

    def _detect_version(self, framework_name: str, combined: str) -> str:
        patterns = {
            "angular": [
                r"angular(?:\.min)?\.js(?:\?v=|/)(\d+\.\d+(?:\.\d+)?)",
                r'ng-version=["\'](\d+\.\d+(?:\.\d+)?)',
            ],
            "react": [
                r"react(?:\.production(?:\.min)?)?\.js(?:\?v=|/)(\d+\.\d+(?:\.\d+)?)",
                r"react@(\d+\.\d+(?:\.\d+)?)",
            ],
            "vue": [
                r"vue(?:\.runtime(?:\.global)?)?(?:\.prod)?\.js(?:\?v=|/)(\d+\.\d+(?:\.\d+)?)",
                r"vue@(\d+\.\d+(?:\.\d+)?)",
            ],
            "jquery": [
                r"jquery(?:\.min)?\.js(?:\?v=|/|-)(\d+\.\d+(?:\.\d+)?)",
            ],
        }
        for pattern in patterns.get(framework_name, []):
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _vanilla_evidence(self, combined: str) -> list[str]:
        evidence = []
        for signature in ("innerhtml", "document.write", "insertadjacenthtml"):
            if signature in combined:
                evidence.append(signature)
        return evidence or ["no framework signature"]
