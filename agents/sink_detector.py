"""Dangerous DOM sink detection helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass
class Sink:
    name: str
    line: int
    snippet: str
    severity: str = "high"
    source: str = "javascript"


class SinkDetector:
    """Finds dangerous DOM sinks in JavaScript."""

    PATTERNS = [
        ("innerHTML", re.compile(r"\.innerHTML\s*=", re.IGNORECASE)),
        ("outerHTML", re.compile(r"\.outerHTML\s*=", re.IGNORECASE)),
        ("document.write", re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE)),
        ("document.writeln", re.compile(r"\bdocument\.writeln\s*\(", re.IGNORECASE)),
        ("eval()", re.compile(r"\beval\s*\(", re.IGNORECASE)),
        ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*['\"`]", re.IGNORECASE)),
        ("setInterval(string)", re.compile(r"\bsetInterval\s*\(\s*['\"`]", re.IGNORECASE)),
        ("Function()", re.compile(r"(?<!new\s)\bFunction\s*\(", re.IGNORECASE)),
        ("new Function()", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
        ("execScript", re.compile(r"\bexecScript\s*\(", re.IGNORECASE)),
        ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE)),
        (".jquery.html()", re.compile(r"\.\s*html\s*\(", re.IGNORECASE)),
        ("dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b", re.IGNORECASE)),
        ("v-html", re.compile(r"\bv-html\b", re.IGNORECASE)),
        ("ng-bind-html", re.compile(r"\bng-bind-html\b", re.IGNORECASE)),
        ("rerender", re.compile(r"\brerender\s*\(", re.IGNORECASE)),
        ("render", re.compile(r"(?<!re)\brender\s*\(", re.IGNORECASE)),
    ]

    def find_sinks(self, js_content: str) -> list[Sink]:
        """Parse JS and find dangerous sink usages."""
        sinks: list[Sink] = []
        seen: set[tuple[str, int]] = set()

        for line_number, line in enumerate(js_content.splitlines(), start=1):
            for sink_name, pattern in self.PATTERNS:
                if pattern.search(line):
                    key = (sink_name, line_number)
                    if key in seen:
                        continue
                    seen.add(key)
                    sinks.append(
                        Sink(
                            name=sink_name,
                            line=line_number,
                            snippet=line.strip()[:220],
                            severity=self._severity_for_sink(sink_name),
                        )
                    )
        return sinks

    def _severity_for_sink(self, sink_name: str) -> str:
        if sink_name in {"eval()", "Function()", "new Function()", "execScript"}:
            return "critical"
        if sink_name in {"innerHTML", "outerHTML", "document.write", "dangerouslySetInnerHTML"}:
            return "high"
        return "medium"
