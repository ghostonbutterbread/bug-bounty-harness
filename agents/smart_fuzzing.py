"""Deterministic, source-attributed vocabulary extraction for smart fuzzing.

This module performs offline analysis only. It never executes scanners or
changes scope, authentication, rate, or command policy.
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse
import re
from typing import Iterable

_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,80}$")


def _paths(value: str, target_host: str, allowed_hosts: set[str]) -> Iterable[str]:
    """Yield route segments only when an absolute URL is on an allowed host."""
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        host = (parsed.hostname or "").lower()
        if host != target_host or host not in allowed_hosts:
            return ()
        path = parsed.path
    else:
        path = value if value.startswith("/") else ""
    return (segment for segment in path.split("/") if _TOKEN.fullmatch(segment))


def build_deterministic_evidence_pack(
    *, program: str, target_host: str, sources: dict[str, list[str]], allowed_hosts: set[str]
) -> list[dict[str, object]]:
    """Return deduplicated, provenance-labelled vocabulary from offline facts."""
    target_host = target_host.lower()
    allowed_hosts = {host.lower() for host in allowed_hosts}
    candidates: dict[str, set[str]] = defaultdict(set)
    for source_name, values in sources.items():
        for value in values:
            for token in _paths(value, target_host, allowed_hosts):
                candidates[token.lower()].add(source_name)
    return [
        {
            "candidate": candidate,
            "kind": "path_token",
            "sources": sorted(source_names),
            "evidence_refs": [],
            "confidence": "high" if len(source_names) > 1 else "medium",
            "target_host": target_host,
            "proposed_by": "deterministic",
            "reason": "normalized route token from scoped offline evidence",
            "program": program,
        }
        for candidate, source_names in sorted(candidates.items())
    ]
