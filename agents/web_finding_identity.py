"""Route identity for web findings whose source label is not an affected URL."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_SUMMARY_RE = re.compile(r"(?im)^##\s+summary\s*\n\s*`(https?://[^\s`]+)`")
_SOURCE_FILE_RE = re.compile(r"^(?:\.?[\w-]+/)*[\w.-]+\.[A-Za-z0-9]+$")


def web_route(value: Any) -> str:
    """Use origin and exact route, never a hostname-only or prefix identity."""
    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return ""
        origin = parsed.netloc.lower()
        # Reading port triggers validation for malformed authorities.
        _ = parsed.port
        return urlunsplit((parsed.scheme.lower(), origin, parsed.path or "/", "", ""))
    except ValueError:
        return ""


def _label_like_file(finding: dict[str, Any]) -> bool:
    """Only replace a bare technology label, not a plausible source path."""
    text = str(finding.get("file") or "").strip()
    if not text or "/" in text or "\\" in text or text.startswith("."):
        return not text
    # A capitalized bare *.js might be a source file OR a technology label.
    # Only an explicitly asserted affected URL below can resolve that ambiguity.
    return not _SOURCE_FILE_RE.fullmatch(text) or text[0].isupper()


def _narrative_route(text: str, match: re.Match[str]) -> str:
    # A closing backtick delimits a URL exactly; ordinary prose punctuation
    # is not part of the route. Direct URL fields never use this trimming.
    raw = match.group()
    if text[match.end():match.end() + 1] != "`":
        raw = raw.rstrip(".,;)]}")
    return web_route(raw)


def finding_web_route(finding: dict[str, Any]) -> str:
    """Prefer a declared route; recover legacy label rows only if unambiguous."""
    for key in ("url", "endpoint", "file"):
        route = web_route(finding.get(key))
        if route:
            return route
    if not _label_like_file(finding):
        return ""
    narrative = "\n".join(str(finding.get(key) or "") for key in ("description", "impact"))
    # A URL mentioned in prose is not enough. Accept a lead Summary URL or a
    # sentence that directly states the affected/observed surface; documentation
    # links and exploit destinations must not become canonical finding identities.
    asserted: set[str] = set()
    for match in _SUMMARY_RE.finditer(narrative):
        sentence = narrative[match.end():match.end() + 180]
        if not re.search(r"\b(?:not affected|unaffected|not vulnerable|not reproduced|docs?|documentation|reference|not identified)\b", sentence, re.I) and (route := web_route(match.group(1))):
            asserted.add(route)
    for match in _URL_RE.finditer(narrative):
        line = narrative[narrative.rfind("\n", 0, match.start()) + 1:match.start()].strip()
        following = narrative[match.end():match.end() + 120]
        if (re.match(r"(?:confirmed|affected|observed|reproduced|vulnerable)\b", line, re.I)
                and ";" not in line
                and not re.search(r"\b(?:not|never|no|unaffected|docs?|documentation|reference)\b", line, re.I)
                and not re.search(r"\b(?:not affected|unaffected|not vulnerable|not reproduced|not identified)\b", following, re.I)):
            if route := _narrative_route(narrative, match):
                asserted.add(route)
    if len(asserted) != 1:
        return ""
    selected = next(iter(asserted))
    # Allow a mention of the same origin homepage, but do not select one path
    # when the narrative also cites a different route or another host.
    links = {route for match in _URL_RE.finditer(narrative)
             if (route := _narrative_route(narrative, match))}
    if any(route != selected and (urlsplit(route).netloc != urlsplit(selected).netloc
                                  or urlsplit(route).path != "/") for route in links):
        return ""
    return selected


def is_legacy_web_label(finding: dict[str, Any]) -> bool:
    return _label_like_file(finding) and not any(
        web_route(finding.get(key)) for key in ("url", "endpoint", "file")
    )
