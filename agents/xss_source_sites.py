"""Bounded, non-exhaustive named user-input source seeds in JavaScript text.

Source-side twin of :mod:`agents.xss_sink_sites`. These signatures name *places
where attacker-influenceable input enters* (URL params, hash, cookies, storage,
dataset attributes, route params, postMessage, form fields), not attacker
control, a reachable sink, or browser proof. Consumers join source hits against
``scan_sink_sites`` output per artifact to prioritize review.

Captured ``name`` groups are the review payload: reflection testing is
name-keyed on legacy/JSP renderers, so a census that probes random parameter
names is structurally blind there.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class SiteRule:
    signature: str
    family: str
    tier: str  # url, cookie, storage, dom-data, form, route, postmessage
    pattern: re.Pattern[str]
    needles: tuple[str, ...]
    name_group: int  # which regex group carries the captured name (0 = whole match)


def rule(signature: str, family: str, tier: str, pattern: str, *needles: str,
         name_group: int = 1, flags: int = 0) -> SiteRule:
    return SiteRule(signature, family, tier, re.compile(pattern, flags), needles, name_group)


_NAME = r"[A-Za-z0-9_.\-\[\]]{1,64}"
# Receivers that plausibly hold a URLSearchParams-like object.
_QS_RECV = r"(?:searchParams|queryParams|urlParams|urlSearchParams|params|usp|qs|sp|query)"

SOURCE_RULES: tuple[SiteRule, ...] = tuple([
    # -- URL query parameters -------------------------------------------------
    rule("URLSearchParams-receiver.get(NAME)", "url_param", "url",
         rf"(?<![A-Za-z0-9_$]){ _QS_RECV }\s*\.\s*(?:get|getAll|has)\(\s*['\"]({_NAME})['\"]\s*\)",
         ".get(", name_group=1),
    rule("new URLSearchParams(...).get(NAME)", "url_param", "url",
         rf"new\s+URLSearchParams\s*\([^)]{{0,160}}\)\s*\.\s*(?:get|getAll|has)\(\s*['\"]({_NAME})['\"]\s*\)",
         "new URLSearchParams", name_group=1),
    rule("legacy-getQueryString(NAME)", "url_param", "url",
         rf"\b(?:getQueryString|getQueryParam|getParameter|getUrlParam|getParam)\(\s*['\"]({_NAME})['\"]\s*\)",
         "get", name_group=1, flags=re.IGNORECASE),
    rule("router-query.NAME", "url_param", "url",
         rf"\b(?:route|router|req)\s*\.\s*query\s*(?:\.\s*|\[\s*['\"])({_NAME})(?:['\"]\s*\])?",
         "query", name_group=1),
    rule("useSearchParams().get(NAME)", "url_param", "url",
         rf"\buseSearchParams\s*\(\s*\)\s*\.\s*(?:get|getAll|has)\(\s*['\"]({_NAME})['\"]\s*\)",
         "useSearchParams", name_group=1),

    # -- URL fragment ----------------------------------------------------------
    rule("location.hash-read", "url_fragment", "url",
         r"location\s*\.\s*hash\b(?!\s*(?:(?:&&|\|\||\?\?|[+\-*/%&|^?])?=(?!=|>)|\+\+|--))",
         "location", "hash", name_group=0),

    # -- cookies ----------------------------------------------------------------
    rule("Cookies.get(NAME)", "cookie", "cookie",
         rf"\b(?:Cookies|cookies|jsCookie|cookieStore)\s*\.\s*(?:get|read)\(\s*['\"]({_NAME})['\"]\s*\)",
         "ookie", name_group=1),
    rule("getCookie(NAME)", "cookie", "cookie",
         rf"\b(?:getCookie|readCookie|get_cookie)\(\s*['\"]({_NAME})['\"]\s*\)",
         "ookie", name_group=1, flags=re.IGNORECASE),

    # -- web storage --------------------------------------------------------------
    rule("sessionStorage.getItem(KEY)", "web_storage", "storage",
         rf"sessionStorage\s*\.\s*getItem\s*\(\s*['\"]([A-Za-z0-9_.\-]{{2,80}})['\"]\s*\)",
         "sessionStorage", name_group=1),
    rule("localStorage.getItem(KEY)", "web_storage", "storage",
         rf"localStorage\s*\.\s*getItem\s*\(\s*['\"]([A-Za-z0-9_.\-]{{2,80}})['\"]\s*\)",
         "localStorage", name_group=1),

    # -- DOM data attributes -------------------------------------------------------
    rule("dataset.NAME-read", "dom_data", "dom-data",
         r"\.\s*dataset\s*\.\s*([A-Za-z][A-Za-z0-9_]{2,48})\b(?!\s*=)",
         "dataset", name_group=1),
    rule("getAttribute(data-NAME)", "dom_data", "dom-data",
         rf"\.\s*getAttribute\s*\(\s*['\"]data-([a-z0-9\-]{{2,48}})['\"]\s*\)",
         "data-", name_group=1),

    # -- router / route params --------------------------------------------------------
    rule("route-params.NAME", "route_param", "route",
         rf"\b(?:params|match\.params)\s*\.\s*(?!get\b|getAll\b|has\b|set\b|keys\b|values\b|entries\b|forEach\b|length\b)([A-Za-z][A-Za-z0-9_]{{2,48}})\b(?!\s*=)",
         "params", name_group=1),

    # -- form data -----------------------------------------------------------------
    rule("FormData.get(NAME)", "form_field", "form",
         rf"(?:\b(?:formData|fd)|new\s+FormData\s*\([^)]{{0,120}}\))\s*\.\s*(?:get|getAll|has)\(\s*['\"]({_NAME})['\"]\s*\)",
         "FormData", name_group=1),

    # -- postMessage ------------------------------------------------------------------
    rule("message-listener", "postmessage", "postmessage",
         r"addEventListener\s*\(\s*['\"]message['\"]",
         "addEventListener", "message", name_group=0),

    # -- window.name --------------------------------------------------------------
    rule("window.name-read", "dom_data", "dom-data",
         r"(?<![\w.])window\s*\.\s*name\b(?!\s*=)", "window", "name", name_group=0),
])

_NEEDLE_FREE = frozenset(r.signature for r in SOURCE_RULES if not r.needles)
# Receivers can appear under several names; search each as its own anchor.
_QS_ANCHORS = ("searchParams", "queryParams", "urlParams", "urlSearchParams", "params", "usp", "qs", "sp", "query")
_QS_RULE = "URLSearchParams-receiver.get(NAME)"
_QS_SUFFIX_RE = re.compile(r"\s*\.\s*(?:get|getAll|has)\s*\(")


def scan_source_sites(text: str, *, max_hits: int = 300, per_rule: int = 64) -> dict:
    """Find bounded named-source offsets in one artifact. Offsets are Unicode
    character indices. Mirrors :func:`agents.xss_sink_sites.scan_sink_sites`."""
    if max_hits < 1 or per_rule < 1:
        raise ValueError("source-site limits must be positive")
    hits: list[dict] = []
    truncated = False
    for item in SOURCE_RULES:
        if item.signature == _QS_RULE:
            if not any(anchor in text for anchor in _QS_ANCHORS):
                continue
            anchors: tuple[str, ...] = _QS_ANCHORS
        elif item.signature == "FormData.get(NAME)":
            anchors = ("FormData", "formData", "fd")
        elif item.signature not in _NEEDLE_FREE and not all(needle in text for needle in item.needles):
            continue
        elif item.signature == "location.hash-read":
            anchors = ("hash",)
        else:
            anchors = (max(item.needles, key=len),)
        seen: set[tuple[int, int]] = set()
        windows = 0
        for anchor in anchors:
            position = 0
            while (position := text.find(anchor, position)) != -1:
                if item.signature == _QS_RULE and not _QS_SUFFIX_RE.match(text, position + len(anchor)):
                    position += len(anchor)
                    continue
                windows += 1
                if windows > 10_000:
                    truncated = True
                    break
                begin = max(0, position - 600)
                fragment = text[begin:min(len(text), position + 400)]
                for match in item.pattern.finditer(fragment):
                    start, end = begin + match.start(), begin + match.end()
                    if not (start <= position < end) or (start, end) in seen:
                        continue
                    seen.add((start, end))
                    raw_name = match.group(item.name_group) if item.name_group else item.signature
                    hits.append({"signature": item.signature, "family": item.family,
                                 "tier": item.tier, "name": raw_name,
                                 "start": start, "end": end})
                if len(seen) > per_rule:
                    truncated = True
                    break
                position += len(anchor)
            if windows > 10_000 or len(seen) > per_rule:
                break
        if len(seen) > per_rule:
            del hits[-(len(seen) - per_rule):]
    hits.sort(key=lambda h: (h["start"], h["signature"]))
    if len(hits) > max_hits:
        truncated = True
        del hits[max_hits:]
    return {"hits": hits, "truncated": truncated}
