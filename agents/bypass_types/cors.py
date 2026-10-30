"""
CORS misconfiguration bypass module.

Tests for common CORS misconfigurations:
  - Origin reflection (any origin accepted)
  - Null origin accepted
  - Subdomain trust (target.com.evil.com)
  - Wildcard with credentials
  - Pre-domain injection (evil.target.com)
  - HTTP downgrade (http: origin on https: target)

Findings describe CORS header observations, not proven browser access or impact.
Origin control, credentials and sensitive response contents require validation.
"""

import asyncio
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import BypassResult
from agents.bypass_redaction import CORSEvidence

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

# ---------------------------------------------------------------------------
# Test origins
# ---------------------------------------------------------------------------

_EVIL_DOMAIN = "evil-cors-test.com"


def _build_origins(target: str) -> list[tuple[str, str]]:
    """
    Return (category, origin_value) pairs to test against the target.
    """
    parsed = urlparse(target)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    # strip leading "www."
    base = host.removeprefix("www.")

    return [
        ("null_origin",         "null"),
        ("evil_absolute",       f"https://{_EVIL_DOMAIN}"),
        ("evil_http",           f"http://{_EVIL_DOMAIN}"),
        # subdomain of target — pre-domain
        ("pre_domain",          f"https://{_EVIL_DOMAIN}.{base}"),
        # target domain with evil suffix
        ("post_domain",         f"https://{base}.{_EVIL_DOMAIN}"),
        # attacker controls subdomain of target
        ("evil_subdomain",      f"https://evil.{base}"),
        # original scheme downgrade
        ("http_downgrade",      f"http://{host}"),
        # unicode confusion
        ("unicode_dot",         f"https://{base}\u3002{_EVIL_DOMAIN}"),
    ]


# ---------------------------------------------------------------------------
# CORSBypass
# ---------------------------------------------------------------------------

class CORSBypass:
    name = "CORS"
    description = "Cross-Origin Resource Sharing misconfiguration"
    requires_param = False

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Return True if the target sends any ACAO header (CORS is active)."""
        try:
            async with limiter.http():
                resp = await client.options(
                    target,
                    headers={
                        "Origin": f"https://{_EVIL_DOMAIN}",
                        "Access-Control-Request-Method": "GET",
                    },
                )
                limiter.adapt_to_response(resp)
                return "access-control-allow-origin" in resp.headers
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
        results: list[BypassResult] = []
        origins = _build_origins(target)

        coros = [
            self._probe(target, category, origin, client, sem, limiter)
            for category, origin in origins
        ]
        probe_results = await asyncio.gather(*coros, return_exceptions=True)

        for (category, origin), result in zip(origins, probe_results):
            if isinstance(result, (Exception, asyncio.CancelledError)):
                results.append(BypassResult(
                    success=False, vuln_type="cors", technique="origin_header",
                    category=category, payload=origin, url=target,
                    status_code=0, evidence="", note=f"error: {type(result).__name__}",
                ))
            else:
                results.append(result)

        return results

    async def _probe(
        self,
        target: str,
        category: str,
        origin: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> BypassResult:
        async with sem:
            try:
                async with limiter.http():
                    resp = await client.get(
                        target,
                        headers={"Origin": origin},
                    )
                    limiter.adapt_to_response(resp)
            except httpx.RequestError as e:
                return BypassResult(
                    success=False, vuln_type="cors", technique="origin_header",
                    category=category, payload=origin, url=target,
                    status_code=0, evidence="", note=f"request_error: {type(e).__name__}",
                )

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        # Origin equality includes default ports and case-insensitive hostnames.
        def origin_key(value):
            try:
                p = urlparse(value)
                if p.scheme.lower() not in ('http', 'https') or not p.hostname:
                    return None
                host = httpx.URL(value).raw_host.decode('ascii').lower()
                port = p.port if p.port is not None else (443 if p.scheme.lower() == 'https' else 80)
                return (p.scheme.lower(), host, port)
            except (ValueError, UnicodeError, httpx.InvalidURL):
                return None

        reflected = acao == origin or (origin == "null" and acao == "null")
        wildcard  = acao == "*"
        creds     = acac == "true"
        target_key, probe_key = origin_key(target), origin_key(origin)
        same_origin = target_key is not None and target_key == probe_key
        cross_origin = origin == 'null' or (target_key is not None and probe_key is not None and not same_origin)

        conditional = category in {'http_downgrade', 'evil_subdomain', 'pre_domain'}
        incomplete = False
        if reflected and same_origin:
            success = False
            note = "same-origin ACAO; no cross-origin access demonstrated"
        elif reflected and cross_origin and conditional:
            success = False
            incomplete = True
            note = "cross-origin ACAO observed; validate origin control, browser access and sensitive data"
        elif reflected and cross_origin and creds:
            success = True
            note = "cross-origin ACAO with credentials=true; validate origin control, browser access and sensitive data"
        elif wildcard and creds:
            success = False
            note = "wildcard ACAO with credentials=true: browsers reject credentialed access"
        elif reflected and cross_origin:
            success = True
            note = "cross-origin ACAO without credentials; validate browser access and sensitive data"
        elif wildcard:
            success = False
            note = "ACAO: * (no credentials); validate accessible data and impact"
        else:
            success = False
            note = ""

        evidence = CORSEvidence(reflected, wildcard, bool(acao), creds)
        return BypassResult(
            success=success,
            vuln_type="cors",
            technique="origin_header",
            category=category,
            payload=origin,
            url=target,
            status_code=resp.status_code,
            evidence=evidence,
            note=note,
            incomplete=incomplete,
        )
