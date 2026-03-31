"""
CORS misconfiguration bypass module.

Tests for common CORS misconfigurations:
  - Origin reflection (any origin accepted)
  - Null origin accepted
  - Subdomain trust (target.com.evil.com)
  - Wildcard with credentials
  - Pre-domain injection (evil.target.com)
  - HTTP downgrade (http: origin on https: target)

Findings:
  - Access-Control-Allow-Origin reflects attacker origin + ACAO-Credentials: true → exploitable
  - ACAO: * — no credentials, but useful for info disclosure
"""

import asyncio
from typing import Optional
from urllib.parse import urlparse

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
            if isinstance(result, Exception):
                results.append(BypassResult(
                    success=False, vuln_type="cors", technique="origin_header",
                    category=category, payload=origin, url=target,
                    status_code=0, evidence="", note=f"error: {result}",
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
                    status_code=0, evidence="", note=f"request_error: {e}",
                )

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        # Exploitable: reflected origin (not wildcard) + credentials: true
        reflected = acao == origin or (origin == "null" and acao == "null")
        wildcard  = acao == "*"
        creds     = acac == "true"

        if reflected and creds:
            success = True
            note = "EXPLOITABLE: reflected origin + credentials=true → CSRF/data theft possible"
        elif wildcard and creds:
            # Per spec this is invalid but some servers do it
            success = True
            note = "EXPLOITABLE: wildcard ACAO + credentials=true (misconfigured)"
        elif reflected:
            success = True
            note = f"origin reflected in ACAO (no credentials header) — info-disclosure"
        elif wildcard:
            success = False
            note = "ACAO: * (no credentials) — low impact"
        else:
            success = False
            note = ""

        evidence = (
            f"ACAO: {acao!r} | ACAC: {acac!r} | HTTP {resp.status_code}"
        )
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
        )
