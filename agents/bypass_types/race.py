"""
Race condition / TOCTOU bypass module.

Sends the same request N times simultaneously using asyncio and looks for
inconsistent responses that indicate a race window:

  - Status code variance: some requests return 200, others 400/429
  - Response body differences: balance/count changes between parallel responses
  - Duplicate-action success: e.g., gift card redeemed twice

Common race targets:
  - Gift card / coupon redemption  (send same redeem POST x10)
  - Wallet credits / top-ups       (concurrent deposit + withdraw)
  - One-time tokens                (concurrent use of same token)
  - Rate-limited actions           (bypass per-user limits)
  - File write / rename            (TOCTOU on file operations)

How it works:
  1. Capture baseline (one request)
  2. Send RACE_COUNT identical requests concurrently in a single asyncio gather
  3. Analyse variance in status codes and response bodies
  4. Flag if: >1 unique status code OR >1 unique response body (when not trivially different)
"""

import asyncio
import hashlib
from collections import Counter
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
# Configuration
# ---------------------------------------------------------------------------

RACE_COUNT    = 15   # concurrent duplicate requests
BODY_HASH_LEN = 64   # bytes of response body used for hashing

# ---------------------------------------------------------------------------
# RaceBypass
# ---------------------------------------------------------------------------

class RaceBypass:
    name = "Race Condition"
    description = "TOCTOU / race condition via concurrent duplicate requests"
    requires_param = False

    async def detect(
        self,
        target: str,
        client: httpx.AsyncClient,
        limiter,
    ) -> bool:
        """Always returns True — race probing is applicable to any stateful endpoint."""
        return True

    async def scan(
        self,
        target: str,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
        param: Optional[str] = None,
        method: str = "GET",
        body: Optional[bytes] = None,
        extra_headers: Optional[dict] = None,
    ) -> list[BypassResult]:
        """
        Fire RACE_COUNT identical requests simultaneously.

        Args:
            method:        HTTP method (GET or POST for most race targets)
            body:          Request body bytes (for POST race targets)
            extra_headers: Additional headers (e.g. auth token)
        """
        headers = extra_headers or {}

        # Baseline — single request
        baseline = await self._single(target, method, body, headers, client, sem, limiter)

        # Concurrent burst — all fired together
        coros = [
            self._single(target, method, body, headers, client, sem, limiter)
            for _ in range(RACE_COUNT)
        ]
        responses = await asyncio.gather(*coros, return_exceptions=True)

        return self._analyse(target, baseline, responses, method)

    async def _single(
        self,
        target: str,
        method: str,
        body: Optional[bytes],
        headers: dict,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        limiter,
    ) -> Optional[dict]:
        """Make one request, return {"status": int, "hash": str, "text": str} or None."""
        async with sem:
            try:
                async with limiter.http():
                    resp = await client.request(
                        method,
                        target,
                        content=body,
                        headers=headers,
                    )
                    limiter.adapt_to_response(resp)
                text = resp.text
                h = hashlib.sha256(text[:BODY_HASH_LEN].encode()).hexdigest()[:16]
                return {"status": resp.status_code, "hash": h, "text": text}
            except httpx.RequestError:
                return None

    def _analyse(
        self,
        target: str,
        baseline: Optional[dict],
        responses: list,
        method: str,
    ) -> list[BypassResult]:
        results: list[BypassResult] = []

        good = [r for r in responses if isinstance(r, dict) and r is not None]
        errors = len(responses) - len(good)

        if not good:
            results.append(BypassResult(
                success=False, vuln_type="race", technique="concurrent_burst",
                category="race_condition", payload=f"{method}×{RACE_COUNT}",
                url=target, status_code=0, evidence="",
                note=f"all {RACE_COUNT} requests failed",
            ))
            return results

        baseline_status = baseline["status"] if baseline else None
        baseline_hash   = baseline["hash"]   if baseline else None

        status_counts = Counter(r["status"] for r in good)
        hash_counts   = Counter(r["hash"]   for r in good)

        status_variance = len(status_counts) > 1
        body_variance   = len(hash_counts) > 1

        # Success-variance: some 200, some non-200 (classic race win)
        has_200      = 200 in status_counts or 201 in status_counts
        has_non_2xx  = any(s >= 400 for s in status_counts)
        mixed_status = has_200 and has_non_2xx

        success = mixed_status or (body_variance and has_200)

        evidence_lines = [f"Baseline: HTTP {baseline_status}"]
        evidence_lines.append(f"Race results ({len(good)}/{RACE_COUNT} ok, {errors} errors):")
        for status, count in sorted(status_counts.items()):
            evidence_lines.append(f"  HTTP {status}: {count}×")
        if body_variance:
            evidence_lines.append(f"  Body variants: {len(hash_counts)} unique responses")

        note = ""
        if mixed_status:
            note = "RACE WIN: mixed success/failure → possible duplicate-action exploitation"
        elif body_variance:
            note = "Body variance under concurrent load → investigate for data races"
        elif status_variance:
            note = f"Status variance: {dict(status_counts)}"

        results.append(BypassResult(
            success=success,
            vuln_type="race",
            technique="concurrent_burst",
            category="race_condition",
            payload=f"{method}×{RACE_COUNT}",
            url=target,
            status_code=max(status_counts, key=status_counts.get),
            evidence=" | ".join(evidence_lines),
            note=note,
        ))

        # Individual hit records for each unique response variant
        if success and body_variance:
            seen = set()
            for r in good:
                if r["hash"] not in seen:
                    seen.add(r["hash"])
                    results.append(BypassResult(
                        success=True,
                        vuln_type="race",
                        technique="concurrent_burst",
                        category="response_variant",
                        payload=f"hash:{r['hash']}",
                        url=target,
                        status_code=r["status"],
                        evidence=r["text"][:200],
                        note="unique response body observed during race",
                    ))

        return results
