"""
Rate Limiter — Token bucket + sliding window rate limiting for all harnesses.

Usage:
    from rate_limiter import RateLimiter, create_http_limiter, create_api_limiter

    # General usage
    limiter = RateLimiter(requests_per_second=10, burst=20)
    limiter.wait()
    requests.get(url)

    # Per-host limiting
    limiter.wait_for_host("api.example.com")
    requests.get("https://api.example.com/endpoint")

    # Async HTTP context manager
    async with limiter.http():
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            limiter.adapt_to_response(resp)

    # Pre-configured API limiters
    limiter = create_api_limiter("crt.sh")
    limiter = create_http_limiter(program="superdrug", target="api.superdrug.com")
"""

import asyncio
import random
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------

class _TokenBucket:
    """
    Thread-safe token bucket.

    Tokens accumulate at `rate` per second up to `capacity`.
    Each consume() call takes one token, blocking until one is available.
    """

    def __init__(self, rate: float, capacity: int):
        self._rate = max(rate, 0.001)       # tokens per second
        self._capacity = max(capacity, 1)
        self._tokens: float = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time (call under lock)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._capacity),
            self._tokens + elapsed * self._rate,
        )
        self._last_refill = now

    def consume(self, jitter: bool = True) -> None:
        """
        Block until a token is available, then consume one.
        Adds small random jitter to avoid thundering herd.
        """
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # How long until next token
                wait_s = (1.0 - self._tokens) / self._rate

            # Add jitter: ±10% of wait time
            if jitter and wait_s > 0:
                wait_s *= 1.0 + random.uniform(-0.1, 0.1)

            time.sleep(max(0.001, wait_s))

    async def consume_async(self, jitter: bool = True) -> None:
        """Async version of consume — yields to event loop while waiting."""
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_s = (1.0 - self._tokens) / self._rate

            if jitter and wait_s > 0:
                wait_s *= 1.0 + random.uniform(-0.1, 0.1)

            await asyncio.sleep(max(0.001, wait_s))

    def set_rate(self, new_rate: float) -> None:
        """Adjust the rate (e.g. after detecting a 429)."""
        with self._lock:
            self._refill()
            self._rate = max(new_rate, 0.001)

    @property
    def rate(self) -> float:
        return self._rate


# ---------------------------------------------------------------------------
# Main RateLimiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Token bucket rate limiter for API calls and HTTP requests.

    Features:
    - Token bucket algorithm (smooth, allows controlled bursts)
    - Per-host sub-limiters (prevents hammering a single host)
    - Auto-adapts from 429 / Retry-After / X-RateLimit-* headers
    - Jitter to avoid thundering herd
    - Thread-safe; async support via http() context manager
    - Cooldown state after repeated 429s

    Usage:
        limiter = RateLimiter(requests_per_second=10, burst=20)

        # Blocking sync call
        limiter.wait()
        requests.get(url)

        # Async context manager
        async with limiter.http():
            resp = await client.get(url)
            limiter.adapt_to_response(resp)

        # Per-host
        limiter.wait_for_host("api.example.com")
    """

    def __init__(self, requests_per_second: float = 10, burst: int = 20):
        self._rps = requests_per_second
        self._burst = burst
        self._bucket = _TokenBucket(rate=requests_per_second, capacity=burst)

        # Per-host buckets: host -> _TokenBucket
        self._host_buckets: dict[str, _TokenBucket] = {}
        self._host_lock = threading.Lock()

        # Cooldown tracking after 429 storms
        self._cooldown_until: float = 0.0
        self._cooldown_lock = threading.Lock()
        self._consecutive_429s: int = 0

    # ── Blocking sync ─────────────────────────────────────────────────────

    def wait(self) -> None:
        """Blocking wait for a global token. Call before every request."""
        self._wait_cooldown()
        self._bucket.consume()

    def wait_for_host(self, host: str) -> None:
        """
        Per-host rate limiting. Waits on both the global bucket and a
        per-host bucket (capped at half the global rate to be safe).
        """
        self._wait_cooldown()
        self._bucket.consume()
        self._host_bucket(host).consume()

    def _wait_cooldown(self) -> None:
        """Block until any active cooldown period expires."""
        with self._cooldown_lock:
            remaining = self._cooldown_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    # ── Async context manager ─────────────────────────────────────────────

    @asynccontextmanager
    async def http(self):
        """
        Async context manager for HTTP requests with rate limiting.

        Example:
            async with limiter.http():
                resp = await client.get(url)
                limiter.adapt_to_response(resp)
        """
        # Async cooldown
        with self._cooldown_lock:
            remaining = self._cooldown_until - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)

        await self._bucket.consume_async()
        yield

    # ── Response adaptation ───────────────────────────────────────────────

    def adapt_to_response(self, response) -> None:
        """
        Auto-detect rate limits from response headers and status codes.

        Detects:
        - 429 Too Many Requests → exponential backoff
        - Retry-After header (seconds or HTTP date)
        - X-RateLimit-Remaining: 0 → slow down
        - X-RateLimit-Limit / X-RateLimit-Reset → recalculate rate
        - Cloudflare 503 / cf-ray header → short cooldown
        """
        if response is None:
            return

        status = getattr(response, "status_code", None)
        headers = getattr(response, "headers", {}) or {}

        # Normalise header keys to lowercase
        h = {k.lower(): v for k, v in headers.items()}

        if status == 429:
            self._handle_429(h)
        elif status in (503, 520, 521, 522, 524):
            # Cloudflare / upstream down
            if "cf-ray" in h or "server" in h and "cloudflare" in h.get("server", "").lower():
                self._apply_cooldown(15.0)
        else:
            # Successful response — reset consecutive 429 counter
            with self._cooldown_lock:
                self._consecutive_429s = 0

        # Check X-RateLimit-Remaining
        remaining_str = h.get("x-ratelimit-remaining", "")
        if remaining_str.isdigit() and int(remaining_str) == 0:
            reset_str = h.get("x-ratelimit-reset", "")
            if reset_str.isdigit():
                reset_at = float(reset_str)
                now = time.time()
                wait = max(0, reset_at - now + 1.0)
                if 0 < wait < 120:
                    self._apply_cooldown(wait)

        # Dynamically adjust rate if X-RateLimit-Limit present
        limit_str = h.get("x-ratelimit-limit", "")
        if limit_str.isdigit():
            declared_limit = int(limit_str)
            # Use 80% of declared limit as our target rate (safety margin)
            safe_rps = declared_limit * 0.8 / 60.0  # assuming per-minute
            if safe_rps > 0:
                self._bucket.set_rate(safe_rps)

    def _handle_429(self, headers: dict) -> None:
        """Handle a 429 response — parse Retry-After or apply exponential backoff."""
        with self._cooldown_lock:
            self._consecutive_429s += 1
            count = self._consecutive_429s

        retry_after = headers.get("retry-after", "")
        if retry_after:
            try:
                wait = float(retry_after)
                self._apply_cooldown(wait)
                return
            except ValueError:
                # HTTP-date format — try to parse
                try:
                    from email.utils import parsedate_to_datetime
                    from datetime import timezone as _tz
                    dt = parsedate_to_datetime(retry_after)
                    wait = max(0, (dt.replace(tzinfo=_tz.utc).timestamp() - time.time()))
                    self._apply_cooldown(wait)
                    return
                except Exception:
                    pass

        # Exponential backoff: 5s, 10s, 20s, 40s … capped at 120s
        wait = min(5.0 * (2 ** (count - 1)), 120.0)
        # Add 10% jitter
        wait *= 1.0 + random.uniform(0, 0.1)
        self._apply_cooldown(wait)

        # Also halve the current rate permanently after 3+ consecutive 429s
        if count >= 3:
            new_rate = max(self._bucket.rate / 2.0, 0.1)
            self._bucket.set_rate(new_rate)

    def _apply_cooldown(self, seconds: float) -> None:
        """Set a cooldown period, extending if one is already active."""
        target = time.monotonic() + seconds
        with self._cooldown_lock:
            if target > self._cooldown_until:
                self._cooldown_until = target

    # ── Per-host buckets ──────────────────────────────────────────────────

    def _host_bucket(self, host: str) -> _TokenBucket:
        """Get or create a per-host bucket, capped at half the global rate."""
        host = host.lower().split(":")[0]  # strip port
        with self._host_lock:
            if host not in self._host_buckets:
                host_rate = max(self._rps / 2.0, 0.5)
                self._host_buckets[host] = _TokenBucket(
                    rate=host_rate,
                    capacity=max(self._burst // 2, 2),
                )
            return self._host_buckets[host]

    # ── Introspection ─────────────────────────────────────────────────────

    def is_cooling_down(self) -> bool:
        with self._cooldown_lock:
            return time.monotonic() < self._cooldown_until

    def cooldown_remaining(self) -> float:
        with self._cooldown_lock:
            return max(0.0, self._cooldown_until - time.monotonic())

    def current_rate(self) -> float:
        return self._bucket.rate

    def __repr__(self) -> str:
        cd = self.cooldown_remaining()
        return (
            f"RateLimiter(rps={self._bucket.rate:.2f}, burst={self._burst}, "
            f"cooldown={cd:.1f}s)"
        )


# ---------------------------------------------------------------------------
# Factory: per-program HTTP limiter
# ---------------------------------------------------------------------------

# Default conservative limits — adjust per program rules
_PROGRAM_DEFAULTS: dict[str, dict] = {
    "default": {"rps": 5.0,  "burst": 10},
    "hackerone": {"rps": 2.0,  "burst": 5},
    "bugcrowd":  {"rps": 2.0,  "burst": 5},
}


def create_http_limiter(program: str = "default", target: str = "") -> RateLimiter:
    """
    Create a RateLimiter configured for a specific bug bounty program.

    Programs can define custom limits. Falls back to conservative defaults
    if the program is unknown.

    Args:
        program: Program slug (e.g. "superdrug", "hackerone")
        target:  Target hostname — used for logging only

    Returns:
        RateLimiter instance
    """
    cfg = _PROGRAM_DEFAULTS.get(program.lower(), _PROGRAM_DEFAULTS["default"])
    return RateLimiter(
        requests_per_second=cfg["rps"],
        burst=cfg["burst"],
    )


# ---------------------------------------------------------------------------
# Factory: pre-configured API limiters
# ---------------------------------------------------------------------------

# Known API rate limits (requests/second)
_API_LIMITS: dict[str, dict] = {
    "crt.sh":              {"rps": 10.0,  "burst": 20},
    "crtsh":               {"rps": 10.0,  "burst": 20},
    "urlscan.io":          {"rps": 5.0,   "burst": 10},
    "urlscan":             {"rps": 5.0,   "burst": 10},
    "otx.alienvault.com":  {"rps": 20.0,  "burst": 40},
    "otx":                 {"rps": 20.0,  "burst": 40},
    "alienvault":          {"rps": 20.0,  "burst": 40},
    "bufferover":          {"rps": 10.0,  "burst": 20},
    "dns.bufferover.run":  {"rps": 10.0,  "burst": 20},
    "whoxy":               {"rps": 2.0,   "burst": 5},   # varies by plan
    "whoxy.com":           {"rps": 2.0,   "burst": 5},
    "shodan":              {"rps": 1.0,   "burst": 3},
    "shodan.io":           {"rps": 1.0,   "burst": 3},
    "censys":              {"rps": 2.0,   "burst": 5},
    "censys.io":           {"rps": 2.0,   "burst": 5},
    "virustotal":          {"rps": 0.25,  "burst": 4},   # 4 req/min free tier
    "virustotal.com":      {"rps": 0.25,  "burst": 4},
    "securitytrails":      {"rps": 2.0,   "burst": 5},
    "wayback":             {"rps": 5.0,   "burst": 10},
    "web.archive.org":     {"rps": 5.0,   "burst": 10},
    "rdap":                {"rps": 10.0,  "burst": 20},
    "rdap.org":            {"rps": 10.0,  "burst": 20},
    "hackertarget":        {"rps": 1.0,   "burst": 3},
    "hackertarget.com":    {"rps": 1.0,   "burst": 3},
}


def create_api_limiter(api_name: str) -> RateLimiter:
    """
    Return a pre-configured RateLimiter for a known API.

    Known APIs:
        crt.sh          → 10 req/s
        urlscan.io      → 5 req/s
        otx.alienvault  → 20 req/s
        bufferover      → 10 req/s
        whoxy           → 2 req/s  (varies by plan)
        shodan          → 1 req/s
        censys          → 2 req/s
        virustotal      → 0.25 req/s (free tier)
        securitytrails  → 2 req/s
        wayback         → 5 req/s

    Falls back to a conservative 2 req/s for unknown APIs.

    Args:
        api_name: API name or hostname (case-insensitive)

    Returns:
        RateLimiter instance
    """
    key = api_name.lower().strip()
    cfg = _API_LIMITS.get(key, {"rps": 2.0, "burst": 5})
    return RateLimiter(
        requests_per_second=cfg["rps"],
        burst=cfg["burst"],
    )


# ---------------------------------------------------------------------------
# Convenience: extract host from URL
# ---------------------------------------------------------------------------

def host_from_url(url: str) -> str:
    """Extract hostname from a URL string."""
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
