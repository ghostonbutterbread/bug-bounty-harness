from __future__ import annotations

from agents.rate_limiter import RateLimiter


def test_new_host_bucket_uses_adapted_rate_after_429_backoff() -> None:
    limiter = RateLimiter(requests_per_second=10, burst=20)

    limiter._handle_429({})
    limiter._handle_429({})
    limiter._handle_429({})

    host_bucket = limiter._host_bucket("api.example.com")

    assert limiter.current_rate() == 5.0
    assert host_bucket.rate == 2.5
