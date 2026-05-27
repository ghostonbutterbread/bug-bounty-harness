# Executable Harness Template

Use this checklist when writing a hard-coded Python harness, scanner, probe, campaign runner, or deterministic agent module.

This template is for code that performs actions. It is not the template for RAG-style `SKILL.md` files.

## Required Imports

Every live-target harness must import and use both shared safety modules:

```python
from rate_limiter import RateLimiter, create_http_limiter, create_api_limiter, host_from_url
from scope_validator import ScopeValidator, OutOfScopeError, scope_from_campaign
```

## Setup Pattern

```python
# At the top of main() or __init__:

# 1. Scope validator - load from standard file location or campaign state
validator = ScopeValidator(program=args.program)
# OR from campaign state:
# validator = scope_from_campaign(campaign_state)

# 2. Rate limiter - use program-aware factory for HTTP, API factory for external APIs
limiter = create_http_limiter(program=args.program, target=args.target)
crtsh_limiter = create_api_limiter("crt.sh")
otx_limiter = create_api_limiter("otx.alienvault.com")
```

## Before Every HTTP Request

```python
# Scope check - skip out-of-scope targets silently
if not validator.is_in_scope(target):
    print(f"[!] {target} is out of scope, skipping")
    continue

# OR hard-fail mode:
validator.validate_or_fail(target)  # raises OutOfScopeError if not in scope

# Rate limit - blocks until a token is available
limiter.wait()
# OR per-host, recommended for subdomain scanning:
limiter.wait_for_host(host_from_url(url))
```

## Async Pattern

```python
async def fetch(url: str) -> httpx.Response | None:
    if not validator.is_in_scope(url):
        return None

    async with limiter.http():
        async with httpx.AsyncClient(...) as client:
            resp = await client.get(url)
            limiter.adapt_to_response(resp)
            return resp
```

## Filtering Subdomain Lists

```python
# After collecting subdomains from any source:
all_subs = collector.from_crtsh() | collector.from_otx() | ...

# Filter to in-scope only before probing:
in_scope_subs = validator.filter_in_scope(list(all_subs))
print(f"[+] {len(in_scope_subs)}/{len(all_subs)} subs in scope")
```

## Handling 429 Responses

`adapt_to_response()` adjusts the limiter on 429, `Retry-After`, and common rate-limit headers.

```python
resp = requests.get(url)
limiter.adapt_to_response(resp)

if resp.status_code == 429:
    print(f"[!] Rate limited - cooling down for {limiter.cooldown_remaining():.0f}s")
    limiter.wait()
    resp = requests.get(url)
```

## Standard Module Structure

```python
"""
{Agent Name} - {one-line description}.

Usage:
    python3 {module_name}.py --target example.com --program example
"""

# stdlib
import argparse
from pathlib import Path

# harness core
from rate_limiter import create_http_limiter, create_api_limiter, host_from_url
from scope_validator import ScopeValidator, OutOfScopeError

RECON_BASE = Path.home() / "Shared" / "bounty_recon"


def run(target: str, program: str, ...) -> None:
    validator = ScopeValidator(program=program)
    limiter = create_http_limiter(program=program, target=target)

    # agent logic here


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="...")
    p.add_argument("--target", required=True)
    p.add_argument("--program", required=True)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(target=args.target, program=args.program)
```

## Checklist

- [ ] `ScopeValidator` instantiated and used before processing every target.
- [ ] `RateLimiter` instantiated and `wait()` or `wait_for_host()` called before every request.
- [ ] `adapt_to_response()` called after each response.
- [ ] Output written to the standard `~/Shared/bounty_recon/{program}/` structure.
- [ ] CLI has `--target` and `--program` where applicable.
- [ ] Module docstring explains usage with `python3 {name}.py --target X --program Y`.
- [ ] Tests or dry-run checks cover scope, rate limit, and output behavior touched by the change.
