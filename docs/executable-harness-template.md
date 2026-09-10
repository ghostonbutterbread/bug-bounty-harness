# Executable Harness Template

Use this checklist when writing a hard-coded Python harness, scanner, probe, campaign runner, or deterministic agent module.

This template is for code that performs actions. It is not the template for RAG-style `SKILL.md` files.

## Deterministic Accelerator Contract

Scripts should automate repeatable mechanics without becoming an epistemic
authority over an open-world surface. Separate outputs into:

- **observed facts:** mechanically parsed values with evidence pointers;
- **seed signals:** bounded patterns or classifiers that prioritize agent review;
- **unknowns:** input the script did not understand or coverage it cannot prove.

Any output derived from hardcoded keywords, signatures, regexes, framework
lists, payload lists, or classifiers must carry a machine-readable coverage
record. Keep the shape small and stable:

```json
{
  "method": "deterministic_seed_patterns",
  "exhaustive": false,
  "interpretation": "starting_points_for_agent_review"
}
```

`exhaustive: false` means a miss is unknown—not absence, safety, completion, or
proof that a technology or vulnerability class was fully searched. A positive
seed is also not a finding until an agent or deterministic verifier follows its
evidence to the underlying input.

### Live producer/consumer handoff

Long deterministic runs may overlap with agent review when the script publishes
independent completed units. Write each packet atomically (temporary file then
rename) or announce it through an append-only ready record only after the packet
is complete. Give every worker a disjoint packet/report path. Agents may inspect
ready packets while the producer continues, but must not read half-written
indexes, infer global completion from an in-progress run, or append concurrently
to one shared output.

The script remains responsible for ordering, deduplication, provenance, and run
status. The agent remains responsible for nuance: unfamiliar technology,
computed behavior, semantic dataflow, custom parsers, contextual impact, and
evidence-driven expansion beyond the seed vocabulary.

### Learning loop

Agent discoveries may propose a new deterministic rule, but do not teach the
running script by silently editing its pattern set or accepting the agent claim
as truth. Preserve the triggering evidence, add a focused fixture that fails on
the old behavior, implement the generalized rule, and review it before
promotion. Record false positives and unsupported inputs as first-class tuning
evidence so maintenance improves precision as well as recall.

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

- [ ] Heuristic/signature output is labeled as non-exhaustive seed coverage.
- [ ] Misses cannot be interpreted as absence or completed coverage.
- [ ] Observed facts and seeds retain pointers to the underlying input.
- [ ] Unsupported or unparsed input is surfaced as unknown instead of dropped.
- [ ] Concurrent agent review consumes only atomically finalized, disjoint units.
- [ ] Agent-discovered rules require evidence, a failing fixture, and review before promotion.
- [ ] `ScopeValidator` instantiated and used before processing every target.
- [ ] `RateLimiter` instantiated and `wait()` or `wait_for_host()` called before every request.
- [ ] `adapt_to_response()` called after each response.
- [ ] Output written to the standard `~/Shared/bounty_recon/{program}/` structure.
- [ ] CLI has `--target` and `--program` where applicable.
- [ ] Module docstring explains usage with `python3 {name}.py --target X --program Y`.
- [ ] Tests or dry-run checks cover scope, rate limit, and output behavior touched by the change.
