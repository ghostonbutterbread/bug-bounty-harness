---
name: race
description: Test for race conditions and concurrent workflow flaws
---
# Race Condition Testing

Test for race conditions, state desynchronization, and concurrent workflow flaws.

## Common Targets

- Coupon redemption, gift card claims, referral credits
- Balance transfers, withdrawals, refunds, checkout flows
- Inventory reservation, seat booking, stock decrement
- Password reset or email/phone verification flows
- Invite acceptance, one-time links, single-use tokens
- Admin approval queues, role changes, feature unlocks

## Testing Patterns

### Single-use token reuse
Send the same redeem/confirm/claim request concurrently. Check whether the token is accepted more than once before invalidation propagates.

### Limit bypass
Fire concurrent requests against an action with a per-user or per-resource limit. Check whether each worker passes the pre-check before any write commits.

### TOCTOU (Time-of-Check-Time-of-Use)
Trigger a check and a state-changing request at the same time. Look for stale authorization or stale balance/inventory decisions.

### Multi-endpoint workflow races
Overlap steps like `create`, `confirm`, `cancel`, `refund`, or `approve`. Test conflicting transitions in both orders.

## Workflow

1. **Map the stateful action** — Find the exact request that consumes a token, spends a balance, reserves an item
2. **Establish baseline** — Send request once, capture normal response
3. **Identify race windows** — Look for client-side gating, delayed polling, multi-request workflows
4. **Reproduce with concurrency** — Replay same request in parallel (2-5 concurrent first)
5. **Confirm impact** — Check whether state changed more than once or became inconsistent
6. **Document** — Record exact prerequisites, request count, timing, and observable impact

## Tools

```bash
# Parallel curl for race testing
for i in {1..5}; do curl -X POST "https://target.com/api/claim" & done; wait

# Or use Python
python3 -c "import concurrent.futures; [print(i) for i in range(5)]"
```

## Evidence Checklist

- Target endpoint(s) and full stateful action being tested
- Preconditions required for the race
- Number of concurrent requests and timing approach
- Expected result versus actual result
- Proof of duplicated or inconsistent state change

## Stop Conditions

- Stop if behavior risks irreversible financial impact or harms real user data
- Stop if the only effect is duplicate responses with no duplicated state change
- Stop if target becomes unstable

---

## Files

- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/race/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
