# Workflow And Context-Dependent Access Control

## Related Terms

- context-dependent access control
- workflow bypass
- multi-step authorization bypass
- stale token replay
- one-time link replay
- approval bypass
- checkout step bypass

## Detection Keywords

```text
step, state, status, draft, pending, approved, rejected, expired,
finalize, confirm, approve, redeem, cancel, delete, restore, invite, checkout
```

## Try

- Skip directly to final/finalize/confirm/redeem/approve endpoints.
- Replay stale tokens after ownership, membership, payment, or state changes.
- Reuse one-time links, approval IDs, invite IDs, checkout IDs, and export IDs.
- Submit later workflow steps using another owned account's object data.
- Retry after cancellation, deletion, expiration, logout, or membership removal.

## Proof

Wrong user or wrong state completes a protected transition.

## Stop

Next step would purchase, bill, message, delete, publish, or affect non-owned data.
