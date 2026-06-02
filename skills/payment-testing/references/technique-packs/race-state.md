# Race / Payment State

Use when payment-related value or state is consumed, finalized, canceled, or restored across multiple requests.

## Checks

- Identify the state transition first: coupon apply, gift-card redeem, credit consume, order finalize, subscription upgrade, cancellation, refund, or entitlement grant.
- Run a single small owned-resource concurrency test only after baseline behavior is understood.
- Prefer the existing `/race` workflow for execution and evidence capture.
- Confirm duplicated value or inconsistent backend state, not just duplicate HTTP responses.
- Verify cleanup and final balance/entitlement state.

## Race Families

- duplicate coupon or gift-card redemption
- checkout finalization before payment state is locked
- upgrade and cancel in parallel
- refund/cancel and entitlement read/update in parallel
- credit restoration after decline while order still completes

## Evidence Required

- Baseline sequential behavior.
- Concurrent request count and timing summary.
- Final server-side balance/order/subscription/entitlement state.
- Proof of duplicated value, unpaid access, or inconsistent state.

## Stop

Stop if the test risks real money, non-owned value, fulfillment, target instability, repeated payment attempts, or account lockout/risk friction.
