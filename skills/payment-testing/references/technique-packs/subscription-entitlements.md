# Subscription / Entitlement

Use when checkout controls plans, trials, seats, paid features, workspaces, licenses, renewals, or subscription status.

## Checks

- Compare feature access before checkout, after checkout-session creation, after decline, after zero-dollar completion, and after cancellation.
- Verify direct API changes to `plan`, `tier`, `seats`, `trial`, `interval`, `status`, `expiresAt`, or feature flags are rejected or recomputed.
- Check downgrade/upgrade boundaries: paid feature access should match active paid state, not stale UI or pending checkout state.
- Check workspace/team scope: seat increases, owner/admin features, or paid workspace actions should enforce account and tenant boundaries.
- Check renewal/cancellation state only on disposable or clearly owned test subscriptions.

## Evidence Required

- Plan, seat count, interval, and account/workspace alias.
- Payment or zero-dollar state.
- Feature/entitlement read endpoint and visible app behavior.
- Cleanup/cancel status.

## Stop

Stop if the flow requires a non-cancelable subscription, team-wide entitlement changes on a real workspace, vendor review, unclear renewal obligations, or paid activation without confirmed payment.
