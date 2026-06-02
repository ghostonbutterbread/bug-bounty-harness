# Client Trust / Request Tampering

Use when payment truth, totals, plans, or entitlements appear in client-controlled requests.

## Checks

- Change one field family at a time: amount/price, currency, quantity/seats, plan/tier, payment status, or entitlement.
- Compare cart/quote update, checkout-session creation, and finalization endpoints. A rejected early mutation may still be trusted later, or the reverse.
- Check whether the server recomputes totals from immutable server-side product/price IDs.
- Check whether `paid`, `success`, `complete`, `status`, `paymentStatus`, `isPaid`, or return URL fields are ignored until server-side payment verification.
- Check whether direct entitlement or license fields are rejected even after a declined payment.

## Safe Mutation Families

- Increase/decrease owned cart quantity within normal UI bounds.
- Switch between visible plan IDs from owned account context.
- Change total/amount/currency by small obvious values to test recomputation.
- Flip boolean/status fields only on owned checkout or order objects.

## Evidence Required

- Baseline request/result and one changed request/result.
- Non-secret modified fields.
- Server response and resulting order/subscription/entitlement state.
- Proof that the backend accepted the mutation, not just the browser UI.

## Stop

Stop before sending destructive changes, triggering fulfillment, or continuing after a paid entitlement appears without confirmed authorization. Route object ownership issues to `/access-control` or `/idor`.
