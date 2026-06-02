# Payment Testing Playbook

Use this after `/payment-testing` has loaded the policy and context pack. The goal is to find backend trust failures in payment workflows without unnecessary charges, fulfillment, or sensitive payment-data exposure.

## First Pass Map

Capture the smallest owned-account flow that shows:

- product, plan, quantity, seats, currency, tax, shipping, fees, discount, and final total
- cart or quote creation
- checkout session creation
- payment processor boundary or zero-dollar finalization
- return, callback, webhook-driven, or confirmation step
- order, invoice, subscription, license, feature, fulfillment, or credit state after checkout
- cancellation, refund, cleanup, or expiration behavior when reachable without risk

Record full URLs and methods, but never record cookies, auth headers, raw cards, payment tokens, or processor secrets.

## Non-Charging Test Order

1. Map and compare read-only checkout state.
2. Use free plan, no-card trial, or zero-dollar checkout if available.
3. Test server-side recomputation by changing owned-account quote/cart fields.
4. Test coupon, credit, gift-card, and balance rules with owned values.
5. Use `temp card $0` only to validate decline handling or processor-boundary behavior.
6. Ask Ryushe before any approval-gated purchase path or risky subscription/fulfillment state.

## Request Comparison

For every modification, keep a baseline request and one changed request.

Useful comparisons:

- UI-generated cart versus direct API cart update
- checkout-session creation versus confirmation/finalization
- zero-dollar checkout versus declined payment
- pre-payment entitlement state versus post-decline state
- coupon apply versus order finalize
- subscription create versus entitlement read
- invoice read/update across two owned accounts

Do not send broad payload lists. Change one field family at a time so the result is attributable.

## Field Families

### Price and Quantity

Check whether the server recomputes:

- `price`, `amount`, `subtotal`, `total`, `tax`, `shipping`, `discount`
- `currency`, `interval`, `billing_period`
- `quantity`, `seats`, `units`, `addons`
- item, price, SKU, package, or plan IDs

Impact requires app-side acceptance or entitlement/order state change, not a local UI difference.

### Payment Result

Check whether the app trusts:

- `paid`, `success`, `complete`, `status`, `payment_status`, `isPaid`
- return URL parameters
- client-side checkout session fields
- externally visible processor IDs without server revalidation

Impact requires order/subscription/entitlement progression after no authorization, decline, or mismatched amount.

### Discounts and Stored Value

Check whether coupons, credits, gift cards, wallets, points, or promo codes can be:

- applied after expiration
- reused when single-use
- over-applied beyond allowed total
- applied to the wrong account, tenant, product, or currency
- raced before balance lock
- used to create negative totals or extra credit

Use only owned discount/value instruments unless Ryushe explicitly provides a test artifact.

### Entitlements

Check whether plan, trial, seat, license, workspace, or paid feature access changes:

- before payment completion
- after payment decline
- after cancellation
- when direct API requests change plan/feature fields
- when subscription/customer IDs from one owned account are swapped into another

Paid feature access without payment is a stop condition and potential finding.

## Processor Boundary Discipline

Do not attack the processor. Test the target application's trust boundary around the processor:

- whether the target creates sessions with correct server-side amount and currency
- whether the target revalidates payment status server-side
- whether return/callback parameters are treated as proof
- whether decline leaves order/subscription/entitlement state clean
- whether webhook-like state can be simulated only within owned app endpoints and non-secret fields

Never brute force, card test, bypass fraud controls, alter raw payment method values, or replay processor secrets.

## Findings Threshold

A strong finding needs:

- full URL and method
- owned account/resource proof
- baseline request/result
- modified request/result with non-secret fields only
- exact backend state change
- payment authorization or decline evidence
- impact: unpaid/underpaid access, extra value, cross-account billing access, duplicate value use, or premature fulfillment
- cleanup status

## Negative Results

Record negative results when they answer a meaningful question:

- server recomputed total correctly
- declined payment did not grant entitlement
- return URL tampering was ignored
- coupon/gift-card balance locked correctly
- direct plan/seat changes were rejected
- invoice/subscription object IDs enforced ownership

Good negative notes prevent future agents from repeating risky payment probes.
