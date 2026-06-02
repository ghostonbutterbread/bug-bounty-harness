---
name: payment-testing
description: "Route checkout, billing, subscriptions, coupons, credits, gift cards, invoices, refunds, payment authorization, and paid-entitlement testing into safe zero-dollar-first workflows."
---

# Payment Testing

Use for checkout, billing, subscriptions, invoices, coupons, gift cards, credits, refunds, payment authorization, payment processor boundaries, and paid entitlement workflows.

This is a payment workflow router. Most tests should stop before a real purchase: map the flow, reach the processor boundary when needed, and verify what the backend trusts after decline, zero-dollar checkout, or owned-account state changes.

## Load Order

1. Read scope, owned-account context, and active live-testing policy.
2. Read `/payment-testing-policy` before touching payment forms, payment methods, purchases, subscriptions, refunds, credits, gift cards, invoices, or entitlements.
3. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
4. Read `$HARNESS_ROOT/prompts/payment-testing-context-pack.md`.
5. Read only the focused technique pack matching observed behavior:
   - cart total can reach `$0` -> `zero-dollar.md`
   - request has `paid`, `success`, `status`, `price`, `currency`, `amount`, `quantity`, `plan`, `seats`, or entitlement fields -> `client-trust.md`
   - coupon, credit, promo, gift card, wallet, points, or store balance -> `coupons-credits-gift-cards.md`
   - plan, trial, subscription, renewal, seat, feature flag, or paid workspace entitlement -> `subscription-entitlements.md`
   - card form, setup intent, payment intent, hosted checkout, webhook-like callback, or decline path -> `processor-boundary.md`
   - refund, cancellation, invoice, receipt, tax, shipping, or fulfillment state -> `refunds-invoices.md`
   - duplicate submit, concurrent redeem, finalize, or state transition -> `race-state.md`
6. Load `$HARNESS_ROOT/prompts/payment-testing-playbook.md` for full workflow mapping, stuck analysis, or report writing.
7. Route cross-skill work instead of duplicating it:
   - one live request capture or intercept -> `/single-request-grabber`
   - access control, customer/invoice/subscription object ownership -> `/access-control` or `/idor`
   - concurrency -> `/race`
   - header/method/path tricks -> `/headers` or `/bypass`

## Workflow

1. Identify the cheapest non-charging path that answers the hypothesis.
2. Capture the full flow with owned accounts/resources: cart, quote, checkout session, payment boundary, confirmation, entitlement, invoice, and cleanup.
3. Classify one lane from the context pack and load one technique pack.
4. Test backend validation by modifying owned-account requests, never by forcing real fraud or card testing.
5. Stop at the first proof or stop condition, then write a handoff/result card.

## Proof Standard

Promote only when evidence shows a real backend trust failure: unpaid or underpaid entitlement, total manipulation accepted server-side, coupon/credit/gift-card balance abuse, cross-account billing object access, duplicate redemption, refund/credit abuse, or order/subscription state advanced without valid authorization.

Do not promote UI-only price changes, localStorage-only state, processor-hosted declines without app impact, public invoices, owned-account-only expected access, or speculation from response wording.

## Stop Conditions

Stop and ask Ryushe if the next step would spend money, authorize more than policy allows, trigger fulfillment, modify a non-disposable subscription, contact support/vendor review, touch non-owned billing data, repeat failed card attempts, test fraud/risk controls, or require raw card/token material in prompts or logs.

Stop immediately if paid entitlement appears without confirmed payment authorization, a non-owned payment object appears, or `temp card $0` unexpectedly succeeds.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/payment-testing/`.

Record:
- owned account/resource aliases and destructible status
- full URL, method, auth state, and timestamp
- item, plan, quantity, currency, price, coupon, credit, gift-card, or subscription fields tested
- loaded technique pack
- original request shape and non-secret modified fields
- processor boundary reached and decline/authorization/zero-dollar result
- entitlement, invoice, order, fulfillment, or cleanup state
- stop condition and next safe test

Never record raw card numbers, CVV, expiry, billing address, payment tokens, processor secrets, cookies, auth headers, or screenshots containing payment details.
