# Zero-Dollar Checkout

Use when a legitimate path can bring total to `$0` through free plans, coupons, credits, gift cards, trials, or promotions.

## Checks

- Confirm the server, not the browser, computes final total.
- Verify tax, shipping, fees, and minimum-order rules still apply.
- Complete only zero-dollar checkout that does not trigger paid authorization, fulfillment, shipment, invoice finalization, human review, or non-reversible entitlement.
- Compare order, invoice, subscription, license, and feature state before and after completion.
- Try one bounded direct API mismatch on owned resources: alter total, discount, quantity, or plan and check whether the server rejects or recomputes it.

## Evidence Required

- Baseline total and final total.
- Full checkout and confirmation URLs/methods.
- Discount/credit/gift-card alias or promo code alias, not secret material.
- App state after completion.
- Cleanup/cancel status if a subscription/trial was created.

## Stop

Stop if checkout requires paid authorization, triggers fulfillment, creates a paid invoice, changes a non-disposable account globally, or creates an unclear renewal/cancellation obligation.
