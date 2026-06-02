# Processor Boundary

Use when a card form, hosted checkout, setup intent, payment intent, return URL, callback, webhook-like endpoint, or decline path is visible.

## Boundary Rule

Test the target app's trust in processor results. Do not attack the processor, card network, bank, fraud controls, or payment method values.

## Checks

- Verify checkout sessions are created server-side with the expected amount, currency, item, customer, and metadata.
- Verify app confirmation requires server-side processor status, not client-side `success` or return URL parameters.
- Use `temp card $0` only for one bounded decline-path hypothesis when policy permits.
- After decline, check order, invoice, subscription, license, fulfillment, and entitlement state.
- Check whether a processor ID from one owned checkout can be reused with another owned checkout only when non-secret and target-side.
- Check whether client-return endpoints ignore tampered `status`, `paid`, `session_id`, `payment_intent`, and similar parameters unless server verification succeeds.

## Evidence Required

- Processor boundary reached: hosted checkout, card validation, decline, authorization, or no-card zero-dollar path.
- Target app request/result around the boundary.
- App state after return/callback.
- Confirmation that no raw payment token or card detail was recorded.

## Stop

Stop on fraud/risk/CAPTCHA/issuer friction, unexpected successful payment on `temp card $0`, repeated failure temptation, or any need to manipulate raw processor secrets or payment method data.
