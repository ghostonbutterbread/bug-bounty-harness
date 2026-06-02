# Coupons, Credits, Gift Cards

Use when coupons, credits, gift cards, points, wallets, balances, rewards, or promo codes affect checkout or entitlement state.

## Checks

- Validate product, account, tenant, currency, expiration, first-order, minimum-total, and usage-count restrictions server-side.
- Try only owned or target-provided test instruments.
- Check whether discount math can produce negative totals, extra credit, or over-applied balances.
- Compare apply, preview, checkout-session creation, and finalization endpoints.
- Check whether single-use value is locked before finalization and remains consumed or restored correctly after cancellation/decline.
- For gift cards/store credit, compare balance reads and redemption writes across two owned accounts before considering `/access-control`.

## Race Candidates

Route to `/race` or `race-state.md` when:

- one code/value can be applied twice in parallel
- checkout preview and finalize both consume value
- cancellation or decline restores value inconsistently
- balance lock happens after order state changes

## Evidence Required

- Instrument alias, not raw secret value.
- Starting balance/usage state.
- Endpoint sequence and full URLs.
- Final balance, order total, and entitlement state.
- Whether cancellation/decline restored or consumed value.

## Stop

Stop if testing would use non-owned value, enumerate gift-card numbers, brute force promo codes, exploit public customer codes outside target policy, or create irreversible stored value.
