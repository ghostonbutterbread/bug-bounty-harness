---
name: password-reset
description: "Test password reset, forgot-password, reset-token, email reset, and account recovery flows for account takeover risks."
---

# Password Reset

Use when testing forgot-password, reset-token, account recovery, email reset, reset-link generation, password-change-by-token, or recovery API behavior.

Treat the reference examples as idea patterns, not a fixed checklist. Adapt them to the target's actual request shape, parser, auth state, and ownership model.

## Load Order

1. Read scope, owned-account context, and `/live-testing-policy`.
2. Confirm every email address, inbox, reset token, target account, and resource is owned or explicitly approved.
3. If a disposable/destructible account is needed, load `/temporary-email`. If Ghost's mailbox is needed, load `/gmail`.
4. Capture the baseline reset request, reset email/link behavior, and final password-change request without storing raw reset links, tokens, cookies, passwords, or private email bodies.
5. Read `references/ato-patterns.md`.
6. Route focused lanes:
   - host/header-generated reset links -> `/headers`
   - user/account ID swapping -> `/access-control` or `/idor`
   - reset race or token mix-up -> `/race`
   - CSRF on password reset/change -> `/csrf`
   - parser, encoding, WAF, or filter behavior -> `/bypass`

## Workflow

1. Map the flow: request reset, receive link/code, redeem token, change password, invalidate sessions.
2. Identify the trust boundary: email recipient, reset token, account identifier, session state, origin/host, rate limit, and final password-change target.
3. Test one hypothesis at a time using owned accounts only.
4. Compare baseline vs mutation: recipient, generated link host/path, token account binding, token reuse, response deltas, session invalidation, and email side effects.
5. Stop after minimum proof of cross-account impact, token leakage, token confusion, unauthorized password change, or non-owned data exposure.
6. Write evidence under `$HARNESS_SHARED_BASE/{program}/ghost/password-reset/`.

## Proof Standard

Promote only with reproducible evidence that a reset flow can affect the wrong owned account, leak or redirect a reset token, reuse an expired/used token, bypass account binding, skip required verification, or perform an unauthorized password change.

Do not promote generic reset email delivery, cosmetic response differences, normal plus-address behavior without account confusion, public metadata, or caller-owned password changes.

## Stop Conditions

Stop before changing a non-owned account password, sending reset mail to non-owned recipients, collecting raw reset links/tokens in chat or reports, brute forcing tokens/codes, lockout-prone retry loops, staff-visible abuse, or exceeding the live-testing policy's race/rate boundaries.

## Evidence

Record full URLs, request method, auth state, owned account aliases, destructible status, mutation class, response/email deltas, token lifecycle result, loaded route skills, and cleanup notes.

Never record raw passwords, cookies, bearer tokens, reset links, reset tokens, email verification links, private email bodies, or mailbox credentials.
