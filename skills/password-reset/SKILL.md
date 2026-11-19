---
name: password-reset
description: "Test password reset, recovery, and related magic-link/login-code flows for account takeover risks."
---

# Password Reset

Use when testing forgot-password, reset-token, account recovery, email reset, reset-link generation, password-change-by-token, related magic-link/login-code flows, or recovery API behavior.

Treat the reference examples as idea patterns, not a fixed checklist. Adapt them to the target's actual request shape, parser, auth state, and ownership model.

## Load Order

1. Read scope, owned-account context, and `/live-testing-policy`.
2. Confirm every email address, inbox, reset token, target account, and resource is owned or explicitly approved.
3. If a disposable/destructible account is needed, load `/temporary-email`. If Ghost's mailbox is needed, load `/gmail`.
4. Observe a baseline request, delivered link/code behavior, and final redemption/account result when available, without storing raw links, tokens, cookies, passwords, or private email bodies. If a baseline cannot yet be observed, consult the hidden-endpoint ideas in `references/ato-patterns.md` first; do not treat a missing fixture as a negative.
5. Read `references/ato-patterns.md` for technique examples and controls.
6. Route focused lanes:
   - whitespace/encoding, multiple emails, duplicate fields, or lookup-versus-delivery disagreement -> `references/recipient-parsing.md`; use `/bypass` for the observed parser/filter boundary
   - host/header-generated reset links -> `/headers`
   - user/account ID swapping -> `/access-control` or `/idor`
   - reset race or token mix-up -> `/race`
   - CSRF on password reset/change -> `/csrf`
   - parser, encoding, WAF, or filter behavior -> `/bypass`

## Mentality and technique map

The goal is to find a recovery path that sends usable authority to the wrong recipient, affects the wrong account, or bypasses the proof that should protect recovery. Start from the observed function or API and learn enough of its behavior to choose meaningful tests; a complete auth-system map is not a prerequisite. Treat these as idea seeds, not an exhaustive checklist or a payload ceiling:

- **Recipient confusion:** Can account lookup select A while a usable recovery link/code goes to B? Explore observed request forms, JSON objects/arrays, multiple addresses, duplicate fields, field precedence, encodings, and lookup-versus-delivery parsing. Use `references/recipient-parsing.md` for mechanisms, controls, and advanced composition.
- **Link/code construction and binding:** Which observed URL fields or artifact claims identify an account, purpose, transaction, or expiry? Compare a valid owned artifact against a changed selector or another owned account, transaction, or purpose. Do not assume an encoded field can be modified or a signature forged; verify what the server accepts and which account it affects.
- **Proof and final reset:** Does the completion endpoint require and bind the expected proof, or trust a client-supplied identifier, verification state, or skipped step? Compare missing/invalid and valid wrong-context proof using owned fixtures; route a claimed prerequisite to `/assumption-testing`.
- **Lifecycle and alternate paths:** Do issuance, redemption, replay, expiry, email change, session state, or another observed client/API route change what proof is accepted or which account is affected? Route race and token-mix-up questions to `/race`.
- **Delivery and exposure:** Can a generated link be redirected to an owned destination via header trust, or does a valid link leak through browser requests, redirects, or telemetry? Use `/headers` and `references/ato-patterns.md`; an external request without token exposure is not leakage.

When an observed parser, representation, or stack leaves a creative question, use `references/recipient-parsing.md` to derive distinct stage disagreements and use `/bypass` for the actual filter boundary. Consult `research-knowledge-management` for a targeted ResearchMap and, when useful, external source search; research informs hypotheses, not target proof, and is not a per-payload gate.

## Workflow

1. Map the actual flow: request reset or login link/code, receive it, redeem it, inspect the resulting account/session or password change, and check session invalidation when relevant.
2. Identify the trust boundary: email recipient, link/code purpose and account binding, session state, origin/host, rate limit, and final account or password-change target.
3. Test one hypothesis at a time using owned accounts only.
4. Compare baseline vs mutation: recipient, generated link host/path, token account binding, token reuse, response deltas, session invalidation, and email side effects.
5. Stop after minimum proof of cross-account impact, token leakage, token confusion, unauthorized password change, or non-owned data exposure.
6. Route records through `/data-store-guidance`: deliberate comparisons to `/attempt-recording-policy`, observed app behavior to `/map-store`, private candidate chains to `/hypothesis-ledger`, human handoffs to `/bounty-notes`, and proven findings to `/findings`. Use `/bounty-storage` for retained artifacts and the resolved family/lane.

## Proof Standard

Promote only with reproducible evidence that a reset or login-link flow can affect the wrong owned account, leak or redirect a usable token, reuse an expired/used token, bypass account/purpose binding, skip required verification, create a wrong-account session, or perform an unauthorized password change.

Do not promote generic reset email delivery, cosmetic response differences, normal plus-address behavior without account confusion, public metadata, or caller-owned password changes.

## Stop Conditions

Stop before changing a non-owned account password, sending reset mail to non-owned recipients, collecting raw reset links/tokens in chat or reports, brute forcing tokens/codes, lockout-prone retry loops, staff-visible abuse, or exceeding the live-testing policy's race/rate boundaries.

## Evidence

Record full URLs, request method, auth state, owned account aliases, destructible status, mutation class, response/email deltas, token lifecycle result, loaded route skills, and cleanup notes.

Never record raw passwords, cookies, bearer tokens, reset links, reset tokens, email verification links, private email bodies, or mailbox credentials.
