---
name: stored-xss
description: Use when attacker-controlled input is saved and rendered later in a profile, comment, title, notification, admin view, export, email, feed, upload metadata, or other stored render surface.
---

# Stored XSS

Use this lane when the interesting behavior is persistence plus later rendering.

Stored XSS work is two problems: finding the write primitive and finding the
render context. Treat both as first-class evidence.

## Load First

- `xss`
- `live-testing-policy`
- `account-testing-policy` before creating accounts or mutating owned state
- `waf-live-policy` if filtering or sanitizer behavior matters
- `skills/xss/references/payload-selection.md`

## Ownership And Blast Radius

Use owned, disposable, or explicitly approved resources.

Allowed examples:

- owned profile fields
- owned draft/private documents
- owned comments between owned accounts
- owned uploads
- owned notification/invite/comment flows where all recipients are owned

Ask before anything that can hit staff, moderation, support, marketplace/app
review, real users, public feeds, email/SMS/push to non-owned recipients, or
hard-to-clean state.

## Discovery Targets

High-signal stored fields:

- title, name, display name, username
- profile bio/about fields
- comments, reviews, captions, descriptions
- file names and upload metadata
- notification title/body fields
- team/workspace/project names
- saved addresses, labels, tags
- chat/message content between owned accounts
- admin/support/moderation views
- exports, PDFs, emails, and receipts

## Testing Loop

1. Write an inert canary first.
2. Verify persistence at the storage point.
3. Find every render point that shows the canary.
4. Classify each render context separately.
5. Replace the canary with the smallest context-matched payload only when the
   resource, viewer, and cleanup path are owned/approved.
6. Verify in the render location with browser or target-owned checker.
7. Restore/delete/privatize the owned test state when possible.

## Payload Strategy

Stored payloads should be deliberate. A noisy payload can affect future agents,
public surfaces, notifications, or moderation queues.

Use a progression:

1. inert canary
2. context probe containing safe delimiters
3. low-noise execution payload
4. mutation/bypass families only after render context is known

Good stored XSS often comes from downstream consumers:

- safe-looking title becomes notification HTML
- escaped profile field becomes admin `innerHTML`
- filename becomes download page attribute
- markdown becomes sanitized HTML with a bypass
- JSON field becomes email/template HTML
- mobile and desktop render differently

## Multi-Account Proof

For cross-account stored XSS:

- identify sender and recipient aliases
- confirm both are owned
- keep raw cookies/tokens out of notes
- record only account aliases and request metadata
- stop after minimum proof of execution or reachability

## Cleanup

Record:

- object/resource ID or alias
- original value when relevant
- payload value class, not raw secrets
- cleanup action taken
- cleanup verification status

If cleanup fails, note it loudly in the run summary.

## Report

Include:

- write endpoint and field
- render endpoint/view
- viewer role/account
- stored context
- payload and mutation family
- execution proof
- interaction needed
- blast-radius assessment
- cleanup status
