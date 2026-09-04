---
name: credential-exposure-validation
description: Use when in-scope artifacts expose login credentials or a portal needs a bounded default-admin credential check.
---

# Credential Exposure Validation

Use when an in-scope URL, page source, JavaScript bundle, source map, configuration artifact, or target documentation exposes a complete login username/password pair, or when a discovered in-scope portal/admin panel needs a bounded default-admin check.

This skill validates target-disclosed credentials and tiny fixed default-pair sets. It does **not** run wordlists, enumerate users, permute passwords, spray accounts, or stuff third-party credential sets.

## Load Order

1. Read published program rules and scope, then load `general-security-testing-policy`, `live-testing-policy`, and `resource-safety-policy` before a real authentication attempt or local artifact analysis.
2. Read the target artifact with provenance: source URL/path, panel/service association, and in-scope first-party host.
3. Load `attempt-recording-policy` before submitting any credential pair.
4. Use `/js` when JavaScript/source-map evidence produced the credential, and `/analyze-endpoint` when the login request contract needs mapping.

## JavaScript Lens

For JavaScript or source-map evidence, require the loading page/flow, JS URL,
content hash or packet reference, and the nearby login-panel/service association.
Route only a complete username/password pair with that in-scope provenance into
this skill; generic secret-like strings remain `/js` review signals.

## Program-rule distinction

An explicit prohibition on authentication testing, disclosed-credential use, password/default-credential guessing, credential spraying, or traffic against a named panel controls this skill.

A generic "do not brute force" restriction prohibits systematic searching of unknown credential space. It does not prohibit validating a complete username/password pair already exposed by the in-scope target. Respect all stated rate, CAPTCHA, lockout, and panel-specific restrictions.

## Workflow

### Exposed credentials

1. Confirm that a complete username/password pair came from an in-scope target artifact; retain sanitized provenance only. Completion: the pair and candidate login panel are attributable to the program.
2. Submit the disclosed pair once to its named or implied in-scope panel, then once to each relevant in-scope first-party login panel encountered in the application at the allowed normal rate. This is credential validation, not brute force: no password candidates or user list are generated. Completion: every attempted panel has a redacted Attempt outcome.
3. Stop on the first successful authentication, CAPTCHA, 429, lockout signal, or unexpected state. On success, capture only the authenticated landing state or visible account-tier proof; do not navigate, call APIs, read records, change settings, or otherwise operate the account. Completion: minimal proof and stop reason are recorded.

Do not use a disclosed pair against an out-of-scope or third-party service, derive variants, alter the username, or expand it into a general reuse campaign.

### Bounded default-admin checks

1. For a discovered in-scope portal/admin login, prefer a product/version-matched documented default pair when page, JS, headers, or documentation identifies the product. Completion: the source of the default-pair association is recorded.
2. If no product match exists, try no more than three conventional default/admin credential pairs appropriate to that single panel. Submit one pair at a time at the allowed normal rate. Completion: the capped set is exhausted or a stop condition occurs.
3. Stop on success, CAPTCHA, 429, lockout, or unexpected state. Completion: no further pairs are sent after a stop condition.

A fixed set of up to three conventional default/admin pairs on one panel is a bounded default-configuration check. Loading common-password wordlists, iterating passwords, varying users across an account list, retrying through lockout signals, or distributing the same password over many accounts is brute force, spraying, or stuffing and is not part of this skill.

## Evidence and handoff

Write one redacted Attempt per submitted pair. Record the panel, source category (`target-exposed`, `product-default`, or `bounded-default`), source provenance, rate/lockout observation, outcome, minimal successful-auth proof, and stop reason. Never retain raw passwords, tokens, cookies, response bodies, or session material.

Promote a success to the reporting/findings flow as exposed/default credentials with the observed account tier. A successful login proves access; it is not permission for post-login exploration.
