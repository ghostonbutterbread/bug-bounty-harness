---
name: credential-exposure-validation
description: Use when in-scope artifacts expose login credentials or a portal needs a bounded default-admin credential check.
---

# Credential Exposure Validation

Use when an in-scope URL, page source, JavaScript bundle, source map, configuration artifact, or target documentation exposes a complete login username/password pair. Also trigger immediately when mapping reaches an in-scope admin, claim, portal, or other privileged login panel.

This skill validates target-disclosed credentials and runs a capped default-admin credential campaign on discovered privileged panels. It does **not** enumerate users, permute unbounded passwords, spray an account list, or stuff third-party credential sets.

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

An explicit prohibition on authentication testing, disclosed-credential use, password/default-credential guessing, credential spraying/brute force, or traffic against a named panel controls this skill. A panel-specific restriction wins over a general program allowance.

A generic "do not brute force" restriction prohibits systematic searching of unknown credential space. It does not prohibit validating a complete username/password pair already exposed by the in-scope target. Respect all stated rate, CAPTCHA, lockout, and panel-specific restrictions.

## Workflow

### Exposed credentials

1. Confirm that a complete username/password pair came from an in-scope target artifact; retain sanitized provenance only. Completion: the pair and candidate login panel are attributable to the program.
2. Submit the disclosed pair once to its named or implied in-scope panel, then once to each relevant in-scope first-party login panel encountered in the application at the allowed normal rate. This is credential validation, not brute force: no password candidates or user list are generated. Completion: every attempted panel has a redacted Attempt outcome.
3. Stop on the first successful authentication, CAPTCHA, 429, lockout signal, or unexpected state. On success, capture only the authenticated landing state or visible account-tier proof; do not navigate, call APIs, read records, change settings, or otherwise operate the account. Completion: minimal proof and stop reason are recorded.

Do not use a disclosed pair against an out-of-scope or third-party service, derive variants, alter the username, or expand it into a general reuse campaign.

### Admin-panel default credential campaign

1. Trigger this check immediately for every discovered in-scope admin, claim, portal, or privileged login panel. Check the published program rules and panel-specific restrictions first. If authentication testing or default-password guessing is prohibited for the panel, make no default-credential submissions: record the restriction and stop. Completion: the panel's scope and relevant auth-testing rule are recorded.
2. When the program does not expressly prohibit brute force or credential spraying on that panel, run a fixed campaign of at most five likely default/admin credential pairs. Every pair must be supported by product/version/panel documentation or observed in-scope target configuration evidence. Submit one pair at a time at the program's stated login rate, or the normal rate-safe baseline with backoff when the program has none. Completion: no more than five pairs are sent to that panel and each has a specific evidence rationale.
3. When the program expressly prohibits brute force or credential spraying on that panel, do not launch the five-pair campaign. Use one to five pairs only where each username/password combination is supported by product/version/panel documentation or observed in-scope target configuration evidence. Submit one pair at a time at the program's stated login rate, or the normal rate-safe baseline with backoff when the program has none. Completion: every attempted pair has that specific evidence rationale and the cap is not exceeded.
4. Stop on success, CAPTCHA, 429, lockout, or unexpected state. Completion: no further pairs are sent after a stop condition.

A five-pair campaign against one discovered privileged panel is bounded default-admin coverage, not an unbounded password search. Do not load a generic password wordlist, vary usernames across an account list, retry through lockout signals, or distribute the same password across many accounts. Those actions are brute force, spraying, or stuffing beyond this skill's automatic panel trigger.

## Evidence and handoff

Write one redacted Attempt per submitted pair. Record the panel, source category (`target-exposed`, `product-default`, or `bounded-default`), source provenance, rate/lockout observation, outcome, minimal successful-auth proof, and stop reason. Never retain raw passwords, tokens, cookies, response bodies, or session material.

Promote a success to the reporting/findings flow as exposed/default credentials with the observed account tier. A successful login proves access; it is not permission for post-login exploration.
