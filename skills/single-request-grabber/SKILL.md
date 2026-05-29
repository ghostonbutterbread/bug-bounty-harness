---
name: single-request-grabber
description: "Capture one live owned-session request through proxy or browser, then perform a bounded modify/replay test for CSRF, access-control, header, or request-shape validation."
---

# Single Request Grabber

Use when a test needs the exact live request shape, token, cookie state, or browser-generated headers for one action.

This is a RAG-style live-request skill. It captures one request, classifies the safe modification, executes at most the bounded test, and writes an action/error trail.

## Load Order

1. Read program scope, owned-account context, current task goal, and live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/single-request-grabber-context-pack.md`.
4. Classify the lane:
   - CSRF token or one-time action token -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/csrf-token.md`
   - approved account/resource substitution -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/access-control-replay.md`
   - header or request-shape repair -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/request-shape-repair.md`
5. Read `$HARNESS_ROOT/prompts/single-request-grabber-playbook.md` for step-by-step operation or report writing.
6. Route instead of duplicating:
   - CSRF impact -> `/csrf`
   - workspace/account/resource authorization -> `/access-control` or `/idor`
   - header mechanics -> `/headers`
   - error classification -> `/error-triage`
   - proxy setup -> `/agent-proxy`, `/caido`, or `/chromium-test`

## Workflow

1. Choose one action and one owned account/session.
2. Capture the live request through browser/proxy or proxy history.
3. Sanitize notes: never store raw cookies, tokens, auth headers, or secrets.
4. Confirm ownership and destructible status for every account/resource touched.
5. Modify only the approved field, header, method, body, or owned-resource identifier.
6. Send at most the bounded replay/forward test needed to answer the question.
7. Record the action/error trail before routing to another skill.

## Proof Standard

Promote only when the captured request proves a security-relevant delta: CSRF protection failure, cross-account/tenant access, header trust issue, request-shape downgrade, or server-side policy mismatch.

Do not promote expected denials, generic errors, UI-only differences, public data, caller-owned access, or unverified speculation.

## Stop Conditions

Stop if the action is destructive and the target resource is not explicitly `destructible: yes`, if the request would touch non-owned data, if token/account ownership is unclear, if CAPTCHA/WAF/rate-limit enforcement appears, or if the test requires guessing secrets/tokens.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/single-request-grabber/` or the owning finding lane.

Record action goal, full URL, method, account/resource aliases, destructible status, captured request source, sanitized mutation, result, routed skill, stop condition, and raw artifact path if available.
