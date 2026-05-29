---
name: error-triage
description: "Classify HTTP error responses during bug bounty testing and route agents into the next safe skill or stop condition based on goal, ownership, status code, and response evidence."
---

# Error Triage

Use when an agent sees an error response and needs to decide whether to investigate, route to another skill, record a note, back off, or stop.

This is a RAG-style decision skill. It does not authorize broader testing by itself.
Its route list is a set of likely next moves, not an exhaustive policy table. If no
listed route fits, classify the ambiguity, preserve the evidence, and choose the
smallest safe next step under the current goal.

## Load Order

1. Read program scope, owned-account context, current task goal, and live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/error-triage-context-pack.md`.
4. Classify by current goal plus observed response:
   - login/session/account setup errors -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/auth-errors.md`
   - `401`, `403`, ownership, or authorization errors -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/access-errors.md`
   - `500`, framework, server, or infrastructure errors -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/server-errors.md`
   - `400`, `415`, schema, content-type, or parser errors -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/parser-errors.md`
   - `405` or method mismatch -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/method-errors.md`
   - `429`, WAF, CAPTCHA, bot challenge, or temporary block -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/rate-limit-waf.md`
   - unclear, mixed, custom, or unhandled errors -> `$HARNESS_ROOT/skills/error-triage/references/technique-packs/unhandled-errors.md`
5. Read `$HARNESS_ROOT/prompts/error-triage-playbook.md` for deep review, stuck analysis, or report writing.
6. Route instead of duplicating:
   - concrete owned `403` -> `/403`
   - WAF/rate-limit behavior -> `/waf`
   - auth boundary -> `/access-control`
   - object ownership -> `/idor`
   - parser/header behavior -> `/headers` or `/bypass`
   - route discovery -> `/fuzz` or `/live-map`
   - fresh token, browser-generated request, or one-shot action request -> `/single-request-grabber`

## Workflow

1. Capture the error response with full URL, method, auth state, account/resource ownership, status, headers, body length, and visible message.
2. Ask: under the current task, is this error expected evidence or a blocker?
3. Load one matching reference pack.
4. Either route to the next bounded skill, record a note, retry once with a minimal baseline, ask for a live capture, or stop.
5. Write a triage card before handing off.

## Proof Standard

Promote only when the error exposes security-relevant behavior: unauthorized data/action, internal route disclosure, framework/stack leakage with impact, parser differential, or policy bypass.

Do not promote generic errors, expected failed login, expected forbidden access, soft 404s, cache artifacts, or unsupported speculation.

## Stop Conditions

Stop when the error is rate limiting, bot protection, CAPTCHA, out-of-scope, destructive, tied to non-owned resources, or requires credentials/resources whose ownership is unclear.

If the error is ambiguous but still in scope and safe, do not stop just because the
status code is not mapped. Record the uncertainty and pick a bounded exploratory
move, such as one baseline retry, one request-shape comparison, `/live-map`,
`/fuzz`, `/headers`, or a manual handoff.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/error-triage/` or the owning finding lane.

Record the current task goal, full URL, status, auth state, owned resource decision, loaded reference pack, classification, route/stop decision, and next safe test.
