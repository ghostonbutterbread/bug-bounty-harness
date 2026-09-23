---
name: single-request-grabber
description: "Capture one live owned-session request through proxy or browser, then perform a bounded modify/replay test for CSRF, access-control, header, or request-shape validation."
---

# Single Request Grabber

Use when a test needs the exact live request shape, token, cookie state, or browser-generated headers for one action or one short action flow.

This is a live-request capture/replay skill. Capture one owned request or short
flow through the browser's task MITM, make one approved bounded mutation by
replay, and write an action/error trail. Pause/modify/forward applies only when
an explicitly supported temporary interception mechanism is available; the
default provisioner listener is capture-only, not a hot-edit control API.

Routing is secondary. Do not route away before capturing the request if the current task specifically needs the live token/request shape.

This skill decides when fresh request context is needed. `intercepted-proxy`
owns any supported live interception mechanics; otherwise capture through the
task MITM and use approved replay. Do not assume Caido MCP is an HTTP proxy or
that a capture-only task listener supports pause/Tamper.

For single-use, nonce-bound, CSRF-bearing, signed, or browser-generated actions,
load `intercepted-proxy` to assess whether a supported exact-match live rule is
available. If not, capture and replay safely with fresh owned state or stop at
the missing primitive; never claim to have paused the request.

Default source wording: if Ryushe says "look at the request <request>", inspect or pull that request from Ryushe's proxy unless he specifies another source. Treat it as source shape only; replay with the agent's owned session through its task MITM, except for the explicit local-Abommie active-Caido permission.

This direct-replay preference applies only to replaying known request shapes. It does not apply to live browser exploration. For live testing, use Chromium/Playwright attached to the agent's local browser proxy and pull the live request from that local agent proxy when needed.

If direct HTTP replay fails from browser/client differences, first confirm the
same task MITM and owned session were used. Browser-only state may require a
new browser action; an MCP control endpoint is not a replay proxy.

## Agent Note

This skill is designed to be used with other skills. Use it to capture or mutate the live request/flow; use `/access-control`, `/idor`, `/csrf`, `/headers`, `/error-triage`, or another owning skill to interpret the security result.

## Load Order

1. Read program scope, owned-account context, current task goal, and live-testing policy.
2. If dispatcher diagnosis is needed, run `bbh --root`; do not select a checkout manually.
3. Read `prompts/single-request-grabber-context-pack.md`.
4. Classify the mutation lane:
   - CSRF token or one-time action token -> `skills/single-request-grabber/references/technique-packs/csrf-token.md`
   - approved account/resource substitution -> `skills/single-request-grabber/references/technique-packs/access-control-replay.md`
   - header or request-shape repair -> `skills/single-request-grabber/references/technique-packs/request-shape-repair.md`
5. Read `prompts/single-request-grabber-playbook.md` for step-by-step operation or report writing.
6. Use proxy setup helpers only if needed:
   - task-owned MITM listener -> `/agent-proxy`
   - explicit Ryushe Caido source-history lookup -> `/caido` (read-only outside Abommie)
   - PwnFox colored profile/session filtering -> `/pwnfox`
   - browser-driven capture -> `/chromium-test`
   - live intercept/modify/forward lifecycle -> `/intercepted-proxy`
7. After the result, route instead of duplicating:
   - CSRF impact -> `/csrf`
   - workspace/account/resource authorization -> `/access-control` or `/idor`
   - header mechanics -> `/headers`
   - error classification -> `/error-triage`

## Workflow

1. Choose one action or short action flow and one owned account/session.
2. Decide capture mode:
   - load `intercepted-proxy` for single-use or nonce-bound flows only when a
     supported exact-match live intercept is needed; otherwise capture/replay
     with fresh owned state or record the missing primitive
   - use passive proxy history when the request is repeatable and only needs shape review
   - use direct HTTP replay when the request shape is already known and fresh browser state is not needed
3. Capture the live request through the provisioned browser's task MITM flow.
   Label any Caido history as separate source shape, not agent replay evidence.
4. Only if a supported live intercept is configured, inspect paused requests,
   forward unrelated setup traffic, and stop on the target request family.
5. Sanitize notes: never store raw cookies, tokens, auth headers, or secrets.
6. If the source request came from Ryushe's proxy, use it only as a request-shape
   template; active replay uses the agent's task MITM except explicitly permitted
   local Abommie Caido transport.
7. Replay with `curl`, `httpx`, or a focused script through that listener,
   preserving method, URL, headers/body shape and owned session; for HTTPS
   origins trust the returned task CA.
8. If replay fails for browser/client-fingerprint reasons, use a fresh browser
   action through the same task MITM; do not switch to an MCP URL or shared port.
9. Confirm ownership and destructible status for every account/resource touched.
10. Modify only the approved field, header, method, body, cookie/session context, or owned-resource identifier.
11. Send at most the bounded replay/forward test needed to answer the question.
12. Complete the browser/proxy flow if safe, then remove any temporary
    interception rule; release the browser and finish the task proxy after replay.
13. Record the action/error trail before routing to another skill.

## Proof Standard

Promote only when the captured request proves a security-relevant delta: CSRF protection failure, cross-account/tenant access, header trust issue, request-shape downgrade, or server-side policy mismatch.

Do not promote expected denials, generic errors, UI-only differences, public data, caller-owned access, or unverified speculation.

## Stop Conditions

Stop if the action is destructive and the target resource is not explicitly `destructible: yes`, if the request would touch non-owned data, if token/account ownership is unclear, if CAPTCHA/WAF/rate-limit enforcement appears, or if the test requires guessing secrets/tokens.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/single-request-grabber/` or the owning finding lane.

Record action goal, flow boundary, full URL, method, account/resource aliases,
destructible status, captured request source, PwnFox color/header filter when
used, forwarded non-target request count, sanitized mutation, result,
intercept-off confirmation, routed skill, stop condition, and raw artifact path
if available.
