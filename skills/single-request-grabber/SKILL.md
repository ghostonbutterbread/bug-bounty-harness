---
name: single-request-grabber
description: "Capture one live owned-session request through proxy or browser, then perform a bounded modify/replay test for CSRF, access-control, header, or request-shape validation."
---

# Single Request Grabber

Use when a test needs the exact live request shape, token, cookie state, or browser-generated headers for one action or one short action flow.

This is a RAG-style live-request skill. Its primary job is operational: capture one request or one short flow through the proxy/MCP or browser, forward non-target requests until the target request appears, optionally pause it while fresh, make one approved mutation, forward or replay it, finish the flow, disable intercept, and write an action/error trail.

Routing is secondary. Do not route away before capturing the request if the current task specifically needs the live token/request shape.

Default source wording: if Ryushe says "look at the request <request>", inspect or pull that request from Ryushe's proxy unless he specifies another source. If an agent then replays the request, prefer direct HTTP replay with agent-owned session state unless the agent is on the same host as Ryushe's proxy and `my proxy` resolves to `localhost` from that runtime.

This direct-replay preference applies only to replaying known request shapes. It does not apply to live browser exploration. For live testing, use Chromium/Playwright attached to the agent's local browser proxy and pull the live request from that local agent proxy when needed.

If direct HTTP replay fails in a way that looks caused by a non-browser client, such as Cloudflare/bot challenges, TLS/header fingerprint mismatch, browser-only flow state, or missing JS-generated tokens, the agent may re-plug the sanitized request into its own local proxy/MCP and send it from the agent lane.

## Agent Note

This skill is designed to be used with other skills. Use it to capture or mutate the live request/flow; use `/access-control`, `/idor`, `/csrf`, `/headers`, `/error-triage`, or another owning skill to interpret the security result.

## Load Order

1. Read program scope, owned-account context, current task goal, and live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/single-request-grabber-context-pack.md`.
4. Classify the mutation lane:
   - CSRF token or one-time action token -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/csrf-token.md`
   - approved account/resource substitution -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/access-control-replay.md`
   - header or request-shape repair -> `$HARNESS_ROOT/skills/single-request-grabber/references/technique-packs/request-shape-repair.md`
5. Read `$HARNESS_ROOT/prompts/single-request-grabber-playbook.md` for step-by-step operation or report writing.
6. Use proxy setup helpers only if needed:
   - agent-lane proxy/MCP -> `/agent-proxy`
   - Caido MCP inspection/replay -> `/caido`
   - PwnFox colored profile/session filtering -> `/pwnfox`
   - browser-driven capture -> `/chromium-test`
7. After the result, route instead of duplicating:
   - CSRF impact -> `/csrf`
   - workspace/account/resource authorization -> `/access-control` or `/idor`
   - header mechanics -> `/headers`
   - error classification -> `/error-triage`

## Workflow

1. Choose one action or short action flow and one owned account/session.
2. Capture the live request through browser/proxy, proxy MCP history, or proxy intercept.
3. If intercepting a flow, inspect each paused request, forward requests that are not relevant, and stop only on the target request or request family.
4. Sanitize notes: never store raw cookies, tokens, auth headers, or secrets.
5. If the source request came from Ryushe's proxy, use it as a request-shape template only and switch to the agent lane before active replay/testing unless the same-host localhost exception applies.
6. For replay, try direct HTTP first with `curl`, `httpx`, or a focused script while preserving method, full URL, relevant headers, content type, body encoding, redirect behavior, and agent-owned auth/session material.
7. If direct replay fails for browser/client-fingerprint reasons, retry through the agent's local proxy/MCP. Keep this fallback agent-local.
8. Confirm ownership and destructible status for every account/resource touched.
9. Modify only the approved field, header, method, body, cookie/session context, or owned-resource identifier.
10. Send at most the bounded replay/forward test needed to answer the question.
11. Complete the browser/proxy flow if safe, then turn off intercept.
12. Record the action/error trail before routing to another skill.

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
