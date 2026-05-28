---
name: headers
description: "Route security testing for HTTP header trust, origin validation, proxy context, route overrides, host routing, method overrides, content negotiation, and auth-header precedence."
---

# Headers

Use when the security question depends on how the server interprets request headers.

This is a RAG-style mechanism skill. Classify the header lane first, load one focused reference pack, then test only the smallest safe mutation set.

## Load Order

1. Read program scope, owned-account context, and active live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/headers-context-pack.md`.
4. Classify the lane:
   - `Origin` or `Referer` behavior -> `$HARNESS_ROOT/skills/headers/references/technique-packs/origin.md`
   - client IP or proxy trust -> `$HARNESS_ROOT/skills/headers/references/technique-packs/proxy-trust.md`
   - internal route rewrite or forbidden path access -> `$HARNESS_ROOT/skills/headers/references/technique-packs/route-override.md`
   - HTTP method tunneling -> `$HARNESS_ROOT/skills/headers/references/technique-packs/method-override.md`
   - tenant, virtual host, or upstream routing -> `$HARNESS_ROOT/skills/headers/references/technique-packs/host-routing.md`
   - `Accept`, `Content-Type`, charset, compression, or API version behavior -> `$HARNESS_ROOT/skills/headers/references/technique-packs/content-negotiation.md`
   - auth header/session precedence -> `$HARNESS_ROOT/skills/headers/references/technique-packs/auth-context.md`
5. Read `$HARNESS_ROOT/prompts/headers-playbook.md` for deep review, stuck analysis, or report writing.
6. Route instead of duplicating:
   - concrete `403` endpoint -> `/403`
   - broad bypass or parser mutation -> `/bypass`
   - CORS policy impact -> `/csrf` or future `/cors`
   - direct object ownership -> `/access-control` or `/idor`

## Workflow

1. Capture a baseline request and response with full URL, method, auth state, cookies, and relevant headers.
2. Load one lane reference pack based on observed behavior.
3. Mutate one header family at a time.
4. Compare response status, redirects, body length, cache headers, downstream route, account boundary, and side effects.
5. Stop after a material delta or after the bounded lane fails.

## Proof Standard

Promote only when header behavior changes authorization, routing, origin trust, object/account boundary, parser behavior, or security policy in a reproducible way.

Do not promote cosmetic error changes, cache artifacts, same-content redirects, public data, or caller-owned access.

## Stop Conditions

Stop before touching real-user data, bypassing explicit target policy, escalating outside approved accounts, performing destructive state changes, or continuing after rate-limit/WAF enforcement. Route those cases to `/waf`, `/403`, `/access-control`, or Ryushe for approval.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/headers/` or the owning finding lane.

Record full URLs, baseline headers, mutated headers, auth state, owned account/resource used, response delta, loaded reference pack, proof/no-proof result, and next safe test.
