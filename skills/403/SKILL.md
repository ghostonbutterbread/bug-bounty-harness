---
name: "403"
description: "Use when an in-scope endpoint returns 403 Forbidden and the agent owns the endpoint or it is a server endpoint safe to probe with bounded access-bypass checks."
---

# 403 Forbidden Bypass

Use only after a concrete `403 Forbidden` response is observed on an in-scope endpoint.

This is a RAG-style child skill. Classify why the 403 exists, load one focused reference pack, then test the smallest safe bypass family.

## Load Order

1. Read program scope, owned-account context, active live-testing policy, and the current agent's assigned surface.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Confirm the endpoint returned `403` in the current owned context and is agent-owned, assigned server/API surface, or tied to Ryushe's approved test account set.
4. Read `$HARNESS_ROOT/prompts/403-context-pack.md`.
5. Classify the lane:
   - path or route normalization -> `$HARNESS_ROOT/skills/403/references/technique-packs/path-normalization.md`
   - trusted route/client headers -> `$HARNESS_ROOT/skills/403/references/technique-packs/trusted-headers.md`
   - auth-state or owned-account comparison -> `$HARNESS_ROOT/skills/403/references/technique-packs/auth-state.md`
6. Read `$HARNESS_ROOT/prompts/403-playbook.md` for deep review, stuck analysis, or report writing.
7. Route instead of duplicating:
   - broader header behavior -> `/headers`
   - WAF or bot enforcement -> `/waf`
   - object ownership or role boundary -> `/access-control` or `/idor`
   - broader mutation families -> `/bypass`

## Workflow

1. Capture the baseline `403` with method, full URL, auth state, redirects, body length, response headers, and visible denial reason.
2. Record why the endpoint/resource is safe to probe.
3. Load one lane reference pack.
4. Run a bounded pass: baseline, one mutation family, compare, then stop or pivot.
5. Record the result as a note unless there is a security-relevant delta.

## Proof Standard

Promote only when a mutation changes authorization, route reachability, protected behavior, or approved-account boundary in a reproducible way.

Do not promote cosmetic error changes, soft redirects, cache artifacts, public data, generic 403 pages, or caller-owned access.

## Stop Conditions

Stop if the resource belongs to a real user or organization outside approved accounts, the endpoint is out of scope, the path is destructive, the block is rate-limit/WAF enforcement, or the next step would bypass billing, abuse controls, privacy controls, or explicit program policy.

## Evidence

Write artifacts under `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/` or the owning finding lane.

Record full URLs, exact modified headers/path/method, auth state, account/resource ownership, response delta, loaded reference pack, and why the tested resource was safe to probe.
