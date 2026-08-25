---
name: ssrf
description: "Use when testing Server-Side Request Forgery, URL fetchers, webhooks, importers, metadata access, internal reachability, redirect bypasses, or server-side URL validation."
---

# SSRF Testing

Use for Server-Side Request Forgery: server-side features that fetch, render,
import, preview, proxy, convert, or validate attacker-controlled URLs or network
resources.

This is a RAG-style skill. Load a small "where to look" reference first, then a
small "what to try" reference once a fetch surface exists. Treat references as
idea seeds, not checklists or ceilings.

Do not treat a blocked URL as a dead lane when fetch behavior exists. A public
callback hit, DNS lookup, parser error, redirect difference, private-IP block,
scheme-specific error, async queue behavior, or status delta is signal. Signal
means classify the fetch/filter boundary and enter pressure mode.

## Load Order

Read `general-security-testing-policy` first and follow its Cold-Start guidance (mirrored in `agents/index.md`):

1. **Scope Gate** — Read program scope, owned-account context, and
   live-testing policy. Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Resolve `$HARNESS_ROOT`; default is
   `/home/ryushe/projects/bug_bounty_harness`. Look at the target for
   fetch/URL-handling surfaces directly. Observe what the app does with URLs.
   Avoid broad prior-state reads until the agent has current observations.
3. **Fresh Observations** — Aim to identify 3-5 fetch surfaces, URL parameters, webhook
   endpoints, or import flows from direct observation.
4. **Memory Overlay** — Now read `injection-testing-policy` once a URL/fetch
   sink exists or is strongly suspected. Query prior MapStore/hunt entries for
   the concrete URL, parameter, fetch surface, or parser boundary the agent
   found. Use prior results to rebound from known boundaries and avoid
   duplicates, not to choose the first target.
5. Read `references/common-locations.md` to decide where to hunt.
6. After finding a fetch surface, read `references/idea-seeds.md` for bypass,
   parser, metadata, header, WAF, and segmentation ideas.
7. Optional deeper packs:
   - direct outbound fetch -> `references/technique-packs/baseline-fetch.md`
   - allowlist, hostname, IP, redirect, or URL parser filtering -> `references/technique-packs/parser-redirect.md`
   - cloud metadata or internal protocol reachability -> `references/technique-packs/metadata-scheme.md`
8. Read `$HARNESS_ROOT/prompts/ssrf-playbook.md` only for deep review, stuck
   analysis, or report writing.
9. Route instead of duplicating:
   - URL/parser/filter bypasses -> `/bypass`
   - header-required metadata or proxy trust behavior -> `/headers`
   - WAF/rate-limit blocks -> `/waf`
   - profile image or upload fetchers -> `/pfp`

## Workflow

1. Mine the current application map, UI/API flows, and JavaScript for URL-handling
   candidates, then identify the server-side fetch sink and parameter.
2. Form a first-pass hypothesis about how the app handles that URL/fetch
   surface from direct behavior.
3. Query MapStore and prior attempts for this URL/fetch surface to avoid
   duplicate work and reuse known parser/filter boundaries.
4. Confirm server-side fetch when possible with an owned controlled callback. If
   outbound callbacks are unavailable, use the smallest safe internal URL proof
   available—response/status delta, timing, job state, or other direct server
   behavior—and record that the evidence is indirect or bounded by the surface.
5. If no callback, reflection, status change, or visible delta appears, classify
   likely controls anyway: allowlist, private-IP block, redirect handling, DNS
   timing, scheme block, URL parser split, sanitizer, WAF, or async fetch.
6. Use the idea seeds that match the observed or plausible filtering/routing
   behavior, then run a bounded mutation ladder. Once a backend fetch boundary
   is confirmed, cover as many distinct representation variants as useful at the
   permitted rate; expand a family when a variant behaves differently, and stop
   repeating variants that normalize or behave identically.
7. Prefer status, banner, callback, or low-risk root proof over secret retrieval.
8. Stop after the impact boundary is proved or, when impact proof is not yet
   available, after representative mutation families show the filter boundary is
   understood.

## Pressure Mode

Resolve the canonical lane stream with `resolve_attempts_path(...)` and write
every deliberate SSRF probe through `append_attempt(...)` to
`<lane>/attempts/_runs/<run-id>/attempts.jsonl`. Record the exact URL payload,
payload family, placement, expected fetch behavior, callback or response
evidence, observed filter, block reason, and next mutation. Class, payload
family, target, parameter, and input location are redacted event metadata. Use
`read_attempt_bucket(program, where=..., limit=...)` for bounded cross-run
discovery and `read_attempts(exact_path, ...)` for exact-run forensic review.

Use this state model:

- `cold`: no fetch, DNS, parser, timing, status, or callback signal yet.
- `warm`: some fetch/filter behavior appears, but reachability is unproven.
- `hot`: controlled callback, redirect behavior, parser split, or partial
  internal-routing clue exists.
- `exhausted`: representative families failed and the fetch/filter boundary is
  understood.

Only pivot automatically from `cold` or `exhausted`. If the lane is `warm` or
`hot`, keep pressure on the same fetch vector with matching mutation families
unless policy, ownership, rate, or safety gates stop the next probe.

Typical SSRF pressure ladder:

1. identify fetch sink and trigger timing
2. public callback proof
3. request-shape capture: method, headers, user agent, redirect behavior, DNS
   timing, body/content-type, and auth context when visible
4. block classification: scheme, hostname allowlist, private IP, redirect,
   parser split, content-type, async queue, WAF, or header requirement
5. family queue: redirects, DNS tricks, parser confusion, userinfo, IPv6,
   octal/decimal, suffix/prefix allowlist, protocol smuggling, Host/header
   trust
6. internal-surface discovery when reached with a low rate limit: IP/root
   checks, service identity/protocol/banner/status classification, and candidate
   surface mapping from non-sensitive evidence
7. impact proof, residual next probe, or exact kill reason

## Primary Harness

```bash
python agents/bypass_harness.py --target https://target.example/fetch?url=x \
  --type ssrf --param url --program target --concurrency 5 --rps 2
```

Lower concurrency and RPS when rules are unclear or the fetcher fans out server-side.

## Proof Standard

Promote only when evidence shows the server, not the client, reached a controlled, internal, metadata, or otherwise security-relevant destination.

Do not promote client-side-only navigation, generic fetch errors, public URL fetches without impact, or unsupported timing speculation.

## Escalation And Stop Conditions

After proving a server-side fetch boundary, continue with a bounded,
rate-limited, read-only internal proof ladder when program rules permit. Internal
reads may establish impact, including the minimum sensitive response needed to
show the reachable boundary; preserve only the smallest necessary proof and
never disclose raw secrets or third-party data. Stop after the impact boundary
is proved, on instability, or when a next request may change state, authenticate
with retrieved credentials/tokens, persist data, cause destructive behavior, or
broaden into an uncontrolled scan. DNS rebinding still requires explicit
approval. Use the observed fetcher's service cost and program rules—not an
arbitrary payload-count cap—to set rate, concurrency, and backoff.

## Evidence

Write findings to `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssrf/findings.md` and bypass artifacts to `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`.

Record full URL, sink/parameter, loaded reference pack, destination class,
exact URL payloads or canaries tried, payload family, callback or response
evidence, observed filter/block reason, required bypass/header, attempts
artifact path, MapStore pointer, pressure state, confirmation status, and
impact boundary reached.
