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

## Load Order

1. Read program scope, owned-account context, and active live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `injection-testing-policy` once a URL/fetch sink exists or is strongly
   suspected. Do not stop just because the first callback or response canary
   produces no visible signal.
4. Read `references/common-locations.md` to decide where to hunt.
5. After finding a fetch surface, read `references/idea-seeds.md` for bypass,
   parser, metadata, header, WAF, and segmentation ideas.
6. Optional deeper packs:
   - direct outbound fetch -> `references/technique-packs/baseline-fetch.md`
   - allowlist, hostname, IP, redirect, or URL parser filtering -> `references/technique-packs/parser-redirect.md`
   - cloud metadata or internal protocol reachability -> `references/technique-packs/metadata-scheme.md`
7. Read `$HARNESS_ROOT/prompts/ssrf-playbook.md` only for deep review, stuck
   analysis, or report writing.
8. Route instead of duplicating:
   - URL/parser/filter bypasses -> `/bypass`
   - header-required metadata or proxy trust behavior -> `/headers`
   - WAF/rate-limit blocks -> `/waf`
   - profile image or upload fetchers -> `/pfp`

## Workflow

1. Identify the server-side fetch sink and parameter.
2. Confirm a benign controlled outbound fetch when possible.
3. If no callback, reflection, status change, or visible delta appears, classify
   likely controls anyway: allowlist, private-IP block, redirect handling, DNS
   timing, scheme block, URL parser split, sanitizer, WAF, or async fetch.
4. Use the idea seeds that match the observed or plausible filtering/routing
   behavior, then run a bounded mutation ladder.
5. Prefer status, banner, callback, or low-risk root proof over secret retrieval.
6. Stop after proving the boundary reached.

## Primary Harness

```bash
python agents/bypass_harness.py --target https://target.example/fetch?url=x \
  --type ssrf --param url --program target --concurrency 5 --rps 2
```

Lower concurrency and RPS when rules are unclear or the fetcher fans out server-side.

## Proof Standard

Promote only when evidence shows the server, not the client, reached a controlled, internal, metadata, or otherwise security-relevant destination.

Do not promote client-side-only navigation, generic fetch errors, public URL fetches without impact, or unsupported timing speculation.

## Stop Conditions

Stop before harvesting secrets, deep internal enumeration, DNS rebinding without explicit approval, high-volume scans, non-owned private resources, or destructive protocol interactions.

## Evidence

Write findings to `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssrf/findings.md` and bypass artifacts to `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`.

Record full URL, sink/parameter, loaded reference pack, destination class, callback or response evidence, required bypass/header, confirmation status, and impact boundary reached.
