---
name: ssrf
description: "Use when testing Server-Side Request Forgery, URL fetchers, webhooks, importers, metadata access, internal reachability, redirect bypasses, or server-side URL validation."
---

# SSRF Testing

Use for Server-Side Request Forgery leads in URL fetchers, webhooks, importers, renderers, previews, media proxies, and server-side URL validation.

This is a RAG-style skill. Classify the fetch primitive, load one focused reference pack, then test with the lowest-noise proof.

## Load Order

1. Read program scope, owned-account context, and active live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/ssrf-context-pack.md`.
4. Classify the lane:
   - direct outbound fetch -> `$HARNESS_ROOT/skills/ssrf/references/technique-packs/baseline-fetch.md`
   - allowlist, hostname, IP, redirect, or URL parser filtering -> `$HARNESS_ROOT/skills/ssrf/references/technique-packs/parser-redirect.md`
   - cloud metadata or internal protocol reachability -> `$HARNESS_ROOT/skills/ssrf/references/technique-packs/metadata-scheme.md`
5. Read `$HARNESS_ROOT/prompts/ssrf-playbook.md` for deep review, stuck analysis, or report writing.
6. Use `$HARNESS_ROOT/prompts/ssrf-reference.md` only when adapting metadata roots, destination classes, or parser-confusion variants.
7. Route instead of duplicating:
   - URL/parser/filter bypasses -> `/bypass`
   - header-required metadata or proxy trust behavior -> `/headers`
   - WAF/rate-limit blocks -> `/waf`
   - profile image or upload fetchers -> `/pfp`

## Workflow

1. Identify the server-side fetch sink and parameter.
2. Confirm a benign controlled outbound fetch when possible.
3. Load one SSRF reference pack based on observed filtering.
4. Prefer status, banner, callback, or low-risk root proof over secret retrieval.
5. Stop after proving the boundary reached.

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
