---
name: jwt-auth
description: "Route JWT/JWS/JWK/JWKS authorization testing into focused token, claim, key-source, and format-confusion lanes."
---

# JWT Auth

Use when an application uses JWTs for authentication or authorization, especially when a `403` depends on a Bearer token, JWT cookie, JWS header, JWKS key lookup, issuer, audience, role, tenant, or object claim.

This is a RAG-style child skill. Classify the token behavior, load one focused reference pack, then test the smallest safe JWT mutation family.

## Load Order

1. Read program scope, owned-account context, active live-testing policy, and the current `/403`, `/access-control`, `/idor`, or `/api` handoff.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Capture and decode only header/payload metadata. Redact signatures, tokens, cookies, and secrets in chat or broad reports.
4. Read `$HARNESS_ROOT/prompts/jwt-auth-context-pack.md`.
5. Classify the lane:
   - `alg:none`, missing signature, or signature not checked -> `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/algorithm-signature.md`
   - `iss`, `aud`, `jti`, role, scope, tenant, or object claims drive access -> `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/claims.md`
   - `kid`, `jku`, `x5u`, `x5c`, `x5t`, inline `jwk`, or JWKS lookup appears -> `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/key-source.md`
   - RS256/HS256 switching, weak HMAC secret, or public key as secret -> `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/key-confusion-weak-secret.md`
   - malformed JWT, duplicate claims, whitespace, nested token, JWE/JWS confusion -> `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/format-confusion.md`
6. Read `$HARNESS_ROOT/prompts/jwt-auth-playbook.md` for deep review, stuck analysis, or report writing.
7. Route instead of duplicating:
   - path/header/method 403 bypass -> `/403`, `/headers`, or `/bypass`
   - direct object authorization -> `/access-control` or `/idor`
   - SSRF from `iss`, `jku`, or `x5u` URL fetching -> `/ssrf` after using only owned callback URLs

## Workflow

1. Capture baseline denied and allowed requests, including full URL, auth location, status, response size, and safe decoded claims.
2. Identify what the server appears to trust: signature, algorithm, key source, issuer, audience, role/scope, tenant, object ID, expiry, or token format.
3. Load one reference pack and run a bounded mutation pass against owned resources only.
4. Minimize any working token mutation and compare with the original denied baseline.
5. Write a note or finding handoff before switching lanes.

## Proof Standard

Promote only when a token mutation changes authorization, role, tenant, object access, authenticated state, or protected data/action in a reproducible way.

Do not promote token decode alone, public claims, cosmetic response changes, generic `200` responses, caller-owned data, or unverified crack attempts.

## Stop Conditions

Stop if the next step requires real secrets, non-owned tokens, non-owned private data, destructive actions, internal network probing, brute force beyond offline weak-secret checks, or target policy violations. For URL-based key/issuer tests, use only owned callback infrastructure unless Ryushe approves otherwise.

## Evidence

Write artifacts under `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/jwt-auth/` or the owning auth/access-control lane.

Record full URLs, auth state, token location, decoded header/payload with secrets redacted, loaded reference pack, mutation tried, response delta, account/resource ownership, and cleanup status.
