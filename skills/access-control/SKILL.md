---
name: access-control
description: "Route broken access control, IDOR, BOLA, role, tenant, workflow, method, header, path, and auth-state testing into focused authorization lanes."
---

# Access Control

Use for broken access control, IDOR/BOLA, role confusion, tenant isolation, workflow authorization, unauthenticated access to authenticated-only resources, and object/function-level authorization bugs.

This is a router skill. Keep the first pass small: classify the boundary, load one focused reference pack, then spawn or hand off when the category changes.

## Load Order

Follow the Cold-Start Doctrine from `agents/index.md`:

1. **Scope Gate** — Read scope, owned-account context, and live-testing
   policy. Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Resolve `$HARNESS_ROOT` first; default is
   `/home/ryushe/projects/bug_bounty_harness`. Look at the target
   endpoint/object with fresh eyes. Observe auth boundaries and response
   patterns directly. Do NOT query prior maps or MapStore yet.
3. **Novelty Quota** — Identify 3-5 fresh object references, role differences,
   auth boundaries, or access patterns from direct observation.
4. **Memory Overlay** — Now load prior state:
   - Load `/account-management` and check
     `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json` for
     owned accounts, user IDs, PwnFox lanes, object IDs, and any account-level
     destructive restrictions.
   - Read `$HARNESS_ROOT/skills/access-control/references/account-setup.md`.
   - Confirm the needed owned accounts/resources exist. If not, ask for the
     account path, or use `/temporary-email` when a separate test account is
     needed for account-level destructive flows.
   - Check `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/` for
     existing `/live-map` routes, objects, hypotheses, and handoff packets.
     Use map entries as exploration leads, not proof.
5. Read `$HARNESS_ROOT/skills/access-control/references/related-terms.md` for
   search vocabulary and route/parameter keywords.
6. Classify the lane:
   - peer object/resource access -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/horizontal.md`
   - admin/support/owner/moderator/paid functionality -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/vertical.md`
   - org/workspace/team/project/store isolation -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/tenant.md`
   - wrong order, stale state, replay, skipped step -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/workflow.md`
   - anonymous, logged-out, expired, or stale session -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/auth-state.md`
   - GraphQL arguments or global IDs -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/graphql-bola.md`
   - signed URLs, CDN objects, exports, attachments, media -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/storage-links.md`
   - JWT/Bearer/cookie claims influence role, tenant, object, issuer, audience, or token lifecycle -> load `/jwt-auth`
   - method/header/path/parser discrepancy -> load `/headers` for header mechanisms or `/bypass` with type `403`/`idor`
   - one live browser/proxy request must be captured and safely modified -> `/single-request-grabber`
9. For IDOR/BOLA object mutations, load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md`.
10. For header mechanisms, load `/headers`; for encoding, parser, path, WAF, or filter mutations, load `/bypass` instead of duplicating bypass content here.
11. Load `$HARNESS_ROOT/prompts/access-control-playbook.md` only for deep review, stuck analysis, or report writing.

## Sub-Agent Rule

The parent agent scouts and classifies. Spawn a focused child when:
- more than one lane is plausible
- the lane needs different accounts/roles/tenants
- mutation work moves into `/bypass`
- one live request must be captured or intercepted through `/single-request-grabber`
- the finding needs separate verification from the scout

Give the child only:
- flow summary and full URL(s)
- account/resource boundary
- owned account aliases, user/resource IDs, PwnFox colors, role/tenant relationship, and any account-level destructive restrictions from `/account-management`
- one technique pack
- mutation pack path, if needed
- token claim/header summary with secrets redacted, if JWT-driven
- relevant request/response shape
- evidence path
- stop condition

## Proof Standard

Promote only if the evidence shows unauthorized read, list, export, write, delete, workflow transition, privileged action, or cross-tenant access.

Do not promote public data, response-size differences, soft redirects, generic errors, UI-only hiding, or caller-owned data.

Stop on non-owned private data after minimum proof. Normal create/update/delete
actions on owned objects are allowed when they are ordinary application behavior
for that object, such as deleting an owned note to test whether arbitrary note
deletion is possible. Stop and ask before account deletion, permanent important
data loss, paid/staff-visible actions, or changes where ownership is unclear.
