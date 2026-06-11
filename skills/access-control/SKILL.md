---
name: access-control
description: "Route broken access control, IDOR, BOLA, role, tenant, workflow, method, header, path, and auth-state testing into focused authorization lanes."
---

# Access Control

Use for broken access control, IDOR/BOLA, role confusion, tenant isolation, workflow authorization, unauthenticated access to authenticated-only resources, and object/function-level authorization bugs.

This is a router skill. Keep the first pass small: classify the boundary, load one focused reference pack, then spawn or hand off when the category changes.

## Load Order

1. Read scope, owned-account context, and live-testing policy.
2. Resolve `$HARNESS_ROOT` first; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Load `/account-management` and check `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json` for owned accounts, user IDs, PwnFox lanes, object IDs, and destructible/cleanup status.
4. Read `$HARNESS_ROOT/skills/access-control/references/account-setup.md`.
5. Confirm the needed owned accounts/resources exist and record whether each is `destructible: yes|no|unknown`. If not, ask for the account path, or use `/temporary-email` when a disposable/destructible account is needed.
6. Check `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/` for existing `/live-map` routes, objects, hypotheses, and handoff packets. Use map entries as exploration leads, not proof.
7. Read `$HARNESS_ROOT/skills/access-control/references/related-terms.md` for search vocabulary and route/parameter keywords.
8. Classify the lane:
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
- owned account aliases, user/resource IDs, PwnFox colors, role/tenant relationship, and destructible status from `/account-management`
- one technique pack
- mutation pack path, if needed
- token claim/header summary with secrets redacted, if JWT-driven
- relevant request/response shape
- evidence path
- stop condition

## Proof Standard

Promote only if the evidence shows unauthorized read, list, export, write, delete, workflow transition, privileged action, or cross-tenant access.

Do not promote public data, response-size differences, soft redirects, generic errors, UI-only hiding, or caller-owned data.

Stop on non-owned private data after minimum proof. Also stop before destructive actions unless the account/resource is explicitly marked `destructible: yes`. Capture metadata and ask Ryushe before expanding.
