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
3. Read `$HARNESS_ROOT/skills/access-control/references/account-setup.md`.
4. Confirm the needed owned accounts/resources exist. If not, ask Ryushe for the account path, or use `/temporary-email` when Ryushe requested a disposable account or the test may permanently delete/burn the account.
5. Read `$HARNESS_ROOT/skills/access-control/references/related-terms.md` for search vocabulary and route/parameter keywords.
6. Classify the lane:
   - peer object/resource access -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/horizontal.md`
   - admin/support/owner/moderator/paid functionality -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/vertical.md`
   - org/workspace/team/project/store isolation -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/tenant.md`
   - wrong order, stale state, replay, skipped step -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/workflow.md`
   - anonymous, logged-out, expired, or stale session -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/auth-state.md`
   - GraphQL arguments or global IDs -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/graphql-bola.md`
   - signed URLs, CDN objects, exports, attachments, media -> `$HARNESS_ROOT/skills/access-control/references/technique-packs/storage-links.md`
   - method/header/path/parser discrepancy -> load `/bypass` with type `403` or `idor`
7. For IDOR/BOLA object mutations, load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md`.
8. For encoding, parser, path, method, header, WAF, or filter mutations, load `/bypass` instead of duplicating bypass content here.
9. Load `$HARNESS_ROOT/prompts/access-control-playbook.md` only for deep review, stuck analysis, or report writing.

## Sub-Agent Rule

The parent agent scouts and classifies. Spawn a focused child when:
- more than one lane is plausible
- the lane needs different accounts/roles/tenants
- mutation work moves into `/bypass`
- the finding needs separate verification from the scout

Give the child only:
- flow summary and full URL(s)
- account/resource boundary
- approved account aliases and role/tenant relationship
- one technique pack
- mutation pack path, if needed
- relevant request/response shape
- evidence path
- stop condition

## Proof Standard

Promote only if the evidence shows unauthorized read, list, export, write, delete, workflow transition, privileged action, or cross-tenant access.

Do not promote public data, response-size differences, soft redirects, generic errors, UI-only hiding, or caller-owned data.

Stop on non-owned private data after minimum proof. Capture metadata and ask Ryushe before expanding.
