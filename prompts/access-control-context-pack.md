# Access Control Context Pack

Use this as the progressive-disclosure index for `/access-control`.

Do not load every access-control reference at once. Load `related-terms.md`, classify the lane, then load one focused technique pack. If mutation tricks become the main task, switch to `/bypass`.

## Source Files

- Related terms and route keywords: `$HARNESS_ROOT/skills/access-control/references/related-terms.md`
- Account setup routing: `$HARNESS_ROOT/skills/access-control/references/account-setup.md`
- Temporary email creation: `/temporary-email` for disposable inbox/account setup when Ryushe requests it or when testing permanent account deletion.
- IDOR-specific object mutations: `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md`
- Horizontal access: `$HARNESS_ROOT/skills/access-control/references/technique-packs/horizontal.md`
- Vertical access: `$HARNESS_ROOT/skills/access-control/references/technique-packs/vertical.md`
- Tenant/workspace isolation: `$HARNESS_ROOT/skills/access-control/references/technique-packs/tenant.md`
- Workflow/context-dependent access: `$HARNESS_ROOT/skills/access-control/references/technique-packs/workflow.md`
- Auth-state access: `$HARNESS_ROOT/skills/access-control/references/technique-packs/auth-state.md`
- GraphQL BOLA: `$HARNESS_ROOT/skills/access-control/references/technique-packs/graphql-bola.md`
- Storage/CDN/export/media links: `$HARNESS_ROOT/skills/access-control/references/technique-packs/storage-links.md`
- Shared bypass mutations: `/bypass` and `$HARNESS_ROOT/prompts/bypass-playbook.md`
- Deep reference only when needed: `$HARNESS_ROOT/prompts/access-control-playbook.md`

## Router

- Missing approved owned accounts/resources -> use existing approved accounts, or `/temporary-email` if Ryushe requests a disposable account or the test may permanently delete/burn the account.
- Peer-owned resource/object -> horizontal pack or `/idor`
- Admin/support/owner/mod/paid function -> vertical pack
- Org/workspace/team/project/store boundary -> tenant pack
- Wrong order, stale state, replay, skipped step -> workflow pack
- Anonymous/logged-out/expired/stale session -> auth-state pack
- GraphQL IDs, nodes, cursors, mutations -> GraphQL BOLA pack
- Signed URLs, CDN objects, exports, attachments, media -> storage-links pack
- Method, header, path, parser, encoding, WAF, or URL-normalization trick -> `/bypass`
- IDOR/BOLA object, ownership, tenant, lifecycle, GraphQL ID, or storage-link mutation -> IDOR mutations pack

## Child Handoff

When spawning a category child, pass only:

- program and scope boundary
- full URL(s) and method(s)
- owned account/resource aliases
- account setup state, `/temporary-email` output when used, and missing account/resource blockers
- relevant request/response shape
- one technique pack path
- mutation pack path, if needed
- whether `/bypass` is allowed
- evidence path
- stop condition

## Local Note Anchors

Use only if a lane needs expansion:

- `/home/ryushe/.openclaw/workspace/memory/bugbounty_methodology.md`
- `/home/ryushe/.openclaw/workspace/memory/bugbounty_advanced_methodology.md`
- `/home/ryushe/.openclaw/workspace/memory/2026-03-11-lfi-idor-learning.md`
- `/home/ryushe/.openclaw/workspace/memory/2026-03-18.md`
- `/home/ryushe/notes/appsec/ghost-field-notes/2026-05-25-pfp-common-vulns.md`
