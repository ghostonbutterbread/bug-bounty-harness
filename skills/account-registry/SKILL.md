---
name: account-registry
description: "Maintain canonical non-secret account registries, migrations, and lease eligibility."
---

# Account Registry

Use when consolidating, moving, validating, or consuming reusable owned-account metadata across bounty programs. This complements `account-management`, which owns account/resource content and auth handoff.

## Canonical location

Resolve the canonical non-secret inventory with `account-management` and
`bbh skills/account-management/scripts/account_inventory.py show <program>`.
Under the documented default shared base it is:

```text
${HARNESS_SHARED_BASE:-$HOME/Shared/web_bounty}/{normalized-program}/credentials/account_inventory.json
```

Do not create a parallel Markdown account table or a second program registry. Browser profiles and secret-bearing auth seeds remain local and restricted; registries contain only non-secret pointers and metadata.

### Program-path consumer invariant

One selected testing program must map to exactly one normalized registry path
for **every** account consumer: inventory CLI, auth resolver, Chromium launcher,
and browser-profile lease helper. Put program-key normalization and path
construction in one importable helper; consumers must not independently choose
case rules, separator handling, or append a browser lane such as `web/` beneath
the registry. Add a focused regression that invokes all consumers with a
separator-bearing label (for example, `Acme Platform`) and asserts the same
canonical path.

## Read and migration rules

1. Resolve `HARNESS_SHARED_BASE` through the account-management helper; its documented default is `$HOME/Shared/web_bounty`.
2. For an inspected inventory, validate the JSON object and supported schema version using `account_inventory.py` before planning a migration. Do not assume all consumers enforce those checks: the Chromium launcher currently accepts retired inventories, and the auth resolver and browser lease helper do not reject unsupported schema versions.
3. Do **not** publish a `status: retired` tombstone as a hard stop yet. The account CLI, auth resolver, and lease helper reject it with `replaced_by`, but the Chromium launcher does not. Until every consumer rejects it, retirement is not an enforced cross-consumer boundary; preserve the legacy source and avoid directing agents through it.
4. When migrating a registry, preserve and reconcile its complete non-secret data before retiring the old path. Use a small `status: retired` / `replaced_by` tombstone only **after** all consumers demonstrably support it and retaining the path is intended. For explicitly authorized removal of a redundant root, archive outside the synced tree, remove the legacy root, and put replacement guidance in shared metadata—not a compatibility symlink or second writable registry.
5. Update every reader, example environment file, skill/playbook, and lease helper in the same change. A default-path change is incomplete if an exported environment variable can still override it to the old root.

## Retiring a redundant synced registry

This sequence is a migration plan, not permission to retire a live registry
while the cross-consumer gates above still fail.

1. Bound discovery to the exact legacy inventories and their canonical counterparts; do not recursively scan unrelated corpora. Reject unexpected files or symlink ancestors before acting.
2. Compare aliases with duplicate detection, then distinguish missing accounts from differing historical metadata. Equal alias sets do not prove equal records: preserve the full originals and do not overwrite canonical lifecycle, identity, or auth fields merely to reconcile duplicates.
3. Prepare every participating host before any cloud mutation: save its complete legacy bytes outside synced roots, restrict backup permissions, and record SHA-256 manifests plus canonical inventory hashes. Verify each backup; a cloud move can remove a peer's source before that peer acts.
4. Retire through one cloud publisher using the exact inspected node handle and a verified-unused rubbish destination. Preserve versions rather than permanently deleting them. Recheck each host: an already-absent source is acceptable only after its backup and cloud retirement verify; archive any unchanged residual tree locally.
5. Read back absence on both hosts and the active cloud path, recoverability of the exact archived cloud node, backup hashes, and unchanged canonical hashes. Publish one concise replacement note and verify peer arrival. Report this bounded retirement separately from global sync health or untested legacy consumers.

## Lease eligibility

### Primary IDOR accounts and lease visibility

For reusable owned second identities in IDOR/BOLA work, maintain an ordered
program-level `primary_idor_accounts` list of existing ordinary owned aliases.
It is selection metadata only: it does not alter an account's role, email, or
permission, and it does not authorize a silent identity substitution.

Immediately before an IDOR run, query the profile-host lease helper for the
current primary-account and PwnFox-color state. Prefer an explicitly available
primary account for **lease acquisition**; if none is available, surface
eligible ordinary-account fallbacks and choose one explicitly. `available`
means lease-eligible and not locked, **not** verified authenticated or cleared
for a target request: a first acquisition can be available without any prior
healthy release. Check the chosen identity's current auth/session health in
its exact owned profile before using it for IDOR work; if that check fails,
stop testing and release as `needs-refresh`, not `healthy`. A terminal run
releases its exact lease immediately with the observed disposition. Keep
lockouts or step-up sessions unavailable/`needs-refresh` until a dedicated
repair/re-authentication lease records a healthy release.

Lease selection requires `browser_lease_enabled: true` and an explicit
`lifecycle: active`; the current lease helper also accepts legacy
`lifecycle: live`. Do not present `active` as the only enforced value until that exception
is removed with a tested migration. Neither a missing lifecycle nor a missing
lease flag is eligible. New or edited records should use:

```text
lifecycle: active
browser_lease_enabled: true
```

Historical session notes and lease `available` are not a current authentication
clearance. The helper does not perform a live health check on first acquisition;
do not use the lease for target work until the current, scoped check succeeds.
When a currently leased account later becomes unavailable, status output must
still show its safe active-lease metadata so an operator can release or hand it
off.

## Schema and handoff fields

Each account record should carry non-secret values for `role`, `tier`, `lifecycle`, `browser_lease_enabled`, `organization_access`, and session-health provenance. Resolver-safe outputs and lease summaries must expose the same non-secret capability fields.

### Session transport policy

Store a program-level `auth_session_mode` in the inventory, with an optional
account-level override when a host/account genuinely differs. Valid values are:

- `browser-bound`: session material must remain in the exact browser profile
  that owns the login. The resolver and browser launcher must reject proxy
  extraction, seed inspection/injection, and direct replay—even if a caller
  supplies an explicit auth-seed path. Return a structured browser-handoff
  result instead: exact profile lease, loopback-only Tailscale Serve handoff,
  SSH-loopback fallback, `awaiting-input`, then in-browser revalidation.
- `proxy-replayable`: the selected account may use only its explicitly approved
  proxy/session source before active traffic resumes through the task MITM lane.
- `hybrid`: retain the approved safe seed/proxy/secret-store fallback sequence.
- `unknown`: do not infer that copied session material is safe; resolve the
  program policy or use the browser-handoff path.

`auth_refresh_source` answers *where* an approved refresh may be found;
`auth_session_mode` answers whether that material may leave its owner browser.
Do not conflate them.

### Browser-bound recovery and current implementation

Published program policy controls what may be tested. The inventory supplies
non-secret account identity and `auth_session_mode`; it is not an authorization
policy or an executable login recipe. `auth_resolver.py resolve` currently returns
`needs-browser-handoff` for `browser-bound` sessions without inspecting or
copying a seed. Follow `account-management` and the browser owner's exact-profile
lease/handoff contract; any browser-native login must follow the approved
account workflow and be verified in that same browser. If it cannot complete,
retain the lease as `awaiting-input` and give the private Tailscale/SSH handoff.
Do not claim that the resolver loads a program `auth-policy.json`, performs OTP
login, or provisions that handoff automatically: those are not implemented by
this registry skill. Keep Bitwarden, mailbox, and session secrets out of the
inventory. See `references/program-auth-recovery.md` for the ownership split.

When schema changes, provide an explicit migration for prior records or reject unsupported versions. Never silently relabel an old schema version.

### Central integration profile

A program may designate exactly one existing **owned** account as its active `integration-profile` for explicitly requested external-service connections. Store only a non-secret account-alias pointer, lifecycle/status, and provenance in the canonical inventory; the profile is not a new email, does not rename the selected account, and does not broaden its access.

Resolvers may accept `integration-profile` as a selector only when the record is explicit, active, and points to a current owned account whose `lifecycle` is also `active`. Missing, inactive, malformed, or dangling designations must fail closed—never silently substitute another account. Linked social identities and integrations remain attached to the underlying account record with their non-secret provider/connection/status/capability provenance.

Reserve both `integration-profile` and `integration_profile`: reject them as ordinary account aliases, check the reserved selector before normal alias lookup, and fail closed if a legacy/manual collision exists even when a designation is otherwise active. Enforce case-insensitive alias uniqueness in the shared loader and account writer. For resolver safety, the designated alias must resolve to exactly one case-insensitive candidate whose stored alias exactly matches the designation; do not use a case-folded dictionary with last-record-wins behavior.

When evolving the schema for this designation, migrate prior inventories to an explicit unset value and test: designation of an existing active account, selector resolution through both ledger and auth paths, preservation of existing links during upserts, inactive/dangling rejection, reserved-alias collisions with and without a configured designation, and case-variant duplicate aliases.

### Provider integration-account selection

Before an agent creates, connects, reconnects, or reauthorizes provider `<provider>`, it must read the canonical inventory for the active integration profile and every existing `<provider>` integration. Treat `connected` and `unknown` records as occupied; absence of a record is not proof that an account is available.

Then follow the approved Bitwarden preflight and count only active owned accounts with an approved `bitwarden:<item>` reference. Prefer an existing active, Bitwarden-ready, provider-available account; the usable provider pool is bounded by those valid owned entries. If no candidate is clearly available, stop before signup or connection creation rather than creating another account from incomplete state. Creation of a new non-disposable email/credential remains an owner decision.

Immediately after a successful connection, write the exact underlying account's non-secret provider/connection-or-external-handle/status/capability/source record. A child handoff that created or observed a connection must include that registry update command or patch; never use the `integration-profile` alias as a substitute for recording the concrete account.

### Shared-loader migration target (not yet implemented)

There is no single shared inventory loader today. The account CLI, auth resolver,
Chromium launcher, and browser lease helper use separate readers; the account
CLI validates schema versions, but the others do not. Before relying on
cross-consumer retirement or version rejection, implement JSON parsing,
tombstone rejection, schema validation, v1→current migration, and account-default
normalization in one importable module. Route **every** consumer through it,
including Chromium, and test that none accepts a version another rejects.

The migration target is for a fresh `add-account` record and a migrated legacy
record to have the same materialized fail-closed representation:

```json
{
  "role": "unknown",
  "tier": "unknown",
  "lifecycle": "unknown",
  "browser_lease_enabled": false,
  "organization_access": [],
  "capabilities": []
}
```

## Verification

- When changing the non-secret inventory secret guard, first keep benign prose
  and opaque references writable. Test synthetic credential assignments in JSON,
  header containers, indexed keys, URL-decoded query keys, camelCase, and
  prefixed/suffixed names against the old and new guards. A regex ending a secret
  word at `\b` can miss `token_value` or `secret_access_key`. Keep real secrets
  out of fixtures, logs, and review handoffs; request independent full-diff
  review of the acceptance boundary after focused tests.
- Source the checked-in example config and assert it selects `web_bounty`.
- Before any retirement, exercise **every** reader against a tombstone and assert a non-zero, replacement-directed error. This gate currently fails for the Chromium launcher; do not retire on the basis of the account CLI alone.
- Exercise a canonical inventory lookup and one eligible/unavailable lease status.
- Run the focused account-inventory, resolver, Chromium-launcher, and browser-lease tests.
- Search adjacent orchestrators (for example AutoRecon) for direct inventory consumers; either route each through the canonical helper or record that the bounded source audit found none.
- Search user-facing skills and playbooks for literal inventory paths; update them to the normalized-program form in the same change.
- Only after the shared-loader migration and retirement checks pass, confirm no legacy registry remains writable or authoritative.
