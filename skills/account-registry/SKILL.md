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
2. Before consuming an inventory, validate it is a JSON object, its schema version is supported, and it is not retired.
3. A registry with `status: retired` is a hard error, not an empty account fleet. Surface its `replaced_by` path directly.
4. When migrating a registry, preserve and reconcile its complete non-secret data before retiring the old path. Use a small `status: retired` / `replaced_by` tombstone only when consumers support it and retaining the path is intended. For explicitly authorized removal of a redundant root, archive outside the synced tree, remove the legacy root, and put replacement guidance in shared metadata—not a compatibility symlink or second writable registry.
5. Update every reader, example environment file, skill/playbook, and lease helper in the same change. A default-path change is incomplete if an exported environment variable can still override it to the old root.

## Retiring a redundant synced registry

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
primary account; if none is available, surface eligible ordinary-account
fallbacks and choose one explicitly. A terminal run releases its exact lease
immediately so it returns to the pool. Keep lockouts or step-up sessions
unavailable/`needs-refresh` until a dedicated repair/re-authentication lease
records a healthy release.

Lease selection must fail closed. An account is eligible only when both are explicit:

```text
lifecycle: active
browser_lease_enabled: true
```

Historical session notes are not a current clearance. Leave accounts unavailable until a current, scoped health check confirms them. When a currently leased account later becomes unavailable, status output must still show its safe active-lease metadata so an operator can release or hand it off.

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

### Program auth policy and autonomous recovery

Keep auth operations out of scope authorization: published program policy controls
what the program permits to test, while the program's resolved `auth-policy.json`
controls the non-secret mechanics for obtaining the selected owned account.
The resolver must load both the program auth policy and account registry; do not
infer passwordless, password+OTP, proxy portability, or manual-handoff behavior
from prose.

The auth policy may specify session mode, login method/URL, approved OTP channel,
browser-native post-login check, and recovery order. The registry supplies only
exact owned-account facts and opaque references such as `bitwarden:<item>` and
`gmail:<owned-alias>`; never write credentials, OTPs, magic links, cookies, or
tokens into either file.

Recovery order: reuse the exact healthy owned profile → lease/provision that
profile → run the policy-declared owned browser login (Bitwarden/password and
approved Gmail OTP only for the initiating account flow) → verify in the same
browser → create private Tailscale Serve/SSH handoff only for CAPTCHA, passkey or
wallet confirmation, lockout, missing/ambiguous OTP, unexpected step-up, or
failed verification. Preserve the exact lease as `awaiting-input` while paused.

Treat an explicit Ryushe phrase such as “pull from my proxy” as a natural-language
one-run transport exception for the exact program/account/host. It must never
rewrite policy or inventory, must leave non-secret run provenance, and must not
turn active testing into Ryushe-proxy traffic. On the next autonomous run, revert
to normal policy. See `references/program-auth-recovery.md` for the
separation of authority and `account-management` for the current resolver.

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

### Shared-loader invariant

Put JSON parsing, tombstone rejection, schema validation, v1→current migration, and account-default normalization in one importable schema module. Every consumer—including account CLI, auth resolver, and browser lease helper—must call it. Do not accept a version in one reader that another rejects.

A fresh `add-account` record and a migrated legacy record must have the same materialized fail-closed representation:

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

- Source the checked-in example config and assert it selects `web_bounty`.
- Exercise every reader against a tombstone and assert a non-zero, replacement-directed error.
- Exercise a canonical inventory lookup and one eligible/unavailable lease status.
- Run the focused account-inventory, resolver, Chromium-launcher, and browser-lease tests.
- Search adjacent orchestrators (for example AutoRecon) for direct inventory consumers; either route each through the canonical helper or record that the bounded source audit found none.
- Search user-facing skills and playbooks for literal inventory paths; update them to the normalized-program form in the same change.
- Confirm no legacy registry remains writable or authoritative.
