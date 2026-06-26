# MapStore Request Contracts

Status: draft
Owner: Ghost
Canonical path: `docs/mapstore-request-contracts.md`
Supersedes: none
Replaced by: none
Implementation commit: pending
Last reviewed: 2026-06-26

## Purpose

MapStore records reusable facts about app surfaces. Request contracts extend that
memory with replay-grade request templates so future agents can retest access,
auth, entitlement, parser, and feature-gate behavior when a new account, role,
token, or hypothesis appears.

The goal is:

- keep the MapStore entry queryable by URL, surface, gate, status, and retest
  state
- keep the replayable request artifact under the canonical mounted bounty root
- preserve source request provenance, such as proxy request ID, without depending
  on proxy history as the only source of truth
- avoid tag drift by generating search tags from controlled fields
- allow target-specific retest dimensions without forcing every app into one
  fixed role model

## Storage Layout

Request contracts live beside the program's recon artifacts.

```text
<canonical-root>/
  recon/
    maps/
      map.jsonl
    requests/
      <host>/
        <stable-request-name>.json
```

Example:

```text
/home/ryushe/Shared/web_bounty/flourish/web/
  recon/
    requests/
      app.flourish.studio/
        api_data_table_csv_url.json
        api_company.json
        api_user_generate_sdk_token.json
```

MapStore entries should point to request artifacts with a path relative to the
canonical root, for example:

```json
"artifact": "recon/requests/app.flourish.studio/api_data_table_csv_url.json"
```

## MapStore Entry Shape

MapStore stores the searchable observation and pointer.

```json
{
  "url": "https://app.flourish.studio/api/data_table/{id}/csv-url",
  "surface": "ssrf-authz",
  "scope": "url",
  "tags": [
    "request-contract",
    "gate:feature",
    "status:403",
    "reason:no_access_to_feature",
    "retest:sdk_token"
  ],
  "artifact": "recon/requests/app.flourish.studio/api_data_table_csv_url.json",
  "source_proxy": {
    "system": "ryushe-caido",
    "request_id": 26306,
    "pwnfox_color": "blue",
    "captured_at": "2026-06-25T19:47:43Z"
  }
}
```

Proxy IDs are provenance, not the only replay source. If proxy history is gone,
the local request artifact should still be enough to rebuild the request shape
with a current auth seed.

## Request Artifact Shape

Request artifacts store replay shape, baseline results, and retest state. They
must not store raw cookies, CSRF tokens, SDK tokens, bearer tokens, API keys, or
other secret values.

```json
{
  "schema": "mapstore.request_contract.v1",
  "name": "live_csv_url_feature_gate",
  "program": "flourish",
  "family": "web_bounty",
  "lane": "web",
  "method": "POST",
  "url_template": "https://app.flourish.studio/api/data_table/{owned_data_table_id}/csv-url",
  "auth_refs": {
    "blue_session": "credentials/auth_seeds/blue.json",
    "cyan_session": "credentials/auth_seeds/cyan.json"
  },
  "header_names": [
    "cookie",
    "csrf-token",
    "content-type"
  ],
  "body_template": {
    "live_csv_url": "https://owned-callback.example/csv",
    "version_number": 1
  },
  "gate": {
    "type": "feature",
    "status": 403,
    "reason": "no_access_to_feature",
    "body_fingerprint": "error.message contains You do not have access to that feature"
  },
  "retest_matrix": {
    "basic_user": false,
    "canva_linked_user": false,
    "sdk_token": null,
    "paid_plan": null,
    "company_admin": null
  },
  "retest_notes": {
    "basic_user": "2026-06-23: cyan returned 403 feature gate.",
    "canva_linked_user": "2026-06-23: Canva-linked account still returned 403."
  },
  "last_retested_for": [
    "basic_user",
    "canva_linked_user"
  ],
  "next_retest_when": [
    "sdk_token_available",
    "paid_plan_available",
    "company_account_available"
  ],
  "source_proxy": {
    "system": "ryushe-caido",
    "request_id": 26306,
    "pwnfox_color": "blue",
    "captured_at": "2026-06-25T19:47:43Z"
  },
  "safety": {
    "owned_resource_required": true,
    "destructive": false,
    "notes": "Use owned data table only. Do not send internal SSRF payloads until public callback confirms gate bypass."
  }
}
```

## Retest Matrix Rules

The `retest_matrix` is intentionally extensible. Different targets have
different meaningful auth states, so agents may add custom keys when the local
app model needs them.

Rules:

- Keys must be lowercase `snake_case`.
- Values must be `true`, `false`, or `null`.
- `true` means access or bypass worked in that auth context.
- `false` means tested and blocked in that auth context.
- `null` means not tested yet.
- Every `true` or `false` entry should have a short matching
  `retest_notes.<key>` entry with date, account/role label, and result summary.
- Agents should reuse existing keys in the same program before adding a new one.
- Agents should prefer specific keys over vague keys.

Good keys:

- `basic_user`
- `linked_user`
- `same_user_fresh_session`
- `sdk_token`
- `company_member`
- `company_admin`
- `admin_user`
- `paid_plan`
- `cross_account_user`
- `tenant_admin`

Avoid vague or drifting keys:

- `normal`
- `newauth`
- `user2`
- `worked`
- `company`
- `feature`

If a target has a unique role or entitlement, add it in snake_case and explain
it in `retest_notes`, for example `canva_linked_user`,
`workspace_owner`, or `billing_admin`.

## Controlled Gate Fields

Use controlled field values for automation. Tags should be generated from these
fields instead of invented by hand.

Suggested `gate.type` values:

- `auth`
- `csrf`
- `feature`
- `plan`
- `role`
- `company`
- `tenant`
- `ownership`
- `object_acl`
- `parser`
- `unknown`

Suggested `gate.reason` values:

- `auth_required`
- `missing_token`
- `missing_sdk_token`
- `csrf_required`
- `csrf_mismatch`
- `invalid_permissions`
- `not_in_company`
- `no_access_to_feature`
- `plan_required`
- `role_required`
- `owner_required`
- `tenant_required`
- `acl_permission`
- `parser_before_auth`
- `not_found_or_hidden`
- `unknown`

Agents may introduce a new `gate.reason` only when none of the existing reasons
fits. New reasons must be lowercase snake_case and should be added to the local
normalizer/tag-maker list in the same change.

## Generated Tags

Search tags should be generated from structured fields:

```text
request-contract
gate:<gate.type>
status:<gate.status>
reason:<gate.reason>
retest:<matrix-key>        # for null entries worth retesting
tested:<matrix-key>        # for true/false entries already tested
```

Examples:

```text
request-contract
gate:company
status:403
reason:not_in_company
tested:basic_user
retest:sdk_token
retest:company_admin
```

Do not hand-write near-duplicates such as `company-gate`,
`company_gate`, `not-company`, and `company-only`. Use the controlled fields and
generated tags.

## Helper Script

Use `agents/map_request_tags.py` to normalize request-contract gate, retest, and
tag metadata.

Example:

```bash
python3 agents/map_request_tags.py explain \
  --gate company \
  --status 403 \
  --reason not_in_company \
  --tested basic_user=false \
  --tested same_user_fresh_session=false \
  --next sdk_token \
  --next company_admin
```

It should output:

- normalized `gate`
- normalized `retest_matrix` patch
- canonical generated tags
- warnings for unknown gate/reason names
- suggestions for equivalent known keys when a likely drift term appears

The helper supports custom retest keys, but enforces snake_case and warns when a
key looks vague.

## Agent Workflow

When an agent sees a replayable MapStore entry:

1. Query MapStore by URL, surface, tags, or structured field.
2. Open the `artifact` under the mounted bounty root.
3. Resolve current auth from `auth_refs` or the account registry.
4. If needed, use `source_proxy.request_id` only to recover exact original
   shape or provenance.
5. Replay through the agent testing lane, not Ryushe's proxy lane, unless a
   skill explicitly allows same-host proxy replay.
6. Update `retest_matrix`, `retest_notes`, `last_retested_for`, and
   `next_retest_when`.
7. Regenerate tags and write the updated observation back to MapStore.

## Maintenance Check

- Existing canonical artifact checked: `skills/map-store/SKILL.md`,
  `skills/map-store/references/map-store-reference.md`,
  `agents/map_store.py`
- Neighboring patterns checked: error-mapper request/result artifacts,
  auth seed references, proxy-curl guidance
- Duplicate logic/spec risk: low
- Merge/deprecation plan: keep this as the canonical design doc for request
  contracts; `agents/map_request_tags.py` owns the first normalization helper
