# IDOR Reference Mutations

Use this for object, ownership, tenant, and lifecycle mutations. If the main question becomes encoding, parser confusion, method override, path normalization, trusted headers, or WAF behavior, switch to `/bypass`.

## Account Baseline

IDOR needs comparison accounts.

- Prefer two approved owned accounts at the same privilege level.
- For vertical checks, use an approved low-privileged account and approved higher-privileged baseline.
- For tenant checks, use two approved owned workspaces/orgs/projects.
- If accounts are missing, stop and request account setup instead of guessing.
- Look for stored account context under `$HARNESS_SHARED_BASE/{program}/credentials/`.
- Do not print cookies, bearer tokens, auth headers, passwords, or session values.

## Object Reference Mutations

- Swap User A object ID into User B request.
- Swap only the parent ID: `workspace_id`, `project_id`, `org_id`, `account_id`.
- Swap only the child ID: `file_id`, `document_id`, `order_id`, `invoice_id`, `asset_id`.
- Mismatch parent and child: owned parent with another owned account's child object.
- Replace numeric ID with UUID/GUID discovered elsewhere.
- Replace UUID/GUID with numeric/internal ID if both appear in traffic.
- Use copied, cloned, imported, archived, deleted, or transferred object IDs.
- Reuse an object ID after ownership, membership, visibility, or lifecycle changes.

## Ownership Field Mutations

- Change `owner_id`, `created_by`, `user_id`, `account_id`, `member_id`.
- Omit the ownership field and see whether the server derives it from session.
- Send conflicting ownership in path, query, and body.
- Duplicate ownership fields with different values.
- Mutate nested ownership fields: `owner.id`, `user.id`, `assignee.id`.
- Mutate arrays: `members[]`, `user_ids[]`, `account_ids[]`, `owners[]`.

## List Versus Direct Fetch

- Get object IDs from a list response, then direct-fetch them from another owned account.
- Direct-fetch objects that list/search/export correctly filters out.
- Compare `/objects/{id}` with `/users/{user_id}/objects/{id}`.
- Test read, update, delete, export, download, and finalize endpoints separately.
- Mix authorized and unauthorized IDs in batch/bulk requests.

## Tenant And Workspace Mutations

- Swap `tenant_id`, `org_id`, `workspace_id`, `team_id`, `project_id`, `store_id`.
- Use role/membership from tenant A against object in tenant B.
- Reuse invite/member IDs across workspaces.
- Change active workspace header/cookie while object ID stays fixed.
- Omit tenant/workspace ID and check default/current workspace assumptions.

## GraphQL And Opaque ID Mutations

- Swap GraphQL `id`, `nodeId`, `gid`, `cursor`, and object argument values.
- Test `node(id:)`, direct object resolvers, list resolvers, and mutations separately.
- Decode base64/global IDs only to identify object type and source ID.
- Mutate nested input IDs in create/update/bulk mutation inputs.
- Batch authorized and unauthorized IDs in the same query or mutation.

## Lifecycle And Stale Reference Mutations

- Access draft, pending, archived, deleted, private, expired, or cancelled object IDs.
- Replay object IDs after ownership transfer.
- Replay invite/export/download/finalize IDs after revocation or expiration.
- Update or delete after membership removal.
- Retry after logout, account switch, role downgrade, or plan change.

## Storage And Media Mutations

- Swap avatar, media, crop, transform, version, export, and attachment IDs.
- Compare original file URL against transformed/CDN URL authorization.
- Access old media versions after replacement.
- Delete or finalize another owned account's uploaded-but-not-finalized object.
- Reuse pre-signed object keys after logout, expiration, deletion, or role removal.

## Encoding-Like Cases

Keep these IDOR-specific. For general encoding/parser tricks, use `/bypass`.

- Base64/global IDs that encode object type and source ID.
- Hashids or opaque IDs that map to internal IDs.
- URL-encoded object keys in download/export/media paths.
- JSON number versus string: `123` vs `"123"`.
- Scalar versus array: `id=1`, `ids[]=1`, `ids=[1,2]`.
- Composite IDs: `user:123`, `project:456:file:789`.
- Cursors or page tokens that embed user, tenant, or object scope.

## Proof

The mutation must prove unauthorized read, list, export, write, delete, finalize, workflow transition, or cross-tenant access.

## Stop

Stop when non-owned private data appears, when account baselines are missing, or when the next step would affect real users, billing, messages, purchases, deletion, or public state.
