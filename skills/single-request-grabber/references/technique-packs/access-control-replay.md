# Access-Control Replay

Use when a live request must be replayed or modified across approved accounts, roles, tenants, workspaces, or owned resources.

## Checks

- Confirm both source and target accounts/resources are approved and record aliases.
- Record role, tenant, workspace, ownership, and destructible status.
- Modify only the identifier, workspace, tenant, role, or resource field under test.
- Compare expected denial/allow behavior against actual behavior.

## Allowed Modifications

- source owned resource ID -> target approved owned resource ID
- account A session -> account B approved comparison session
- workspace/team/project ID within approved test set
- role/tenant header only if `/headers` owns the mechanism

## Evidence Required

- Account/resource aliases, not secrets.
- Authorization expectation.
- Baseline request and modified request summary.
- Response delta and before/after state when safe.

## Stop

Stop immediately if a real user/org resource appears, if ownership is uncertain, or if the action would be destructive without `destructible: yes`.
