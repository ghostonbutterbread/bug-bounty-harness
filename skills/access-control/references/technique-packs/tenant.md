# Tenant And Workspace Isolation

## Related Terms

- tenant isolation bypass
- cross-tenant access
- workspace authorization bypass
- organization ID tampering
- team membership bypass
- role confusion across tenants

## Detection Keywords

```text
tenant_id, org_id, organization_id, workspace_id, team_id, project_id,
store_id, shop_id, group_id, member_id, role, owner_id, invite_id
```

## Try

- Load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md` for object, parent/child, and tenant-reference mutations.
- Swap tenant/workspace/project IDs between two owned contexts.
- Test role mismatch: viewer in one workspace, owner in another.
- Replay invites, removed memberships, and pending membership requests.
- Check storage/CDN keys that embed tenant or project IDs.
- Test admin APIs that accept explicit org/workspace IDs.

## Proof

Account crosses org/workspace/team/project boundary or reuses authority from one tenant in another.

## Stop

No approved second tenant/workspace baseline exists.
