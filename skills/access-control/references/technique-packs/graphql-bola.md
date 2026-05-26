# GraphQL BOLA

## Related Terms

- GraphQL IDOR
- GraphQL BOLA
- GraphQL resolver authorization
- GraphQL global ID
- GraphQL node ID
- GraphQL mutation authorization

## Detection Keywords

```text
id, ids, node, nodeId, cursor, gid, userId, accountId, ownerId,
workspaceId, projectId, organizationId, tenantId, fileId, documentId
```

## Try

- Load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md` for GraphQL/global-ID object mutations.
- Treat every query argument that selects an object as an authorization boundary.
- Test mutations separately from queries.
- Decode base64/global IDs only to identify object type and source ID.
- Compare resolver behavior across list, node, direct object, and search queries.
- Test batch queries and fragments because resolver auth may differ.

## Proof

Query or mutation returns or changes an object outside the caller's allowed scope.

## Stop

No owned second account/object baseline exists.
