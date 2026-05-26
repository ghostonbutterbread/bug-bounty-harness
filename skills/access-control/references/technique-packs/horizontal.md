# Horizontal Access Control

## Related Terms

- horizontal privilege escalation
- IDOR
- BOLA
- object ownership bypass
- user ID tampering
- direct object reference

## Detection Keywords

```text
user_id, account_id, customer_id, owner_id, member_id, profile_id,
file_id, document_id, order_id, invoice_id, uuid, guid, gid, node_id, cursor
```

## Try

- Load `$HARNESS_ROOT/skills/access-control/references/mutations/idor.md` for IDOR-specific object/reference mutations.
- Swap User A object ID into User B request.
- Compare list endpoint filtering against direct object fetch.
- Check 302, 401, and 403 response bodies for leaked private data.
- Find GUIDs in HTML, JS, exports, emails, or links, then fetch directly.
- Test batch, bulk, and export endpoints separately.

## Proof

User B reads, lists, exports, updates, deletes, or acts on User A private object.

## Stop

Non-owned private data appears, or no approved second owned account/resource exists. Capture minimum metadata and stop.
