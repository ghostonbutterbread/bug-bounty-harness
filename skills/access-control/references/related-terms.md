# Access Control Related Terms

Use this as the search vocabulary and first-pass scent list. Do not load every technique pack at once.

## Core Terms

- broken access control
- authorization bypass
- IDOR
- BOLA
- object-level authorization
- function-level authorization
- privilege escalation
- horizontal privilege escalation
- vertical privilege escalation
- tenant isolation
- role confusion
- forced browsing

## Object And Reference Terms

- user ID tampering
- account ID tampering
- organization ID tampering
- workspace ID tampering
- project ID tampering
- direct object reference
- predictable object IDs
- UUID disclosure
- GUID disclosure
- leaked object handles
- GraphQL global ID
- cursor abuse
- node ID authorization

## Workflow Terms

- context-dependent access control
- multi-step access control bypass
- workflow bypass
- stale token replay
- expired invite reuse
- one-time link replay
- pre-signed URL reuse
- approval bypass
- checkout step bypass
- finalize authorization bypass

## Bypass Terms

Load `/bypass` for these instead of expanding here:

- HTTP method override
- path normalization bypass
- encoded slash bypass
- trailing slash bypass
- case sensitivity bypass
- extension suffix bypass
- content type confusion
- Referer-based access control
- Origin header bypass
- X-Original-URL
- X-Rewrite-URL
- X-HTTP-Method-Override

## API And Messaging Terms

- REST BOLA
- GraphQL IDOR
- GraphQL authorization bypass
- GraphQL resolver authorization
- batch endpoint authorization
- bulk update authorization
- mass assignment authorization
- nested object authorization
- websocket authorization bypass
- RPC authorization bypass

## Storage And Media Terms

- signed URL authorization
- CDN object authorization
- storage bucket object IDOR
- file download IDOR
- export link authorization
- attachment access control
- avatar delete IDOR
- media object ownership

## Route And Parameter Keywords

```text
id, ids, user_id, account_id, customer_id, owner_id, member_id,
org_id, organization_id, tenant_id, workspace_id, team_id, project_id,
role, permission, is_admin, admin, owner, editor, viewer, support,
invite_id, export_id, file_id, document_id, folder_id, asset_id,
order_id, invoice_id, payment_id, subscription_id, plan_id,
webhook_id, integration_id, token, key, session, node_id, cursor,
uuid, guid, gid, slug, handle
```
