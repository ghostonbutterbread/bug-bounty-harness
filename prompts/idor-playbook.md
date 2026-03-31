# IDOR Testing Playbook

## Overview

Use this as a decision tree: capture the baseline, map object references and ownership boundaries, choose the matching authorization lane, verify access with the correct account context, then report the exact object transition and impact.

## Decision Tree

1. Capture the legitimate baseline first.
2. Identify every object reference and ownership marker in the workflow.
3. If the object belongs to another peer user, go down the horizontal lane.
4. If the object is privileged or admin-scoped, go down the vertical lane.
5. If the workflow spans create, approve, redeem, or delete steps, go down the workflow lane.
6. Verify with the minimum cross-account access needed, then report the boundary failure.

## 1. Capture Baseline

Baseline quality determines whether an apparent access control gap is real.

1. Record the full authenticated request for User A.
2. If possible, capture the same object shape for User B.
3. Note:
   - HTTP method
   - endpoint path
   - query and JSON identifiers
   - hidden ownership fields
   - any role or tenant headers

If the request mutates state, capture before and after values so you can prove the change later.

## 2. Map Object References

Do not focus only on obvious numeric IDs.

### Coverage Checklist

- Path IDs and slugs
- Query parameters such as `id`, `user_id`, `account`, `order`, `tenant`
- JSON body fields that name users, resources, or assignees
- Export, download, and attachment handles
- Indirect references surfaced in responses, links, or web sockets

### Ownership Questions

- Who owns the object right now?
- Which account should be allowed to read it?
- Which account should be allowed to update or delete it?
- Does the server derive ownership from the session, or trust a client-supplied field?

## 3. Choose Lane

### Horizontal Lane

Use when the target object belongs to another user at the same privilege level.

1. Swap the object reference from User A to User B.
2. Compare the response to both baselines.
3. Check whether the server returns User B's data, not just a generic `200`.

### Vertical Lane

Use when the object or endpoint belongs to an admin or higher-trust role.

1. Identify the privileged resource or role-bound object.
2. Attempt access with the lower-privileged account.
3. Confirm whether the failure is only UI-level or whether the server actually enforces it.

### Write Lane

Use when the request changes state.

1. Replay the write against another user's object.
2. Confirm the server accepted the mutation.
3. Verify the change by re-fetching the object or observing side effects.

### Workflow Lane

Use when authorization may fail between steps rather than on a single fetch.

1. Map creation, approval, redemption, cancellation, sharing, and deletion steps.
2. Replay later steps with another user's identifiers or tokens.
3. Confirm whether ownership is rechecked at each transition.

## 4. Verify

Verification should prove broken authorization, not just identifier guessing.

### Verification Standard

1. Reproduce with the minimum identifier change needed.
2. Show one of:
   - another user's data returned
   - another user's data modified
   - privileged action accepted without the required role
   - workflow step completed on an unauthorized object
3. Compare the result to the legitimate baseline so a generic response is not mistaken for success.
4. Record whether the access works by direct ID swap, hidden field tampering, or role/header trust.

### Status Rules

- `Confirmed`: unauthorized read, write, delete, or transition succeeded.
- `Potential`: the server behavior differs, but ownership or impact is not yet proven.
- `False Positive`: the response is generic, cached, or still bound to the caller's own data.

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/idor/findings.md`

Include:

- IDOR type: horizontal, vertical, write, or workflow
- Exact object reference that was changed
- Caller account and unauthorized target account or role
- Method and endpoint
- Evidence of unauthorized access or state change
- Any headers, hidden fields, or workflow tokens involved
