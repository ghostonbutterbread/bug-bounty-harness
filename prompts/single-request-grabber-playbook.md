# Single Request Grabber Playbook

Use this when one live request must be captured and safely modified.

This skill is the proxy-intercept primitive. It should help an agent get the request it could not safely synthesize: live CSRF token, browser-generated body, exact cookies, current workspace context, or one-time action state.

## Safety Boundary

- One action.
- One source owned session.
- One approved target account/resource context, when doing cross-account comparison.
- One bounded mutation.
- Approved account/resource set only.
- No raw secret material in notes.
- No destructive action unless the target resource is explicitly `destructible: yes`.

## Operating Modes

### Observe Then Replay

Use when the request can be captured from proxy/MCP history and replayed safely.

1. Trigger the action in an owned session.
2. Locate the request in proxy/MCP history.
3. Copy a sanitized request summary.
4. Modify one approved field.
5. Replay once or a very small bounded set.

### Intercept Then Modify

Use when the token is per-action/per-request and a replayed old request would fail.

1. Prepare the browser/proxy.
2. Trigger the action in the owned session.
3. Pause/intercept the outgoing request when the token is fresh.
4. Modify only the approved field.
5. Forward the request once.
6. Capture before/after evidence.

### Source Account To Approved Target Resource

Use when the source account can generate the correct live request, but the test asks whether the server enforces authorization on the target account/resource.

1. Create or select an approved target resource.
2. Confirm whether it is `destructible: yes|no`.
3. Trigger the source-account action only far enough to capture the outgoing request.
4. Change exactly one authorization-relevant field, such as user ID, resource ID, workspace ID, tenant ID, role ID, or account cookie/session context.
5. Forward/replay once.
6. Route the result to `/access-control` or `/idor` after logging the trail.

Do not run this against real-user resources. For dangerous actions such as account deletion, billing changes, ownership transfer, email/password/MFA changes, or invite/removal flows, the target must be an approved throwaway/destructible resource.

## Action/Error Trail

Write one trail entry per captured request:

```text
single-request-grabber:
- goal:
- mode: observe-replay | intercept-modify
- account/session alias:
- resource alias:
- destructible: yes|no
- full URL:
- method:
- request source: browser | caido history | caido MCP | intercepted proxy
- token handling: present redacted | absent | extracted from owned flow
- mutation:
- result:
- routed skill:
- stop condition:
```

## Route Matrix

| Signal | Route |
|--------|-------|
| fresh CSRF token needed | `/csrf` plus CSRF token pack |
| same action across approved accounts | `/access-control` or `/idor` |
| header, content-type, method, or request-shape repair | `/headers` |
| unexpected error response | `/error-triage` |
| proxy setup needed | `/agent-proxy`, `/caido`, or `/chromium-test` |

Routing happens after the single-request operation unless setup is blocked. The skill should not abandon the capture just because the eventual impact belongs to CSRF, IDOR, access control, or headers.

## Stop Conditions

Stop before deleting, purchasing, inviting, changing email/password/MFA, transferring value, or modifying non-owned resources unless the exact resource is approved and marked `destructible: yes`.
