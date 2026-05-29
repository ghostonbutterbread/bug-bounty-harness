# Single Request Grabber Playbook

Use this when one live request or one short action flow must be captured and safely modified.

This skill is the proxy-intercept primitive. It should help an agent get the request it could not safely synthesize: live CSRF token, browser-generated body, exact cookies, current workspace context, one-use challenge token, payment/action request shape, or one-time action state.

## Safety Boundary

- One action.
- One short flow only when needed to reach the target request.
- One source owned session.
- One approved target account/resource context, when doing cross-account comparison.
- One bounded mutation.
- Approved account/resource set only.
- No raw secret material in notes.
- No destructive action unless the target resource is explicitly `destructible: yes`.
- Intercept must be turned off after the target request is handled and the flow is complete.

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
3. As requests pause, inspect method, URL, headers summary, and body shape.
4. Forward non-target requests that are needed to continue the flow.
5. Pause on the target request or target request family when the token/body/state is fresh.
6. Modify only the approved field.
7. Forward the request once.
8. Let the flow complete only if completion is safe.
9. Turn off intercept.
10. Capture before/after evidence.

### Shape Only, Do Not Complete

Use when the goal is to see the request shape for a sensitive one-time action without completing it against the main account.

1. Prepare an owned browser session and proxy intercept.
2. Trigger the flow only far enough to expose the target outbound request.
3. Record a sanitized request summary.
4. If a safe approved target exists, mutate the request to that target and forward once.
5. If no safe approved target exists, drop/cancel the request and stop.
6. Turn off intercept and record that the main action was not completed.

Examples:
- payment processor request shape
- account deletion request shape
- ownership transfer request shape
- email/password/MFA change request shape

### Source Account To Approved Target Resource

Use when the source account can generate the correct live request, but the test asks whether the server enforces authorization on the target account/resource.

1. Create or select an approved target resource.
2. Confirm whether it is `destructible: yes|no`.
3. Trigger the source-account action only far enough to capture the outgoing request.
4. Change exactly one authorization-relevant field, such as user ID, resource ID, workspace ID, tenant ID, role ID, or account cookie/session context.
5. Forward/replay once.
6. Complete the flow only if the target is approved for that action.
7. Turn off intercept.
8. Route the result to `/access-control` or `/idor` after logging the trail.

Do not run this against real-user resources. For dangerous actions such as account deletion, billing changes, ownership transfer, email/password/MFA changes, or invite/removal flows, the target must be an approved throwaway/destructible resource.

## Action/Error Trail

Write one trail entry per captured request:

```text
single-request-grabber:
- goal:
- mode: observe-replay | intercept-modify | shape-only | source-to-approved-target
- account/session alias:
- resource alias:
- destructible: yes|no
- flow boundary:
- full URL:
- method:
- request source: browser | caido history | caido MCP | intercepted proxy
- forwarded non-target requests:
- token handling: present redacted | absent | extracted from owned flow
- mutation:
- result:
- intercept disabled: yes|no
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

## Examples

- Fresh CSRF or challenge token: intercept the flow, forward setup requests, pause at the action request, preserve the fresh token, modify one approved field, forward once, turn intercept off, then route the result to `/csrf` or `/access-control`.
- Payment processor shape: intercept until the payment handoff request appears, record sanitized shape, do not complete the payment unless using an approved test/sandbox path.
- Account deletion shape: intercept the main-account deletion request only to understand shape or redirect to a pre-approved destructible account/resource; never complete deletion against the main account by accident.

## Stop Conditions

Stop before deleting, purchasing, inviting, changing email/password/MFA, transferring value, or modifying non-owned resources unless the exact resource is approved and marked `destructible: yes`. Stop if intercept cannot be turned off cleanly or the agent cannot tell which paused request is the target.
