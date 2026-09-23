# Single Request Grabber Playbook

Use this when one live request or one short action flow must be captured and safely modified.

This skill captures a request the agent cannot safely synthesize: live CSRF
token, browser-generated body, owned session context, or one-time action state.
The provisioner's default task MITM captures traffic; it does **not** expose a
hot pause/edit API. Use live interception only when a supported temporary
exact-match rule is available; otherwise replay through that task MITM or stop.

## Safety Boundary

- One action.
- One short flow only when needed to reach the target request.
- One source owned session.
- One approved target account/resource context, when doing cross-account comparison.
- One bounded mutation.
- Approved account/resource set only.
- No raw secret material in notes.
- No destructive action unless the target resource is explicitly `destructible: yes`.
- Any supported temporary intercept must be turned off after the flow.

## Operating Modes

### Observe Then Replay

Use when the request can be captured from the agent's task-MITM history and replayed safely. Caido history is separately labeled source shape only outside Abommie.

1. Trigger the action in an owned session.
2. Locate the request in the task flow file.
3. Copy a sanitized request summary.
4. Modify one approved field.
5. Replay once or a very small bounded set.

### Intercept Then Modify

Use only when the token is per-action/per-request **and** an actual supported
live interception mechanism is available. Do not present capture-only mitmdump
as a pause/modify/forward proxy; without that mechanism, capture and replay
with fresh owned state or record the blocker.

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

1. Prepare an owned browser session and a verified live intercept mechanism;
   a capture-only task MITM cannot safely drop the pending action request.
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
| proxy setup needed | `/agent-proxy` and `/chromium-test`; `/caido` only for explicit source-history lookup or local Abommie permission |

Routing happens after the single-request operation unless setup is blocked. The skill should not abandon the capture just because the eventual impact belongs to CSRF, IDOR, access control, or headers.

## Examples

- Fresh CSRF or challenge token: capture an owned browser flow through the task
  MITM. If a supported exact-match live intercept exists, pause/modify/forward
  once and remove it; otherwise replay with fresh owned state or stop at the
  missing primitive before routing to `/csrf` or `/access-control`.
- Payment processor shape: intercept until the payment handoff request appears, record sanitized shape, do not complete the payment unless using an approved test/sandbox path.
- Account deletion shape: intercept the main-account deletion request only to understand shape or redirect to a pre-approved destructible account/resource; never complete deletion against the main account by accident.

## Stop Conditions

Stop before deleting, purchasing, inviting, changing email/password/MFA, transferring value, or modifying non-owned resources unless the exact resource is approved and marked `destructible: yes`. Stop if intercept cannot be turned off cleanly or the agent cannot tell which paused request is the target.
