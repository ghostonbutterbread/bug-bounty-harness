# Single Request Grabber Playbook

Use this when one live request must be captured and safely modified.

## Safety Boundary

- One action.
- One owned session.
- One bounded mutation.
- Approved account/resource set only.
- No raw secret material in notes.
- No destructive action unless the target resource is explicitly `destructible: yes`.

## Operating Modes

### Observe Then Replay

Use when the request can be captured from proxy history and replayed safely.

1. Trigger the action in an owned session.
2. Locate the request in proxy history.
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
- request source: browser | caido history | intercepted proxy
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

## Stop Conditions

Stop before deleting, purchasing, inviting, changing email/password/MFA, transferring value, or modifying non-owned resources unless the exact resource is approved and marked `destructible: yes`.
