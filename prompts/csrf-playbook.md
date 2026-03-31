# CSRF Testing Playbook

## Overview

Use this as a decision tree: identify a state-changing request, classify the protection model, choose the simplest cross-site request shape that could still send the victim's credentials, verify whether the state change succeeds, then report the missing or weak control.

## Decision Tree

1. Capture a real authenticated state-changing request.
2. If no anti-CSRF token is present, test the missing-token lane first.
3. If a token is present, test whether it is actually enforced and session-bound.
4. If cookies are the main defense, test the `SameSite` lane.
5. If the app relies on `Origin` or `Referer`, test that validation explicitly.
6. Verify a safe state change and report the exact victim prerequisites.

## 1. Capture The Request

Prioritize requests that change meaningful state.

### Good Targets

- Profile, email, and MFA changes
- Billing, payout, and transfer actions
- Password and recovery changes
- Role, team, or membership management
- Webhook or integration changes
- Any `GET` request that performs an action

### Record

- Method and endpoint
- Cookies and `SameSite` attributes
- Presence and location of any CSRF token
- `Origin` and `Referer` behavior
- Required content type and headers

## 2. Choose Lane

| Lane | Use When | What To Confirm |
|------|----------|-----------------|
| Missing token | No anti-CSRF token is required | Plain cross-site form or navigation succeeds |
| Weak token | Token exists but may not be bound or enforced | Omitted, stale, replayed, or cross-session token still works |
| SameSite | Cookies appear to be the main protection | Browser still sends cookies in a cross-site scenario that triggers the action |
| Origin / Referer | Server checks request metadata | Validation is absent, weak, or inconsistently enforced |
| Request-shape downgrade | JSON or custom-header flow looks protected | A simpler form-encoded or alternate shape still reaches the action |

## 3. Verify

Verification should prove a real cross-site state change, not just that the request can be sent.

### Verification Standard

1. Build the smallest cross-site PoC that matches the accepted request shape.
2. Trigger a safe state change in a controlled account.
3. Capture:
   - before-state
   - PoC HTML or trigger method
   - after-state
4. Record whether the exploit required user interaction such as:
   - opening a page
   - clicking a link or button
   - top-level navigation

### Status Rules

- `Confirmed`: the cross-site request caused the authenticated state change.
- `Potential`: controls appear weak, but the state change was not reproduced safely.
- `False Positive`: the request was blocked by token binding, custom headers, `SameSite`, or origin checks in practice.

## 4. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/csrf/findings.md`

Include:

- Vulnerable endpoint and method
- Protection model bypassed or missing
- Victim cookies and relevant attributes
- Whether a token existed and how it failed
- Required victim interaction
- Before-and-after state evidence
