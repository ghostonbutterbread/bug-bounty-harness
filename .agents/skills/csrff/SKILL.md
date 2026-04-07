---
name: csrf
description: Test for Cross-Site Request Forgery vulnerabilities, including missing anti-CSRF protections, weak token validation, SameSite bypass opportunities, and broken Origin or Referer enforcement
---
# CSRF Testing

Test for Cross-Site Request Forgery vulnerabilities on authenticated, state-changing functionality.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (CSRF items only)
4. `todo.md` (CSRF items only)

## Primary Harness

There is no dedicated `agents/csrf_hunter.py` in this repo yet. Run CSRF work manually with a browser, proxy, and reproducible PoC HTML. Use `baseline_capture.py` when you need to snapshot authenticated before-and-after state or inspect reflected anti-CSRF headers during a controlled replay.

## Mode Matrix

| Mode | Use When | What It Tests |
|------|----------|---------------|
| `no-token` | State-changing request succeeds without a token | Missing anti-CSRF protection |
| `weak-token` | Token exists but validation may be weak | Omission, replay, cross-session reuse, or cookie duplication |
| `samesite` | Cookies appear to be the main defense | Cross-site navigation and `SameSite` edge cases |
| `origin` | Headers appear to enforce cross-site policy | Weak, absent, or inconsistent `Origin` and `Referer` validation |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/csrf-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **CSRF Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/csrf/findings.md`
- **CSRF Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/csrf/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/csrf-playbook.md`.
3. Capture authenticated state-changing requests and build the simplest matching cross-site PoC.
4. Use `baseline_capture.py` when you need before-and-after evidence or to inspect anti-CSRF headers during controlled replay.
5. Write findings to `agent_shared/findings/csrf/findings.md`.
6. Update CSRF entries in `checklist.md`, `todo.md`, and relevant notes.
