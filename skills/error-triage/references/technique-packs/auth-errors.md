# Auth Errors

Use when login, signup, session refresh, MFA, password reset, or account setup returns an authentication error.

## Checks

- Determine whether auth failure is expected for the current task.
- Compare known-good owned account login to the failing flow.
- Record whether the failure happens before or after session creation.
- Check whether error wording leaks account existence only when program policy allows safe enumeration checks.

## Route

- If testing auth logic, continue in `/access-control` or the relevant auth lane.
- If setting up an account, treat repeated auth failure as a blocker.
- If the error is caused by WAF/CAPTCHA/rate limiting, route to `/waf` or manual handoff.

## Evidence Required

- Current task goal.
- Account alias and ownership.
- Baseline known-good behavior when available.
- Whether the error is expected evidence or a blocker.

## Stop

Stop before account enumeration, credential stuffing patterns, MFA bypass expansion, or non-owned account testing.
