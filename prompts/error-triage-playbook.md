# Error Triage Playbook

Use this after `/error-triage` classifies the error or when writing a handoff/report.

## Core Question

The same error can be evidence or a blocker depending on the task.

- During auth testing, `auth failed` may be expected evidence.
- During account setup, `auth failed` may block the workflow.
- During fuzzing, `403` may be a lead if ownership and scope are safe.
- During live testing, stop blocked automation on `429` and follow cooldown and controller review; route CAPTCHA decisions to `captcha-policy`.

## Triage Steps

1. Capture the response.
2. Identify the current task goal.
3. Identify ownership:
   - owned account/resource
   - approved test account set
   - server/API endpoint
   - unknown or real-user resource
4. Classify the status and body.
5. Decide:
   - route to another skill
   - retry once with a minimal baseline
   - record a note
   - capture one fresh browser/proxy request if the request shape is the blocker
   - stop and ask Ryushe

## Route Matrix

For a CAPTCHA-bearing `403`, follow `captcha-policy` before `/403`; this
does not release any `429` cooldown or active `operator_review`.

| Signal | Default Route |
|--------|---------------|
| owned `403` without a CAPTCHA | `/403` |
| `401` or auth-state mismatch | `/access-control` |
| object ownership denial | `/idor` or `/access-control` |
| `405` or method-specific behavior | `/headers` method-override |
| `400` or parser/schema/content-type error | `/headers` content-negotiation or `/bypass` parser |
| `500` with framework/server hints | server-error triage, then `/fuzz`, `/headers`, or source review |
| CAPTCHA | `captcha-policy` |
| `429`, WAF page | stop blocked automation for `429`; route WAF evidence to `/waf` |
| soft 404/weird route error | `/fuzz` or `/live-map` |
| fresh CSRF token or one-shot browser request needed | `/single-request-grabber` |
| unclear/custom/mixed error | record ambiguity, then bounded baseline retry, `/live-map`, `/fuzz`, `/headers`, or manual handoff |

The route matrix is not a closed list. If the active skill has better context for
the current goal, it can keep ownership and use `/error-triage` only as the
decision log.

## Handoff Card

```text
Error triage:
- task goal:
- full URL:
- method:
- auth state:
- account/resource ownership:
- status/body length:
- key headers:
- visible error:
- classification:
- loaded pack:
- decision:
- next safe test:
- stop condition:
```

## Stop Conditions

Stop if the error is tied to a non-owned private object, destructive operation, non-CAPTCHA anti-abuse control, target policy enforcement, unclear credentials, or unexplained high-volume blocking. For CAPTCHA, follow `captcha-policy` without releasing rate-control or other applicable stops.
