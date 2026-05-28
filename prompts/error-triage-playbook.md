# Error Triage Playbook

Use this after `/error-triage` classifies the error or when writing a handoff/report.

## Core Question

The same error can be evidence or a blocker depending on the task.

- During auth testing, `auth failed` may be expected evidence.
- During account setup, `auth failed` may block the workflow.
- During fuzzing, `403` may be a lead if ownership and scope are safe.
- During live testing, `429` or CAPTCHA usually means stop/back off.

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
   - stop and ask Ryushe

## Route Matrix

| Signal | Default Route |
|--------|---------------|
| owned `403` | `/403` |
| `401` or auth-state mismatch | `/access-control` |
| object ownership denial | `/idor` or `/access-control` |
| `405` or method-specific behavior | `/headers` method-override |
| `400` or parser/schema/content-type error | `/headers` content-negotiation or `/bypass` parser |
| `500` with framework/server hints | server-error triage, then `/fuzz`, `/headers`, or source review |
| `429`, CAPTCHA, WAF page | `/waf`, manual handoff, or stop |
| soft 404/weird route error | `/fuzz` or `/live-map` |

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

Stop if the error is tied to a non-owned private object, destructive operation, anti-abuse control, target policy enforcement, unclear credentials, or unexplained high-volume blocking.
