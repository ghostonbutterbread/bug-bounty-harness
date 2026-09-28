# ATO flow map and handoff

**Status:** active optional reference. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/flow-handoff.md`. **Supersedes:** generic setup, flow map, reportability, and handoff material in retired `prompts/ato-playbook.md`. Load for a complex identity flow, stuck analysis, report, or specialist handoff; not for every ATO task.

## Map the transition

Use owned A/B accounts when the hypothesis needs a comparison; add owned IdP or disposable factors only if the observed flow uses them. For each relevant step, capture the entry URL/method, submitted identity claim, required proof, pending transaction, delivery/IdP/MFA/invite artifact, final confirmation, resulting server-side account/session/security state, and notification/audit side effects. Keep secrets redacted.

Compare a valid baseline with a single bounded mutation at a time, reading back the exact target after each. A negative binding result closes that hypothesis, not every other plausible flow. A confirmed wrong-account session/link, recovery/factor change, or unauthorized role is the proof threshold; a UI flag, response discrepancy, or successful callback alone is not. Stop escalation on the proven path at minimum safe evidence.

## Specialist handoff card

```text
Program and in-scope flow:
Full URL(s) and methods:
Owned account / IdP aliases and fixture status:
Claim and verifier expected:
Pending transaction and observed binding fields:
Baseline result and redacted mutation:
Final server-side account/security state:
Question for selected specialist:
Stop condition, cleanup, and evidence path:
```

Choose `/password-reset`, `/access-control`, `/idor`, `/csrf`, `/race`, `/headers`, `/bypass`, or `/single-request-grabber` for the actual mechanism. The specialist need not reload unrelated ATO references. Preserve negative findings when they close a hypothesis and explain which binding held.
