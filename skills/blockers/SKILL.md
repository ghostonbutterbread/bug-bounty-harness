---
name: blockers
description: "Use when an agent hits an external prerequisite it cannot solve, or needs an end-of-run blocker brief."
---

# Blockers

Use this only after **remediation-first** work establishes that the condition is
outside the agent's authorized ability to fix. The agent must first attempt any
feasible ordinary authorized remedy: create the needed owned resource/fixture,
create or repair an owned account, use a permitted free trial or signup path,
complete normal feature setup, and perform bounded login/session recovery. A
blocker is only for the remainder: human-only verification, unavailable owned
account/role, resource fixture the agent cannot create, environment outage, or a
required scope/policy decision. It is not limited to BOLA and is not a general
failure log, retry queue, or mandatory preflight.

## Known blocker check

When an external prerequisite appears likely, check the exact operation/scope:

```bash
bbh agents/blockers.py check --program {program} \
  --subject "<exact operation/flow>" --test-scope "<class>:<surface>"
```

- If `known_blocker: true`, first decide whether this agent can now clear it
  through normal authorized remediation: permitted signup/free trial, owned
  account/resource or fixture creation, normal feature setup, or bounded auth
  recovery. If yes, **do that work and freshly verify the flow**. A known
  blocker is never permission to stop a runnable task. Only if the remaining
  action is still outside the agent's authority should it avoid repeating the
  specific already-failed dead end and preserve the unblock condition.
- If no known blocker matches, do normal authorized setup first. Record only if
  feasible remediation is exhausted and the required action remains outside the
  agent's authority.

## Record external blockers

```bash
bbh agents/blockers.py record --program {program} --producer <agent-or-skill> \
  --run-id <run-id> --subject "<exact operation/flow>" \
  --test-scope "<class>:<surface>" --blocker-key "<stable-prerequisite-key>" \
  --blocker-type <account-capability|owned-fixture|feature-access|auth-state|environment|scope-policy|observation> \
  --reason "<observed external condition>" \
  --remediation-evidence "<sanitized attempt ref or attestation: feasible authorized remedies tried>" \
  --unblock-condition "<smallest action Ryushe or a capable agent can take>"
```

An open record is rejected unless it includes a sanitized `--remediation-evidence`
reference or attestation. Never record secrets, raw requests, or speculative
workarounds.

## Completion brief

Only for runs that recorded blockers, produce the compact handoff receipt:

```bash
bbh agents/blockers.py brief --program {program} --run-id <run-id>
```

The result contains:
- what remained open from that run;
- why it was blocked;
- the exact action that would unblock it (`next_to_push`).

Agents should include that output in their completion update, not automatically
retry it. A future agent can use `check` to avoid spending time rediscovering a
known external blocker.
