---
name: blockers
description: "Use when an agent hits an external prerequisite it cannot solve, or needs an end-of-run blocker brief."
---

# Blockers

Use this only for a factual condition outside the agent's authorized ability to
fix: human-only verification, unavailable owned account/role, unavailable
resource fixture that the agent cannot create, environment outage, or a required
scope/policy decision. It is not limited to BOLA and is not a general failure
log, retry queue, or mandatory preflight.

## Known blocker check

When an external prerequisite appears likely, check the exact operation/scope:

```bash
bbh agents/blockers.py check --program {program} \
  --subject "<exact operation/flow>" --test-scope "<class>:<surface>"
```

- If `known_blocker: true`, do not repeat setup/exploration already known to be
  impossible. Continue only if this agent can now perform the stated
  `unblock_condition`.
- If no known blocker matches, do normal authorized setup first. Record only if
  the required action remains outside the agent's authority.

## Record external blockers

```bash
bbh agents/blockers.py record --program {program} --producer <agent-or-skill> \
  --run-id <run-id> --subject "<exact operation/flow>" \
  --test-scope "<class>:<surface>" --blocker-key "<stable-prerequisite-key>" \
  --blocker-type <account-capability|owned-fixture|feature-access|auth-state|environment|scope-policy|observation> \
  --reason "<observed external condition>" \
  --unblock-condition "<smallest action Ryushe or a capable agent can take>"
```

Never record secrets, raw requests, or speculative workarounds.

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
