# Hunter Memory Playbook

Hunter Memory turns mapping and hunting into an observe-learn-adapt loop. It is
for experiments, constraints, boundaries, next actions, and reusable claims.

## When To Use

Use this when:
- `/live-map` or manual exploration found a surface worth testing.
- A child agent is about to try payloads, role changes, request replays, or
  alternate render paths.
- A probe failed but taught something about the application.
- A vuln class remains plausible but needs a different context.
- Another agent should avoid repeating an identical attempt unless a variable
  changed.

Do not use this as a replacement for findings. Confirmed vulnerabilities still
belong in the normal findings ledger and report path.

## Mental Model

Ask: what did this attempt teach us?

A failed attempt should usually become one scoped boundary:

```text
surface.context: exact attempt did not work because observed reason; still check alternate contexts.
```

Example:

```text
avatar.filename.profile-render: HTML escaped in the user profile; still check
admin moderation, email notification, export, CDN metadata, SVG parsing, and
mobile/API render paths.
```

## Suggested Flow

1. Pick one surface and one hypothesis.
2. Start a Hunter Memory run for that surface/hypothesis.
3. Load the generated prompt into the child agent or manual notes.
4. Try the smallest safe experiment.
5. Record:
   - goal
   - action
   - result
   - observation
   - interpretation
   - learning
   - next action
6. Add a claim only when the learning is reusable by future agents.
7. Continue or hand off with the memory path.

## Evidence Tiers

Use these meanings in attempts and claims:

- `planned`: idea exists but no experiment yet.
- `in_progress`: active experiment or partially observed behavior.
- `tested_no_signal`: exact context produced no meaningful signal.
- `interesting_signal`: behavior changed or a boundary looks promising.
- `blocked`: scope, auth, rate, safety, or environment blocked testing.
- `confirmed`: normal proof standard met.
- `needs_followup`: useful learning but alternate context remains.

## Fenced Harvest Blocks

When an agent cannot write files directly, it can place JSONL in its final log.
The parent can harvest it later with `agents/hunter_memory_tool.py harvest`.

```hunter-memory-attempts
{"goal":"learn avatar upload render behavior","action":"uploaded benign png baseline","result":"inconclusive","observation":"upload accepted and profile showed image","interpretation":"profile image path exists","learning":"baseline works; filename context still untested","next_action":"test filename reflection and admin render","evidence_refs":[]}
```

```hunter-memory-claims
{"claim":"Profile render HTML-escapes avatar filename, but admin/email/export contexts are untested","status":"needs_followup","confidence":"medium"}
```

## Safety

Do not write raw secrets, cookies, authorization headers, tokens, credentials,
private config values, or full proxy dumps. Store references, sanitized request
shape, response summary, and exact next action instead.

Keep live tests bounded by scope, rate limits, account ownership, and destructive
action rules. If the normal skill says stop, Hunter Memory records the stop
condition and next safe alternative.
