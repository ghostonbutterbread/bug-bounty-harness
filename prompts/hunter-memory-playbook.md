# Hunter Memory Playbook

Hunter Memory turns mapping and hunting into an observe-learn-adapt loop. It is
for experiments, constraints, boundaries, next actions, and run-local claims.
MapStore remains the only shared app-memory layer: promote a compact fact there
when a claim is stable enough to guide another specialist.

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
6. Add a run-local claim only when the learning is reusable in this continuation; if it becomes a stable app fact, promote one concise MapStore entry and link it.
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

## Canonical Evidence Boundary

Hunter Memory does not record raw target-directed probes. The selected testing
skill writes those to the canonical Attempts stream and returns an `attempt_id`
or sanitized stream reference. Hunter Memory records only the distilled learning
that follows from that evidence.

The legacy `hunter-memory-attempts` harvest block is retired for new work. Do
not emit it for live target tests; use the canonical Attempt writer instead.

## Safety

Do not write raw secrets, cookies, authorization headers, tokens, credentials,
private config values, or full proxy dumps. Store references, sanitized request
shape, response summary, and exact next action instead.

Keep live tests bounded by scope, rate limits, account ownership, and destructive
action rules. If the normal skill says stop, Hunter Memory records the stop
condition and next safe alternative.
