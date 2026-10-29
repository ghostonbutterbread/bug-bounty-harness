# Bunny team dispatch

Spawn the subagents needed for the campaign and let them work. Use the current harness's ordinary subagent tools; do not build or require a harness-specific adapter. Give each worker its role, scoped task, applicable skills, and evidence destination. Have each worker read the canonical role file and applicable skills before acting. Role files are in the selected BBH checkout at `agents/bunny-<role>.md`; a role name alone is not the instructions. Do not substitute a generic implementation worker.

## Team communication

- Bunny talks with recon.
- Bunny talks with the hunter.
- Recon and the hunter talk with each other.
- Either worker can ask Bunny for direction, another place to investigate, or
  operational help without waiting for the other worker.
- Recon and the hunter exchange relevant discoveries and follow-up questions.
  Put the details in the existing evidence stores and pass a concise reference.
- If the harness cannot deliver a direct worker-to-worker message, Bunny relays
  that same message. When a worker asks for a handoff, relay the actual message
  promptly and verify the exact evidence pointer; report a missing pointer rather than
  substituting a different observation. Say that it was relayed; do not call the
  relay direct. The recipient chooses its own investigation.
- Workers do not allocate other workers or transfer scope, ownership, or
  authority by talking to each other.
- In explicit offhand mode, use ordinary scoped workers under `bunny-offhand`.
  Do not launch these collaborative role files or require a collaboration
  protocol.

A worker's displayed name is not proof that it loaded its role and skills.
Give it the canonical role and the selected checkout's `bunny-collaborative`
paths, and have it read both before any target action. Verify the effective
model/provider and applicable approval gate before live work. If those gates
cannot be verified, use a suitable worker route or stop before target actions.
Check the actual reads.
When the worker can pause and continue, have it
report readiness and wait for Bunny's go-ahead. For a completion-only worker,
inspect its returned transcript and report any unverified read; do not
claim Bunny confirmed it before the action. If it cannot be resumed, continue in
a bounded follow-up with its evidence rather than pretending it was steered.
