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
  that same message. Say that it was relayed; do not call the relay direct.
- Workers do not allocate other workers or transfer scope, ownership, or
  authority by talking to each other.
- In explicit offhand mode, use ordinary scoped workers under `bunny-offhand`.
  Do not launch these collaborative role files or require a collaboration
  protocol.

A worker's displayed name is not proof that it loaded its role and skills.
Check its actual work before treating the role as active. The model, approval,
scope, and rate gates in `bunny` still apply.
