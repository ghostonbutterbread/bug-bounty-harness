# Bunny team dispatch

Spawn the subagents needed for the campaign and let them work. Use the current harness's ordinary subagent tools; do not build or require a harness-specific adapter. Give each worker its role, scoped task, applicable skills, and evidence destination. Packets include the named load list and standing ownership question from `bunny` shared boundaries. Have each worker read the canonical role file and applicable skills before acting. Role files are in the selected BBH checkout at `agents/bunny-<role>.md`; a role name alone is not the instructions. Do not substitute a generic implementation worker.

**Fetcher-family spawn gate.** Before spawning `bunny-hunter` onto a URL-fetch / SSRF / preview / ingest / webhook / oembed / upload-from-url surface, read the campaign record's family→steward map. An **open** family stays on that map until it is evidence-closed; an ended process does not clear it. If the packet matches an open family and that steward is still interactable, **do not spawn**; steer it or wait for its checkpoint. Compaction rotation does not spawn while the steward is live. If the packet matches an open family and the prior process has confirmed exit or otherwise ended, spawn either a **successive bounded segment** of that steward (same role, same family, predecessor stream cited, packet “continue this family at discriminator D”) or a **compaction successor** that inherits the family lease (packet must name compaction successor). Neither is a greenfield hunter. A steward that is not interactable and has no confirmed exit is not process-ended; inspect status and steer. Spawn a **greenfield** hunter only when the packet says why this is a new family or independent verification. Family identity is owned by `bunny-collaborative` fetcher-family stewardship.

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

For browser-dependent assignments, Bunny selects the policy-permitted browser
tier before dispatch. For a supported Bunny-owned team browser on the same
trusted browser node as the worker, Bunny issues `team-grant` only at a safe
checkpoint and sends its **private reference** to the exact worker/run through
the trusted worker packet. The worker does not call the provisioner; its
Chromium Test wrapper uses `team_browser(reference, worker, run)` to attach and
disconnect; the packet contains no raw CDP URL. A worker on another host or
without that wrapper does not have this direct-control route.
Bunny reads `team-status` for the granted worker and adapter activity without
asking the worker whether it is done. A quiet adapter is not release: after the
worker's natural completion or a verified handoff checkpoint, Bunny calls
`team-return` on its exact reference before granting another worker. If the
route cannot grant or return safely, retain the owner-driver relay or queue the
browser-dependent slice; do not release and re-provision merely to take turns.

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

For collaborative hunter/recon packets, name the current session's compaction
count and source (or `unknown`), and request a checkpoint when it changes.
After the second compaction, prepare the pointer-based handoff; by the third,
use `bunny-collaborative`'s fresh-worker rotation and confirmed-exit/ACK gate.
A replacement packet carries the outgoing worker's verified references and
remaining limits, not its entire conversation. This does not apply to offhand
workers or require a harness-specific monitoring adapter.
