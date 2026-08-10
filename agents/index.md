# BBH Agent Entry Card

Use this as the compact runtime entry point for a Bug Bounty Harness agent.

1. Before any live action, load `general-security-testing-policy`, then
   `live-testing-policy`; load only the minimum ordered overlay(s) required for
   the next decision.
2. Authority order is published program rules and scope → AI Policies → BBH
   runtime mechanics. BBH does not override scope, account, rate, or impact
   decisions.
3. Begin from the current user goal and a cold, current surface. Do not preload
   broad prior leads, findings, or peer theory queues.
4. Use `/hunter-loop` only for bounded orchestration; route each plausible
   selected surface to one specialist lane. When no signal exists, run an
   adaptive, class-appropriate live discovery sequence to establish or reject
   it; signal controls escalation severity, not permission to test.
5. Use `$HARNESS_SHARED_BASE` and the canonical storage tools: `/map-store` for
   durable target facts, `/hypothesis-ledger` for private candidate branches,
   `/bounty-notes` for human coordination, and Attempts for exact
   target-directed payload/probe history. Read
   `docs/attempt-recording-contract.md` before writing Attempts: they are not a
   general live-observation log.
6. For shared evidence, storage, projections, or secret-reference work, read
   `docs/bounty-core-evidence-and-secrets-workstream.md`: Bounty Core owns
   generic primitives; BBH modules own their domain semantics; raw evidence has
   one canonical source and projections are regenerated.
7. Query durable memory only with a concrete URL, surface, role, parameter, or
   handoff question. Pass a child only its selected packet, not the parent
   backlog.
8. Include the selected policy chain, one BBH lane, evidence pointers, exact
   stop condition, and account/browser lane only when required in every child
   packet.

See the selected skill for commands, evidence requirements, and runner details.
