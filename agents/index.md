# BBH Agent Entry Card

For a BBH skill being authored or migrated that runs a repository-owned script,
use `bbh <repository-relative-script-path> ...`—for example,
`bbh agents/manual_hunter.py ...`. Do not add a checkout path or a
`HARNESS_ROOT` fallback: `bbh` resolves its own installed symlink and does not
accept a repository-root override. This makes the command run from the selected
beta or stable checkout. Direct Python commands are legacy and must be migrated
before use. See [`docs/bbh-launcher.md`](../docs/bbh-launcher.md) when authoring
or changing a runnable BBH skill command.

Use this as the compact runtime entry point for a Bug Bounty Harness agent.

1. Before any live action, load `general-security-testing-policy`, then
   `live-testing-policy`. Also load `resource-safety-policy` for every agent
   task: it governs local artifact search and processing, including when a
   broad corpus is legitimate but must be scanned with bounded, streaming
   methods. Load only the minimum ordered live-testing overlay(s) required for
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
5. Use `$HARNESS_SHARED_BASE` and the canonical storage tools: `/bounty-storage`
   for Shared vs mounted-artifact vs scratch routing, `/map-store` for durable
   target facts, `/docs` for compact program-specific application-behavior models,
   `/hypothesis-ledger` for private candidate branches, `/leads` for cross-run
   evidence-backed lead synthesis and lifecycle reconciliation, `/bounty-notes` for human
   coordination, and Attempts for exact target-directed payload/probe history.
   For a corpus too large to inspect directly, load `/huge-ingest` before deep
   reading. Program docs explain how this application uses a technology or flow;
   ResearchMap supplies portable mechanisms only when their recognition signals
   match that model or a current observation. Read
   `docs/attempt-recording-contract.md` before writing Attempts: they are not a
   general live-observation log.
6. For shared evidence, storage, projections, or secret-reference work, read
   `docs/bounty-core-evidence-and-secrets-workstream.md`: Bounty Core owns
   generic primitives; BBH modules own their domain semantics; raw evidence has
   one canonical source and projections are regenerated.
7. Recon artifacts are owned by Recon Bus. CWD is never a corpus lookup root.
   Resolve a named corpus with
   `bbh scripts/recon_bus.py query <program> --artifact <name> --format path`.
   Use Recon Bus `append` or `promote-run` for writes; do not create, edit, or
   recursively search for competing corpus files.
8. Query durable memory only with a concrete URL, surface, role, parameter, or
   handoff question. Broad Hypothesis Ledger peer/app views are allowed only by
   their named explicit review modes, never as a cold-start or default query;
   ordinary `list`, `continuation`, and exact Lead follow-up keep their private
   or Lead-bounded semantics. Pass a child only its selected packet, not the
   parent backlog.
9. Include the selected policy chain, one BBH lane, evidence pointers, exact
   stop condition, and account/browser lane only when required in every child
   packet.

See the selected skill for commands, evidence requirements, and runner details.
