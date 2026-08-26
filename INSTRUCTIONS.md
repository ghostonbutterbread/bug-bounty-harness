# Legacy Compatibility Pointer

> **Do not paste this file as a generic agent bootstrap.** It formerly copied
> storage, rate, and workflow policy that is now superseded and would create
> drift.

For a BBH agent, start with [`agents/index.md`](agents/index.md), then load the
shared policy chain and only the BBH skill selected by the immediate task.

Canonical ownership:

- scope, ownership, rate, impact, and stop/ask decisions: **AI Policies**;
- runner commands, packet shape, artifact paths, and evidence schemas: **BBH**;
- reusable app facts: `/map-store`;
- private candidate branches: `/hypothesis-ledger`;
- shared evidence-backed unresolved lead projections: `/leads`;
- exact target-directed probes: the canonical Attempts stream via `/attempt-recording-policy`;
- human decisions and handoffs: `/bounty-notes`.

Do not use the retired `~/Shared/bounty_recon/{program}/ghost/knowledge.md`,
per-skill findings files, or the former fixed request-rate defaults as an agent
bootstrap contract.
