---
name: hypothesis-ledger
description: "Capture agent-generated hypotheses privately, preserve their branches, and reclaim only stale owner work without injecting other agents' ideas."
---

# Hypothesis Ledger

Use during a hunt whenever an agent identifies a plausible, evidence-grounded
idea that it will not immediately test. This is BBH's private-first continuation
ledger; it is not MapStore and it is not a findings ledger. MapStore keeps
observed facts; Bounty Notes keeps human decisions and handoffs; raw attempts
stay in their scoped attempts artifact.

## Capture discipline

Before deepening one lead, preserve every distinct plausible angle as a private
candidate. Each record should name the observed basis (via non-secret evidence
pointer), proposed chain, surface/normalized URL when known, tags, next
safe discriminator or concrete blocker, and wake condition. Do not discard an
idea merely because it is not the current highest-information test.

## Core behavior

- Capture each distinct idea immediately as a private `candidate` owned by the
  current `agent_id` + `run_id`.
- Renew the owner lease through the Hypothesis Store lifecycle hook. It uses
  Bounty Core's namespaced heartbeat primitive, so future modules can adopt the
  same atomic liveness semantics without depending on BaseTeam. The default
  private TTL is two hours. Time passing does **not** release an active agent's
  backlog; only a missing owner heartbeat makes unresolved work reclaimable.
- Do not query another agent's unexpired hypotheses. A caller sees its own
  private candidates plus stale, reclaimable hypotheses matching its explicit
  URL/surface/tag query.
- Delegate only one selected branch to one child. The child receives that branch
  only, not the parent agent's other private hypotheses.
- At a natural completion/pivot checkpoint, query `continuation` first. It
  returns counts only; do not inject candidate content unless the owner elects
  to review it.
- MapStore records observed facts. Link evidence through `--evidence-ref`, but
  do not write an untested hypothesis into MapStore as factual behavior. When a
  private candidate has a durable observed fact plus one bounded unresolved
  security question, create or update the sanitized `/leads` projection; it may
  link this hypothesis ID but must not copy private rationale.
- Ordinary `list` is private to the caller's exact `agent_id` + `run_id`.
  For deliberate follow-up, select a concrete public MapStore Lead ID/path and
  use `lead-followup`; it returns that public card plus only owner, released, or
  stale/reclaimable context linked to that exact Lead. It never grants a broad
  peer-hypothesis feed.

## Commands

Use the selected lane's dispatcher:

```bash
bbh agents/hypothesis_ledger.py create <program> \
  --agent-id <agent> --run-id <run> \
  --title "Worker may fetch signed export URL under a different auth context" \
  --surface export --url "https://app.example/export" \
  --tag export --tag worker --tag auth-boundary \
  --expected-chain "signed URL -> worker fetch -> cross-account object" \
  --next-discriminator "owned two-account export comparison" \
  --evidence-ref "mapstore:recon/maps/export/..." \
  --lead-id "<MapStore-relative-public-lead-path>"

bbh agents/hypothesis_ledger.py heartbeat <program> --agent-id <agent> --run-id <run>
bbh agents/hypothesis_ledger.py continuation <program> --agent-id <agent> --run-id <run> --surface export
bbh agents/hypothesis_ledger.py transition <program> H-... --agent-id <agent> --run-id <run> --status active
bbh agents/hypothesis_ledger.py list <program> --agent-id <agent> --run-id <run> --url "https://app.example/export" --tag worker
bbh agents/hypothesis_ledger.py release <program> H-... --agent-id <agent> --run-id <run>
bbh agents/hypothesis_ledger.py lead-followup <program> --agent-id <agent> --run-id <run> --lead-id "<MapStore-relative-public-lead-path>"
bbh agents/hypothesis_ledger.py delegate <program> H-... --agent-id <parent> --run-id <parent-run> --child-agent-id <child> --child-run-id <child-run>
bbh agents/hypothesis_ledger.py reclaim <program> H-... --agent-id <new-agent> --run-id <new-run>
bbh agents/hypothesis_ledger.py complete <program> H-... --agent-id <agent> --run-id <run> --status completed
```

## Tabletop and automation preflight

First inspect `bbh agents/hypothesis_ledger.py --help`; do not invent a
command surface. Offline exercises must use the real CLI and a task-scoped
`--root` placed **before** the command, for example:

```bash
bbh agents/hypothesis_ledger.py --root /tmp/hypothesis-tabletop create <program> ...
```

Retain the temporary-root path plus sanitized command/result summaries. Never
write ledger records directly to SQLite or emulate a missing CLI. To choose an
active branch after preserving alternatives, run `transition ... --status active`
and verify it remains private to the current owner.

## Storage

The ledger is lane-local at:

```text
~/Shared/<family>/<program>/<lane>/hypotheses/hypothesis_ledger.sqlite
```

It stores non-secret coordination metadata only. The current access control is a
**trusted-cooperative agent protocol**, not a security boundary against arbitrary
same-OS-user processes: callers must use the BBH CLI and must not impersonate
another agent/run identity. Do not put cookies, tokens, credentials, raw
requests, or sensitive response bodies in titles, tags, evidence references, or
expected chains.

## Completion rule

A surface can be marked exhausted only after the owner receives the optional
continuation count and consciously decides whether to review remaining private
ideas. An agent is never required to clear every candidate before moving on.
