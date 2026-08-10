# Bounty Core Evidence and Secrets Workstream

## Status

- **Owner:** Ryushe / Ghost
- **State:** Track A foundational slice implemented; projection materializers and
  Track B secret resolution remain deferred
- **Canonical related spec:** [`bounty-core-shared-module-spec.md`](bounty-core-shared-module-spec.md)
- **Implementation provenance:** 2026-08-07 — `bounty_core.evidence` provides
  the generic event envelope, redaction, locked append, bounded reads, and BBH
  Attempts compatibility facade; no MapStore/Hypothesis migration yet

## Purpose

Refactor repeated bug-bounty persistence and identity mechanics into Bounty
Core, while preserving each BBH module's domain semantics. This work supports:

- MapStore;
- Hypothesis Ledger;
- Attempts;
- findings and report/ledger flows; and
- future modules that need the same durable mechanics.

Design principle:

> Be explicit where ambiguity is dangerous—identity, storage, references,
> secrets, lifecycle, and generated views. Keep vulnerability classes and
> experimental observations open-world so new techniques can be recorded before
> a dedicated harness exists.

Do **not** implement every workstream at once. Build the shared evidence substrate
first; treat the secret-resolution backend as a separate, later slice.

## Ownership Boundary

### Bounty Core owns reusable primitives

Bounty Core should own generic, product-neutral behavior:

- canonical `family / program / lane` storage resolution;
- normalized subject identity (`url`, `host`, `api_operation`, `workflow`,
  `file`, `message`, `account_relation`, etc.);
- run, artifact, evidence, and opaque secret references;
- append-only event mechanics, locking, atomic writes, redaction, and schema
  versioning;
- projection/index generation and read-only bounded queries;
- migrations and validation of generic persisted shapes.

Bounty Core must not own vulnerability-class policy, payload selection, a
specific renderer/sink model, MapStore lifecycle meaning, Hypothesis privacy
policy, or agent scheduling.

### BBH modules own domain semantics

- **MapStore:** durable target facts, status meaning, and URL/surface observations.
- **Hypothesis Ledger:** private candidate branches, owner leases, continuation,
  delegation, reclaim, and hypothesis lifecycle.
- **Attempts:** raw append-only experiment history.
- **Findings:** finding/report lifecycle and proof semantics.
- **Skills, agents, and teams:** policy routing, live-testing decisions, payload
  experimentation, and class-specific reasoning.

No consumer should compose durable paths, reimplement locking/redaction, or
hand-edit another module's canonical state.

## Track A — Shared Evidence Primitives

### Required generic event envelope

Every deliberate observation must be writable even if the vulnerability class is
new. The write path must not require a class adapter.

```json
{
  "schema_version": 1,
  "attempt_id": "A-...",
  "run_id": "run-...",
  "timestamp": "2026-08-06T00:00:00Z",
  "producer": "agent-or-tool",
  "vuln_class": "xss-or-any-new-string",
  "event_type": "probe",
  "subject": {"kind": "url", "origin": "https://app.example", "path": "/search"},
  "outcome": "observed",
  "reason": "exploratory discriminator",
  "artifact_refs": [],
  "details": {}
}
```

`details` is open-world. Established classes may later add helpers,
vocabularies, summaries, or advisory checks, but no class registry may reject a
novel valid observation.

### Payload experimentation doctrine

Attempts must support live experimental sequences. A complete static model is
not a prerequisite to trying a follow-up payload. Record the changed dimension
and what the comparison is intended to distinguish:

```text
baseline → safe marker → representation/context variation → observation
```

Useful fields include `reason`, `unknown`, `variable_changed`,
`expected_information`, `parent_attempt_id`, and `comparison_to`. Do not impose a
hard completeness gate before writing an attempt. Later materializers may emit
non-blocking hints about missing browser state, fixture comparison, or an
unexplained boundary.

### Canonical evidence versus generated projections

The raw run event stream is the only canonical source for attempts:

```text
{lane}/attempts/_runs/{run_id}/attempts.jsonl
```

Generate all class, URL, parameter, host, workflow, and time views from it:

```text
{lane}/attempts/_index/
  by-class/
  by-url/{host}/{path}/{input}/
  by-host/
  by-workflow/
  attempts.sqlite
```

Indexes contain summaries and references, never copied canonical events. They
must be reproducible and safe to refresh. A URL is the primary web selector,
but not every subject is a URL; do not force workflows, files, messages, hosts,
or account relations into a false URL identity. Never use raw query/body values
as directory names or identity fields.

### Store linkage

Use references, not duplicated data:

```text
attempt event → private Hypothesis Ledger candidate (when a branch remains)
attempt event → MapStore fact (only after target behavior is durable)
attempt event → ResearchMap retrieval record (when research changes a next check)
MapStore/Hypothesis/finding → sanitized attempt/artifact pointer
```

MapStore remains concise and factual. Hypothesis Ledger remains private and
candidate-only. Exact payloads, sequences, and raw observations remain in
Attempts.

### First implementation slice

1. Survey existing Bounty Core storage/ledger/index helpers and BBH `attempts.py`,
   MapStore, and Hypothesis Ledger call sites.
2. Extract only product-neutral `SubjectRef`, `RunRef`, `ArtifactRef`,
   `EvidenceRef`, generic event envelope, redaction, append/lock, and storage
   resolution into Bounty Core.
3. Keep a thin BBH compatibility facade so existing callers do not break.
4. Add a read-only materializer/query command that builds generated URL/class
   projections from immutable event streams.
5. Migrate one consumer end-to-end—Attempts/XSS is the initial candidate—without
   requiring an XSS-only schema for generic writes.
6. Prove a second unlike consumer can write and query the same contract before
   expanding the abstraction.

### Acceptance criteria

- A previously unknown class can append a valid attempt without code changes.
- Raw attempts have one canonical event source; projections rebuild from it.
- Concurrent writers do not corrupt JSONL or indexes.
- Secret-bearing data is redacted before any artifact/index write.
- URL/parameter query returns bounded references and summaries without loading
  unrelated historical work.
- MapStore/Hypothesis/finding references remain valid after projection rebuild.
- Bounty Core tests cover primitives; BBH tests cover one real consumer and
  compatibility/migration behavior.

## Track B — Secret References and Ephemeral Resolution

This is deliberately separate from Track A. Do not block generic Attempts work
on a new secret-store implementation.

### Current foundation and gap

Current account metadata already stores non-secret `credential_ref` /
`auth_seed_ref` values, and BBH recognizes `bitwarden:` and `secret-store:`
reference types. Locked-down local auth-seed/session material and Bitwarden are
existing sources. A universal secret-store resolver with scoped ephemeral
injection is not yet established.

Before implementation, resolve the storage ambiguity: raw sessions, cookies,
bearer values, CSRF values, passwords, and refresh material must never reach
cloud-backed Shared artifacts, mounted artifact storage, commits, chat, or
indexes. Shared records retain opaque references and safe metadata only.

### Desired contract

```text
Shared artifact / attempt / MapStore
  → account alias, SecretRef, safe fingerprint/version, expiry metadata,
    injection provenance

restricted local backend
  → actual secret values and session material

selected owned-account/profile lease
  → authorizes narrowly scoped resolution for one program, target, purpose,
    and short-lived execution context
```

Preferred injection order:

1. direct in-memory client/browser injection;
2. ephemeral child-process environment injection when a tool requires it;
3. owner-only short-lived file or FD handoff only as a compatibility fallback.

Never put a secret in a command argument, log, prompt, JSONL record, generated
projection, shared manifest, or persistent general environment.

Rotation changes the secret value while retaining an opaque reference. Attempts
record a safe secret version/fingerprint and immutable provenance, not historical
secret values. A later replay resolves a current authorized value or performs an
approved refresh; it never expects the old secret to be stored in evidence.

### Deferred implementation sequence

1. Inventory the current Bitwarden, auth-seed, session bridge, account lease,
   and `secret-store:` paths and identify actual secret-bearing storage.
2. Define a Bounty Core `SecretRef` and resolver interface without committing to
   a backend.
3. Implement one restricted local backend/adapter and lease-checked resolution.
4. Add one in-memory injection integration and one existing CLI-compatible
   child-process integration.
5. Add expiry/rotation metadata, audit-safe provenance, and tests that prove
   secrets never enter normal artifacts.
6. Migrate callers incrementally; keep old auth paths as explicit compatibility
   adapters until every reader uses the shared resolver.

## Agent Guidance

Before modifying this workstream:

1. Read this note, `docs/bounty-core-shared-module-spec.md`,
   `docs/attempt-recording-contract.md`, repository `AGENTS.md`, and the
   relevant current module/test code.
2. Inspect dirty worktrees and preserve unrelated work; stage only task-owned
   paths.
3. Prefer extraction plus compatibility shims over a broad rewrite.
4. Keep one canonical raw source and regenerate views; never hand-edit a derived
   projection to compensate for a missing writer.
5. Do not widen secret exposure to make a test convenient. Use opaque references
   and the approved restricted resolver path.
6. Deliver a narrow tested slice, update this status/provenance section, and
   leave the deferred track untouched unless it is the explicitly selected task.
