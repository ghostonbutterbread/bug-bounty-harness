---
name: agent-audit
description: "Use when auditing one bug-bounty agent run: reconcile its actions, target requests, Attempts, evidence promotions, and cleanup against the assigned scope and goal."
---

# Agent Run Audit

This is the BBH owner for a **read-only, evidence-backed audit of an agent run**. Invoke as `/agent-audit <program> <run-id-or-handoff>` when Ryushe asks what an agent actually did, whether it stayed within its assignment, or whether its claimed coverage/finding survived review. This skill does not run the agent again, send target traffic, validate a vulnerability, or replace a program's scope or live-testing policy. An audit of several runs repeats this procedure per run and then compares the resulting receipts.

## Identify the run and sources

Start from the program, agent identity, run/session ID, assigned goal, scope/rate/ownership constraints, and time window. A chat thread, subagent trace, task-MITM capture, and Attempts stream may use **different IDs**; establish their links from a handoff, run metadata, timestamps, and target identity rather than assuming matching strings. If the run ID is unknown, use the bounded program handoff or agent/session history to identify candidate runs before opening artifacts. Resolve the **actual family, lane, and shared base** from the run's target profile/handoff or `/bounty-storage`; do not infer web defaults for a binary run. `agents.storage_resolver.resolve_storage` does not read `HARNESS_SHARED_BASE` by itself. Pass the recorded `base_root` (the parent of `<family>/<program>/<lane>`) or the recorded canonical lane root as `root_override`. If only `HARNESS_SHARED_BASE` is configured as a family root (for example `<shared-base>/web_bounty`), use its **parent** as the shared base after verifying the family suffix; do not pass an arbitrary custom family root directly, since Core only strips a bare family suffix under a directory literally named `Shared`. For binary runs, use the recorded binary-family lane root or the same verified shared base, never a web-family root. Do not use cwd or assume the default `~/Shared` when a custom root is configured. Read `docs/attempt-recording-contract.md` for the Attempts reader and privacy contract.

Collect the available original records, keeping provenance and visibility distinct:

- **Intent and execution:** original agent/session transcript, parent assignment and child handoffs, task/job receipt, tool output, and any `SubagentLogger` trace if that runner actually emitted one. A design document claiming all agents log is not evidence this run did.
- **Target actions:** task-scoped MITM/proxy history or browser evidence for requests and effects; the run's canonical Attempts JSONL for deliberate tests. For discovery, use `agents.attempts.read_attempt_bucket(program, family=<actual-family>, lane=<actual-lane>, root_override=<recorded-shared-root>, where={"run_id": <attempt-run-id>}, limit=<bounded-count>)`; then use `read_attempts(exact_path, ...)` for the known stream. Verify that the selected `resolve_storage(program, family=..., lane=..., root_override=..., create=False).lane_root` matches the run's recorded lane root before interpreting an empty result. An empty query is not proof of no traffic; identify the lane, family, root, ID linkage, and capture coverage first.
- **Interpretation and outcomes:** linked MapStore facts, sanitized public Leads, Bounty Notes handoffs, Findings/Evidence Report, and cleanup/fixture receipts. The private Hypothesis Ledger is not an audit feed: ordinary `list` is owner/run-private, and its peer/operator review modes have different, explicit purposes. Do not impersonate a run owner or invoke broader review merely to fill an audit gap. Use only a branch the owner deliberately handed off or an independently authorized review purpose under `/hypothesis-ledger`; otherwise mark private continuation **not available to this audit**. Retrieve records through their owning skills/tools; projections and conclusions do not replace originating observations.

Do not broad-scan all programs or dump full transcripts into a prompt. Follow concrete IDs/pointers, inspect bounded slices, and expand only when a gap requires it. Raw traces and proxy data can contain secrets or private content: keep them in their authorized store, redact excerpts, and do not publish private hypotheses or reusable credentials in the audit.

## Reconcile the chain

Build a chronological, cited chain: assignment and prerequisites → agent decisions and delegation → actual tool/browser/request actions → observed response or independent effect → interpretation/promotion → cleanup and handoff. Compare planned versus executed scope, rate, owned resources, stop/approval boundaries, and what the final claim says. Pair representative Attempts with proxy/tool observations where possible; note absent or conflicting rows without silently treating either source as complete. Distinguish passive exploration from deliberate tests, a request sent from an effect verified, and an agent's assertion from independent evidence. Check whether durable observed facts reached MapStore, private candidate material was not leaked into public projections, reportable proof reached Findings, and controlled state was cleaned or clearly retained.

This audit **does not append Attempts**: `/attempt-recording-policy` owns writing deliberate tests. Do not repair a missing historical event by pretending it was contemporaneously recorded. A correction to an existing durable fact belongs with that store's owner, linked to this audit; never silently rewrite raw evidence.

## Audit receipt

Return a concise, sanitized receipt with:

1. **Run and authority:** program, agent/run identity, time window, assigned goal, scope and owned-fixture boundary, and exact source pointers.
2. **Observed timeline:** consequential actions and outcomes with timestamp and source/record IDs; clearly label inferred links.
3. **Reconciliation:** requested versus observed actions, Attempts versus proxy/tool records, finding/coverage claims versus proof, promotions, and cleanup.
4. **Verdict and gaps:** supported, contradicted, or not verifiable *per material claim*; missing logs/capture windows, ID mismatches, and the precise evidence needed to resolve them. Never turn missing evidence into a clean bill or claim complete coverage from one store.
5. **Disposition:** correction, owner handoff, or no action, with links to the canonical records. The audit itself is read-only. If a durable human handoff is separately authorized afterward, load `/bounty-notes` and save only a sanitized summary there; do not turn that optional follow-up write into a prerequisite for the audit.

Do not call the audit complete until the identified run's available sources have been reconciled and each material gap is explicitly stated. A missing prerequisite is an honest **partial audit**, not fabricated execution evidence.
