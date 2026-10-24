# XSS chain-card continuation integration dossier

- **Status:** feature (handoff for independent review)
- **Owner:** focused hybrid-runner agent
- **Branch / owning ref:** `feat/xss-chain-card-continuation`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-chain-card-continuation`
- **Base commit:** `ca76506b830880c691316e8912a83ec50e4d313f` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-24 UTC
- **Latest immutable recovery checkpoint:** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`
- **Feature implementation commit(s):** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`
- **Inspiration / canonical references:** `agents/hybrid_runner.py`, `agents/leads.py`, XSS router, Coverage and MapStore/Leads policies.

## Intent

Preserve parameter-to-route provenance and turn a completed XSS worker's one bounded handoff into an evidence-linked, review-only chain card and follow-up packet. This is not the current Hoster Bunny/Pi orchestrator. No automatic follow-up dispatch, target probe, finding, or new canonical evidence schema is implied.

## Implemented contract

- Planning creates `worker_packets/<id>-mapped.md` from selected route and literal parameter names, citing `classification.jsonl`, marking consumer unknown and no connected edge. Query values are not copied into this card.
- The worker packet routes through `xss`, not just DOM/reflected classes; it specifies one optional `handoff.json` with source/field route, consumer, mapped/connected state, observed basis, candidate chain, blocker, exact unknown, discriminator, and existing run-relative evidence pointers.
- After a **completed** worker, the runner validates a single XSS handoff against that packet's routes and named fields, ensures referenced files resolve within the run, and requires worker-owned evidence for a worker-reported connected edge. It emits `continuations/<id>.md` and `continuation_state.json`; invalid or incomplete input yields no continuation. These are ephemeral review packets, not MapStore/Leads/Coverage records. The reviewer must inspect the cited evidence and use canonical writers for reusable facts and deliberate tests.
- `execute_plan` return shape and deep-dive stdout remain unchanged. The runner never starts a continuation worker from untrusted handoff content.

## Evidence and review

- `python3 -m pytest -q agents/test_hybrid_runner.py` → 15 passed (offline, mock CLI for continuation path).
- `git diff --check` → clean.
- Tests cover route/field pairing, absent consumer, connected handoff packet, rejected wrong field/route, missing/escaped evidence, malformed JSON, and incomplete worker skip. No target traffic occurred.
- Independent review: pending parent/reviewer.
- Merge/ancestry: feature based on fetched `origin/beta` at base SHA; no merge/push requested.

## Blockers and deferred work

- No live XSS result, source-to-sink proof, or Hoster Bunny/Pi integration is claimed. A future authorized task would need selected program scope, owned fixture, live policy and evidence before any live test. This does not block this offline artifact feature.
- Independent diff review and integration-lane checks are the next gate; parent owns review and eventual merge decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-chain-card-continuation`
- **Latest immutable recovery checkpoint:** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`; inspect any later dossier-only tip too.
- **Feature implementation commit(s):** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`.
- **Exact resume point:** review `agents/hybrid_runner.py` and tests, then decide integration into `beta`.
- **Working-tree state at handoff:** expected clean after feature commit.

## Decision gates

- **Integration gate:** independent review and focused offline tests on reconciled beta tip; parent handles integration.
- **Activation / cohort gate:** none requested; no claim of deployed Hoster orchestration.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-24 — implemented bounded review-only continuation, offline suite green; implementation checkpoint committed, independent review pending.
