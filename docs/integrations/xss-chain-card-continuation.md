# XSS chain-card continuation integration dossier

- **Status:** feature (initial mapping-card redaction repair verified offline; independent re-review pending)
- **Owner:** focused hybrid-runner agent
- **Branch / owning ref:** `feat/xss-chain-card-continuation`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-chain-card-continuation`
- **Base commit:** `ca76506b830880c691316e8912a83ec50e4d313f` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-24 UTC
- **Latest immutable recovery checkpoint:** `b9fc537dd588e299e287c770614419ba9270aaf4` (pre-mapping repair; inspect current tip for this fix)
- **Feature implementation commit(s):** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`, `2c0249bf401c462be7dc1ed74da6d7a6eb8ed550`, `b4ebe4fcf99402512bc96b86daf8b8f4b3820e9c`, `b9fc537dd588e299e287c770614419ba9270aaf4`, plus current tip for mapping repair
- **Inspiration / canonical references:** `agents/hybrid_runner.py`, `agents/leads.py`, XSS router, Coverage and MapStore/Leads policies.

## Intent

Preserve parameter-to-route provenance and turn a completed XSS worker's one bounded handoff into an evidence-linked, review-only chain card and follow-up packet. This is not the current Hoster Bunny/Pi orchestrator. No automatic follow-up dispatch, target probe, finding, or new canonical evidence schema is implied.

## Implemented contract

- Planning creates `worker_packets/<id>-mapped.md` from selected route and literal parameter names, citing `classification.jsonl`, marking consumer unknown and no connected edge. It excludes query values and redacts each derived route and field before Markdown interpolation using the same value helper as continuation cards; ordinary parameter names remain actionable. The run-local classification and packet inventory are not this derived-card disclosure boundary.
- The worker packet routes through `xss`, not just DOM/reflected classes; it specifies one optional `handoff.json` with source/field route, consumer, mapped/connected state, observed basis, candidate chain, blocker, exact unknown, discriminator, and existing run-relative evidence pointers.
- After a **completed** worker, the runner validates a single XSS handoff against that packet's routes and named query fields; body fields are optional observed enrichment only when a separate worker-owned structured JSON observation records the exact route/location/key and is cited by the handoff. It ensures referenced files resolve within the run and requires worker-owned evidence for a worker-reported connected edge. A connected card requires an explicit sink-context category; absence remains usable for a mapped card. Generated cards carry worker-reported source/field, consumer, sink context, observed basis, candidate chain, blocker, unknown, next discriminator, and explicit run-relative evidence pointers. Every interpolated value is passed through derived-output redaction, including provenance and refs; the shared redactor now handles synthetic `api_key=...` and JSON API key values without discarding ordinary explanation. Pointers containing secrets may be redacted and no longer directly resolvable; the run-local handoff remains the review source. Worker observations are claims for reviewer verification, not independently proven request captures. On rerun, the runner clears the prior continuation, state, and task-owned XSS `workers/<id>/handoff.json` **before dispatch**; a successful worker that produces no new handoff cannot reuse an old one. It emits `continuations/<id>.md` and `continuation_state.json`; invalid or incomplete input yields no continuation. These are ephemeral review packets, not MapStore/Leads/Coverage records. The reviewer must inspect the cited evidence and use canonical writers for reusable facts and deliberate tests.
- `execute_plan` return shape and deep-dive stdout remain unchanged. The runner never starts a continuation worker from untrusted handoff content.

## Evidence and review

- `python3 -m pytest -q agents/test_hybrid_runner.py::test_xss_successful_rerun_without_new_handoff_does_not_reuse_old_one` → red before fix (old handoff still present at dispatch), green after fix.
- `python3 -m pytest -q agents/test_hybrid_runner.py::test_xss_initial_mapping_redacts_derived_route_and_field_without_query_values` → red before fix (raw secret in mapped route/field), green after fix; offline fixture covers encoded query-key syntax, three excluded query values, and ordinary `q`/`title` fields.
- `python3 -m pytest -q agents/test_hybrid_runner.py` → 20 passed (offline; continuation regression exercises real `execute_plan`, with only CLI spawn mocked; separate redaction regressions cover both initial mapping and every emitted handoff value with ordinary text).
- `git diff --check` → clean.
- Tests cover route/field pairing, absent consumer, connected handoff packet with actionable fields and evidence pointers, rejected wrong field/route, missing/escaped evidence, malformed JSON, incomplete worker skip, body-key observation mismatch, synthetic `api_key=do-not-copy` in prose/source/field/ref, ordinary text preservation, explicit connected sink context, failed-rerun stale-card cleanup, and successful rerun without a new handoff. No target traffic occurred.
- Independent review: prior P1/P2 feedback addressed; re-review pending parent/reviewer.
- Merge/ancestry: feature based on fetched `origin/beta` at base SHA; no merge/push requested.

## Blockers and deferred work

- No live XSS result, source-to-sink proof, or Hoster Bunny/Pi integration is claimed. A future authorized task would need selected program scope, owned fixture, live policy and evidence before any live test. This does not block this offline artifact feature.
- Independent diff review and integration-lane checks are the next gate; parent owns review and eventual merge decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-chain-card-continuation`
- **Latest immutable recovery checkpoint:** `b9fc537dd588e299e287c770614419ba9270aaf4`; inspect current tip for mapping repair.
- **Feature implementation commit(s):** `3b4d4b86a541add63f6ab6a6bd88f3d3d8897e86`, `2c0249bf401c462be7dc1ed74da6d7a6eb8ed550`, `b4ebe4fcf99402512bc96b86daf8b8f4b3820e9c`, `b9fc537dd588e299e287c770614419ba9270aaf4`, plus current tip.
- **Exact resume point:** independently re-review the initial mapping-card derived-output redaction against the implementation and offline tests, then decide integration into `beta`.
- **Working-tree state at handoff:** expected clean after feature commit.

## Decision gates

- **Integration gate:** independent review and focused offline tests on reconciled beta tip; parent handles integration.
- **Activation / cohort gate:** none requested; no claim of deployed Hoster orchestration.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-24 — implemented bounded review-only continuation, offline suite green; implementation checkpoint committed, independent review found P1/P2 issues.
- 2026-10-24 — addressed body-key provenance, generated-card text safety, explicit connected sink context, and stale rerun cleanup; offline suite 17 passed, re-review pending.
- 2026-10-24 — addressed successful-rerun stale handoff reuse before dispatch, with a red/green offline test through real artifact validation; offline suite 18 passed, re-review pending. No merge/push or target traffic.
- 2026-10-24 — restored bounded actionable fields and explicit evidence refs in generated continuation, with per-value derived redaction for provenance and prose; offline suite 19 passed including real `execute_plan` card path and synthetic secret regression. Independent review pending; no merge/push or target traffic.
- 2026-10-24 — final review reproduced a raw synthetic `api_key=do-not-copy` in the initial mapped card. Reused the per-value derived-output redactor for both mapped route and field, preserving ordinary names and excluding query values; offline regression red before fix, full focused suite 20 passed. Independent re-review pending; no merge/push or target traffic.
