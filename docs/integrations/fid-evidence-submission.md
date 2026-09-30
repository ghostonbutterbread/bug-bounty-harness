# FID evidence-to-submission lifecycle integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/fid-evidence-submission`
- **Base commit:** `0afc6960b2856ed3d16e77157170c615856c1e59`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** `45f36fd` (initial slice; correction checkpoint pending)
- **Feature implementation commits:** `45f36fd`; subsequent correction commit pending
- **Inspiration / canonical references:** Ryushe's FID → evidence → rough report → exploration → concise submission workflow; `security-reporting`, `manual-hunter`, Bounty Core report writer.

## Intent

Create one evidence and rough report per verified FID, evolve the proven impact on the same finding, and create one concise submission after the boundary is understood. Never auto-submit externally, silently replace hand edits, invent proof, or run live target probes from storage code.

## Implemented contract

In progress: Bounty Core provider owns packet initialization and draft; BBH owns the reporting agent route, readiness operation and scoped investigation handoff. One `EVIDENCE.md`, `REPORT.md`, and `SUBMISSION.md` per FID.

## Evidence and review

- Tests and commands: provider full 158 passed; consumer focused 34 passed against provider feature source. Installed pinned-provider and post-merge tests pending.
- Independent review: two passes found free-form secret copying and empty program-form acceptance; both corrected with tests. Final provider acceptance and consumer pin review pending.
- Replay/cohort/fixture evidence: isolated provider→consumer packet-to-submission test, no target traffic.
- Merge/ancestry evidence: feature reconciled with fetched `origin/beta` via `dd14cf2`; base `0afc696`.

## Blockers and deferred work

- **Missing test or evidence:** provider API review, consumer integration against pinned provider, focused packet and readiness tests.
- **Command / fixture:** provider `tests/test_reports.py tests/test_ledger_v2_contract.py`; consumer `agents/test_finding_submission.py agents/test_manual_hunter.py` with temp storage.
- **Trigger:** provider feature accepted and integrated to immutable beta commit.
- **Why it blocks integration:** BBH cannot claim automatic packet creation against an unpinned provider.
- **Next step:** review provider, pin verified SHA, install manifest, exercise end-to-end.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** `45f36fd` (corrections awaiting commit)
- **Feature implementation commit(s):** `45f36fd`
- **Exact resume point:** accept provider, pin published beta SHA, install and test consumer, then integrate.
- **Working-tree state at handoff:** intentionally uncommitted corrections until local checks and commit.

## Decision gates

- **Integration gate:** focused tests and independent reviews for both repos, exact provider pin and installed provenance.
- **Activation / cohort gate:** beta merge is separate from runtime skill projection.
- **Promotion gate:** no stable/main promotion without explicit owner direction.

## Decision record

- 2026-09-29 — feature worktree created from fetched beta; implementation underway.
