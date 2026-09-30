# FID evidence-to-submission lifecycle integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/fid-evidence-submission`
- **Base commit:** `0afc6960b2856ed3d16e77157170c615856c1e59`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration / canonical references:** Ryushe's FID → evidence → rough report → exploration → concise submission workflow; `security-reporting`, `manual-hunter`, Bounty Core report writer.

## Intent

Create one evidence and rough report per verified FID, evolve the proven impact on the same finding, and create one concise submission after the boundary is understood. Never auto-submit externally, silently replace hand edits, invent proof, or run live target probes from storage code.

## Implemented contract

In progress: Bounty Core provider owns packet initialization and draft; BBH owns the reporting agent route, readiness operation and scoped investigation handoff. One `EVIDENCE.md`, `REPORT.md`, and `SUBMISSION.md` per FID.

## Evidence and review

- Tests and commands: pending provider and consumer focused tests.
- Independent review: pending.
- Replay/cohort/fixture evidence: pending isolated fixture.
- Merge/ancestry evidence: base matches fetched `origin/beta`.

## Blockers and deferred work

- **Missing test or evidence:** provider API review, consumer integration against pinned provider, focused packet and readiness tests.
- **Command / fixture:** provider `tests/test_reports.py tests/test_ledger_v2_contract.py`; consumer `agents/test_finding_submission.py agents/test_manual_hunter.py` with temp storage.
- **Trigger:** provider feature accepted and integrated to immutable beta commit.
- **Why it blocks integration:** BBH cannot claim automatic packet creation against an unpinned provider.
- **Next step:** review provider, pin verified SHA, install manifest, exercise end-to-end.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** finish provider and consumer code, integrate pin, review and test.
- **Working-tree state at handoff:** intentionally uncommitted during active development.

## Decision gates

- **Integration gate:** focused tests and independent reviews for both repos, exact provider pin and installed provenance.
- **Activation / cohort gate:** beta merge is separate from runtime skill projection.
- **Promotion gate:** no stable/main promotion without explicit owner direction.

## Decision record

- 2026-09-29 — feature worktree created from fetched beta; implementation underway.
