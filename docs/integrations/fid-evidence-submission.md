# FID evidence-to-submission lifecycle integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/fid-evidence-submission`
- **Base commit:** `0afc6960b2856ed3d16e77157170c615856c1e59`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** `89bd76c` (installed pin; final review fix pending)
- **Feature implementation commits:** `45f36fd`, `21ebf0c`, `89bd76c`; final fix pending
- **Inspiration / canonical references:** Ryushe's FID → evidence → rough report → exploration → concise submission workflow; `security-reporting`, `manual-hunter`, Bounty Core report writer.

## Intent

Create one evidence and rough report per verified FID, evolve the proven impact on the same finding, and create one concise submission after the boundary is understood. Never auto-submit externally, silently replace hand edits, invent proof, or run live target probes from storage code.

## Implemented contract

In progress: Bounty Core provider owns packet initialization and draft; BBH owns the reporting agent route, readiness operation and scoped investigation handoff. One `EVIDENCE.md`, `REPORT.md`, and `SUBMISSION.md` per FID.

## Evidence and review

- Tests and commands: provider beta full 158 passed and focused 41 passed; BBH installed pinned provider `54ac5e8` via `.venv` direct_url.json; consumer focused 36 passed and relevant subset 30 passed (4 stale assertions excluded). The same four report-layout tests fail in unmodified BBH beta against the installed provider and are not caused by this feature.
- Independent review: two passes found free-form secret copying and empty program-form acceptance; corrected with tests. Final provider review accepted `1122ea5` and beta is published at `54ac5e8`. Consumer review found that 'unverified' in an honest negative was rejected; corrected with a regression, final re-review pending.
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
- **Latest immutable recovery checkpoint:** `89bd76c` (final reviewer correction pending commit)
- **Feature implementation commit(s):** `45f36fd`, `21ebf0c`, `89bd76c`
- **Exact resume point:** final consumer review, integration to beta, launcher and skill resolver verification.
- **Working-tree state at handoff:** intentionally uncommitted final correction until regression checks.

## Decision gates

- **Integration gate:** focused tests and independent reviews for both repos, exact provider pin and installed provenance.
- **Activation / cohort gate:** beta merge is separate from runtime skill projection.
- **Promotion gate:** no stable/main promotion without explicit owner direction.

## Decision record

- 2026-09-29 — feature worktree created from fetched beta; implementation underway.
