# FID evidence-to-submission lifecycle integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/fid-evidence-submission`
- **Base commit:** `0afc6960b2856ed3d16e77157170c615856c1e59`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** `97b5669` (final reviewed implementation)
- **Feature implementation commits:** `45f36fd`, `21ebf0c`, `89bd76c`, `97b5669`
- **Inspiration / canonical references:** Ryushe's FID → evidence → rough report → exploration → concise submission workflow; `security-reporting`, `manual-hunter`, Bounty Core report writer.

## Intent

Create one evidence and rough report per verified FID, evolve the proven impact on the same finding, and create one concise submission after the boundary is understood. Never auto-submit externally, silently replace hand edits, invent proof, or run live target probes from storage code.

## Implemented contract

In progress: Bounty Core provider owns packet initialization and draft; BBH owns the reporting agent route, readiness operation and scoped investigation handoff. One `EVIDENCE.md`, `REPORT.md`, and `SUBMISSION.md` per FID.

## Evidence and review

- Tests and commands: provider beta full 158 passed and focused 41 passed; BBH installed pinned provider `54ac5e8` via `.venv` direct_url.json; consumer focused 36 passed and relevant subset 30 passed (4 stale assertions excluded). The same four report-layout tests fail in unmodified BBH beta against the installed provider and are not caused by this feature.
- Independent review: provider privacy and consumer structural issues corrected with regressions. Final provider review accepted `1122ea5` and beta published `54ac5e8`; final consumer re-review accepted `97b5669` for beta.
- Replay/cohort/fixture evidence: isolated provider→consumer packet-to-submission test, no target traffic.
- Merge/ancestry evidence: feature reconciled with fetched `origin/beta` via `dd14cf2`; base `0afc696`.

## Blockers and deferred work

- **Missing test or evidence:** four pre-existing legacy-path assertions remain red on both unchanged beta and this feature; no new lifecycle evidence is missing.
- **Command / fixture:** rerun the four named sync/BaseTeam tests after their separate path-expectation repair; installed `.venv` provider is `54ac5e8`.
- **Trigger:** separate bounded test-maintenance task; do not restore duplicate report layout.
- **Why it blocks integration:** it does not block this reviewed feature because the baseline reproduces identically; it prevents claiming a wholly green reporting suite.
- **Next step:** merge the accepted feature into beta, run focused tests there, activate the selected runtime and verify its skill/launcher path.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/fid-evidence-submission`
- **Latest immutable recovery checkpoint:** `97b5669` (final reviewed code; dossier update pending)
- **Feature implementation commit(s):** `45f36fd`, `21ebf0c`, `89bd76c`, `97b5669`
- **Exact resume point:** accepted feature ready for beta merge, focused post-merge tests, launcher/skill projection check.
- **Working-tree state at handoff:** clean after dossier commit.

## Decision gates

- **Integration gate:** focused tests and independent reviews for both repos, exact provider pin and installed provenance.
- **Activation / cohort gate:** beta merge is separate from runtime skill projection.
- **Promotion gate:** no stable/main promotion without explicit owner direction.

## Decision record

- 2026-09-29 — feature worktree created from fetched beta; implementation underway.
