# JavaScript coverage-depth vocabulary integration dossier

- **Status:** review-ready
- **Owner:** Hermes (bugfix profile)
- **Branch:** `fix/js-coverage-depth-vocabulary`
- **Base commit:** `0034f9c9f064e0d87b9477d69d8cfb05c9149f3a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `fix/js-coverage-depth-vocabulary`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `/home/ryushe/Shared/skill_seeds/2026-10-08-js-coverage-depth-vocabulary.md`; `skills/js-{pull,hunt}/SKILL.md`

## Intent

Distinguish never-observed JavaScript from shallow/legacy observations and evidenced deep claims. Avoid implying all lenses are exhausted from one observation. Scope is canonical guidance in two skills; do not modify live target data, append-only observations, or writer schema.

## Implemented contract

`js-pull` names four review-depth statuses and legacy handling. `js-hunt` provides disjoint SQL queues using `EXISTS`/`NOT EXISTS` against multiple observation rows; unknown-only statuses remain in the shallow queue, and an independent diagnostic finds unknown statuses even when a deep claim exists for the same hash. A deep claim is lens/flow-scoped, subject to evidence review and reopening. This is writer guidance, not runtime status validation; callers bypassing it can still write arbitrary statuses.

## Evidence and review

- Tests and commands: `python3 /home/ryushe/.hermes/profiles/bugfix/cache/scratch/js_coverage_sql_smoke.py` passed; `python3 -m pytest agents/test_js_analyzer.py -q` 209 passed; `git diff --check` passed.
- Independent review: initial review found mixed deep/unknown hashes absent from the unknown diagnostic; added separate diagnostic query and tested mixed row. Second reviewer found SQL comment implied evidence verification; corrected to say status-only claim/evidence unchecked and clarified exclusion is not completion. Narrow final re-review accepted both corrections; no residual blocker.
- Replay/cohort/fixture evidence: synthetic SQLite fixture for never observed, shallow, legacy, unknown, mixed shallow/deep, mixed deep/unknown, and changed hashes; no private program data.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** none for this guidance-only change; runtime writer validation intentionally not part of the two-skill patch.
- **Command / fixture / environment needed:** none.
- **Trigger to run it:** not applicable.
- **Why it blocks integration, activation, or promotion:** no remaining integration blocker.
- **Next completion step / successor reference:** integrate beta, sync and load active skills; any future enforcement change requires a separate code/data compatibility review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/js-coverage-depth-vocabulary`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit reviewed two-skill patch and temporary dossier; integrate into current beta, omit dossier from beta, publish and resync.
- **Working-tree state at handoff:** intentionally uncommitted: in-progress patch.

## Decision gates

- **Integration gate:** accepted — SQL semantics and 209 targeted tests passed; independent reviewers' two findings corrected and re-reviewed.
- **Activation / cohort gate:** beta commit published, focused aiskillsync no-op dry-run, runtime symlinks resolve beta and skill loads show updated guidance.
- **Promotion gate:** stable only on explicit user direction.

## Decision record

- 2026-10-08 — created from seed; narrow guidance-only change on current beta base.
- 2026-10-08 — 209 JS tests and synthetic SQL passed; independent review found mixed deep/unknown diagnostic gap, corrected and fixture retested. Runtime writer validation remains out of scope for this two-skill update.
- 2026-10-08 — final independent re-review accepted status-only wording and unknown-status audit; integrate to beta without this temporary dossier.
