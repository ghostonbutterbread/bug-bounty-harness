# Recon Bus noisy-raw promotion integration dossier

- **Status:** feature (awaiting independent review; not integrated)
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/recon-bus-noisy-raw`
- **Worktree:** `/home/ryushe/worktrees/bbh-recon-bus-noisy-raw`
- **Base commit:** `5b31aab52282d39e52053f64ce8cd4132b7ad604` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none before implementation commit; current branch tip after commit is the recovery point
- **Feature implementation commit(s):** pending
- **Inspiration:** PC-20261003-012719-0518d9ab; PC-20261003-012719-66a99c06

## Intent and ownership

Repair `agents/recon/promote_run.py` candidate parsing and candidate-file discovery. Synthetic pre-fix regressions reproduced both bugs: console lines in `raw/httpx.txt` were written into alive inventory; manifest-declared `dirs_status/_logs/alive.txt` was discovered as alive. Malformed URL-shaped input (`http://[broken`) did not receive a source-located error. No live target traffic or existing run corpus was used.

## Implemented contract

Known URL-bearing output files are parsed into normalized HTTP(S) URL candidates before any append; console lines are counted but not promoted, while malformed URL-looking lines raise a file:line diagnostic. Existing scope enforcement stays with Recon Bus append. `dirs_status` recursion and manifest-declared files exclude `_logs` directories, not normal status results. Promotion result reports discovered source files, per-file line/accepted/ignored/duplicate counts, and excluded internal log paths. No URL probing in the synthetic reproduction.

## Evidence and review

- RED: four synthetic test cases added; original first three failed with console contamination, log discovery, and missing malformed URL diagnostic respectively.
- GREEN: `python3 -m unittest tests.test_recon_bus tests.test_recon_promote_run` — 39 tests passed.
- `git diff --check` — passed.
- Independent review: pending parent/release gate.
- Branch topology: fetched `origin/beta`; local `master` is not the selected lane. No integration or push authorized.

## Blockers and deferred work

- No live Recon-Ry artifact replay: prohibited for this task. Trigger a controlled replay only after normal independent review and authorization, using a disposable/synthetic run root and scope store; not an integration gate for this offline repair.
- Independent review and beta integration are intentionally deferred to parent. No papercut closure authorized.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/recon-bus-noisy-raw`
- **Latest immutable recovery checkpoint:** implementation commit after commit creation; see branch tip
- **Feature implementation commit(s):** pending
- **Exact resume point:** independent review of source/test diff, then parent decides integration.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** independent review and parent approval; not done here.
- **Activation / cohort gate:** none in this offline patch.
- **Promotion gate:** not authorized; no beta/main publication.

## Decision record

- 2026-10-15 — reproduced both defects against fetched beta and implemented isolated offline repair; awaiting independent review.
