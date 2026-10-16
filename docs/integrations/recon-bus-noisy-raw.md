# Recon Bus noisy-raw promotion integration dossier

- **Status:** first independent review blocked; path-handling defects patched, re-review pending
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/recon-bus-noisy-raw`
- **Worktree:** `/home/ryushe/worktrees/bbh-recon-bus-noisy-raw`
- **Base commit:** `5b31aab52282d39e52053f64ce8cd4132b7ad604` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `a592750` on `fix/recon-bus-noisy-raw`, followed by the merge of fetched `origin/beta` `19c8f22`
- **Feature implementation commit(s):** `5de0a04918bfef65f0ba7b6cec28170b06e2ebcd`, `a592750`
- **Inspiration:** PC-20261003-012719-0518d9ab; PC-20261003-012719-66a99c06

## Intent and ownership

Repair `agents/recon/promote_run.py` candidate parsing and candidate-file discovery. Synthetic pre-fix regressions reproduced both bugs: console lines in `raw/httpx.txt` were written into alive inventory; manifest-declared `dirs_status/_logs/alive.txt` was discovered as alive. Malformed URL-shaped input (`http://[broken`) did not receive a source-located error. No live target traffic or existing run corpus was used.

## Implemented contract

Known URL-bearing output files are parsed into normalized HTTP(S) URL candidates before any append; console lines are counted but not promoted, while malformed URL-looking lines raise a file:line diagnostic. Existing scope enforcement stays with Recon Bus append. `dirs_status` recursion and manifest-declared files exclude `_logs` directories, including symlink targets, not normal status results. Promotion result reports discovered source files, per-file line/accepted/ignored/duplicate counts for URL-bearing and alive queues, and excluded internal log paths. Non-URL source kinds retain their existing parsing rather than receiving those counters. No URL probing in the synthetic reproduction.

## Evidence and review

- RED: four synthetic test cases added; original first three failed with console contamination, log discovery, and missing malformed URL diagnostic respectively.
- GREEN: `python3 -m unittest tests.test_recon_bus tests.test_recon_promote_run` — 39 tests passed.
- `git diff --check` — passed.
- Initial independent review blocked: an absolute manifest file with relative run root crashed at `relative_to`, and a manifest symlink re-admitted an internal `_logs` target. Both now have synthetic regressions; 41 focused tests pass. Reviewer also corrected the scope of coverage counters to URL-bearing/alive queues.
- Reconciled the advanced beta `19c8f22` without conflict and reran 41 focused tests and diff checks on the reconciled feature tip; no target traffic.
- Branch topology: fetched `origin/beta`; local `master` is not the selected lane. No integration or push authorized.

## Blockers and deferred work

- No live Recon-Ry artifact replay: prohibited for this task. Trigger a controlled replay only after normal independent review and authorization, using a disposable/synthetic run root and scope store; not an integration gate for this offline repair.
- Independent re-review and beta integration are intentionally deferred to parent. No papercut closure authorized.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/recon-bus-noisy-raw`
- **Latest immutable recovery checkpoint:** `a592750` plus reconciled beta merge (exact tip from branch ref)
- **Feature implementation commit(s):** `5de0a04918bfef65f0ba7b6cec28170b06e2ebcd`, `a592750`
- **Exact resume point:** obtain independent re-review of the reconciled tip, both path-handling corrections and full diff. Parent decides integration.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** first review rejected path-handling; correction awaits re-review and parent approval.
- **Activation / cohort gate:** none in this offline patch.
- **Promotion gate:** not authorized; no beta/main publication.

## Decision record

- 2026-10-15 — reproduced both defects against fetched beta and implemented isolated offline repair; awaiting independent review.
- 2026-10-15 — reviewer reproduced relative-root crash and symlink log admission; patched both with focused regressions, 41 tests passed; re-review pending.
- 2026-10-15 — reconciled `origin/beta` `19c8f22`, 41 focused tests and diff checks passed; re-review pending.
