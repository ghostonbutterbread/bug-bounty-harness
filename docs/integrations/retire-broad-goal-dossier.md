# Retire merged broad-goal dossier — integration dossier

- **Status:** review-ready (tests green; independent review pending)
- **Owner:** Hermes Agent, Kanban `t_8ed0b321`
- **Branch:** `fix/retire-broad-goal-dossier`
- **Base commit:** `f4196f7b0798cbddad390b585466fa4843ab0ad2`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `fix/retire-broad-goal-dossier`
- **Latest immutable recovery checkpoint:** `50f084c7d02e2b22c7a3393144be0c3712b1e537`
- **Feature implementation commit(s):** `50f084c7d02e2b22c7a3393144be0c3712b1e537`
- **Inspiration / canonical references:** completed Kanban `t_fbef4b24`; BBH branch-local dossier lifecycle; `tests/test_skill_command_lane_safety.py`.

## Intent

Remove a completed, branch-local handoff dossier accidentally retained on beta. It contains historical direct-run command receipts, which the lane-safety test scans as runnable guidance. The actual broad-goal feature is already merged; Git history preserves the handoff. Do not edit the historical test receipt, weaken the lane-safety scanner, or alter runtime goal behavior.

## Implemented contract

- Delete only the stale `docs/integrations/broad-goal-map-reconciliation.md` from beta through a dedicated fix branch; remove its resolved `BUGFIXES.md` entry.
- No runtime code or current skill changes.

## Evidence and review

- Red baseline: `PYTHONPATH=. python3 -m unittest tests/test_skill_command_lane_safety.py -q` fails on this tracked dossier's historical direct-Python commands.
- Focused: `PYTHONPATH=. python3 -m unittest tests/test_skill_command_lane_safety.py -q` — 2 passed.
- Full isolated suite: `PYTHONPATH=. python3 -m unittest discover -s tests -q` — 129 run, 1 skipped, no failures.
- Reference-impact audit: the only remaining path reference is this branch-local dossier; no live registry, launcher, skill, or test consumer depends on the removed file. The stale `BUGFIXES.md` entry is removed.
- Independent review: pending.
- Merge/ancestry: file exists on beta, not stable `master`; the owning feature's Kanban card is done.

## Blockers and deferred work

- **Missing test or evidence:** independent review and beta post-merge suite.
- **Command / fixture / environment needed:** repository checkout with task branch first on `PYTHONPATH`.
- **Trigger to run it:** after the independently reviewed feature commit and after beta integration.
- **Why it blocks integration, activation, or promotion:** beta currently has a red full suite; Technique Discovery must not merge on a red baseline.
- **Next completion step / successor reference:** commit and obtain independent review, merge fix into beta, remove this branch-local dossier from beta, and rerun the integrated suite.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/retire-broad-goal-dossier`
- **Latest immutable recovery checkpoint:** `50f084c7d02e2b22c7a3393144be0c3712b1e537`
- **Feature implementation commit(s):** `50f084c7d02e2b22c7a3393144be0c3712b1e537`
- **Exact resume point:** obtain independent read-only review of `f4196f7b0798cbddad390b585466fa4843ab0ad2..fix/retire-broad-goal-dossier`; if accepted, merge into clean beta excluding this temporary dossier and rerun suite.
- **Working-tree state at handoff:** clean after dossier-only handoff commit.

## Decision gates

- **Integration gate:** green focused/full suite, independent review, clean beta.
- **Activation / cohort gate:** none; no runtime behavior changes.
- **Promotion gate:** no stable promotion in this task.

## Decision record

- 2026-10-07 — isolated beta-based fix opened; focused RED reproduced.
- 2026-10-07 — `50f084c7d02e2b22c7a3393144be0c3712b1e537` removes only stale handoff and resolved defect note; focused 2 green, full 129 run/1 skipped/0 failed. Independent review pending.
