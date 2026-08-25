# Submission State and Closed Queue — Integration Dossier

- **Task / branch:** t_0b4cc1f7 / `feat/submission-state-closed-queue`
- **Base / target:** `492493a1eec36c727372e8d98532e121e15bb93f` / `beta`

## Intent

Keep operator reporting to one sentence while preventing confirmed, submitted,
and duplicate findings from becoming default next-work material.

## Implemented contract

- Each manual finding carries only `submission.state`, `submission.report`, and
  optional `submission.duplicate_of`; states are `not_submitted`, `submitted`,
  or `duplicate`.
- `manual_hunter.py --set-submission FID` patches the canonical finding and
  refreshes its report navigation.
- `me_ledger.py list` hides closed findings by default; `--include-closed`
  retains the explicit portfolio/status view.
- Default manual and single-agent hunt prompts exclude those findings from work
  selection, except for exact dedupe/FID lookup, explicit retest/report/status,
  or an explicit similar-vulnerability request.

## Evidence

- Focused suite: `19 passed` for submission/manual-hunter/single-agent tests.
- Relevant suite with the local Bounty Core import path: `61 passed` after independent-review corrections.
- Independent review caught and the implementation fixed a backward-compatible
  `cmd_list` caller contract and optional duplicate metadata cleanup.

## Activation boundary

No runtime deployment or skill synchronization is performed by this task.

## Deferred

The repository currently has no FID link in MapStore lead records; enforcing
this same exclusion inside a future `leads --push` projection requires that
linkage rather than heuristic matching.
