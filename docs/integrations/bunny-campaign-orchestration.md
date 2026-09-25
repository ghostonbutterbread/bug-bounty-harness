# Bunny campaign orchestration integration dossier

- **Status:** feature
- **Owner:** Hermes (bugfix profile)
- **Branch:** `feat/bunny-campaign-orchestration`
- **Base commit:** `7690fc04e1a539c50013b119cc4a49f3082032f5`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25 UTC
- **Owning feature branch/ref:** `feat/bunny-campaign-orchestration`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's Bunny design discussion; MAPTA coordinator/sandbox/validator pattern; existing `hunter-loop`, `hunt-orchestration`, browser profile and reporting skills.

## Intent

Move the local Bunny prototype into canonical BBH as an opt-in, distinct campaign-coordinator skill. Preserve the existing solo-primary hunt orchestration mode. No new runner, live testing, Docker rollout, or credential sharing.

## Implemented contract

`skills/bunny/SKILL.md` defines coordinator ownership, focused hunter/recon/verifier/reporter roles, upward event vocabulary, evidence and account lease boundaries, and active pressure without claiming motivational language is proof. Registry advertises the opt-in skill; tests check critical boundaries. The skill alone does not implement an automated worker scheduler.

## Evidence and review

- Tests and commands: `python3 -m unittest discover -s tests -p 'test_bunny_skill.py' -v` (3 passed); `git diff --check`; `python3 -m compileall -q tests/test_bunny_skill.py`.
- Independent review: pending.
- Replay/cohort/fixture evidence: not applicable; documentation-only skill.
- Merge/ancestry evidence: feature based on fetched `origin/beta` above; recheck before integration.

## Blockers and deferred work

- **Missing test or evidence:** Fresh consumer resolution on local and Hoster after beta publication.
- **Command / fixture / environment needed:** focused `aiskillsync` dry-run/apply and exact symlink/read-back on both hosts.
- **Trigger to run it:** reviewed feature merged and `origin/beta` contains it.
- **Why it blocks integration, activation, or promotion:** skill text in a feature branch is not an active synced runtime skill.
- **Next completion step / successor reference:** sync both hosts and verify link target/content; no main promotion requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-campaign-orchestration`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run tests, review, commit, merge into current beta, push, sync local/Hoster.
- **Working-tree state at handoff:** intentionally uncommitted until initial test pass.

## Decision gates

- **Integration gate:** focused tests, independent diff review, current beta reconciliation.
- **Activation / cohort gate:** focused sync and runtime resolution on local and Hoster.
- **Promotion gate:** not requested; keep stable untouched.

## Decision record

- 2026-09-25 — created as an opt-in BBH skill on a dedicated beta-based feature branch.
