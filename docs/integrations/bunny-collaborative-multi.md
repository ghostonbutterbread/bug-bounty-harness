# Bunny collaborative multi sub-skill integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/bunny-collaborative-multi`
- **Base commit:** `a2b53d21650ff7e4201d310ecd19cf00c086606f`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/bunny-collaborative-multi`
- **Latest immutable recovery checkpoint:** `e2f993d261a30e7ae0f140fac6b7ec91f6ae5273` (implementation)
- **Feature implementation commit(s):** `e2f993d261a30e7ae0f140fac6b7ec91f6ae5273`
- **Inspiration / canonical references:** Discord correction 1556756300031852725, `skills/bunny-collaborative/SKILL.md`, `skills/bunny/SKILL.md`, prior beta overlay a2b53d2

## Intent

The multi-program parameter belongs to Bunny Collaborative, not the `/goal` workflow. Move the earlier portfolio rules to a coordinator-only conditional skill without changing collaborative worker behavior or program-specific safety boundaries.

## Implemented contract

Explicit Bunny `multi` routes `bunny` → `bunny-collaborative` → `bunny-multi` (coordinator only). Ordinary collaborative workers do not load the portfolio queue. No `multi` retains the single-program Bunny contract. Remove the `/goal bunny multi` special case from `bug-goals`; when the invocation also uses `/goal`, the overlay applies its one-plan-per-program helper guidance. Offhand plus multi is not silently combined. The run-local queue, maximum three active subagents globally, depth-first checkpoints, and program evidence isolation remain. No standalone CLI runner or live target testing is added.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_bunny_skill.py tests/test_goal_router.py` (13 passed); `python3 scripts/goal_router.py plan --program example --objective 'Find an ATO in password reset' --class auth` (single-program focused-surface plan); `git diff --check` clean.
- Policy alignment: `bunny` mode router, `bunny-collaborative` owner, `bunny-offhand`, `bug-goals`, and registry compared; only `bunny-multi` owns portfolio rules.
- Independent review: pending.
- Replay/cohort/fixture evidence: guidance-only change; no live testing.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

No known blocker. Remote agent hosts are not part of the local beta projection check.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-collaborative-multi`
- **Latest immutable recovery checkpoint:** `e2f993d261a30e7ae0f140fac6b7ec91f6ae5273` (implementation)
- **Feature implementation commit(s):** `e2f993d261a30e7ae0f140fac6b7ec91f6ae5273`
- **Exact resume point:** obtain independent review of the committed feature, integrate into beta and verify local projected skill resolution.
- **Working-tree state at handoff:** clean after dossier-only handoff commit (verify with Git).

## Decision gates

- **Integration gate:** tests, independent review, beta merge checks.
- **Activation / cohort gate:** verify local skill projections resolve new `bunny-multi` and updated routing skill text. No live target activity.
- **Promotion gate:** do not promote to main without explicit direction.

## Decision record

- 2026-10-05 — extracted portfolio overlay into conditional collaborative sub-skill and removed `/goal`-specific route.
