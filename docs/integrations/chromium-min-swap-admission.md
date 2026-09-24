# Chromium minimum-free-swap admission guidance

- **Status:** feature
- **Owner:** Hermes bugfix profile
- **Branch:** `docs/chromium-min-swap-admission`
- **Base commit:** `3b305878200dda94261a120b59cbda0a5a6826f5`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-24
- **Owning feature branch/ref:** `docs/chromium-min-swap-admission`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryu's correction in Discord thread 1552725966894272573; provisioner `admission()` and request flag.

## Intent

Tell agents how to provision a browser when free swap alone falls below the default threshold, without turning off swap or bypassing the RAM gate. Preserve provisioner ownership and queueing for other causes.

## Implemented contract

The Chromium skill permits a same-task retry with `--min-swap-free-mib 0` when the admission result shows only a swap-threshold failure, RAM suffices, and current memory pressure is healthy. The option changes only a per-request minimum; it does not disable swap. No executable code or host settings change.

## Evidence and review

- Tests and commands: `git diff --check` passed; source inspection confirms `--min-swap-free-mib` on request and admission compares `MemAvailable` and `SwapFree` against independent thresholds.
- Independent review: pending.
- Replay/cohort/fixture evidence: not applicable to documentation-only change.
- Merge/ancestry evidence: based on fetched `origin/beta` 3b30587; pending integration.

## Blockers and deferred work

No known blocker. Hoster runtime activation/projection is distinct from pushing beta; verify separately before claiming Hoster agents consume this wording.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/chromium-min-swap-admission`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Commit, independently review, merge to beta, test, push, read back remote.
- **Working-tree state at handoff:** changes uncommitted until checkpoint.

## Decision gates

- **Integration gate:** independent review and clean diff on current beta.
- **Activation / cohort gate:** separate Hoster projection verification if requested.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-09-24 — created scoped skill guidance; review pending.
