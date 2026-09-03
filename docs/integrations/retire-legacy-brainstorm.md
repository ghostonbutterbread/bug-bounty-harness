# Retire legacy BBH Brainstorm skill integration dossier

- **Status:** review-ready
- **Owner:** BBH / General Skills migration
- **Branch:** `chore/retire-general-brainstorm`
- **Base commit:** `52f8c4672906d4904fbfd19b844d1d57c11eb3fd`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-03
- **Owning feature branch/ref:** `chore/retire-general-brainstorm`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** General Skills beta commit `83d1bd2` (`merge: add seed-assisted general brainstorm skill`)

## Intent

Move reusable Brainstorm ownership from BBH to General Skills without retaining two runnable canonical skills named `brainstorm`. BBH retains its distinct `brainstorm-spec` runtime and workflow support unchanged.

## Implemented contract

Deletes only BBH's legacy `skills/brainstorm/SKILL.md` and `_meta.json`. The shared General Skills capability owns domain-general brainstorming guidance; BBH's `brainstorm-spec` remains the BBH-specific dynamic-agent feature. No live testing, target scope, runner, storage, or runtime behavior changes.

## Evidence and review

- Tests and commands: `PYTHONPATH=. python3 -m pytest tests/test_migrated_skill_commands.py tests/test_skill_command_lane_safety.py -q` — 3 passed, 57 subtests passed; reviewer additionally ran 33 focused BBH runtime/spec tests and relevant static compilation successfully.
- Independent review: accepted with no blocking findings in delegation `deleg_93f77890`.
- Merge/ancestry evidence: General Skills beta contains reviewed replacement at `83d1bd2`; BBH review confirmed no Python import or direct legacy-path reference remains.

## Blockers and deferred work

- **Missing test or evidence:** profile sync activation after BBH beta integration.
- **Command / fixture / environment needed:** normal profile-aware `aiskillsync` dry-run, apply, follow-up dry-run, symlink resolution, and fresh Hermes skill load.
- **Trigger to run it:** immediately after the BBH deletion is integrated and pushed to `beta`.
- **Why it blocks integration, activation, or promotion:** it does not block source integration, but it blocks calling the shared skill active in the current Hermes runtime.
- **Next completion step / successor reference:** sync verification receipt after beta push.

## Interruption / resume handoff

- **Owning feature branch/ref:** `chore/retire-general-brainstorm`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit the reviewed deletion and this dossier, merge into clean BBH `beta`, remove dossier from beta, then execute profile-aware sync verification.
- **Working-tree state at handoff:** intentionally uncommitted pending the final feature commit.

## Decision gates

- **Integration gate:** deletion is limited to legacy skill files; independent review accepts; focused BBH regression checks pass.
- **Activation / cohort gate:** sync projection must resolve `brainstorm` only to General Skills beta; a fresh Hermes resolver must load it.
- **Promotion gate:** no main promotion requested; beta-only integration.

## Decision record

- 2026-09-03 — reviewed legacy-skill retirement; accepted for beta integration pending feature commit.
