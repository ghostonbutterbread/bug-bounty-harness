# Bunny firsthand policy loads integration dossier

- **Status:** feature
- **Owner:** hermes
- **Branch:** feat/bunny-firsthand-policy-loads
- **Base commit:** f44dc138cd7087eb53524bebe56c57a74b31b092
- **Intended integration target:** beta
- **Last updated:** 2026-11-12
- **Owning feature branch/ref:** feat/bunny-firsthand-policy-loads
- **Latest immutable recovery checkpoint:** b0bc806923292d663e048ce27621723fd8b87a11
- **Feature implementation commit(s):** b0bc806923292d663e048ce27621723fd8b87a11
- **Inspiration / canonical references:** `~/Shared/skill_seeds/2026-11-12-bunny-worker-firsthand-policy-loads.md` (Ghost review: promote the principle, not the body draft). Whatnot campaign note `campaign-20261111-xss-deep-dive.md` Policy violation + corrective.

## Intent

Stop Bunny workers from treating a coordinator paraphrase as the safety channel. Packets name live policies to load. Before engagement, workers ask whose resource the **action** touches and load `account-testing-policy` when it is not ours or is unclear. Do not restate that policy's engagement rule in Bunny.

## Implemented contract

- `skills/bunny/SKILL.md`: named policy loads (explicit requirement) and a standing ownership question on every packet, including offhand.
- `skills/bunny-collaborative/SKILL.md`: per-action ownership check; packet does not override a loaded policy.
- `skills/bunny-offhand/SKILL.md`: offhand packets still carry the load list and ownership question because those workers do not load Bunny mode skills.
- `skills/bunny/references/dispatch.md`: pointer to the same packet fields.
- Related-skill edges point at `account-testing-policy`; they do not copy its rule.
- Non-claims: no GSTP / hunt-orchestration-policy edit; no role-file restatement; no `skill://` URI; no Whatnot-specific fixture language.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill -v` — 16 passed, including `test_named_policy_loads_and_ownership_question`. `git diff --check` clean.
- Independent review: not started.
- Replay/cohort/fixture evidence: not applicable; text contract only.
- Merge/ancestry evidence: based on `origin/beta` `f44dc138`. Local commit only; not pushed; not merged.

## Blockers and deferred work

- **Missing test or evidence:** independent review of the complete diff; runtime activation on Hoster/beta skill projection; no live Bunny dispatch was run.
- **Command / fixture / environment needed:** independent reviewer on this feature worktree; after merge, verify a fresh consumer loads the new packet/worker sentences.
- **Trigger to run it:** review request from this task; activation after beta merge.
- **Why it blocks integration, activation, or promotion:** BBH policy changes merge to beta only after independent review. A local feature commit does not activate workers.
- **Next completion step / successor reference:** independent review, then merge to `beta` without this dossier.

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/bunny-firsthand-policy-loads
- **Latest immutable recovery checkpoint:** b0bc806923292d663e048ce27621723fd8b87a11
- **Feature implementation commit(s):** b0bc806923292d663e048ce27621723fd8b87a11
- **Exact resume point:** independent review of `b0bc8069` plus this dossier; do not merge to beta until that review accepts.
- **Working-tree state at handoff:** clean after the dossier commit.

## Decision gates

- **Integration gate:** independent review of the complete diff and test evidence; merge into a clean current beta worktree; drop this dossier from beta.
- **Activation / cohort gate:** Hoster/beta skill projection includes the new sentences; a fresh Bunny coordinator would emit the load list and ownership question.
- **Promotion gate:** not requested; do not promote to `main`.

## Decision record

- 2026-11-12 — implemented two-layer contract on `feat/bunny-firsthand-policy-loads`; tests green; awaiting independent review.
