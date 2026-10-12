# Bunny model arguments integration dossier

- **Status:** review-ready
- **Owner:** Hermes / Kanban `t_32c13336`
- **Branch:** `feat/bunny-model-args`
- **Base commit:** `05ad56b7f17dd3d013ce0f76ec6363b307407009`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12
- **Owning feature branch/ref:** `feat/bunny-model-args`
- **Latest immutable recovery checkpoint:** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`
- **Feature implementation commit(s):** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`
- **Inspiration / canonical references:** Discord thread `1559275839219306567`; `skills/bunny/SKILL.md` and `tests/test_bunny_skill.py`; Hermes native delegation and CLI model routing.

## Intent

Accept mode (`multi`, `offhand`) and run-local worker model/provider arguments to Bunny without hardcoded model-family routing or a global inference/config change. Preserve collaborative checkpoint and safety boundaries. This is a skill/workflow change, not permission for target testing or a Hermes core tool rewrite.

## Implemented contract

`Bunny` composes `multi`/offhand mode selection with a run-local worker model argument. The coordinator retains its model. The router resolves an authenticated provider/model route without a vendor map, checks native inheritance and any global delegation pin, then verifies each worker's actual route before live work. Hermes's current model-facing `delegate_task` cannot enforce a per-worker override, so an explicit override uses an interactive Hermes worker launched with invocation-scoped model/provider flags. No global config edits or approval-bypassing one-shot live worker; unresolved routes stop before target actions. The collaborative skill preserves checkpoints/steering on interactive workers and bounded segments for completion-only transports.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill -v` (8 pass); `git diff --check` (pass); Hermes provider-qualified startup resolver returned `StartupModelRoute(model='gpt-6-sol', provider='openai-codex')` with a hypothetical ZAI current provider; interactive `hermes -m gpt-6-sol --provider openai-codex --cli` returned `/status` `Model: gpt-6-sol (openai-codex)`, `Approvals: smart`, and a real `READY` model response; exited 0. No target traffic.
- Independent review: pending.
- Replay/cohort/fixture evidence: read-only worker spawn above; no target traffic or cross-provider network test. Source audit: `delegate_task` resolves one config-derived credential bundle per batch, with no model-facing per-task override; a provider pin resolves the provider's own credential bundle.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** a live cross-provider Bunny campaign was deliberately not run; provider-qualified startup resolution was checked offline and an explicit-provider worker launched and answered from its authenticated runtime.
- **Command / fixture / environment needed:** an authorized campaign with explicit cross-provider model selection, only when the owner invokes Bunny for target work.
- **Trigger to run it:** future authorized Bunny invocation specifying a different provider/model.
- **Why it blocks integration, activation, or promotion:** not an integration blocker for skill guidance; no target authorization was requested here.
- **Next completion step / successor reference:** independently review scoped diff, integrate beta, verify projected skill.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-model-args`
- **Latest immutable recovery checkpoint:** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`
- **Feature implementation commit(s):** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`
- **Exact resume point:** review implementation commit and this later dossier-only handoff commit, then integrate beta.
- **Working-tree state at handoff:** clean after dossier-only commit.

## Decision gates

- **Integration gate:** focused tests, read-only spawn smoke, independent review, clean beta merge.
- **Activation / cohort gate:** verify local projected skill resolves to merged beta; no target run.
- **Promotion gate:** no stable/main promotion in this task.

## Decision record

- 2026-10-12 — created task and dedicated worktree from current beta.
- 2026-10-12 — implementation checkpoint `0e2bc513077549a1a5860079a7c366b9cc5eb98e`; focused skill tests and read-only provider startup smoke passed.
