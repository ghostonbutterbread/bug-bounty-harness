# Bunny model arguments integration dossier

- **Status:** accepted for beta integration
- **Owner:** Hermes / Kanban `t_32c13336`
- **Branch:** `feat/bunny-model-args`
- **Base commit:** `05ad56b7f17dd3d013ce0f76ec6363b307407009`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12
- **Owning feature branch/ref:** `feat/bunny-model-args`
- **Latest immutable recovery checkpoint:** `ad388a3c1fdee5a74f4f596b4547286660dc3407`
- **Feature implementation commit(s):** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`, `ad388a3c1fdee5a74f4f596b4547286660dc3407`
- **Inspiration / canonical references:** Discord thread `1559275839219306567`; `skills/bunny/SKILL.md` and `tests/test_bunny_skill.py`; Hermes native delegation and CLI model routing.

## Intent

Accept mode (`multi`, `offhand`) and run-local worker model/provider arguments to Bunny without hardcoded model-family routing or a global inference/config change. Preserve collaborative checkpoint and safety boundaries. This is a skill/workflow change, not permission for target testing or a Hermes core tool rewrite.

## Implemented contract

`Bunny` composes `multi`/offhand mode selection with a run-local worker model argument. The coordinator retains its model. The skill directs provider/model resolution through configured authenticated routes rather than a vendor map, checks native inheritance and any global delegation pin, then requires verification of each worker's route and approval mode before live work. Hermes's current model-facing `delegate_task` cannot enforce a per-worker override, so the documented fallback is an owned interactive PTY with invocation-scoped model/provider flags, bounded checkpoint turns, and process-ID accounting. No global config edits or approval-bypassing one-shot live worker; unresolved routes stop before target actions. The offhand worker remains final-result-only and the multi cap counts CLI workers.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill -v` (8 pass); `git diff --check` (pass); Hermes provider-qualified startup resolver returned `StartupModelRoute(model='gpt-6-sol', provider='openai-codex')` with a hypothetical ZAI current provider. One interactive `hermes -m gpt-6-sol --provider openai-codex --cli` returned `/status` `Model: gpt-6-sol (openai-codex)`, `Approvals: smart`, and `READY`; exited 0. A second owned PTY at PID 256611 reported the same route/approval mode, returned `CHECKPOINT observation=none next=steer`, accepted a second bounded instruction on the same PTY and returned `STEER_ACK`, then exited 0. No tools or target traffic.
- Independent review: `70eefac6dd68fa7d733640ff64631f44538fdad0` BLOCK on inherited YOLO/off approvals, incomplete interactive process/checkpoint/slot lifecycle, and overstated evidence. Fresh read-only review of `08904323a06823fc87b048ed1e064db8808671de` returned PASS: focused suite 8/8, clean diff, effective approval status, PTY ownership and multi-cap, offhand final-only, and bounded evidence claims.
- Replay/cohort/fixture evidence: read-only worker transport smoke above; no live cross-provider Bunny campaign or target action. Source audit: `delegate_task` resolves one config-derived credential bundle per batch, with no model-facing per-task override; a provider pin resolves the provider's own credential bundle.
- Merge/ancestry evidence: feature reconciled with then-current beta `cfdc9ddf0d54516e3bd369b6d8edb72ae024a4c1` via `70eefac6dd68fa7d733640ff64631f44538fdad0`; expected feature delta remains Bunny skills, test, and dossier only.

## Blockers and deferred work

- **Missing test or evidence:** a live cross-provider Bunny campaign was deliberately not run; provider-qualified startup resolution was checked offline and an explicit-provider worker completed a read-only two-turn checkpoint/steer lifecycle.
- **Command / fixture / environment needed:** an authorized campaign with explicit cross-provider model selection, only when the owner invokes Bunny for target work.
- **Trigger to run it:** future authorized Bunny invocation specifying a different provider/model.
- **Why it blocks integration, activation, or promotion:** not an integration blocker for skill guidance; no target authorization was requested here.
- **Next completion step / successor reference:** integrate reviewed skill changes into beta while excluding this branch-local dossier; verify pushed beta and projected skill.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-model-args`
- **Latest immutable recovery checkpoint:** `ad388a3c1fdee5a74f4f596b4547286660dc3407`
- **Feature implementation commit(s):** `0e2bc513077549a1a5860079a7c366b9cc5eb98e`, `ad388a3c1fdee5a74f4f596b4547286660dc3407`
- **Exact resume point:** integrate accepted feature from reviewed `08904323a06823fc87b048ed1e064db8808671de` with this decision-record-only successor commit; exclude dossier from beta.
- **Working-tree state at handoff:** clean after dossier-only commit.

## Decision gates

- **Integration gate:** focused tests, read-only spawn smoke, independent review, clean beta merge.
- **Activation / cohort gate:** verify local projected skill resolves to merged beta; no target run.
- **Promotion gate:** no stable/main promotion in this task.

## Decision record

- 2026-10-12 — created task and dedicated worktree from current beta.
- 2026-10-12 — implementation checkpoint `0e2bc513077549a1a5860079a7c366b9cc5eb98e`; focused skill tests and read-only provider startup smoke passed.
- 2026-10-12 — reconciled feature with `cfdc9ddf0d54516e3bd369b6d8edb72ae024a4c1`; reviewer blocked approval/lifecycle/evidence claims on `70eefac6dd68fa7d733640ff64631f44538fdad0`; corrected guidance and ran a two-turn PTY smoke.
- 2026-10-12 — review correction checkpoint `ad388a3c1fdee5a74f4f596b4547286660dc3407`; fresh verdict pending.
- 2026-10-12 — fresh independent review PASS on `08904323a06823fc87b048ed1e064db8808671de`; accepted beta integration, with live cross-provider campaign evidence deferred until authorized invocation.
