# ATO chain composition integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/ato-chain-composition`
- **Base commit:** `5bd12fbb76f8506dfc4e78eab6de59d904a2a9c5`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Owning feature branch/ref:** `docs/ato-chain-composition`
- **Latest immutable recovery checkpoint:** `f99e5586eb77547689dcc81fcfa68a28de384801`
- **Feature implementation commit(s):** `f99e5586eb77547689dcc81fcfa68a28de384801`
- **Inspiration / canonical references:** Ryu's Discord request in thread `1560368390349262923`; existing `skills/ato/SKILL.md` and topical references; October 12 owned SoundCloud ATO handoff as motivating example (not a target claim in the skill).

## Intent

Help an ATO agent reason about a missing causal edge between an observed primitive and unauthorized control without loading a fixed checklist, asserting speculative victim reachability, or duplicating specialists. Preserve existing `/ato` safety/proof and on-demand routing.

## Implemented contract

The root router names non-exhaustive entry, authority, binding, and final-proof pieces and conditionally loads one new `references/chain-composition.md` when a primitive stalls. The optional reference provides an observed-signal-to-specialist bridge and smallest owned-account discriminator, separating browser delivery from bearer authority and same-origin access from sibling-host execution. Existing focused references and specialist skills remain owners of mechanics; `flow-handoff.md` remains the flow-map template.

## Evidence and review

- Tests and commands: `git diff --check`; Python assertions that `/ato` frontmatter is intact, root references the new file, and `flow-handoff.md` remains present. PortSwigger source bodies retrieved through safe-fetch. No target live testing.
- Independent review: ACCEPT for beta integration at feature tip `752d699fb817c7ef6af7919d769cdbb850d5a268`; read-only checks passed for frontmatter, references, source labels, specialist names, dossier SHA ancestry, and clean worktree. Dossier excluded from beta merge.
- Replay/cohort/fixture evidence: none; instruction-only change, no live target action.
- Merge/ancestry evidence: pending beta integration.

## Blockers and deferred work

None known. Review and projection verification remain release gates, not waived tests.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ato-chain-composition`
- **Latest immutable recovery checkpoint:** `f99e5586eb77547689dcc81fcfa68a28de384801`
- **Feature implementation commit(s):** `f99e5586eb77547689dcc81fcfa68a28de384801`
- **Exact resume point:** independent review of current feature tip, then integrate reviewed branch into clean `beta`, push, and verify runtime resolver.
- **Working-tree state at handoff:** clean after dossier commit; feature tip includes a later dossier-only handoff commit.

## Decision gates

- **Integration gate:** targeted text/pointer checks, clean diff, independent review; beta merge only after acceptance.
- **Activation / cohort gate:** resolved synced `ato` pointer and fresh load of new reference on intended runtime.
- **Promotion gate:** beta only; no main promotion implied.

## Decision record

- 2026-10-15 — drafted minimal root router plus optional chain-composition reference in isolated feature worktree.
- 2026-10-15 — independent read-only reviewer accepted tip `752d699fb817c7ef6af7919d769cdbb850d5a268` for beta integration; no blockers or deferred tests. Integrate only the two skill files, excluding this branch-local dossier.
