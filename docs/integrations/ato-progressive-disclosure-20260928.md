# Progressive ATO idea discovery — integration dossier

- **Status:** re-review pending
- **Owner:** Hermes / Kanban `t_d68599c3`
- **Branch:** `docs/ato-progressive-disclosure-20260928`
- **Base commit:** `74db0772e459b646297a98d5dacd112d466879ed`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Owning feature branch/ref:** `docs/ato-progressive-disclosure-20260928`
- **Latest immutable recovery checkpoint:** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`
- **Feature implementation commit(s):** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`
- **Inspiration / canonical references:** prior ATO atlas `skills/ato/references/methods.md`, repo-root ATO context/playbook, `skills/password-reset/references/ato-patterns.md`, user feedback in Discord thread 1553084831322083382.

## Intent

Keep all plausible ATO idea families discoverable without demanding full reference loads. Preserve full hypothesis coverage (no numerical cap), current ownership/scope gates, primary-source attribution, and focused specialist ownership.

## Implemented contract

`/ato` now contains the compact observable-signal idea map and loads only relevant topical expansion(s) or specialists while explicitly preserving unrestricted plausible-hypothesis coverage. The 26-source atlas and duplicate repo-root context/playbook were migrated into four topical references, one optional flow-handoff reference, and `/password-reset`'s owned pattern reference; all 26 source URLs remain reachable in the topical/specialist files. The registry now points to the router. Related magic-login/code purpose is routed to the expanded password-reset specialist. No live target behavior changes.

## Evidence and review

- Tests and commands: all topical/specialist citation blocks rendered from the source ledger and individually verified (non-strict; per-file unused-ledger warnings expected); all 26 original source URLs preserved; static route assertions cover all six referenced paths, no legacy mandatory reads, and no fixed idea cap; `git diff --check` passed. Historical mandated load: 34,160 bytes of four documents. Current root: 5,760 bytes; root + largest relevant ATO expansion: 11,117 bytes. These are file-size comparisons, not measured token/runtime savings. Reviewer scenario checks and post-merge runtime resolution pending.
- Independent review: pending.
- Replay/cohort/fixture evidence: none; documentation-only change.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

Initial independent review blocked integration on two method-loss gaps: token leakage after opening a valid reset link, and support-assisted recovery recognition. Both were restored in the owning routes; a fresh independent verdict is required before merge. Citation checker counts one source-bearing Markdown bullet as several sentences because citations follow the final sentence; standalone topical files therefore pass URL/ID verification without a numerical coverage threshold. Do not infer unsupported claims from the mechanical percentage.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ato-progressive-disclosure-20260928`
- **Latest immutable recovery checkpoint:** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`
- **Feature implementation commit(s):** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`
- **Exact resume point:** independently review source conservation, owner routing, and representative flow discovery; address blockers, then merge into beta and push.
- **Working-tree state at handoff:** clean after this dossier-only handoff commit; current tip is later than implementation commit.

## Decision gates

- **Integration gate:** independent review, clean beta, source/route checks.
- **Activation gate:** managed runtime symlink and fresh skill/reference resolution.
- **Promotion gate:** no main promotion without explicit direction.

## Decision record

- 2026-09-28 — user explicitly requested skill update and push; created dedicated feature worktree from current beta.
