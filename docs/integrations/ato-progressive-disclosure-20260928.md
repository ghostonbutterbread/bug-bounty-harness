# Progressive ATO idea discovery — integration dossier

- **Status:** accepted for beta integration after metadata correction
- **Owner:** Hermes / Kanban `t_d68599c3`
- **Branch:** `docs/ato-progressive-disclosure-20260928`
- **Base commit:** `74db0772e459b646297a98d5dacd112d466879ed`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Owning feature branch/ref:** `docs/ato-progressive-disclosure-20260928`
- **Latest immutable recovery checkpoint:** `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`
- **Feature implementation commit(s):** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`, `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`
- **Inspiration / canonical references:** prior ATO atlas `skills/ato/references/methods.md`, repo-root ATO context/playbook, `skills/password-reset/references/ato-patterns.md`, user feedback in Discord thread 1553084831322083382.

## Intent

Keep all plausible ATO idea families discoverable without demanding full reference loads. Preserve full hypothesis coverage (no numerical cap), current ownership/scope gates, primary-source attribution, and focused specialist ownership.

## Implemented contract

`/ato` now contains the compact observable-signal idea map and loads only relevant topical expansion(s) or specialists while explicitly preserving unrestricted plausible-hypothesis coverage. The 26-source atlas and duplicate repo-root context/playbook were migrated into four topical references, one optional flow-handoff reference, and `/password-reset`'s owned pattern reference; all 26 source URLs remain reachable in the topical/specialist files. The registry now points to the router. Related magic-login/code purpose is routed to the expanded password-reset specialist. No live target behavior changes.

## Evidence and review

- Tests and commands: all topical/specialist citation blocks rendered from the source ledger and individually verified (non-strict; per-file unused-ledger warnings expected); all 26 original source URLs preserved; static route assertions cover all six referenced paths, no legacy mandatory reads, and no fixed idea cap; `git diff --check` passed. Historical mandated load: 34,160 bytes of four documents. Current root: 6,238 bytes; root + largest relevant ATO expansion: 11,727 bytes. These are file-size comparisons, not measured token/runtime savings. Reviewer scenario checks passed; post-merge runtime resolution pending. Focused skill-test discovery ran 19 tests with one unrelated pre-existing failure in `test_skill_command_lane_safety.py` caused by `docs/integrations/broad-goal-map-reconciliation.md:24`, confirmed present in `origin/beta`; this task does not modify that dossier.
- Independent review: first review blocked two method omissions; corrected in `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`. Fresh review found ATO content and beta compatibility acceptable, but blocked on this dossier's stale checkpoint/size metadata; corrected here. No content blocker remains.
- Replay/cohort/fixture evidence: none; documentation-only change.
- Merge/ancestry evidence: pending actual beta merge and post-merge checks.

## Blockers and deferred work

Initial independent review blocked integration on two method-loss gaps: token leakage after opening a valid reset link, and support-assisted recovery recognition. Both were restored in the owning routes and verified in the fresh review. The remaining administrative blocker was stale dossier metadata, corrected here. Citation checker counts one source-bearing Markdown bullet as several sentences because citations follow the final sentence; standalone topical files therefore pass URL/ID verification without a numerical coverage threshold. Do not infer unsupported claims from the mechanical percentage.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ato-progressive-disclosure-20260928`
- **Latest immutable recovery checkpoint:** `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`
- **Feature implementation commit(s):** `572e6ed0cb5bb3b75acf2ac7b81b6680e0e87055`, `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`
- **Exact resume point:** verify this metadata correction and compatibility from current beta; merge the accepted feature while excluding this branch-local dossier, run focused checks, push beta, and verify runtime projection.
- **Working-tree state at handoff:** clean after the dossier-only handoff commit; current tip is later than both implementation commits.

## Decision gates

- **Integration gate:** independent review, clean beta, source/route checks.
- **Activation gate:** managed runtime symlink and fresh skill/reference resolution.
- **Promotion gate:** no main promotion without explicit direction.

## Decision record

- 2026-09-28 — user explicitly requested skill update and push; created dedicated feature worktree from current beta.
- 2026-09-28 — initial review identified two method-loss blockers; corrected in `4ce1e2706a5777403da8cb1e581f6cca1a5b9a94`. Fresh review found no remaining ATO content blockers and a conflict-free beta preflight; its sole integration objection was stale dossier metadata, corrected in this handoff commit. Accepted for beta integration subject to a clean actual merge and post-merge checks.
