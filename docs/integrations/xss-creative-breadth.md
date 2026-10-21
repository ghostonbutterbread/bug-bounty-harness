# XSS Idea-Tree Creative Breadth — Integration Dossier

- **Status:** independent release review accepted with two minor wording fixes applied; corrected tip pending verification
- **Owner:** Hermes / BBH XSS
- **Branch/worktree:** `docs/xss-idea-tree-creative-breadth` at `/home/ryushe/worktrees/bbh-xss-creative-breadth`
- **Base beta commit:** `51194c7039af2b2637815656c8de5540cc7d5d64`
- **Intended integration target:** `beta`; no `main` promotion or Hoster rollout
- **Immutable implementation checkpoint:** `42b2b38091f422461c2ad61b81d4853ff9dff953` (latest material correction; this documentary update follows it)
- **Inspiration:** Ryu's feedback in Discord thread `1562231426932539452`, message `1562276037243576503`, and independent read-only methodology review `deleg_3e21b829` of beta `51194c7`.

## Intent and Contract

The published XSS tree already broadens mechanisms but describes "one hypothesis, safe control and falsifier" and a second leaf only for a distinct observed feeder/defense. Revise agent and human routes so agents can retain and explore multiple distinct hypotheses, combine leaves, and invent mechanisms outside the 29-heading source. A comparison/falsifier is a tool for a **particular causal claim** and for interpreting an inert outcome, not an ideation quota or admission gate. Preserve source/sink reachability for a claimed execution path, exact Attempts writer, selected lane's browser proof, and inherited live scope/rate/effects constraints.

## Implemented Change and Evidence

- Owners: `skills/xss/SKILL.md`, `skills/xss-payload-engineering/SKILL.md`, conditional reference tree and narrow leaves, `docs/xss-idea-tree.md`, prior `docs/xss-mechanism-ideation.md` diagram, focused routing tests. The tree now admits unlisted ideas and multiple hypotheses; negatives retire tested links, not sibling feeders/consumers. Each causal claim still needs the relevant execution evidence.
- No target traffic, account actions or payload execution. No global policy rewrite or separate payload catalog.
- Focused test selection after the minor corrections: **9 passed, 1 opt-in browser skipped**. Full feature suite with the checkout-local `.venv` and `PYTHONPATH` rooted here: **305 passed, 1 skipped, 2 failed**. Unchanged beta under the *same feature-venv interpreter*: **304 passed, 1 skipped, the same 2 failed**. Both failures are in unrelated, unchanged `skills/stack-to-program/scripts/README.md` contracts: missing `Outputs/Mutates` fields and an executable lane example. The initial global interpreter's 17 additional failures were caused by this worktree missing `.venv`; `./setup.sh --install-python-deps` resolved them. `git diff --check` clean. Initial independent review accepted; narrow readback and integrated beta/projection verification are **pending**.
- Independent release review of exact `51194c7..d4f1edb` diff returned **ACCEPT for beta review** with two non-blocking wording issues: sink-first exploration was gated by the derived leaf's introductory "first establish" phrase, and a client-interpreter row deferred mechanism ideation until after a suspected reparse was already proven. The human diagram also sounded narrower than its prose. Corrected all three spots and added focused assertions; no technical proof boundary or route inventory changed. A narrow readback of the corrected commit remains before beta integration.

## Release and Interruption Gates

1. Initial implementation and focused regression committed at `5fd1ea9962d00e3ed353254c975c98593632d9dd`; reviewer-led sink-first/reparse corrections committed at `42b2b38091f422461c2ad61b81d4853ff9dff953`. This later documentary checkpoint records provenance only.
2. Independent reviewer accepted creative breadth and evidence/safety boundaries on `d4f1edb`; verify the minor corrections after commit, then beta merge into the clean current integration worktree excluding this branch-local dossier.
3. Run focused and full suite on the integrated tree, identify any pre-existing failures, push beta only from beta worktree, verify the projected route and an on-demand leaf through the skill resolver.
4. Until then the active projection remains the earlier wording at `51194c7`. Resume with an independent read-only review of the corrected branch tip; do not claim activation from this feature branch.

## Decision Record

- 2026-10-20 PDT — independent read-only review held agent-facing wording for a narrow creativity correction, while accepting the tree's mechanism coverage and browser-proof standard. This branch is a methodology correction, not permission for out-of-scope or indiscriminate live tests.
- 2026-10-20 PDT — implementation committed at `5fd1ea9962d00e3ed353254c975c98593632d9dd` after focused 9 pass/1 optional skip and full 305 pass/1 skip/2 unrelated baseline failures. Awaiting independent release review and beta integration.
- 2026-10-20 PDT — fresh read-only reviewer accepted the `d4f1edb` methodology and proof boundaries with two non-blocking minor ambiguities; sink-first and suspected-reparse wording were corrected. Focused/full tests and narrow readback on the corrected tip remain release gates.
- 2026-10-20 PDT — corrected implementation and focused regression committed at `42b2b38091f422461c2ad61b81d4853ff9dff953`; focused 9 passed/1 skipped, full 305 passed/1 skipped/2 unchanged baseline failures. Narrow readback pending.
