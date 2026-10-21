# XSS Idea-Tree Creative Breadth — Integration Dossier

- **Status:** implementation complete; awaiting independent release review
- **Owner:** Hermes / BBH XSS
- **Branch/worktree:** `docs/xss-idea-tree-creative-breadth` at `/home/ryushe/worktrees/bbh-xss-creative-breadth`
- **Base beta commit:** `51194c7039af2b2637815656c8de5540cc7d5d64`
- **Intended integration target:** `beta`; no `main` promotion or Hoster rollout
- **Immutable implementation checkpoint:** pending first commit; Git will supply the ID
- **Inspiration:** Ryu's feedback in Discord thread `1562231426932539452`, message `1562276037243576503`, and independent read-only methodology review `deleg_3e21b829` of beta `51194c7`.

## Intent and Contract

The published XSS tree already broadens mechanisms but describes "one hypothesis, safe control and falsifier" and a second leaf only for a distinct observed feeder/defense. Revise agent and human routes so agents can retain and explore multiple distinct hypotheses, combine leaves, and invent mechanisms outside the 29-heading source. A comparison/falsifier is a tool for a **particular causal claim** and for interpreting an inert outcome, not an ideation quota or admission gate. Preserve source/sink reachability for a claimed execution path, exact Attempts writer, selected lane's browser proof, and inherited live scope/rate/effects constraints.

## Implemented Change and Evidence

- Owners: `skills/xss/SKILL.md`, `skills/xss-payload-engineering/SKILL.md`, conditional reference tree and narrow leaves, `docs/xss-idea-tree.md`, prior `docs/xss-mechanism-ideation.md` diagram, focused routing tests. The tree now admits unlisted ideas and multiple hypotheses; negatives retire tested links, not sibling feeders/consumers. Each causal claim still needs the relevant execution evidence.
- No target traffic, account actions or payload execution. No global policy rewrite or separate payload catalog.
- Focused test selection after final wording edits: **9 passed, 1 opt-in browser skipped**. Full feature suite with the checkout-local `.venv` and `PYTHONPATH` rooted here: **305 passed, 1 skipped, 2 failed**. Unchanged beta under the *same feature-venv interpreter*: **304 passed, 1 skipped, the same 2 failed**. Both failures are in unrelated, unchanged `skills/stack-to-program/scripts/README.md` contracts: missing `Outputs/Mutates` fields and an executable lane example. The initial global interpreter's 17 additional failures were caused by this worktree missing `.venv`; `./setup.sh --install-python-deps` resolved them. `git diff --check` clean. Independent release review and integrated beta/projection verification are **pending**.

## Release and Interruption Gates

1. Commit testable wording changes and this dossier on the isolated feature branch; record the exact implementation SHA in a later documentary checkpoint.
2. Independent reviewer verifies creative breadth and evidence/safety boundary, then beta merge into clean current integration worktree excluding this branch-local dossier.
3. Run focused and full suite on the integrated tree, identify any pre-existing failures, push beta only from beta worktree, verify the projected route and an on-demand leaf through the skill resolver.
4. Until then the active projection remains the earlier wording at `51194c7`. Resume at the next incomplete gate; do not claim activation from this feature branch.

## Decision Record

- 2026-10-20 PDT — independent read-only review held agent-facing wording for a narrow creativity correction, while accepting the tree's mechanism coverage and browser-proof standard. This branch is a methodology correction, not permission for out-of-scope or indiscriminate live tests.
