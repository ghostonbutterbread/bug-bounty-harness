# Trim /scripts skill — integration handoff

- Status: review-ready
- Owner: Hermes Agent; branch: `docs/trim-scripts-hunt-policy`
- Base: `28c8a27e205c5525ae6654db44d5618f01c95753`; target: `beta`
- Implementation checkpoint: `22a32abb3642a1b1c1c73a9b6d1d7a2d24601a03`

## Intent and contract

Ryu requested less policy prose. Reduce `skills/scripts/SKILL.md` to its trigger, non-exhaustive script evidence, and concurrent application/class-specific inquiry during longer runs. Leave routing, script discovery, class proof, and live safety with their existing owners. No script code or inventory changes.

## Evidence and review

- Focused script-policy and XSS mapper tests: 40 passed; `git diff --check` clean. Skill is 12 lines including frontmatter (68 words).
- Wider `pytest tests`: 183 passed, 1 skipped, 3 unchanged baseline failures (stale Hoster policy assertion, dependency pin expectation, unrelated old integration dossier command). No changed file is implicated.
- Independent review: approved feature tip `041a0bd` with 40 focused tests and clean diff. Fetched `origin/beta` remains `28c8a27`, matching the branch base; integrated focused tests remain before publishing.

## Handoff and gates

- Branch: `docs/trim-scripts-hunt-policy`; checkpoint: `22a32abb3642a1b1c1c73a9b6d1d7a2d24601a03`; worktree clean after dossier checkpoint.
- Resume: merge the approved feature into beta with this temporary dossier retired, push beta, verify already-linked runtime skill content.
- Activation: update clean Hoster beta source only after reviewed publication; existing sessions retain loaded text. No main promotion.
