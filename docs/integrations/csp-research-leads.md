# CSP research leads — integration handoff

- Task: `t_76cc1159`; owner: Hermes; source: Discord thread `1568041036264120410`.
- Feature worktree: `/home/ryushe/worktrees/bbh-csp-research-leads`; branch: `docs/csp-research-leads`; base: `dfa4cc58` (fetched `origin/beta`); target: `beta`.
- Scope: add CSPBypass lookup, PDF-validator/JSON-polyglot consumer distinction, predictable nonces, and dynamic CSP injection to `skills/csp-bypass/SKILL.md`. Broader proactive XSS routing is not authorized by this task.
- Evidence: independent review approved the skill diff (SHA-256 `e5bd3b55f575ec1ae540ee7ccdbb1a056c6a8035b5f288d9e96220340813276e`) with no technical blockers. Focused unittest passed 4 tests on both feature and integration trees; `git diff --check` passed. Implementation checkpoint: `c332deb65edb786a2b4e684bbba780822d90db28`.
- Published: isolated clean beta integration checkout `/home/ryushe/worktrees/bbh-csp-release` applied only the skill and test paths; source and integrated stable patch IDs both `cf5f65d8cc1fba843235a010ce48d24c4495e4ed`. Published beta commit `ffbf641c3ae459aa030e494c9e5d3838c7f47699` was read back from the remote.
- Activation blocker: the active beta source checkout `/home/ryushe/worktrees/bbh-beta-integration-offline` has 10 local-only and 17 remote-only commits. Its projected skill does not contain CSPBypass. Do not reset, force-refresh, or merge those unrelated histories as part of this task.
- Next: coordinate/reconcile the active beta checkout with its owners, then verify the published commit is present, run the focused profile sync dry-run, and load the projected skill in a fresh Hermes process. No claim of runtime activation until all three pass.
