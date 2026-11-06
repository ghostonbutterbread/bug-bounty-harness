# CSP research leads — integration handoff

- Task: `t_76cc1159`; owner: Hermes; source: Discord thread `1568041036264120410`.
- Feature worktree: `/home/ryushe/worktrees/bbh-csp-research-leads`; branch: `docs/csp-research-leads`; base: `dfa4cc58` (fetched `origin/beta`); target: `beta`.
- Scope: add CSPBypass lookup, PDF-validator/JSON-polyglot consumer distinction, predictable nonces, and dynamic CSP injection to `skills/csp-bypass/SKILL.md`. Broader proactive XSS routing is not authorized by this task.
- Evidence: independent review approved the exact skill diff (SHA-256 `e5bd3b55f575ec1ae540ee7ccdbb1a056c6a8035b5f288d9e96220340813276e`), with no technical blockers; focused unittest passed 3 tests, and `git diff --check` passed. A focused assertion test was then added for the new guidance and must be rerun before integration.
- Integration blocker: the active beta integration checkout `/home/ryushe/worktrees/bbh-beta-integration-offline` diverged from fetched `origin/beta` (10 local-only and 16 remote-only commits at preflight). Do not merge or publish unrelated commits. Review must determine an isolated release and activation path or obtain an operator decision.
- Next: finish independent review, correct blockers and rerun tests; commit task-owned files on the feature branch. If beta reconciliation remains out of scope, preserve a recoverable feature commit and report release/runtime activation as pending.
