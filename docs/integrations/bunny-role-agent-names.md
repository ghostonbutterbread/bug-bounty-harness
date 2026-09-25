# Bunny role-visible agent names

- Intent: Neon manual Bunny workers appeared as indistinguishable `general-purpose` agents despite distinct hunter/recon roles. Give the operator role-and-surface identifiers in Claude Code's agent manager.
- Branch/worktree: `feat/bunny-role-agent-names` at `../bunny-role-agent-names`; base `origin/beta` `d077b8971b3e87fbd1278f4874cd53399564b74f`; target `beta`.
- Contract: The Bunny coordinator supplies a unique short role-and-surface `name` on Claude Code Agent invocations alongside a scoped description and task packet. Other runtimes use their supported role-named type. This does not alter role authority, scope, or goal state.
- Source evidence: Hoster's Neon Bunny run `neon-bunny-extpriv-20260925T0549Z` used three `general-purpose` worker calls. Claude Code 2.1.282 is installed on Hoster; current Claude Code subagent documentation describes the Agent tool `name` parameter and named background agents.
- Verification: compare the skill with Bunny's role/dispatch sections; run repository lint; independently review the exact diff. After beta publication and Hoster beta projection, start a fresh disposable non-target Bunny role invocation and inspect the agent manager's displayed name before asserting runtime behavior. Do not interrupt the ongoing Neon run just to rename it.
- Activation boundary: this branch is not live. Reviewed merge to `beta`, publication, and Hoster beta skill projection are separate. Existing running agents retain their names.
- Deferred: dispatch-readiness rule and program-shared request admission queue are separate tasks, not part of this change.
- Next: validate/review, merge and publish beta if clean, refresh Hoster beta projection, verify a fresh agent sees the guidance and name field.
