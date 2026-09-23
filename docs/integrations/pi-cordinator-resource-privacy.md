# PI resource coordination skill integration

- Intent: Promote Ryu's resource-only peer coordination seed without leaking vulnerability details to another agent.
- Owner: Hermes; task `t_7ada9f63`.
- Worktree: `/home/ryushe/worktrees/bbh-pi-cordinator`; branch `feat/pi-cordinator-resource-privacy`.
- Fetched base: `0ecb1b61f8381e8f4589c399bb343426b25b2302` (`origin/beta`).
- Target: `beta` in `bug-bounty-harness`; not stable/main.
- Contract: new `skills/pi-cordinator/SKILL.md`, conditional route in `agents/index.md`, discoverability row in `SKILL_REGISTRY.md`. No agent transport or enforced lock is introduced. Peer resource messages omit investigation details; operator evidence/reporting remains separate.
- Verification: frontmatter/route assertions and `git diff --check` passed. Pending repository skill validation, independent review, beta integration, Hoster profile projection and consumer read-back.
- Activation: only after reviewed beta commit is pushed, Hoster beta source updated and security profile sync resolves both entry route and new skill.
- Next action: validate and review exact diff, reconcile target, integrate and deploy.
