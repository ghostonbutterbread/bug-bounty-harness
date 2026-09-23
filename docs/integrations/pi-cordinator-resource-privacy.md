# PI resource coordination skill integration

- Intent: Promote Ryu's resource-only peer coordination seed without leaking vulnerability details to another agent.
- Owner: Hermes; task `t_7ada9f63`.
- Worktree: `/home/ryushe/worktrees/bbh-pi-cordinator`; branch `feat/pi-cordinator-resource-privacy`.
- Fetched base: `0ecb1b61f8381e8f4589c399bb343426b25b2302` (`origin/beta`).
- Target: `beta` in `bug-bounty-harness`; not stable/main.
- Contract: new `skills/pi-cordinator/SKILL.md`, conditional route in `agents/index.md`, discoverability row in `SKILL_REGISTRY.md`; peer-visible hunter-loop presence template/route now contains neutral resource logistics only. Detailed flow and evidence stay in the operator's private run record. No agent transport or enforced lock is introduced.
- Verification: frontmatter/route assertions and `git diff --check` passed. Independent review of `6d30455` found an existing peer presence leak; addressed by changing the presence owner and indirect-metadata guidance. Pending re-review of revised diff, beta integration, Hoster profile projection and consumer read-back.
- Activation: only after reviewed beta commit is pushed, Hoster beta source updated and security profile sync resolves both entry route and new skill.
- Next action: validate and review exact diff, reconcile target, integrate and deploy.
