# Remote-pi explicit-only coordination

- Intent: Ryu withdrew default Pi coordinator use; agents work independently and use resource provisioners directly. Only an explicit operator request to ask/contact another agent enables peer coordination.
- Owner/task: Hermes `t_38b76e02`; branch `fix/remote-pi-explicit-only` at `/home/ryushe/worktrees/bbh-remote-pi-explicit-only`; fetched base `af9dae91dfbddc0dae90ae17b3c3ed49a5f4a89d`; target `beta`.
- Contract: `pi-cordinator` remains a privacy guard for explicitly requested remote-pi peer contact; normal browser/resource acquisition uses owning provisioner, not peer lookup/broadcast. No automatic active-run presence exchange. Operator private reporting and program-wide safety remain.
- Alignment: BBH `agents/index.md`, skill registry, hunter-loop root/reference/presence template, and upstream generated remote-pi `agent-network` (transport only). No root AGENTS edit, extension installation/removal, or new runtime hook.
- Verification: pending focused assertions, independent review, beta integration, Hoster selected-source and projected-skill read-back. Fresh Pi read-only default-case check planned.
- Blocker from prior work: universal remote-pi hook was never installed; no longer required for default-off policy. Existing remote-pi extension may still be independently invoked by explicit user request; skill guidance is not executable enforcement.
- Next: review revised diff, merge/push beta, update Hoster source, run read-only Pi smoke and close task.
