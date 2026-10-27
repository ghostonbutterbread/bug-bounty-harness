# Canonical Bunny agent source migration

- Task: t_cf47e3cc; Discord thread 1564493127669252127.
- Worktree: `/home/ryushe/worktrees/bbh-canonical-bunny-agents`.
- Branch: `feat/canonical-bunny-agents`.
- Base: `9e0702536791c49d38e9b5cc48442dea91e613ee`; target: `beta`.
- Intent: one physical set of reusable agent files in BBH `agents/`, projected
  by AI Skill Sync into compatible consumers instead of hand-maintained copies.

## Contract and provenance

Hoster had four Claude files: bunny-hunter, bunny-recon, bunny-verifier and
bunny-reporter. Exact non-secret originals and SHA-256 manifest were retained
under `~/.hermes/state/validation/bunny-agent-sync/hoster-originals*`.
All four names and descriptions match existing BBH definitions. BBH bodies are
richer collaborative roles, so retain those byte-for-byte instead of regressing
them to the old Hoster stubs. Move them from `skills/bunny/agents/` into root
`agents/`; preserve old skill/package paths with relative file symlinks.

No policy or model behavior changes, live target actions, new accounts, runtime
restarts, other profile modifications or stable promotion. Actual Claude
adoption belongs to the paired synchronizer release and backs up old files.
The concurrent `feat/bunny-pipeline` task t_8db7e67e was notified of this source
ownership change; preserve its role refinements when integrating either branch.

## Verification and release gate

Focused verification passed: 15 Bunny tests plus 12 subtests; staged archive
contains all four regular canonical files and their exact relative skill links.
All four canonical bodies compare byte-for-byte equal to the integration base.

Pending: independent read-only review; merge into clean current beta and read
back remote; paired synchronizer CLI/wheel tests and deployment on local/Hoster;
both agent projections must resolve to the reviewed regular files and repeat
dry-run no-op.
The source move alone is not a runtime agent launch or model-behavior test.

## Recovery and next step

Implementation checkpoint: `7c51ab0f88b73e71aaa1244fcf631ed0c6ffc562` on
`feat/canonical-bunny-agents`; the later dossier-only commit records this
receipt. Parent owns review, release and deployment. This dossier is
branch-local and must be removed from the integration target on acceptance.
Durable usage guidance: `agents/README.md`.
