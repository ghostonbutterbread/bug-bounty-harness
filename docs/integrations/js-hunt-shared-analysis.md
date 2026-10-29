# JS hunt and on-demand analysis integration

- Status: in progress; owner Hermes, Kanban t_b4f4054f.
- Worktree: `/home/ryushe/worktrees/bbh-js-hunt-shared-analysis`; branch `feat/js-hunt-shared-analysis`; base `dc0661b3cab1db8d5df08b57411c63537975642b`; target `beta`.
- Goal: an unqualified standalone JS hunt uses a sufficient existing corpus or invokes `/js-pull` for missing scoped inventory; normal hunts load the same canonical JS reasoning lens only when relevant, without a broad campaign. Keep collection mechanics, specialist proof, and policy boundaries at their current owners.
- Constraints: keep explicit offline and collection-only requests, immediate strong leads, partial evidence and provenance gaps. Browser-observed asset discovery can inform collection; no full inventory gate or unrequested live target tests. Avoid duplicated analysis doctrine and preserve compatibility routes.
- Verification: RED route regressions followed by full feature suite using checkout-local environment and feature `PYTHONPATH`: 406 passed, 1 skipped, 231 subtests. Packaged symlink reference resolution checked by a test; independent semantic walkthrough and review remain pending. No live target action or account creation.
- Activation: beta publication and runtime projection are separate; do not touch unrelated Hoster AI Policies work. Hoster fresh-consumer verification is a separate gate when authorized.
- Recovery checkpoint: implementation and tests commit `2ee868cc37fc2fd563c3b709a9b105a94b42bebd`; a later dossier-only commit records this immutable checkpoint. Next: fresh independent semantic review, resolve blockers, re-review before beta integration.
