# Manual duplicate intelligence integration

- Objective: preserve operator-provided duplicate and known-issue observations for target selection and report triage without requiring platform authentication or inventing counts.
- Base: `origin/beta` at `a58e4fa54e32069320da58c5bfbadc912ccc0c46`; branch `feat/manual-duplicate-intelligence`; target `beta`.
- Contract: initialize `duplicate-intelligence.md` only if absent after a successful scope save; retain manual entries on every scope refresh; store provenance and independent program/asset/category observations, never infer scope or confirmed duplicates from aggregate counts.
- Verification: focused regression initially failed because the file did not exist; after implementation, `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-proxy-fallback-beta-release-20261108/.venv/bin/python -m pytest -q agents/test_scope_puller_seed_files.py` passed 38 tests. The reused interpreter supplies dependencies and resolved the feature source.
- Blockers / next: hunt-entry and submission-triage companion changes exist in AI Policies and the report-skill feature worktree; verify a real manual-entry exercise, complete independent cross-repository review and beta integration. Do not automatically collect platform data or create fabricated Linktree observations.
- Activation: feature worktree only until reviewed and integrated; no main promotion or remote publication.
