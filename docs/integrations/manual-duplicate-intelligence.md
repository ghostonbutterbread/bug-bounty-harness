# Manual duplicate intelligence integration

- Objective: preserve operator-provided duplicate and known-issue observations for target selection and report triage without requiring platform authentication or inventing counts.
- Base: `origin/beta` at `a58e4fa54e32069320da58c5bfbadc912ccc0c46`; branch `feat/manual-duplicate-intelligence`; target `beta`.
- Contract: initialize `duplicate-intelligence.md` only if absent after a successful scope save; retain manual entries on every scope refresh; store provenance and independent program/asset/category observations, never infer scope or confirmed duplicates from aggregate counts.
- Verification: focused regression initially failed because the file did not exist; after implementation, `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-proxy-fallback-beta-release-20261108/.venv/bin/python -m pytest -q agents/test_scope_puller_seed_files.py` passed 37 tests. The reused interpreter supplies dependencies; execution must be checked to resolve feature sources.
- Blockers / next: research and owner-routing review pending; add and verify hunt-entry and submission-triage consumers, real manual-entry exercise, independent review, and beta integration. Do not automatically collect platform data or create fabricated Linktree observations.
- Activation: feature worktree only until reviewed and integrated; no main promotion or remote publication.
