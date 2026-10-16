# Focused BBH skill triage

- Owner/card: Hermes in-thread, `t_86eff61e`
- Worktree/branch: `/home/ryushe/worktrees/bbh-skill-triage-20261016`, `feat/bbh-skill-triage-20261016`
- Base: `origin/beta` at `e6e12b4`; target: reviewed `beta` only
- Source: Discord message `1560733134524260465`

## Intent and ownership

Add `cookie-session-analysis` and `form-submission-testing` as BBH skills, adapting machine-local CookieMonster instructions and preserving authorized form baseline gates. Cookie analysis is synthetic-fixture-only until an independently verified isolated secret-handling adapter exists. Selectively merge only still-valid exact-host scope guidance from local `scope-aware-recon` into `recon` and its mandatory `recon-ry` playbook route; the current host-granular wrapper cannot enforce an origin-limited scheme/port grant, and its detached queue is not a containment guarantee. The separate AI Policies beta slice owns the missing inert-preview guard from `triager-poc-authoring`; existing `triager-first-poc-authoring` remains the sole runnable PoC authoring skill. `adaptive-security-testing` and `recon-automation` are explanations only, not promoted here. Three named Ghost-local skills (`finding-ingestion`, `offline-agent-analysis`, `severity-recording-contract`) were confirmed non-symlink, with no active inbound owner pointers in local skills, this BBH feature, or AI Policies, then archived outside the active root at `~/.hermes/archived-skills/2026-10-16-bbh-triage/`; that archive's README records the four source-file hashes. No BBH canonical skill by those names was deleted.

Parallel owner `t_e6ec07ac` is changing nine distinct RCE/BBH skill routes. Do not edit its feature worktree or merge before reconciling the two reviewed tips.

## Gates and evidence

- Focused validation: `python -m pytest -q agents/test_recon_ry.py tests/test_skill_triage_routes.py tests/test_skill_command_lane_safety.py tests/test_recon_ry_scope_files.py` → 76 passed; `git diff --check` passed. CookieMonster v1.5.0 `--help` verified on Ghost and Hoster (offline only). An unrelated `tests/test_recon_docs.py` collection with system Python failed on absent `bounty_core`; its missing-interpreter prerequisite is tracked as an existing papercut, not a green full suite.
- Full regression comparison: pending; the changed paths are skill text and route tests, not Recon-Ry implementation.
- Independent review: first pass blocked unsafe recon wording and unclear cookie boundary; both were corrected with an offline host-granularity regression and explicit synthetic-only stop boundary. Second pass confirmed those fixes but blocked the stale mandatory `recon-ry` child playbook; that route and its regression test were corrected. Fresh review of the corrected tip is pending. AI Policies preview rule passed its separate read-only review and 44 policy-lint tests.
- Beta merge/push: pending. AI Policies beta has three unrelated, previously local commits ahead of origin without recorded independent semantic review; pushing the task-owned preview commit would also publish those. Do not push that beta stack without review/owner decision or a safely isolated task-only publication path.
- Ghost/Hoster projection and fresh resolver: pending.
- No live target testing, no cookies or credentials in repository or handoff.

## Resume

Review the corrected branch tip and tests independently, then reconcile concurrent beta integration intentionally. The three local directories are already preserved in the archive with matching SHA-256 and absent from the active root. Do not mark any runtime active from a source commit alone.
