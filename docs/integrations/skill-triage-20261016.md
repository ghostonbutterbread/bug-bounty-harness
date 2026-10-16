# Focused BBH skill triage

- Owner/card: Hermes in-thread, `t_86eff61e`
- Worktree/branch: `/home/ryushe/worktrees/bbh-skill-triage-20261016`, `feat/bbh-skill-triage-20261016`
- Base: `origin/beta` at `e6e12b4b64cab8af3e7939ee8e0d7099294f1f57`; target: reviewed `beta` only
- Implementation commits: `0f56ac87b7037e4379b0953c3d11acc993e446af`, `35fabb272b8afc447188e83fcad18f25c1bf5055`, `a13544d0cb38d062c7de49cedb1a37efa9b00988`, `f93703d300f4ba84086ccb320988199c5bb2b470`, `df2edd7c37969f8be9e38fe107b05892d4c0b383`, and `41e69026d204a5fc7af42939f72b4d6373390fe0` (completed-project current-data route); a parent `/recon` ingest-route clarity fix is pending a commit. `4a81072c822a64191a4f989968fd23ee2581b394` was a prior dossier-only receipt. This dossier update follows the implementation commit. Verify review/merge against the complete feature range and current tip, not an earlier pass.
- Source: Discord message `1560733134524260465`

## Intent and ownership

Add `cookie-session-analysis` and `form-submission-testing` as BBH skills, adapting machine-local CookieMonster instructions and preserving authorized form baseline gates. Cookie analysis is synthetic-fixture-only until an independently verified isolated secret-handling adapter exists. Selectively merge only still-valid exact-host scope guidance from local `scope-aware-recon` into `recon` and its mandatory `recon-ry` playbook route; the current host-granular wrapper cannot enforce an origin-limited scheme/port grant, and its detached queue is not a containment guarantee. The separate AI Policies beta slice owns the missing inert-preview guard from `triager-poc-authoring`; existing `triager-first-poc-authoring` remains the sole runnable PoC authoring skill. `adaptive-security-testing` and `recon-automation` are explanations only, not promoted here. Three named Ghost-local skills (`finding-ingestion`, `offline-agent-analysis`, `severity-recording-contract`) were confirmed non-symlink, with no active inbound owner pointers in local skills, this BBH feature, or AI Policies, then archived outside the active root at `~/.hermes/archived-skills/2026-10-16-bbh-triage/`; that archive's README records the four source-file hashes. No BBH canonical skill by those names was deleted.

Parallel owner `t_e6ec07ac` is changing nine distinct RCE/BBH skill routes. Do not edit its feature worktree or merge before reconciling the two reviewed tips.

## Gates and evidence

- Focused validation: `.venv/bin/python -m pytest -q tests/test_skill_triage_routes.py agents/test_recon_ry.py tests/test_skill_command_lane_safety.py tests/test_recon_ry_scope_files.py` → 79 passed; `git diff --check` passed. CookieMonster v1.5.0 `--help` verified on Ghost and Hoster (offline only).
- Full isolated suite: `./setup.sh --install-python-deps` created this worktree's `.venv` with `bounty-core` at the exact `requirements.txt` pin `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`; `.venv/bin/python -m pytest -q tests` → 245 passed, 171 subtests passed. Earlier runs using system Python and another checkout's stale venv failed collection on missing/mismatched `bounty_core`; neither is a failure of this feature branch.
- Independent review: earlier rounds blocked unsafe recon wording/cookie handling, mandatory child playbook, mixed wildcard+restricted-origin `full` route, registry cookie argument, entry playbook, and exact-host ingest source. The sixth confirmed the ingest correction but blocked stale program-root *current-data/history* pointers in both recon-ry docs and the parent recon playbook. Those now select the completed run's recorded project for broad or each exact host, with a focused route regression; fresh review is required. The installed `recon-ry` skill still points at existing beta, not this feature. AI Policies preview rule passed its separate read-only review and 44 policy-lint tests.
- Beta merge/push: pending; `origin/beta` and clean local beta integration now point to `29263d0468c206266075aed224683406a92371d2`, fourteen commits beyond this feature's base (including the RCE promotion). Preflight/review the combined tree before merge. AI Policies beta has three unrelated local commits ahead of origin without recorded independent semantic review; pushing the task-owned preview commit would also publish them. A release-choice prompt timed out, so do not push that stack without an explicit decision or a safely isolated task-only publication path.
- Ghost/Hoster projection and fresh resolver: pending.
- No live target testing, no cookies or credentials in repository or handoff.

## Resume

Review the completed-project current-data correction and complete branch tip independently, then reconcile beta integration intentionally. The three local directories are already preserved in the archive with matching SHA-256 and absent from the active root. Do not mark any runtime active from a source commit alone.
