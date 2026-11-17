# Nebula SSH disconnect lock release — blocked review handoff

- **Branch/worktree:** `fix/nebula-stale-lock`, `/home/ryushe/worktrees/bbh-nebula-stale-lock`.
- **Base:** `8cee9829c1098e2fb60337a142b0d125866c106b`; **target:** `beta`.
  Base was supplied; this child did not fetch. No commit exists for these edits.
- **Intent:** Replace the old remote `sleep infinity` holder with a remote
  `cat` under the same flock. SSH stdin EOF releases the lock when the server
  observes disconnect; stream-token readiness replaces the remote ready file.
- **Boundaries:** This is only a partial SSH-disconnect improvement, not idle
  detection. A still-running abandoned SSH session retains the lock. Readiness
  proves acquisition at one instant, not atomic ownership during later actions;
  local unit/PID checks do not remove the race. Guidance preserves uncertain
  remote state and does not authorize destructive Chrome/profile/lock cleanup.
  The untracked `tests/test_nebula_abandoned_lock_regression.py` remains an
  explicitly skipped, obsolete experiment; do not include it in the release.
  To resume idle work, rewrite it for the then-current skill entry point and
  verify real observed-idleness behavior before removing its skip.
- **Review fixes:** The skill documents a Hoster OMP/agent foreground
  user-systemd launch, helper-based controller dispatch, journal/ownership
  inspection, and exact-unit stop. SSH failure diagnostics cover possible local
  port failure without asserting it was the cause. Old and new holders use the
  same flock in both-direction local collision tests.
- **Evidence:** An isolated Docker fixture with `--network none`, read-only
  checkout, scratch-only state, no auto-loaded pytest plugins, and loopback/
  non-loopback preflight produced **34 passed, 1 skipped, 1 failed** for
  `tests/test_nebula_disconnect_lock.py`, `tests/test_nebula_browser_lane_skill.py`,
  `tests/test_nebula_abandoned_lock_regression.py`, and `tests/test_script_policy.py`.
  The failure is the pre-existing `chromium-test/scripts/README.md` missing
  fields for `raw_history_search.py`; the skip is the deferred idle test. After
  the final changes, rerunning with that one repository-wide index test
  deselected gave **34 passed, 1 skipped, 1 deselected**; the same index
  validator separately passed for the Nebula script index.
  The occupied-port test uses a real bound loopback socket but a simulated SSH
  transport that maps the requested 9333 forward to an isolated fixture port;
  it is not real OpenSSH port-forward or live Hoster evidence. RED was observed
  for the prior ambiguous diagnostic and for the absent systemd guidance.
- **Authority/activation:** The parent authorized the overall task and a live
  fixture; this delegated child was explicitly prohibited from contacting
  remote hosts, deploying, or committing. Therefore it did not contact Hoster
  or Nebula. No merge, push, activation, or release happened. Do not interpret
  this child constraint as a user prohibition on a later release.
- **Parent observations:** A disposable real Hoster-to-Nebula SSH/flock fixture
  demonstrated that the old remote sleep retained its lock after local SSH
  termination; a remote stdin-EOF reader released the isolated lock after SSH
  termination. Both fixture directories were removed. This tested the transport
  mechanism, not this helper, its unit integration, or idle expiry. The existing
  real Nebula owner was observed working and was not interrupted.
- **Blockers/next:** Keep unpromoted. Re-review the final diff and exercise the
  documented Hoster unit launch/readiness/inspection/stop path using a disposable
  remote lock and forwarding port; test real OpenSSH occupied-port behavior and
  old/new holder contention. The current proposed skill removes routine browser
  cleanup without a safe replacement; restore safe usable cleanup with proven
  exact-generation remote ownership before integration. Reconcile current beta
  and the pre-existing index failure. For the original user request, establish a
  trustworthy task-specific activity and human-handoff signal and prove that an
  abandoned owner releases after the requested 10–15 minute interval while a
  working owner and handoff remain protected. The skipped idle regression is
  not acceptance evidence.
