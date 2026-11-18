## Delayed browser-start generation fence — uncommitted

- A private fsynced start reservation is created before SSH dispatch. An
  interrupted, timed-out, failed, or lost-reply start blocks handoff, acquisition,
  and other starts until exact-receipt `browser-stop` succeeds; failure to spawn
  SSH clears only the newly created reservation. A confirmed start clears it
  only after the lease is renewed again.
- Remote starts and stops serialize on the browser ID under
  `~/AI/nebula-lane/browser-generations`. Stop fsyncs a permanent tombstone under
  that lock before checking/stopping the exact unit; a late start refuses the
  tombstone. A missing unit is accepted only after `LoadState=not-found` is
  confirmed. Existing operation-specific stop receipts remain retry-safe. A
  stopped ID is single-use: release and reacquire a new lease to launch again.
  Do not delete tombstones/operation receipts while delayed commands can arrive.
- RED before implementation: the delayed-start integration test executed the
  captured remote continuation after interrupted start, stop, and handoff; it
  failed because the initial uncertain start allowed handoff. GREEN: network-none
  Docker with read-only checkout, isolated state and fake SSH/systemd reported
  **39 passed** across `test_nebula_browser_isolation.py`,
  `test_nebula_abandoned_lock_regression.py`, `test_nebula_disconnect_lock.py`,
  and `test_nebula_browser_lane_skill.py`. Coverage includes start-first lock,
  stop-first late continuation, SIGTERM, real timeout, never-spawned SSH,
  wrong-receipt and acquisition refusal, missing/uninspectable unit, prior stop
  retries, and late duplicate. Fake SSH is the only SSH executable on fixture
  PATH; no fallback to host SSH. A selector EOF/poll race in the fixture and
  timing margins were repaired after observed fixture failures.
- Same-UID cooperative boundary remains; this does not fence raw SSH/CDP,
  deleted state, or external processes. No live SSH, real systemd, or browser
  was exercised. Independent review, permitted disposable real-host verification,
  beta reconciliation, and activation remain for the parent. No live host,
  deploy, fetch, or commit. Branch `fix/nebula-stale-lock`, worktree
  `/home/ryushe/worktrees/bbh-nebula-stale-lock`, base
  `8cee9829c1098e2fb60337a142b0d125866c106b`, target `beta`.

## Handoff/cleanup and cancellation review fixes — uncommitted

- A nonblocking per-state-directory operation flock serializes browser start/stop,
  handoff admission, and acquisition through readiness. Busy operations refuse;
  an acknowledged handoff blocks cleanup. A private durable stop marker is
  written before SSH and retained for failures, signals, lost replies, and crash;
  pending/invalid markers block handoff, start, and acquisition. Only the exact
  receipt can retry. Preflight refusal is distinct from uncertain remote outcome.
- A random stop-operation ID is retained locally and replayed remotely. On Nebula,
  an operation-specific flock and fsynced completion receipt in
  `~/AI/nebula-lane/stop-operations` make retries idempotent even if the original
  SSH command arrives late after a successful retry and a relaunch. These remote
  records must not be deleted while late commands could arrive. Local/remote
  coordination is same-user cooperative, not protection against raw SSH/CDP,
  deleted state, or hostile same-user processes. A lost or corrupt local receipt
  requires owner reconciliation; it is not automatically cleared.
- SIGTERM/SIGINT/SIGHUP now fail control/browser commands with unknown-outcome
  diagnostics; holder signal shutdown may still return zero. A running browser
  SSH child is explicitly terminated and reaped, but its remote action can persist.
- RED before implementation: concurrent delayed stop allowed `begin-handoff` to
  return success; interrupted `browser-start` returned zero. New behavioral
  coverage includes handoff-first refusal, live cleanup race, SIGTERM and SIGHUP,
  exact local SSH reaping, SIGKILL in-flight, same-receipt retry, wrong-receipt
  refusal, blocked acquisition, lost reply, and late duplicate after relaunch.
  A separate RED showed local SSH exec failure unnecessarily left an uncertain
  marker; a fresh failed exec now clears it, while an earlier uncertain marker
  survives failed retries. Final focused suite: **32 passed** in read-only,
  network-none Docker with disposable HOME/XDG/TMPDIR, fake SSH and systemd.
  `git diff --check` passed; this is not real SSH or systemd verification.
- Remaining gates: independent review of the complete candidate and the permitted
  real disposable Hoster→Nebula browser/systemd/SSH failure-path fixture, including
  remote receipt durability and interrupted/late SSH, before activation. Parent's
  earlier real current-generation lock fixture is not browser fencing evidence.
  No live host/service, deployment, fetch, or commit in this worker. Branch
  `fix/nebula-stale-lock`, base `8cee9829c1098e2fb60337a142b0d125866c106b`,
  target `beta`; uncommitted candidate supersedes the race limitation below.

## Browser-isolation follow-up — candidate for independent review

- `hold_lane.py` now implements `browser-start` and `browser-stop` at the actual
  dispatcher entry point. A private receipt includes a separately random,
  non-secret browser ID; a renewed lease is required for start. The remote
  helper bind-tests CDP port 9333 before launching a named user-systemd unit
  with a per-ID profile under `~/AI/nebula-lane/runs/`, then verifies that unit
  active and the port reachable. An occupied port refuses startup, including a
  surviving old browser. Start failures require exact cleanup or reconciliation.
  Browser stop can use an expired receipt and stops/verifies only that ID's unit;
  it refuses while a durable handoff marker exists. Profiles are retained.
- RED: the busy-port test initially failed because `browser-start` did not
  exist; a handoff-protection test failed because stop was allowed during a
  reservation. Both passed after implementation. Network-none Docker,
  read-only checkout, fixture-only HOME/XDG/TMPDIR, real disposable TCP sockets,
  fake SSH and fake user-systemd: **25 passed** across browser isolation,
  lease, disconnect, and skill tests. This exercises the actual CLI but is not
  real SSH, systemd, Chrome, or display evidence. A fixed-delay contender test
  failed twice under container scheduling; it now waits for the loser and for
  the winner's actual readiness before asserting remote lock state.
- Scope/limits: same-UID cooperating operators; raw CDP, separate SSH commands,
  bind-to-start races, partition or holder loss during launch are not fenced.
  Stop and reconcile on uncertainty; timeout can leave Chrome alive and block a
  successor until exact cleanup. The 900-second default and 600-second option
  remain. Legacy Chrome without a receipt must be reconciled by the owner.
  Handoff-marker inspection and remote stop are not atomic: cooperating owners
  must not race handoff creation and cleanup.
- No remote access, deployment, commit, fetch or independent review in this
  follow-up. Parent must independently review and exercise real disposable
  Hoster→Nebula SSH/systemd, browser start/stop, occupied-port and stale-receipt
  cases before any activation; prior transport evidence is not that test.

## Historical review follow-up — superseded browser blocker

- The 10-minute option is now shown in both actual launch commands as
  `--timeout 600`; `--timeout 900` and the 900-second default are also
  documented. Renewal remains explicit, not observed activity. A focused
  documentation regression was RED before the change and GREEN afterward.
- **HIGH remains unresolved; do not deploy or use this candidate for browser
  work.** Its SSH forward still targets remote port 9333 and the skill still
  launches the fixed profile. After timeout a surviving old Chrome can be
  reattached by the next generation. The previous real-SSH receipt does not
  validate generation isolation or exact-owned cleanup. No safe replacement
  was implemented in this follow-up; the existing commands must not be treated
  as a supported safe solution.
- A complete fix needs a fresh, exclusively created generation-owned profile
  under Nebula `~/AI`, an endpoint bound and verified to that generation rather
  than a reused fixed port, and a task-owned browser lifecycle with verified,
  exact-generation stop and profile cleanup. Do not infer ownership from a PID,
  fixed port, or local holder liveness; preserve ambiguity. Exercise two
  generations with a surviving first browser, old-profile/endpoint collision,
  and exact cleanup in an isolated fixture, followed by the permitted disposable
  real Hoster→Nebula path. Human handoff and explicit renewal still apply.
- After the timeout/docstring change, isolated Docker `--network none`,
  read-only checkout, private HOME/XDG/TMPDIR, and disabled plugin autoload:
  `tests/test_nebula_abandoned_lock_regression.py`,
  `tests/test_nebula_disconnect_lock.py`, and
  `tests/test_nebula_browser_lane_skill.py`: **19 passed**. This is not browser
  isolation evidence. `origin/beta` fetched at
  `8cee9829c1098e2fb60337a142b0d125866c106b`. No live host/service, commit,
  deployment, or independent re-review was performed by this worker.

## Cooperative 15-minute lease — current uncommitted work

- Branch `fix/nebula-stale-lock`, worktree `/home/ryushe/worktrees/bbh-nebula-stale-lock`; base `8cee9829c1098e2fb60337a142b0d125866c106b`, target `beta`, checkpoint `aba5e79e6960fe8fef123f61cffddada41b5dd0d` remains intact. No commit, fetch, deployment, host or service access in this follow-up, as directed.
- `hold_lane.py` is now the actual CLI lease owner. It preserves the existing remote flock/SSH stdin/tunnel, with a 900-second monotonic deadline renewed only through a generation-authenticated Linux Unix socket and private receipt. Serialized handoff writes a durable private marker before acknowledging; exact-receipt completion clears it after human confirmation even if the holder died. Local flock coordinates cooperating holders on the same host and state directory; ambiguous marker/owner fails closed. Expiry closes/reaps only the owned SSH child; it does not clean up Chrome, profiles or lock inode. The unsupported experimental core and its tests were removed rather than left as dead code.
- RED: the rewritten public-entry idle regression failed against the existing holder because it rejected the new timeout/receipt options. GREEN: the network-none, read-only Docker test runs the actual `bbh` dispatcher and helper against an isolated SSH pipe and real disposable `flock`, private HOME/XDG/TMPDIR, no user systemd. It covers timeout and renewal, same-inode reacquisition, stale generations, handoff live and across SIGKILL with wrong-generation refusal, concurrent acquisition, unrelated process/data preservation, disconnect and legacy flock compatibility. Real SSH, forwarding and remote systemd were not exercised.
- Combined command over `tests/test_nebula_abandoned_lock_regression.py`, `tests/test_nebula_disconnect_lock.py`, `tests/test_nebula_browser_lane_skill.py`, and `tests/test_script_policy.py`: **40 passed, 1 failed** before the final release-CLI test. The failure is the pre-existing `chromium-test/scripts/README.md` missing record fields for `raw_history_search.py`; it is unrelated to Nebula. Final run with that unrelated test deselected: **41 passed, 1 deselected**; the same validator run directly on the Nebula script index passed. `git diff --check` passed.
- Limitations: cooperating controls only; ordinary task activity and in-flight SSH/CDP commands are not observed or fenced, so agents must explicitly renew. The old holder is not retrofitted; noncooperating raw SSH/CDP and agents with different local state directories are not fenced. A lost receipt or ambiguous handoff requires owner reconciliation; no automatic personal-data cleanup. SSH remote EOF detection can be delayed. Live Hoster-to-Nebula/systemd verification, independent review, beta reconciliation and eventual activation remain separate and unauthorized here.

- User-visible status: the helper is a cooperative, explicitly renewed lease, not
  automatic detection of an agent's task activity. The installed legacy holder
  is not converted. User expectation of automatic renewal remains unmet.
- Parent real-path follow-up: current helper SHA
  `3d13e8fc41c5f57623ed2f0326efe301389b3e505b39f61d0d627f2e27e639c1`
  passed a disposable Hoster-to-Nebula real SSH/flock test (renew, timeout,
  handoff surviving holder kill) and a unique Hoster user-systemd expiry test.
  Fixtures were removed and the test unit was inactive.
- Browser real-path follow-up **failed and is not acceptance**: a fixture's
  SSH command substitution failed to match the quoted remote Python program;
  real user-systemd launched the test listener under the production unit/profile
  prefix and the fixture asserted the wrong unit. The parent identified and
  stopped the exact fixture unit by its unique executable path, verified it
  inactive, removed its empty owned profile, and verified the original Nebula
  flock remained held. Do not rerun until isolating the parsed `python3 -c`
  argument and verifying every substitution before execution. Test browser
  startup, ownership, stop, delayed-start race, and cleanup separately with
  disposable exact resources; do not operate the existing owner.
- Review cleared the three previously reproduced correction paths in offline
  fixtures; the end-to-end supported active lane and real Chrome remain unverified.

## Historical experimental lease-core follow-up — superseded

The prior checkpoint is `aba5e79e6960fe8fef123f61cffddada41b5dd0d`;
base `8cee9829c1098e2fb60337a142b0d125866c106b`, target `beta`.
The previously described skipped regression is tracked, not untracked.
The current follow-up is intentionally uncommitted per task instruction.

`agents/nebula_lease.py` is a working **process-local experimental component**,
not wired to the supported `hold_lane.py` entry point. It has 900-second default
observed-activity expiry, explicit generation renewal, admitted-operation drain,
quiet handoff, nonblocking flock compatibility, and callback-gated cleanup. Its
callbacks in the tests are fixtures, not actual Chrome cleanup or inspection.
The watchdog renews on explicit admit or renew only; a task working elsewhere
without signaling may lose its lease. A quiet human must be put on handoff.

RED evidence: the full idle-expiry/reacquisition test failed before the core
existed; renewal, handoff, in-flight drain, and cleanup-error tests also failed
before each corresponding implementation. Offline Docker `--network none`,
read-only checkout, and private executable `/fixture` tmpfs with HOME, XDG and
TMPDIR set before Python startup produced **42 passed, 1 skipped, 1 failed**
for `tests/test_nebula_lease_core.py`, `tests/test_nebula_disconnect_lock.py`,
`tests/test_nebula_browser_lane_skill.py`,
`tests/test_nebula_abandoned_lock_regression.py`, and
`tests/test_script_policy.py`. The failure is the pre-existing
`chromium-test/scripts/README.md` missing fields for `raw_history_search.py`;
the skip is the obsolete idle test, not acceptance evidence. The equivalent
focused set without the script-policy module gave **18 passed, 1 skipped**.
Initial combined test run failed eight fixture SSH launches because Docker's
fixture tmpfs defaulted to `noexec`; rerunning with
`--tmpfs /fixture:rw,exec,size=128m` addressed the fixture, not production code.

**Blocking boundary:** existing skill launches Chrome over separate raw SSH and
exposes raw CDP through a tunnel; the process-local core cannot observe/fence
those actions or disconnect old control connections. Neither callbacks nor a
PID/command-line guess can establish exact generation-owned Chrome cleanup.
Most critically, process death releases flock even while a human or browser may
still be active. The offline subprocess test `test_process_death_drops_flock_even_during_handoff`
actually kills a fixture owner in handoff and then successfully acquires its
flock in a second owner; that passing test demonstrates the unsafe gap. A
detached local thread cannot safely guarantee human handoff or
resource cleanup on root death. Unknown pre-existing Chrome must fail closed.
Do not connect this core to the live entry point or promote as an idle fix until
an actual remote owner/controller keeps the same flock, serializes and fences
all SSH/CDP command access, revokes exact-generation control connections,
drains admitted actions, and stops/verifies only provably owned generation
resources; it must fail closed across supervisor death and protect handoff.
Exercise those mechanisms in a disposable, network-isolated process fixture,
then separately verify the Hoster→Nebula SSH/systemd boundary only when safely
authorized and the existing owner is not disturbed. No live host contacted, no
service touched, no deploy, commit, or push. Independent review and beta
reconciliation remain outstanding.

## Previous checkpoint

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
