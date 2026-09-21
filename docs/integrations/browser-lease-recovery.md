# Browser resource management — integration dossier

## Ownership and checkpoint

- Task: ordinary browser resource management, parent-owned Kanban `bug-bounty-harness/t_6f1fc293`.
- Worktree: `/home/ryushe/projects/bug_bounty_harness/browser-lease-recovery`.
- Branch: `feat/browser-lease-recovery`; intended integration target **beta**.
- Fetched beta base: `69e9a2a01be26ea1e64a0d00fd6cf23a47704e4e`.
- Previous reviewed lifecycle checkpoint: `2f85d1bcbd5ceff82c0b54f94a91b7f8a7cda14f` (older implementation receipt `ae309c8cf12f74141662df7a2af57917e58cbad1`).
- Recoverable reviewed implementation checkpoint: `3164b2f3667c1ac511da5d061e22c7bc5c36de65` on `feat/browser-lease-recovery`. This following dossier-only commit records the actual SHA; review both the checkpoint and current tip.
- Startup diagnostics implementation checkpoint: `e26b3be16768fdbb18519e056f055b1f0456aa58` on `feat/browser-lease-recovery`; verified final source, 164 tests passed. This following metadata-only commit records the exact SHA. Review both commits; not independent release approval.
- Resume point: **integration remains blocked by an unresolved intermittent startup failure**, in addition to the native-input and handoff-consumer boundaries below. Parent's independent full run failed; investigation reruns passed unchanged and are not proof of a repair. See the startup investigation section. Nothing is activated by this checkpoint.
- No push, merge, deployment, Hoster operation, real account access, or external-site browsing. Parent owns independent integration review and acceptance of the coverage gaps below.

## Implemented contract

### Explicit profile instances, legacy compatibility

`request/start ... --instance-key <slot>` creates an isolated persistent profile at `<artifact-root>/<program>/web/browser-instances/<domain>/<resolved-account>/<slot>`. Distinct slots can use the same account/color concurrently; retries of the same slot remain exclusive. Keys are validated, not silently normalized. Instance directories are separate from legacy profile trees, so legacy retention cannot recursively delete a live instance.

Omitting the key now automatically selects isolated instances for fresh resolved selectors (see the headed/provisioning follow-up below). Existing legacy manager/lease records and known on-disk legacy profile paths retain named single-profile semantics and existing path/configuration; `--legacy-profile` explicitly selects that behavior for fresh selectors. An active legacy lease conservatively blocks parallel instances of the same account/domain, and vice versa. There is no migration, copied cookie store, alternate account selection, or extra authentication retry. Anonymous slots and existing normal launcher session settings remain supported.

`--task-owned` still selects a task-specific namespace without account inventory or auth-seed resolution. Headless activity management works without `--owner-pid`; headed task mode still requires it because native input is untracked. Its namespace remains agent/run-specific rather than sharing state with another task.

### Activity and atomic resource reclamation

New **headless** pipe-controlled browsers track caller-issued CDP work. Navigation, input, evaluation and screenshots count; HTTP discovery, Browser.getVersion, target discovery/attachment and domain enable/disable do not. Passive browser events, open sockets, process liveness, watcher renewal, status calls and ordinary touch heartbeats do not reset idle age. Wall time is only reporting metadata; the live adapter uses a monotonic idle clock.

- `--idle-seconds` is the stored claim window, default 900, permitted 1–7199. It is not the process-stop threshold. A different requester cannot shorten the existing owner's window.
- Request-time cleanup, before capacity admission, stops browsers unused for **at least 7200 seconds**. It retains the profile and releases ownership only after the existing unit/root/CDP verification succeeds. `reap-idle` also invokes this path; its legacy `--idle-seconds` does not lower the two-hour stop threshold.
- A shorter idle claim may reuse the same browser process, tabs and profile through the existing CDP generation fence when the fixed browser-owned proxy/certificate route is compatible. Live owner PID does not prevent an idle claim. Task-owned proxies, incompatible routes and non-revocable control retain the existing verified restart fallback.
- The adapter atomically rechecks inactivity and in-flight commands/reservations, then freezes command admission on its single event loop. Node locking alone was insufficient because CDP commands do not take that lock. A winning command or reservation blocks cleanup/claim; a winning freeze rejects later commands/reservations. Failed stop/fence is not reported as successful reuse. A failed stop thaws control only if the exact original runtime is freshly verified healthy; partial stops, replaced identities and unknown runtime health remain fail-closed with an explicit error.
- `touch --work-state awaiting-input --awaiting-seconds N` reserves 1–3600 seconds. Repeated waiting does not slide the bound. `touch --work-state active` cancels the reservation but is not fabricated browser activity. A late waiting renewal is rejected.
- CDP response waits are bounded; pipe writes now have a 60-second backpressure deadline and terminate only their owned browser if a partial frame cannot finish. Dispatch has a 120-second deadline, with at most one bounded write completion during cancellation (up to 180 seconds total).

PID/start-tick/boot/node identity is retained for diagnostics, conservative legacy lifecycle behavior and an explicitly supplied task supervisor's terminal signal. A live PID never blocks idle reclamation. A terminal supervisor still triggers automatic fencing/cleanup, but in-flight commands and bounded reservations win the adapter recheck first. Same-owner retry can enroll a previously absent PID. Missing lifecycle watcher health is reported rather than hidden.

### Passive reports and manual concurrency policy

The lease helper adds:

```
browser_profile_lease.py --state-dir <state> set-browser-policy <program> <account> --auth-domain <domain> --mode single
browser_profile_lease.py --state-dir <state> report-logout --lease-id <id> --agent-id <agent> --reason user-observed
```

`multiple` permits explicitly isolated slots (default); `single` constrains new acquisitions for the resolved program/account/domain under the same SQLite admission transaction. Setting policy does not kill already-running browsers. Reports accept only the structured reasons `user-observed`, `signed-out-ui`, or `session-rejected`; they store lease linkage, timestamp and reason, no URLs/content/session material. Reports never trigger inference, policy changes, auth retries or browser creation. Two generic logouts are not treated as evidence of a single-session platform.

### Stable identity and stale status

Safe manager receipts and private launch records expose `instance_id`, `pane_id`, `instance_key` and account color. Instance/pane ID is the browser UUID: stable across live ownership transfer, new on a real replacement process, distinct for concurrent slots. It is **metadata only**, not an implemented pane UI. Top-level activity reporting for running tracked browsers comes from the live adapter. Old canonical leases after transfer report `handed-off`, and manager-verified released leases report `stopped`, with stale CDP/service fields cleared. Self-managed releases with registered CDP report `unverified-after-release`, rather than inventing stop verification. Old manager lease mutations remain rejected.

## Verification

- Checkout `.venv` resolves Bounty Core pin `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`; environment newer than manifest. No dependency change in this revision.
- Combined deterministic and opt-in disposable real suite: **152 passed in 114.24 seconds**, after review-driven fixes and final fixture updates.
- Real receipt: `docs/integrations/browser-resource-smoke.json`. Older `browser-lease-recovery-smoke.json` is historical evidence for the prior PID-driven contract, not evidence for this revision.
- Real fixtures exercised simultaneous isolated same-account profiles, stable live-transfer pane identity, same PID/page state, old socket/URL/lease rejection, task-proxy restart, PID-free generic task mode, two loopback synthetic login contexts, retained profiles and manifest retention.
- The in-process real pipe fixture deterministically holds an evaluation promise pending while attempting a freeze; the in-flight operation wins. It also checks bounded reservation, discovery not updating activity, stages only its own idle clock, and verifies the 7200-second freeze and generation revocation. Production has no clock-forging endpoint.
- Deterministic fixtures cover threshold equality, changed-activity recheck, concurrent reservation/freeze orderings, failed-stop retention, same-account/color slots, single-policy concurrent acquisition, malformed keys, passive reporting, stale release fields, PID-independent idle ownership, supervisor enrollment and missing watcher health.
- Initial real integration run caught instance-key shadowing by the launch environment loop; fixed before the passing receipt. An initial offline run also caught legacy custom-path lookup incompatibility; restored legacy manifest selection without migrating profiles.

Commands (no external sites):

```sh
.venv/bin/python -m pytest agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_lifecycle.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py -q
BBH_LOCAL_BROWSER_SMOKE=1 BBH_BROWSER_SMOKE_RECEIPT=docs/integrations/browser-resource-smoke.json .venv/bin/python -m pytest agents/test_browser_resources.py agents/test_browser_lifecycle.py agents/test_browser_lifecycle_systemd.py agents/test_browser_lease_recovery.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py tests/test_script_policy.py -q
uvx ruff check --select F skills/chromium-test/scripts/browser_control.py skills/chromium-test/scripts/browser_profile_lease.py skills/chromium-test/scripts/browser_provisioner.py skills/chromium-test/scripts/chromium_test.py agents/test_browser_resources.py agents/test_browser_lifecycle.py agents/test_browser_lifecycle_systemd.py
git diff --check
```

## Independent startup investigation — unresolved

The parent's independent run at `462569e51b2089ef3df7a5f0cf1a118f9c7e03d4`
returned **1 failed, 151 passed in 276.04 seconds**. The first `start(0)` in
`test_systemd_lifecycle_fixture` returned `launch-failed`: no valid private
record within the unchanged 45-second launch deadline. The builder's historical
152-pass receipt above is not an independent release gate.

This delegated investigation inspected `browser_provisioner.start`, launch-record
publication in `chromium_test.main`, pipe readiness/cleanup in `PipeBrowser`,
and fixture teardown. No production or test behavior was changed: the exact
fixture first passed unchanged (**1 passed in 161.10 seconds**), then the full
focused command above passed unchanged (**152 passed in 110.11 seconds**).
`browser-resource-startup-investigation.json` preserves both actual receipts,
commands, the tested SHA, observations, and their limitations. These runs prove
current successful execution, not that the original intermittent defect is fixed.
No test was disabled and no timeout, browser setting, service, or resource policy
was altered.

Evidence and limitations:

- Broad `journalctl --user` queries timed out, including an exact-unit query.
  Selecting only the active `user-1000.journal` with `--file` succeeded. Its
  manager entries identify failed unit
  `browser-1d87fdf9-9e70-4b5c-87a6-dbc13c1f619c.service`, started at
  **11:38:51 PDT** and stopped at **11:39:36 PDT**, 2026-09-21. There are no
  launcher entries for its exact `_SYSTEMD_USER_UNIT` in that active journal.
  This establishes deadline-triggered stop, not a launcher crash or its cause.
- The failed fixture's temporary state was already deleted. Chromium stderr is
  sent to `DEVNULL`; the generic timeout does not distinguish launcher import,
  browser startup, pipe readiness, or record publication. Retrospective evidence
  cannot identify the blocked stage. No OOM or I/O-error explanation was found
  in the bounded active-system-journal window; that is not exhaustive history.
- Investigation snapshots showed substantial I/O pressure: `io some avg300=34.82`,
  `full avg300=32.63`, with 6012 MiB available RAM and 2815 MiB free swap.
  Host contention is a plausible explanation, **not proven causal**: these are
  later snapshots, not measurements at the original failure. Do not kill or
  reconfigure unrelated host workloads to make this fixture pass.
- The first unchanged rerun's initial browser unit reached watcher startup in
  about 21 seconds; the full-suite rerun's initial unit did so in about 3 seconds.
  Variable startup latency is observed, but does not identify its source.
- Post-run `systemctl --user list-units 'browser-*' --all --no-pager --plain`
  showed **zero loaded units**. `/proc` inspection found no browser/launcher/
  provisioner processes referencing either disposable fixture root, and both
  roots had been removed. Only fixture-owned units were stopped by test teardown.
- Installed Bounty Core still resolves the declared
  `7b08495f65a50f733fc18213c38cc3ae8e91bdf5` pin. The worktree was clean before
  this dossier/evidence update. No external fetch was performed under this
  localhost-only delegation; no upstream freshness claim is added.

**Disposition:** no causal source repair is justified by the available evidence.
Keep this branch blocked rather than treating two green reruns as resolution.
Next action is a failing-run capture of the exact task unit's state/process tree,
resource pressure and launcher phase before teardown, using the same commands
and existing time bounds. Any diagnostic fixture change must be reviewed and
regression-tested separately; do not relax the deadline or bypass readiness.
The parent retains release review and the Kanban task. Its child-context guard
was not bypassed; no Kanban write, push, merge, deployment or account/site access
was attempted. This dossier/evidence-only checkpoint is based on reachable
`462569e51b2089ef3df7a5f0cf1a118f9c7e03d4` on `feat/browser-lease-recovery`;
review the current tip for this investigation record.

## Startup diagnostics follow-up — observability verified, cause still unresolved

This scoped delta starts from reachable checkpoint
`33532cf5b5dc3b0f2760b2772685d572b977089e` on the same
`feat/browser-lease-recovery` worktree; intended target remains **beta**.
The defect/diagnostic owner is this feature's launcher/pipe/publication boundary;
no ancestor-lane modification or propagation is authorized in this delegation.
`origin/beta` was fetched without changing this worktree. Installed Bounty Core
was checked against the declared `7b08495f65a50f733fc18213c38cc3ae8e91bdf5` pin
and matched; no environment synchronization or dependency edit was necessary.

Implemented:

- Opt-in `BROWSER_STARTUP_DIAGNOSTICS=1` records private manager/launcher/exec
  snapshots under the task's manager state, independently of the browser profile.
  Fixed phases distinguish dispatch, launcher entry/preparation, spawn, adapter
  binding, pipe readiness, auth application, record publication and registration.
  Monotonic start/elapsed timings and closed error categories preserve boundary
  evidence without exception messages. Each component is capped at 32 events;
  files are 0600 and attempt directories 0700. Writes are atomic and best-effort,
  without fsync on the startup path. Successful exec intentionally leaves an
  `exec:begin` marker because exec replaces the Python process.
- Chromium stderr is drained but **only a capped byte count is retained** (64 KiB,
  4-KiB reads). No raw stderr, command lines, URLs, credentials, cookies, CDP
  bodies or control tokens are persisted in these diagnostics. This does not
  claim that stderr causes have been recovered: counting is intentionally safer
  and less informative than textual logging or heuristic redaction.
- The real fixture preserves a schema-projected bounded receipt outside its
  disposable root before and after cleanup. Failed starts absent from the browser
  registry are included via task-owned UUID launch/diagnostic entries. Only those
  exact units are stopped; unit inactivity, available recorded root identity/CDP
  closure and absence of processes referencing the fixture root are verified
  before deletion. A failed stop retains the profile/root and failure evidence.
- Normal success/API shapes and production startup deadlines remain unchanged.
  No test was disabled, no timeout raised, no browser sandbox/resource setting
  changed, and no native/pane consumer touched.

Actual verification (implementing child, **not independent release approval**):

- Initial offline focused suite: **160 passed, 1 opt-in skip in 24.34 seconds**.
- Initial instrumented real/full suite: **162 passed in 102.38 seconds**.
- Pre-final real suite: **163 passed in 303.12 seconds**. Final diff inspection
  removed an extra filesystem stat from failed-publication diagnostics so an
  unreadable launch record cannot let diagnostics interrupt existing cleanup.
  Added a deterministic permission-error regression for this boundary.
- Final source: **164 passed in 179.22 seconds** using the exact
  command in `browser-resource-startup-investigation.json:diagnostics_followup`.
- Deterministic tests cover publication timeout, malformed/unreadable publication,
  dispatch/registration failure, pipe-readiness timeout, disabled/unwritable
  diagnostics, stderr saturation and secret non-disclosure, private modes,
  evidence surviving deleted profiles, failed-stop retention and exact-unit
  cleanup before registry insertion. A real local exec of a nonexistent binary
  proves categorized failure, reaping and stderr-content exclusion.
- Final disposable loopback/about:blank fixture retained **12 component snapshots
  for 4 launches**, with cleanup verified and no fixture failure. The original
  intermittent timeout did not recur. The longer final suite duration does not
  establish a cause for the historical timeout.
- Final raw private receipt: `/tmp/bbh-startup-evidence-40urrnrf/startup.json`;
  its sanitized data is also embedded in the tracked investigation JSON so the
  evidence remains recoverable after temporary-directory expiry. Normal fixture
  receipt: `/tmp/browser-startup-diagnostics-verified.json`.
- `git diff --check` and Ruff `--select F` passed. After the final suite,
  `systemctl --user list-units 'browser-*' --all --no-pager --plain` reported
  **zero loaded units**. Fixture profile removal ran only after cleanup checks.

**Remaining blocker / exact resume:** the original 45-second startup failure
still has no causal diagnosis or repair. On a recurrence, run the unchanged
fixture command with diagnostics enabled and inspect its preserved phase receipt;
missing launcher metadata points earlier than launcher entry but is not proof of
where Python/systemd stalled. Stderr byte counts cannot identify a Chromium fatal
message. Capture additional narrowly sanitized evidence if needed, without
relaxing readiness/deadlines or blaming host I/O without measurements. The parent
owns independent diff/test review and release acceptance. Native-input and pane
consumer blockers below remain unchanged. No Kanban mutations, push, merge,
external deployment, live sites/accounts or security-testing workflows occurred.

## Explicit incomplete acceptance criteria / activation blockers

1. **Native headed input is not observable through this adapter.** Headed/KasmVNC and pre-revision records deliberately retain conservative PID/explicit-release behavior. They do not gain PID-free automatic idle reclamation. Enabling idle eviction there would risk closing an actively used native browser. Required successor integration: the actual native display/input owner must report meaningful input and atomically participate in reservations/fencing; then add a disposable headed-input test. This revision does not claim complete all-browser activity coverage.
2. **Handoff consumer compatibility is implemented but not fully smoke-verified.** The scoped follow-up below adds exact pipe receipt/control validation and one-instance/one-page UI identity in `skills/chromium-handoff/scripts/cdp_handoff_server.js`. It is not a multi-pane desktop registry. Synthetic consumer tests pass; the new end-to-end real handoff UI smoke addition is blocked on tool approval and remains an explicit acceptance gap. No protected skill body was edited.
3. **The two-hour stop boundary uses deterministic clock staging**, not a literal two-hour wall-clock systemd soak. Real unit stop/root/CDP verification and the real adapter recheck are separately exercised. A soak is optional additional activation evidence; no production clock controls were added to make a fixture easier.
4. **Fresh resolved selectors support automatic isolated pooling** in the follow-up below. Existing legacy profiles/records remain a migration boundary, including stopped legacy profiles. No automatic migration is performed; normal profile and session configuration is unchanged.
5. Existing initial-launch crash gap remains: an interruption before complete runtime registration can leave a conservative managed lease requiring explicit reconciliation. The existing pending-transfer journal covers transfers, not every provisioning crash.
6. Same-UID coordination is not hostile-process isolation. CDP consumers must retain the entire generation URL. Only Linux/user-systemd is tested; no cross-node adoption or remote rollout.
7. Account summary/status views remain conservative account-level summaries; they are not a new multi-instance pane registry. Exact manager lease status and safe per-instance receipts are the supported new identity surface.

## Review and next action

First fresh read-only Claude review completed (session `0750bfe1-3052-42fd-a59f-661d2b1b9732`, success subtype, no permission denials) and independently ran the offline suite: 122 passed, 1 opt-in skip. It withheld checkpoint approval for three issues. All were addressed before the final 152-test real/deterministic run:

- Validate CDP method before incrementing the in-flight counter; malformed frames no longer leak a permanent reservation. The real pipe fixture sends a method-less frame and verifies zero remaining in-flight operations.
- Preserve explicit supervisor terminal cleanup, including the atomic operation/reservation recheck. The real systemd fixture now starts PID-free, verifies normal activity, enrolls a supervisor, terminates it and verifies automatic cleanup. Live-supervisor idle takeover remains tested separately.
- Restore control after a failed stop only for an exact freshly healthy original runtime. Unverifiable or partially stopped runtimes intentionally remain frozen; automatically thawing them would contradict the stop-verification boundary.

Also restored NULL-domain legacy lock priority, marked self-managed release stop status unverified, made unavailable activity probes visible in lifecycle diagnostics, retained the legacy shared_base re-export, and require a supervisor for untracked headed task mode. A repeat real fixture exposed an assertion against the initial task receipt rather than current activity; the fixture now queries exact current status after browser work.

Follow-up review attempt `1ae6a80a-2a95-4d50-a0a8-9382163fdb50` exhausted its 16-turn budget and produced no verdict; optional compound shell commands were denied. It was launched without session persistence, so resuming was unavailable. This is NOT an approval or an independent test receipt.

A final bounded, single-response independent diff review completed successfully: session `2818191a-58aa-4085-955f-4019d9929363`, no tools or permission denials, verdict **APPROVE — recoverable checkpoint (not release, not deployment)**. It confirmed the three corrections and retained the native/pane integration gaps. It did not independently run tests; final 152-test execution is the implementing agent's real receipt. Parent owns the remaining independent release test gate.

Clarifications for the final review's non-blocking questions: `record_info` already catches missing/truncated JSON and returns an empty object; canonical managed leases do not expire merely because their timestamp passes; release rejects mismatched manager IDs; both request/start parsers already define `--idle-seconds`. Those inherited guards are tested. Socket probes can still add bounded status latency.

**Frozen-stop reconciliation:** when exact runtime health is unavailable, leave the lease/profile intact. Restore the local user-systemd/control prerequisite and retry the original owner's `release --lease-id ID --agent-id AGENT --disposition cancelled --profile-health unknown`, or rerun request-time cleanup/`reap-idle` after stop verification becomes possible. Do not remove the lease, force profile reuse, or use `touch` to override a frozen controller. Unidentifiable/replaced root/unit evidence remains a manual operator blocker.

Final undefined/unused-name lint and whitespace checks passed. `origin/beta` was re-fetched and remains the recorded base. Final fixture inspection showed no loaded `browser-*` units. Commit only task-owned scripts/tests/index/dossier/receipt, report the checkpoint and coverage gaps, and do not push, merge or deploy.

## Bounded handoff consumer follow-up

Recoverable implementation checkpoint:
`1d50303103539bc1ecd7fa12d64b27ab93cd9938` on `feat/browser-lease-recovery`.
This subsequent dossier-only commit records its SHA; review both the checkpoint
and current tip. Resume with the pending real handoff-UI smoke approval/test
and independent parent review; do not treat this as beta release approval.

Delegated base: `30f075e08547cf3818d056280b83c83483f67630`; same worktree and
`feat/browser-lease-recovery`, target **beta**. Fetched `origin/beta` remains
`69e9a2a01be26ea1e64a0d00fd6cf23a47704e4e`. This is the feature-owned consumer
compatibility delta, not ancestor repair or release approval. The installed
Bounty Core revision was checked and still matches `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`.

Implemented in the handoff script, associated test/README, and minimal generic
bridge plus its index:

- Preserve fallback/certificate/import gates, exact receipt URL equality and
  raw-port legacy validation. Enforce the documented loopback-only UI listener.
- For new pipe receipts, verify live owned PID/start/boot/node identity, actual
  pipe command line/profile, stable instance/pane UUID, and private Unix socket.
  The adapter's new Unix-only passive `/identity` returns process identity,
  current generation endpoint and frozen/rotating availability. This minimal
  bridge addition is necessary: the browser has no raw CDP port and the prior
  adapter API provided no passive process-to-generation attestation. It does
  not rotate, reserve, issue CDP, or update activity. Same-UID trust remains.
- Load one receipt once; never follow owner/record rewrites. Bind to one
  existing page, with optional `HANDOFF_PAGE_ID` (exact CDP target ID). Missing,
  ambiguous, or closed pages never create/select a replacement tab. Readiness
  follows initial binding; there is no account/color-based pane selection.
- Return safe instance/pane/page identity in readiness and `/identity`, without
  the generation URL. Revoked control/process/page or operation failure becomes
  terminal 410 with safe explanation; UI disables controls and clears the image.
- Remove automatic screenshots rather than exempting real CDP work from idle
  accounting. UI timers only query passive identity. Explicit refresh/actions
  request screenshots and count as real activity. Initial Playwright attachment
  may perform bounded setup; unattended UI polling cannot continuously keep the
  browser alive. One UI remains one instance/page, not a desktop pane registry.

Verification so far (implementer, not independent release approval):

- Original consumer tests: **6 passed** before new coverage.
- Expanded suite first exposed an empty-page *test stub* defaulting to a page;
  changed its `||` default to `??`, preserving the intended zero-page fixture.
- Expanded consumer and existing real pipe/lifecycle plus deterministic manager,
  lease, launcher, startup and script-policy suite: **188 passed in 170.06s**.
  Command: `BBH_LOCAL_BROWSER_SMOKE=1 .venv/bin/python -m pytest agents/test_cdp_handoff_receipt.py agents/test_browser_lifecycle.py agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py agents/test_browser_startup_diagnostics.py tests/test_script_policy.py -q`.
- Node syntax, Ruff `--select F` for changed Python, and `git diff --check` passed.
- An attempted combined run including systemd lost its result at the tool's
  **420-second outer timeout**. Subsequent process inspection showed no pytest
  process and zero loaded browser units. This is not a passing test receipt or
  proof of the historical 45-second startup failure recurring. The isolated
  systemd rerun returned **1 passed in 130.75s**, recorded in
  `/tmp/bbh-handoff-systemd-verification.log`; no loaded `browser-*` units remained.
- After removing an unreachable exit-code assignment, the final consumer source
  rerun returned **25 passed in 10.85s** and Node syntax passed.
- Bounded reference audit found no in-repository reader of readiness `cdp_url`;
  removing the capability from that public metadata does not require a consumer
  update. Protected skill text and external route publisher remain untouched.

Outstanding acceptance and exact resume:

1. **Real handoff-UI smoke remains unverified.** A tool requested approval for
   the separate test-addition operation; the operation was not retried or routed
   through another tool. Parent must resolve approval and add/run
   `test_real_pipe_ui_identity_idle_and_revocation` in the owning test file:
   disposable blank Chromium, real pipe bridge and Node/Playwright handoff,
   exact target ID, identity reads that leave adapter activity unchanged,
   explicit JPEG request that counts as work, and old UI rejection after control
   rotation while the same process/page survives. A fixture may explicitly use
   synthetic fallback/certificate receipt fields, but must label them and never
   claim an actual KasmVNC fallback or CA import. Production gates are unchanged.
2. **Native headed telemetry remains intentionally unimplemented.** Inspected
   `kasmvnc_session.py:build_start_command/start_session`: BBH starts external
   `vncserver`/Xvnc in foreground with loopback WebSocket transport and records
   display/port only. It has no native input event callback. `chromium_test.py`
   correctly labels headed coverage `native-input-untracked`. Required successor:
   integrate with the actual KasmVNC/Xvnc native-input owner, bind accepted input
   to the exact display/browser instance and control generation, and coordinate
   admission with the adapter's atomic freeze/reservation boundary. Prove real
   disposable headed input blocks idle reclaim, while passive display refresh,
   transport liveness and stale-generation signals do not. Do not infer activity
   from screenshots or add a timer heartbeat. Conservative headed policy stays.
3. Parent still owns independent review, original startup investigation and
   beta acceptance. No push, merge, deployment, Kanban mutation, external route,
   live site/account, credential/OTP handling or security workflow was performed.

## Headed workflow / ordinary provisioning follow-up — partial, blocked

Delegated base: `ee1c54b702443835ded9967e2cb53f435fe094e2`, same worktree and
`feat/browser-lease-recovery`, intended target **beta**. Fetched `origin/beta`
remains `69e9a2a01be26ea1e64a0d00fd6cf23a47704e4e`. Parent owns final review;
this is a recoverable scoped checkpoint, **not completion of native activity**.

### Inspection before edits

- Read the actual `kasmvnc_session.py` foreground `vncserver` invocation and
  `chromium_test.py` display/pipe integration. Native input is delivered by the
  external Xvnc server; the Python launcher records display/web port but has no
  accepted-input callback, input admission barrier, or native generation revoke.
  CDP has its own atomic event-loop activity/freeze/reservation boundary.
- Local prerequisite discovery: `command -v Xvnc vncserver Xvfb xinput xdpyinfo`
  found only `/usr/bin/Xvfb`, `/usr/bin/xinput`, `/usr/bin/xdpyinfo`.
  `DISPLAY` is unset. Process-name inspection found an existing Xwayland process,
  not a KasmVNC server; that unrelated desktop was not attached to or modified.
- Traced ordinary caller examples to `request` -> subprocess `start` -> lease ->
  launcher, which previously omitted instance selection and defaulted X display
  to 20. Installed `bbh` resolves to
  `/home/ryushe/projects/bug_bounty_harness/scripts/bbh`, **not this feature
  worktree**. No runtime source switch or activation was performed.
- Inspected `handoff_transport.sh`: it publishes existing loopback UI endpoints
  through Tailscale Serve. Neither the publisher nor routes were changed. The
  pending fallback-UI smoke approval and Kanban child guard were not retried.

### Completed changes

- Ordinary `request/start` with no slot now chooses automatic isolated instances
  for resolved fresh selectors. Same agent/run retries retain their slot;
  otherwise observable idle automatic slots enter the existing authoritative
  freeze path, stopped automatic slots may be reused, and fresh slots use
  agent/run-derived keys (a new unique key when that slot already belongs to
  another controller). Private `instance_selection` provenance excludes explicit
  slots even if their name begins with `auto-`. Account single-browser policy remains enforced by the
  canonical SQLite acquisition transaction. Explicit slots and task namespaces
  are unchanged. Unresolved selectors remain on the legacy resolution path.
- Historical legacy leases, manager records and known canonical/pre-domain/
  Shared disk paths prevent silent migration. `--legacy-profile` is forwarded
  through request/start and explicitly preserves legacy behavior for fresh data.
- Headed auto/KasmVNC starts choose unoccupied display and loopback web port
  under the existing node start lock, before lease acquisition. Registered
  running displays/ports, X sockets/locks and bound ports are excluded. Explicit
  occupied choices queue. This coordinates this manager's callers, not external
  X server launchers. No route is published by selection.
- Same-owner incompatible display-mode retries fail explicitly without stopping
  the existing browser. Live transfer now requires tracked control and a
  headless requester; merely having a pipe adapter without KasmVNC metadata no
  longer permits an untracked native display to cross owners alive.
- Added deterministic selection, legacy, single-policy concurrency,
  selection-versus-freeze race, display/port and mismatch regressions. The real
  systemd fixture now requests the primary instance **without naming a slot**,
  retries it, and later claims it idle while its previous owner PID is alive.
- Real pipe fixture now also runs headed on its own dynamically assigned Xvfb
  display (`-displayfd`, no TCP), then reaps that exact display process. It
  exercises actual headed Chromium/CDP, in-flight/reservation protection and
  generation revocation. **It does not exercise KasmVNC/native input or prove
  headed manager idle reclamation safe.**

### Verification and limits

Final source command:

```sh
BBH_LOCAL_BROWSER_SMOKE=1 .venv/bin/python -m pytest agents/test_browser_resources.py agents/test_browser_lifecycle.py agents/test_browser_lifecycle_systemd.py agents/test_browser_lease_recovery.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py agents/test_browser_startup_diagnostics.py tests/test_script_policy.py -q
```

Result: **184 passed in 121.24s**, including actual headless and isolated headed
Xvfb pipe runs and user-systemd lifecycle execution. Earlier full source passed
177 tests before added native/mode/legacy guards. Initial focused run had one
failure: automatic selection was incorrectly applied to an unresolved account
whose domain was returned later by the lease helper. Fixed by retaining legacy
resolution for unresolved selectors; the unchanged regression passes now.

`uvx ruff check --select F skills/chromium-test/scripts/browser_provisioner.py agents/test_browser_resources.py agents/test_browser_lifecycle.py agents/test_browser_lifecycle_systemd.py`
and `git diff --check` passed. Post-run
`systemctl --user list-units 'browser-*' --all --no-pager --plain` returned
**0 loaded units**. Post-run process inspection found no Xvfb/Xvnc; the original
unrelated Xwayland remained. No dependency manifest changed; the checkout's
environment is newer than the manifest. Original intermittent startup failure
remains undiagnosed; successful runs are not a causal repair.

### Exact missing acceptance / prerequisite

**Authoritative native activity, native-versus-cleanup atomicity and live
KasmVNC cross-owner revocation are still missing.** No native tracker was added
and headed `activity_tracking` remains false. Headed two-hour idle eviction is
disabled; existing explicit release/supervisor-terminal lifecycle is retained.
Tracked headless instances retain PID-independent idle behavior.

Resume on an authorized disposable KasmVNC runtime with `vncserver`/`Xvnc`
available, and integrate at its actual input owner (or a sole enforced input
gateway): accepted keyboard/pointer/clipboard control must be bound to the
exact instance/display and generation, participate in the same admission/freeze
ordering as CDP, and support acknowledged draining/revocation of established
native controllers. Merely installing KasmVNC is necessary for its real fixture
but not sufficient to supply this integration. Asynchronous X event observation
or idle polling alone cannot close the input-versus-freeze race, and raw display
connections bypassing such a gateway cannot be declared revoked.

Only after that integration may a real disposable native-input fixture assert
that input wins cleanup, freeze rejects later native input, stale generations
cannot inject, passive refresh is not work, and distinct displays/ports and
existing Tailscale handoffs survive correctly. No fallback screenshot UI is
substituted. No real accounts/sites, security workflows, external route changes,
push, merge or deployment were performed. Parent must review this partial delta
and resolve the native runtime prerequisite before accepting the full request.
