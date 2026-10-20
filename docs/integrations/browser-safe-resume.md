# Browser safe cleanup and resume integration dossier

- **Status:** implementation checkpoint; isolated systemd acceptance pending
- **Owner:** feature worktree agent, parent integration owner t_a6a67529
- **Branch / owning ref:** `feat/browser-safe-resume`
- **Base commit:** `eaa6cca5483e12b79a427bc06cac1629673e3348` (`origin/beta` fetched)
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `da1ba16aa2aed036ce944c5719309fc23504e2a0` (automatic-slot refinement and final split-suite receipts; dossier-only handoff follows)
- **Feature implementation commit(s):** `54a9433`, `57b4c44`, `f96c0bc`, `da1ba16`
- **Inspiration:** capacity incident where four active browser units were stopped by a mismatched suffix; existing request-triggered two-hour CDP idle sweep.

## Intent and implemented contract

Provisioner `cleanup` dry-run reports node admission and per-browser safe refusal reasons. `--apply` admits only canonical manager-owned, exact-invocation healthy units with positively terminal owner, explicitly headless/non-KasmVNC receipt, zero attached CDP clients and tracked idle >=7200 seconds; atomic detached-activity freeze, stop verification and canonical release remain required. Active and headed/native owners are protected also in the existing request-triggered idle sweep. CDP detachment does not attest viewer quiescence. No proxy listener is finished or profile deleted.

`request` no-capacity returns a safe cleanup next step and retains bounded retry behavior and identity. `resume --browser-id --agent-id --run-id` checks exact owner, canonical lease, healthy unit/CDP and proxy/CA; a live browser returns its existing ID with `browser-control-only` scope, not a viewer availability assertion. Successful new launches persist a private versioned non-secret recipe; release/retire preserve it plus a private stopped-CDP proof. Stopped exact-ID resume checks canonical released lease, owner/run, unit/root/CDP, profile device/inode (or genuinely absent task-owned profile), account/domain/auth-source policy and proxy/CA. It leaves the node lock before dispatching ordinary request/start; the child rechecks old ID, physical profile/instance/policy and proxy under its own lock before lease acquisition. New browser/lease IDs link via `replaces_browser_id`; `about:blank` replaces old target URL, and browser-native authentication must be checked after launch. Missing task-owned profile reports `state_lost: true`. Verified repeated resume reads the exact replacement rather than spawning another. Legacy/no-recipe, ambiguous named legacy, missing external CA, changed profile/policy/proxy and foreign ownership block.

## Evidence and review

- `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q agents/test_browser_safe_resume.py agents/test_browser_resources.py agents/test_browser_provisioner.py --tb=short` — **123 passed, 2 failed**. All six feature-introduced regressions are green: four fixture `clients` initializations and two threshold fixture canonical-owner/terminal/detachment corrections. Two failures predate this repair: `agents/test_browser_provisioner.py::test_task_proxy_completion_indexes_private_default_and_releases[False]` and `[True]`; their subprocess fixture calls mitmproxy `connection.Client` positionally and fails with `TypeError: Client.__init__() takes 1 positional argument but 4 were given` before testing provisioner behavior. No tests omitted from this run.
- Focused canonical-owner, missing-client fail-closed, and threshold cases: 6 passed, 66 deselected (focused run only).
- Added headed/native/KasmVNC zero-stop tests for both cleanup paths and a browser-control-only resume receipt assertion.
- `.venv/bin/python` absent in this worktree; the existing beta checkout `.venv` was used for offline fixtures, never real browser provisioning.
- Current offline receipts: `pytest -q agents/test_browser_safe_resume.py agents/test_browser_resources.py agents/test_browser_provisioner.py agents/test_browser_selection.py agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py -k 'not test_task_proxy_completion_indexes_private_default_and_releases' --tb=short` → **196 passed, 2 deselected, 41 subtests passed**; separate `test_browser_safe_resume.py test_browser_legacy_auto.py test_browser_program_policy.py test_browser_lifecycle.py test_browser_driving_mode.py test_browser_lease_recovery.py` → **106 passed, 6 skipped**. After final idempotent state-loss/readback tightening, focused `test_browser_safe_resume.py test_browser_resources.py test_browser_provisioner.py` → **133 passed, 2 deselected**, `git diff --check` clean. New disposable fixtures exercise lost/existing task-owned dispatch, old-ID/foreign-owner refusal before lease, absent external CA, idempotent successor and private receipt preservation. The child launch itself is stubbed, not an end-to-end systemd/Chromium receipt.
- Final offline receipts after automatic-slot refinement: six-file provisioner/profile group → **197 passed, 2 deselected, 41 subtests passed**; lifecycle/policy/legacy group → **107 passed, 6 skipped**. `git diff --check` clean. The two deselected tests are the known positional mitmproxy fixture failures; no live browser was launched.
- Attempted `agents/test_browser*.py` suite exceeded the tool's 420-second cap without a final receipt; split suites above are the recorded evidence, not a claim that the entire browser suite passed.
- Four simulated live owners with 90000 seconds CDP idle and `--apply`: zero stops, four `owner-active-or-unverified` reasons.
- `git diff --check` clean. No Hoster runtime or live browsers touched.
- Independent review: pending parent.

## Blockers and deferred work

- **Deferred acceptance:** offline fixtures do not exercise a real browser publication, profile lease reacquisition, task MITM CA import or isolated systemd root after release, nor a truly concurrent pair of resume commands. Run the disposable systemd/browser fixture (`BBH_LOCAL_BROWSER_SMOKE=1`) on an isolated browser node, including named explicit/automatic slots and missing task-owned profile, before claiming full operational acceptance. No Hoster or live target may be used by this agent.
- **Supported limits:** pre-recipe historical browsers and ambiguous unkeyed named profiles refuse; named account inventory/auth source changes refuse rather than guessing. `--owner-pid` records refuse automatic replay because a previous supervisor PID cannot be assumed live. An already-finished task MITM refuses rather than minting a different CA/port under the old run. These are deliberate safe boundaries, not authentication restoration.
- **Existing test blocker:** run pinned checkout interpreter and compatible mitmproxy version for `agents/test_browser_provisioner.py::test_task_proxy_completion_indexes_private_default_and_releases`, or repair its fixture API on a separate task; current global mitmproxy positional `Client` constructor fails before feature logic.

## Handoff and decision gates

- **Exact resume point:** parent reviews new checkpoint diff and receipts; isolated disposable systemd/Chromium acceptance, concurrent resume and named pool proof are the next gate. Do not merge/push or activate this branch from this agent.
- **Working tree at handoff:** clean after checkpoint commit.
- **Integration gate:** independent review of refusal/stop boundaries and portability, plus existing dependency fixture decision.
- **Activation gate:** selected beta runtime install and isolated systemd fixture, not this branch-only test.
- **Promotion gate:** separate owner decision; no stable promotion implied.
- **Decision:** guarded stopped-ID auto-reprovision implemented for versioned receipts; operational end-to-end acceptance deferred.
