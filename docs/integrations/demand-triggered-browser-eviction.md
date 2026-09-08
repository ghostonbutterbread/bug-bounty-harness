# Demand-triggered browser eviction integration dossier

- **Status:** feature
- **Owner:** Hermes/default
- **Branch:** `bug-bounty-harness/t_6f1fc293-demand-triggered-stale-browser-eviction`
- **Base commit:** `ffc74f333b0a5a3d086c058aa87a77888b3d326a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-08
- **Owning feature branch/ref:** `bug-bounty-harness/t_6f1fc293-demand-triggered-stale-browser-eviction`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** BBH provisioner capacity admission; operator requirement that active browsers must never be killed.

## Intent

On a capacity rejection, reclaim at most one safely stale, BBH-managed browser and retry admission once. This is demand-triggered only; no timer, cron, arbitrary-process cleanup, or agent-selected victim is introduced.

## Implemented contract

The provisioner atomically claims an expired lease through a non-secret lease-side transaction before it stops a browser. A candidate must be a manager-recorded running unit, older than the configured idle threshold, owned by another agent, and claimable only where `status=active`, `work_state=active`, and `expires_at <= now`. The claim fences renewal. `awaiting-input`, live-heartbeat, unknown, inactive-unit, and failed-claim states are retained. After confirmed unit stop, the same fence token must complete release; the provisioner stops after one candidate and reports reclaim metadata in the provisioning result.

## Evidence and review

- Tests and commands: `python3 -m py_compile skills/chromium-test/scripts/browser_provisioner.py skills/chromium-test/scripts/browser_profile_lease.py`; `PYTHONPATH="$WT" uv run --with pytest pytest -q agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py` — 75 passed.
- Independent review: initial review found a critical renewal race and requester-agent cross-run selection; both were corrected with an atomic claim/fence and agent-wide requester exclusion. Re-review pending.
- Replay/cohort/fixture evidence: deterministic SQLite fixtures in focused tests.
- Merge/ancestry evidence: feature branch starts at `ffc74f333b0a5a3d086c058aa87a77888b3d326a`.

## Blockers and deferred work

- **Missing test or evidence:** Hoster systemd/CDP end-to-end smoke on an actual capacity rejection.
- **Command / fixture / environment needed:** disposable provisioner request on the browser node with a verified stale BBH record.
- **Trigger to run it:** after beta integration, before runtime activation.
- **Why it blocks integration, activation, or promotion:** it blocks activation evidence, not source integration; unit tests cover fail-closed selection.
- **Next completion step / successor reference:** run the focused unit suite, independent review, then beta merge.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_6f1fc293-demand-triggered-stale-browser-eviction`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** inspect diff, run focused tests, obtain independent review, commit, and merge only after review.
- **Working-tree state at handoff:** intentionally uncommitted (implementation and dossier under verification).

## Decision gates

- **Integration gate:** focused tests pass; independent review finds no unresolved safety defect; clean beta merge check.
- **Activation / cohort gate:** disposable Hoster smoke proves only an expired, manager-recorded browser is reclaimed and active/handoff browsers are retained.
- **Promotion gate:** explicit user direction for beta-to-main promotion.

## Decision record

- 2026-09-08 — created feature for demand-triggered, fail-closed stale-browser reclaim.
