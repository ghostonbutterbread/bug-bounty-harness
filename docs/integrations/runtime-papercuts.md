# BBH runtime papercuts integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_6d6bf8c7-resolve-bbh-runtime-papercuts`
- **Base commit:** `7b7abd9a374f9cf4ec20feb0f00e6668b7b6ebc8`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `bug-bounty-harness/t_6d6bf8c7-resolve-bbh-runtime-papercuts`
- **Latest immutable recovery checkpoint:** `ea4386a01f9887ee3f8932a6fa1e58f54dd5de8a`
- **Feature implementation commit(s):** `ea4386a01f9887ee3f8932a6fa1e58f54dd5de8a`
- **Inspiration / canonical references:** Discord `1544427475382046781`; PC-20260825-223955-78c60f84; PC-20260830-190637-53ad9bc6; PC-20260830-182926-9141abea.

## Intent

Remove three BBH-owned execution papercuts without changing any target-facing behavior: a failed unregistered browser launch must not make the profile unavailable; Hoster-local MITM lane commands must run the current checkout instead of SSHing to self or relying on a noninteractive `bbh` PATH; and the BBH agent entry card must state the complete lane-safe launcher contract.

## Implemented contract

- Browser launch failures that occur before a browser is registered release the acquired lease as `cancelled` with `profile-health=healthy`; normal explicit release still uses the caller-provided profile health.
- When `--ssh-host` names the current Hoster, `hoster_mitm_lane.py` invokes this checkout's `scripts/bbh.py` with the active Python interpreter. It returns local return code/stderr on a failure rather than an opaque SSH failure. Remote calls still use bounded SSH.
- The entry card now gives one complete, nonduplicated `bbh` / `HARNESS_ROOT` prohibition and points to the launcher documentation.

## Evidence and review

- Tests and commands: `uv run --with pytest python -m pytest -q agents/test_browser_provisioner.py agents/test_hoster_mitm_lane.py tests/test_bbh_launcher.py` → 29 passed; `python3 -m py_compile skills/chromium-test/scripts/browser_provisioner.py skills/chromium-test/scripts/hoster_mitm_lane.py`; `python3 scripts/bbh.py --print-command skills/chromium-test/scripts/hoster_mitm_lane.py`; `git diff --check`.
- Independent review: pending.
- Replay/cohort/fixture evidence: unit tests cover failed-systemd lease health, Hoster-local dispatcher selection, and local failure diagnostics. No live target or browser launch is required.
- Merge/ancestry evidence: pending after review.

## Blockers and deferred work

- **Missing test or evidence:** Hoster execution smoke using a no-side-effect `status` action after beta is deployed.
- **Command / fixture / environment needed:** Hoster checked out at the merged beta commit with its user runtime available.
- **Trigger to run it:** immediately after beta fast-forward, before reporting runtime deployment.
- **Why it blocks integration, activation, or promotion:** does not block beta integration; it blocks claiming the Hoster runtime has the patch.
- **Next completion step / successor reference:** review, merge into beta, then run the bounded Hoster smoke.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_6d6bf8c7-resolve-bbh-runtime-papercuts`
- **Latest immutable recovery checkpoint:** `ea4386a01f9887ee3f8932a6fa1e58f54dd5de8a`
- **Feature implementation commit(s):** `ea4386a01f9887ee3f8932a6fa1e58f54dd5de8a`
- **Exact resume point:** independent reviewer must inspect `ea4386a` and this dossier-only checkpoint, then merge only after approval.
- **Working-tree state at handoff:** clean after the dossier checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** Hoster fast-forward plus no-side-effect runtime smoke.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — created for BBH runtime papercut remediation.
- 2026-09-01 — implementation checkpoint `ea4386a` passed 29 focused tests and is ready for independent review.
