# Hoster MITM dry-run integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/hoster-mitm-dry-run`
- **Base commit:** `a79486184fd255b00269b6b45dfa63936bf0e030`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `fix/hoster-mitm-dry-run`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Hoster beta smoke after PC-20260901-193838-ffaf7988.

## Intent

Ensure `hoster_mitm_lane.py ensure-default --dry-run` is a successful planning operation. It must expose the chosen local dispatcher command without starting a listener or treating the deliberate dry-run result as a launch failure.

## Implemented contract

`ensure-default` returns `status: dry-run`, intended proxy host/port, and the planned `start` receipt when dry-run is requested. Non-dry-run listener checks and start behavior remain unchanged.

## Evidence and review

- Tests and commands: `uv run --with pytest python -m pytest -q agents/test_hoster_mitm_lane.py agents/test_browser_provisioner.py tests/test_bbh_launcher.py` → 32 passed; `python3 -m py_compile skills/chromium-test/scripts/hoster_mitm_lane.py`; `git diff --check`.
- Independent review: pending.
- Replay/cohort/fixture evidence: a focused unit test verifies dry-run returns planning success and no live external action is performed.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** fresh Hoster beta runtime smoke after merge.
- **Command / fixture / environment needed:** clean clone at the merged beta commit.
- **Trigger to run it:** after beta push.
- **Why it blocks integration, activation, or promotion:** does not block beta integration; blocks claiming Hoster deployment verification.
- **Next completion step / successor reference:** review, merge, update the clean runtime clone, run `ensure-default --dry-run`.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/hoster-mitm-dry-run`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit the patch and dossier, then obtain independent review.
- **Working-tree state at handoff:** intentionally uncommitted while preparing the first checkpoint.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** Hoster clean-runtime dry-run smoke.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — created after deployment smoke revealed dry-run was misclassified as `start-failed`.
