# Chromium row-repair script-index integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `fix/chromium-row-repair-script-index`
- **Base commit:** `869929d8e147fa9b6f35b0fd89d2e57ed69ab769`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `fix/chromium-row-repair-script-index`
- **Latest immutable recovery checkpoint:** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55` (initial implementation; review correction to follow)
- **Feature implementation commit(s):** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55`
- **Inspiration / canonical references:** `SCRIPT_POLICY.md`, `tests/test_script_policy.py`, `skills/chromium-test/scripts/browser_manager_row_repair.py`.

## Intent

Repair one pre-existing script-index contract failure on beta: the historical Chromium browser-manager row repair helper is listed but lacks the structured `##` record required by the index contract. No runtime script logic or launch path changes.

## Implemented contract

Add a complete script record including inputs/outputs/mutation boundary, checkout-local verification, owner, and date. Preserve existing detailed guarded-repair prose immediately below.

## Evidence and review

- Tests and commands: `./setup.sh --install-python-deps`; `.venv/bin/python -m pytest tests/test_script_policy.py agents/test_browser_manager_row_repair.py -q` → 47 passed; `git diff --check` clean.
- Independent review: initial reviewer confirmed the required fields and 47 passing tests; requested removing an overclaim that two sequential snapshots form an atomic pair and refreshing the stale handoff. Both documentation corrections are applied; final re-review pending.
- Replay/cohort/fixture evidence: failure reproduced on unchanged `beta` at base; index and existing row-repair tests now pass in feature worktree.
- Merge/ancestry evidence: feature branched from fetched `origin/beta` above; current remote and clean beta integration checkout must be checked before integration.

## Blockers and deferred work

No feature-specific blocker known. This is documentation only; no live browser repair/apply performed. Re-run tests after any target movement.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-row-repair-script-index`
- **Latest immutable recovery checkpoint:** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55` (initial implementation; review correction to follow)
- **Feature implementation commit(s):** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55`
- **Exact resume point:** verify the review correction and commit the updated README/dossier, then re-review the final tip, reconcile with current beta, integrate and verify; merge corrected beta into the XSS sink-inventory branch and rerun combined gates.
- **Working-tree state at handoff:** README/dossier review corrections intentionally uncommitted until the next checkpoint.

## Decision gates

- **Integration gate:** independent review, clean current beta, passing index and row-repair tests.
- **Activation / cohort gate:** no runtime activation or data repair implied.
- **Promotion gate:** stable/main promotion is separate and owner-directed.

## Decision record

- 2026-10-05 — created as a separate prerequisite repair for the XSS sink-inventory release gate.
