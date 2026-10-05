# Chromium row-repair script-index integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/chromium-row-repair-script-index`
- **Base commit:** `869929d8e147fa9b6f35b0fd89d2e57ed69ab769`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `fix/chromium-row-repair-script-index`
- **Latest immutable recovery checkpoint:** `c393820eece4e2dcff8b4be1b320ee436fd1d7d8` (review correction included; final dossier-only commit may follow)
- **Feature implementation commit(s):** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55`, `c393820eece4e2dcff8b4be1b320ee436fd1d7d8`
- **Inspiration / canonical references:** `SCRIPT_POLICY.md`, `tests/test_script_policy.py`, `skills/chromium-test/scripts/browser_manager_row_repair.py`.

## Intent

Repair one pre-existing script-index contract failure on beta: the historical Chromium browser-manager row repair helper is listed but lacks the structured `##` record required by the index contract. No runtime script logic or launch path changes.

## Implemented contract

Add a complete script record including inputs/outputs/mutation boundary, checkout-local verification, owner, and date. Preserve existing detailed guarded-repair prose immediately below.

## Evidence and review

- Tests and commands: `./setup.sh --install-python-deps`; `.venv/bin/python -m pytest tests/test_script_policy.py agents/test_browser_manager_row_repair.py -q` → 47 passed; `git diff --check` clean.
- Independent review: reviewer confirmed the required fields and 47 passing tests. A second review confirmed backup wording matches sequential snapshot behavior but found the checkpoint/handoff text stale. That final dossier-only correction is now applied; no script or README change remains.
- Replay/cohort/fixture evidence: failure reproduced on unchanged `beta` at base; index and existing row-repair tests now pass in feature worktree.
- Merge/ancestry evidence: feature branched from fetched `origin/beta` above; current remote and clean beta integration checkout must be checked before integration.

## Blockers and deferred work

No feature-specific blocker known. This is documentation only; no live browser repair/apply performed. Re-run tests after any target movement.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-row-repair-script-index`
- **Latest immutable recovery checkpoint:** `c393820eece4e2dcff8b4be1b320ee436fd1d7d8` (review correction included; final dossier-only commit may follow)
- **Feature implementation commit(s):** `35657a2ac9809148b59e1f3071f2dc0de4cb0c55`, `c393820eece4e2dcff8b4be1b320ee436fd1d7d8`
- **Exact resume point:** after committing this dossier-only correction, fetch and reconcile current beta, integrate the reviewed index repair, rerun its tests on beta, then merge corrected beta into the XSS sink-inventory branch and rerun combined gates.
- **Working-tree state at handoff:** clean after the dossier-only commit.

## Decision gates

- **Integration gate:** independent review, clean current beta, passing index and row-repair tests.
- **Activation / cohort gate:** no runtime activation or data repair implied.
- **Promotion gate:** stable/main promotion is separate and owner-directed.

## Decision record

- 2026-10-05 — created as a separate prerequisite repair for the XSS sink-inventory release gate.
- 2026-10-05 — two independent read-only reviews confirmed required index fields and guarded backup semantics after correcting an atomicity overclaim; second reviewer requested this exact checkpoint/handoff correction. Final feature acceptance is conditional on current-beta reconciliation and post-merge 47-test verification; no live data repair is authorized.
