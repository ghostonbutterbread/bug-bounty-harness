# XSS sink inventory route and Hoster beta rollout

- **Status:** feature / release pending
- **Owner:** Hermes
- **Branch:** `docs/xss-sink-inventory-route`
- **Base commit:** `23638e0b5546d14fbf0314045c65245d3fb0773f`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning worktree:** `/home/ryushe/projects/bug_bounty_harness/xss-sink-inventory-route`
- **Recovery checkpoint:** `5e3d0aac8ecd187aca914b61de166d4dab542bf3` (approved route/tests/dossier tip; decision-only commit follows)

## Intent and contract

Route XSS workers to the already-reviewed `agents/js_analyzer.py inventory` sink vocabulary through the owning XSS skill, with the JS skill as the procedure owner. Preserve the non-exhaustive review-seed boundary, manual source-to-sink analysis, and the existing scope guard. Publish the selected BBH beta lane and refresh Hoster's configured clean beta checkout so its active `bbh` launcher and XSS/JS skill links resolve the same revision. No live target testing or stable promotion.

## Evidence and review

- Existing sink change was merged locally as `3ad7330d04563bb612502d4293a7e18cd35e1824`, approved by independent review, and is now an ancestor of published `origin/beta` at base `23638e0b5546d14fbf0314045c65245d3fb0773f`.
- Hoster's actual source is `~/projects/bug_bounty_harness-runtime-beta-clean`, clean at `91953bd77a124702715c83cb73cd470544d64098`; its managed `xss` and `js` symlinks and `~/.local/bin/bbh` launcher resolve to that checkout. Hoster remote beta already advertises `23638e0`; runtime refresh still pending.
- Proposed change: `skills/xss/SKILL.md` gives a conditional static sink-inventory route, clarifies that collection may make scoped network requests, uses the repo-relative dispatcher, and keeps the coverage caveat; `tests/test_script_policy.py` guards the pointer and target artifacts.
- Tests: checkout-local `./setup.sh --install-python-deps`; `.venv/bin/python -m pytest tests/test_script_policy.py agents/test_js_analyzer.py -q` → 141 passed; `./scripts/bbh --print-command agents/js_analyzer.py` resolved the feature worktree; `git diff --check` clean. Initial independent review found two documentation defects (offline wording and stale dossier checkpoint); final independent review approved tip `5e3d0aa` after fixes, 141 focused checks and dispatcher verification. `beta` and `origin/beta` were clean and equal at `23638e0` after fetch; non-mutating merge check passed. Integrated-tree and Hoster smoke pending.

## Blockers and deferred work

No current blocker. Source publication and Hoster projection must be read back separately. Already-running agents may retain prior loaded skill text until a new session; do not restart unrelated workspaces.

## Interruption / resume handoff

Reviewed feature accepted for clean local `beta` at `23638e0`. Merge the feature into the beta integration worktree and retire this dossier there, rerun focused tests, then publish `beta` only from the beta worktree. Fast-forward only Hoster's clean configured beta checkout through its configured sync workflow. Verify active XSS and JS skill route, launcher root, and read-only `js_analyzer.py` help/inventory behavior. If integration or sync encounters divergent/dirty state, preserve it and stop for reconciliation.

## Decision gates

- Integration: focused script-policy and JS-analyzer tests, independent review, current-beta reconciliation.
- Publication: clean selected beta, explicit `git push origin beta`, remote readback.
- Activation: profile-aware synchronizer dry-run, apply only intended changes, post-sync no-op dry-run, managed links and launcher readback, checkout-local read-only smoke.
- Stable/main promotion: separate owner direction.

## Decision record

- 2026-10-05 — independent current-tip review approved `5e3d0aa` after correcting the two documentation findings. Accept for beta integration and Hoster beta rollout only; retire this temporary dossier from beta at merge. Existing agents may keep previously loaded instructions until their next session.
