# Autonomous recon coverage repair integration dossier

- **Status:** independent blocker re-review accepted; reconciled with beta and focused checks pass, not integrated
- **Owner:** Hermes focused subagent / card `t_b317a8e8`
- **Branch:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Latest immutable recovery checkpoint:** `ba58f1a` (merges beta `81da58b` into feature after repair `95c5dcc`)
- **Feature implementation commit(s):** `2f20ce3` (initial coverage), `4f4ae40` (prior scope/checkpoint repair), `eba94f7` (redirect fence and fixture), `f90d2be` (navigation fallback invariant), `95c5dcc` (effective URL and endpoint scope repair)
- **Inspiration / canonical references:** User request and policy-reviewer stop-boundary note; `AGENTS.md`, `SCRIPT_POLICY.md`.

## Intent

Remove silent first-80 JS and first-50/60 page/depth truncation. Keep the existing target/host boundary, saved scope checks, per-attempt network timeouts, and rate limiter. This is an extension of the existing `agents/autonomous_recon.py` owner, not a new script.

## Implemented contract

- Crawl uses a bounded BFS frontier. Browser routes use `route.fetch(max_redirects=0)` and fulfill only non-redirect responses; `route.continue_()` and fulfilled 30x responses can follow redirects without another route callback and are forbidden. Excluded redirects and redirected subresources abort before the destination request, mark the page retryable and pause with a persisted checkpoint; scoped navigation redirects abort in Chromium then use the existing urllib scoped redirect handler for the document. urllib validates and rate-limits every allowed redirect hop. Service workers are blocked; the browser falls back to urllib when WebSocket interception is unavailable. Restored crawl inventory is revalidated against saved scope.
- Relative links, scripts, and forms in a redirected document resolve against its final scoped response URL (both browser/urllib fallback and urllib-only). A document with no effective URL remains retryable rather than completing with wrongly based links. The scoped redirect handler still fences and rates every hop.
- JS-derived root-relative API endpoints are admitted only if their resolved URL passes the same host and saved scope checks as generic extracted URLs; analysis checkpoint and result carry only admitted endpoints.
- Crawl checkpoint persists through analysis and publication; JS analysis checkpoints successful files and extracted findings/endpoints per file so interrupted analysis resumes without recrawling or refetching completed JS. Failed JS fetches retry on next invocation. The checkpoint is removed only after successful output/publication; publication failure retains it. `summary.json` records partial/paused/discovery status and disk-floor reason. CLI returns 2 on incomplete, 0 only on complete. Recon Bus promotion requires complete discovery, crawl, JS analysis, and no disk pause.
- The output filesystem must have at least 5 GiB free before normal artifact writes. At disk-floor pause, keep the pending crawl checkpoint and write only a small atomic summary; do not publish. Existing per-attempt timeouts remain for browser/urllib requests and subprocess discovery (90/120/30 seconds); subprocess timeouts mark discovery partial/retryable rather than complete. The 10,000-URL overflow still requires operator intervention; results remain memory-resident.

## Evidence and review

- `python3 -m pytest agents/test_autonomous_recon.py -q`: 17 passed, including actual loopback urllib redirect-hop zero-hit and rate assertions, browser-route mocks, checkpoint/partial-exit fixtures.
- `node --test agents/test_autonomous_recon_redirect_browser.cjs`: 1 passed using installed Node Playwright and `/usr/bin/google-chrome` against loopback HTTP: 302 `/out-redirect` to excluded `/private-redirect` records zero destination hits; a scoped redirect is aborted by browser and the allowed path succeeds through HTTP fallback. The Node fixture exercises the transport strategy; Python Playwright is absent here, so the Python application browser path is covered by mocks rather than an end-to-end Python browser run.
- `python3 -m pytest agents/test_autonomous_recon.py tests/test_script_policy.py tests/test_scratch_scripts.py -q` after merging `origin/beta` at `6a45a0d`: 55 passed, 1 unrelated pre-existing beta failure (`test_each_skill_index_has_complete_nonstale_records`: `skills/stack-to-program/scripts/README.md` lacks `**Outputs:**`/`**Mutates:**`). Do not claim combined suite green.
- `git diff --check origin/beta...HEAD`: clean. No live target probes.
- Blocker RED: `python3 -m pytest agents/test_autonomous_recon.py -q -k 'resolves_relative_links_against_scoped_redirect_destination or filters_extracted_paths_by_saved_scope'` failed at `/old/detail` versus `/new/detail` and emitted `/api/private` outside `/allowed/`.
- Blocker GREEN: `python3 -m pytest agents/test_autonomous_recon.py -q` 20 passed including missing-effective-URL retryable negative fixture; combined `python3 -m pytest agents/test_autonomous_recon.py tests/test_script_policy.py tests/test_scratch_scripts.py -q` before the final fixture: 58 passed, 1 pre-existing unrelated failure in the stack-to-program index (same missing Outputs/Mutates fields). `git diff --check` clean.
- `node --test agents/test_autonomous_recon_redirect_browser.cjs`: 1 passed post-fix on loopback Chrome. No live targets. The earlier fetched beta `6a45a0d` was merged as `9111c1f`; the later beta tip `81da58b` was reconciled as `ba58f1a`.
- Independent re-review accepted `95c5dcc` after reproducing both prior defects on `c6b8672`; gate required reconciling beta and rerunning the integrated feature checks. Reconciliation merge `ba58f1a` contains beta `81da58b` without conflict; checkout-local `.venv` focused Python suite 20 passed, Node/Chrome loopback 1 passed, `git diff --check` clean. No beta integration or push at dossier writing.


## Blockers and deferred work

- **Residuals:** Python Playwright is not installed in this checkout, so the Python browser path is mocked while an equivalent Node Playwright/Chrome loopback fixture exercises the redirect transport. Redirected subresources deliberately pause instead of silently yielding incomplete dynamic coverage; scoped document redirects use urllib and may not capture browser-generated links on that page. Existing discovery/network timeouts and publication transaction caveats remain.
- **Deferred test:** When Python Playwright is installed in the selected runtime, run loopback redirects through its Python application browser path; verify exact-once Recon Bus publication across a deliberate side-effect/manifest crash window before claiming that stronger guarantee. Current runtime lacks Python Playwright and uses guarded urllib fallback.
- **Trigger:** runtime gains Python Playwright, or an owned disposable publication fixture becomes available; no live target probe authorized.
- **Integration gate:** independent blocker re-review accepted; parent to integrate reconciled feature and retest before rollout. The unrelated stack-to-program metadata test failure is not a recon release signal.
- **Next step:** parent merges reviewed feature into beta, retires this dossier from beta, tests, publishes, and verifies selected Hoster runtime.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Latest immutable recovery checkpoint:** `ba58f1a` after beta reconciliation; this dossier-only acceptance handoff follows.
- **Feature implementation commit(s):** `2f20ce3`, `4f4ae40`, `eba94f7`, `f90d2be`, `95c5dcc`.
- **Exact resume point:** parent beta merge, integrated focused checks, publication, Hoster runtime verification.
- **Working-tree state at handoff:** clean after dossier commit.

## Decision gates

- **Integration gate:** accepted at `95c5dcc`, reconciled with beta `81da58b` in `ba58f1a`, then 20 Python focused tests and 1 real local Node browser fixture passed; parent still verifies integration target.
- **Activation / cohort gate:** separately verify selected runtime source; not activated.
- **Promotion gate:** stable promotion requires separate owner direction and evidence.

## Decision record

- 2026-10-23 — created feature repair from fetched beta; offline tests pass; no live target request, merge, or push.
