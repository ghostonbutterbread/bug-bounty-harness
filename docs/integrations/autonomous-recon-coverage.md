# Autonomous recon coverage repair integration dossier

- **Status:** release blocker repair on feature (awaiting independent review; not integrated)
- **Owner:** Hermes focused subagent / card `t_b317a8e8`
- **Branch:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Latest immutable recovery checkpoint:** `01fbf1b819cbc2927ab44a6f6890577d8b558edb` (feature merge of fetched beta `02d3bb5`; final repair commit follows)
- **Feature implementation commit(s):** `2f20ce3` (repair), `5d69c01` (local beta policy merge)
- **Inspiration / canonical references:** User request and policy-reviewer stop-boundary note; `AGENTS.md`, `SCRIPT_POLICY.md`.

## Intent

Remove silent first-80 JS and first-50/60 page/depth truncation. Keep the existing target/host boundary, saved scope checks, per-attempt network timeouts, and rate limiter. This is an extension of the existing `agents/autonomous_recon.py` owner, not a new script.

## Implemented contract

- Crawl uses one shared bounded BFS frontier. Playwright context routing blocks out-of-scope requests before network transfer, including redirects/subresources, blocks service workers, rate-limits permitted requests, and rejects an out-of-scope final navigation. urllib validates initial requests and every redirect hop, rate-limiting each allowed redirect. Restored crawl inventory (including every JS URL) is revalidated against current saved scope before network activity.
- Crawl checkpoint persists through analysis and publication; JS analysis checkpoints successful files and extracted findings/endpoints per file so interrupted analysis resumes without recrawling or refetching completed JS. Failed JS fetches retry on next invocation. The checkpoint is removed only after successful output/publication; publication failure retains it. `summary.json` records partial/paused/discovery status and disk-floor reason. CLI returns 2 on incomplete, 0 only on complete. Recon Bus promotion requires complete discovery, crawl, JS analysis, and no disk pause.
- The output filesystem must have at least 5 GiB free before normal artifact writes. At disk-floor pause, keep the pending crawl checkpoint and write only a small atomic summary; do not publish. Existing per-attempt timeouts remain for browser/urllib requests and subprocess discovery (90/120/30 seconds); subprocess timeouts mark discovery partial/retryable rather than complete. The 10,000-URL overflow still requires operator intervention; results remain memory-resident.

## Evidence and review

- `python3 -m pytest agents/test_autonomous_recon.py -q`: 15 passed on feature reconciled with `origin/beta` at `02d3bb5` (offline browser route/redirect/retry mock, urllib redirect-hop rejection/rate, changed-scope restored JS, JS analysis interruption, publication retry, disk-floor summary, timeout/exit, existing fixtures).
- `python3 -m pytest agents/test_autonomous_recon.py tests/test_script_policy.py -q`: 39 passed, 1 unrelated beta failure: `test_each_skill_index_has_complete_nonstale_records` reports missing `**Outputs:**`/`**Mutates:**` in `skills/stack-to-program/scripts/README.md`. The same test fails unchanged on the `beta` integration checkout at `02d3bb5`; recon-specific suite remains green. Do not claim all merged-beta checks pass.
- `git diff --check`: clean. No live probes.
- Independent release review: pending parent reviewer; no beta integration or push.
- Reconciliation: merged `origin/beta` through `02d3bb5` into feature branch; latest script-guidance changes did not conflict.


## Blockers and deferred work

- **Residuals:** Existing 90/120/30-second discovery subprocess deadlines and 15/10/6-second network attempt deadlines remain as CPU/network safety bounds; timed-out discovery now marks partial/retryable and blocks publication. Missing tools and some probe failures are still recorded as errors without an exhaustive-coverage guarantee. A process crash between Recon Bus side effects and the local manifest marker can replay publication into the same stable run ID; exact-once behavior across those stores is not proven. Browser WebSocket routing is configured where Playwright supports it, otherwise browser mode falls back to urllib; actual browser/proxy fixture validation remains required.
- **Missing test or evidence:** Real Playwright browser route semantics (including redirect chains), recon-store transaction behavior across mid-publication crashes, and live output-store promotion; offline mocked fixtures only.
- **Command / fixture / environment needed:** Disposable scoped local HTTP/browser fixture and an approved output store, then `python3 -m pytest agents/test_autonomous_recon.py -q` plus browser and publication smoke; no live target probe authorized here.
- **Trigger to run it:** Independent release review before beta integration.
- **Why it blocks integration, activation, or promotion:** Runtime browser interception and storage side effects were not exercised; offline tests are not a live safety receipt.
- **Next completion step / successor reference:** Parent release reviewer examines diff and performs local browser/storage fixture validation; integrate separately only if approved.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/autonomous-recon-coverage-tb317a8e8`
- **Latest immutable recovery checkpoint:** `01fbf1b819cbc2927ab44a6f6890577d8b558edb` (feature merge of fetched beta; repair commit follows)
- **Feature implementation commit(s):** `2f20ce3` (initial coverage repair), current branch tip (release blocker repair).
- **Exact resume point:** independent release review of committed repair, local Playwright/storage fixture tests, and unrelated beta script-index test owner; no integration/push authorized.
- **Working-tree state at handoff:** commit and verify clean worktree.

## Decision gates

- **Integration gate:** independent review and focused fixture verification, plus beta-tip reconciliation.
- **Activation / cohort gate:** separately verify selected runtime source; not activated.
- **Promotion gate:** stable promotion requires separate owner direction and evidence.

## Decision record

- 2026-10-23 — created feature repair from fetched beta; offline tests pass; no live target request, merge, or push.
