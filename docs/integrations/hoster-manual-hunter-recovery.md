# Hoster manual-hunter recovery integration dossier

- **Status:** approved for beta integration
- **Owner:** Hermes
- **Branch:** `recovery/hoster-beta-manual-hunter-20260901`
- **Base commit:** `a9db75eee30ffa8948e49c15887cc45c90afdcff`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `recovery/hoster-beta-manual-hunter-20260901`
- **Latest immutable recovery checkpoint:** `c1b312912cb78ed7e35fa617c093ce1392bd5d40`
- **Feature implementation commit(s):** `0719ba1111e78f2d133e5079badccc332bff07ce`, `f2b0a8f8834c11afe2b71499320ad1f39aee9a1d`, `c1b312912cb78ed7e35fa617c093ce1392bd5d40`
- **Inspiration / canonical references:** recovered from Hoster’s dirty `bug_bounty_harness-aiskillsync-beta` worktree.

## Intent

Recover and integrate the focused manual-finding ingestion fix found on Hoster without losing its accompanying follow-up record. The fix must avoid treating hostname fragments as source files, preserve clean Markdown-derived titles, and flag inferred finding classes.

## Implemented contract

- `FILE_HINT_RE` performs deliberately conservative unlabelled inference: it recognizes simple basenames or slash-separated source paths, and rejects hostname-shaped tokens across recognized TLD/extensions such as `www.example.com`, `.go`, `.rs`, and `.js`. Explicit `File:` values remain authoritative for unusual filenames.
- Markdown heading titles use the first meaningful line rather than joining the following prose.
- Findings with an inferred class carry `class_inferred: true` and emit an actionable warning; explicitly stated classes remain authoritative.
- `BUGFIXES.md` records the analogous `sync_reports.py` regex defect as a separate follow-up, not as silently fixed behavior.

## Evidence and review

- Tests and commands: `PYTHONPATH="$PWD" /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q agents/test_manual_hunter.py` → 18 passed, 4 hostname subtests passed; `python3 -m py_compile agents/manual_hunter.py`; `git diff --check`.
- Independent review: APPROVED after the second corrective rereview. It verified the parse-level slash-path and explicit `File:` tests, hostname guard, py_compile, clean diff/status, and 18-test focused suite.
- Replay/cohort/fixture evidence: direct hostname guard plus parse-level unlabelled path and explicit hostname-shaped `File:` regression tests are included.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** focused repair for the separate `sync_reports.py` duplicate regex.
- **Command / fixture / environment needed:** a dedicated follow-up branch and its own unit regression.
- **Trigger to run it:** after this recovery patch is integrated or as a separately scheduled repair.
- **Why it blocks integration, activation, or promotion:** does not block this manual-hunter repair; remains a documented independent data-corruption risk in the other parser.
- **Next completion step / successor reference:** review, merge to beta, push, then fast-forward Hoster’s clean beta runtime clone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `recovery/hoster-beta-manual-hunter-20260901`
- **Latest immutable recovery checkpoint:** `c1b312912cb78ed7e35fa617c093ce1392bd5d40`
- **Feature implementation commit(s):** `0719ba1111e78f2d133e5079badccc332bff07ce`, `f2b0a8f8834c11afe2b71499320ad1f39aee9a1d`, `c1b312912cb78ed7e35fa617c093ce1392bd5d40`
- **Exact resume point:** integrate the approved recovery branch into a clean/current `beta`, remove this dossier from the integration lane, push beta, and fast-forward the clean actual Hoster checkout.
- **Working-tree state at handoff:** clean after the dossier checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** fresh Hoster clean-runtime source verification.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — recovered from Hoster dirty beta checkout; 16 focused tests passed with the canonical checkout-local environment.
- 2026-09-01 — recovered implementation checkpoint `0719ba1` was reviewable but incomplete: hostname-shaped `.go`, `.rs`, and `.js` tokens still matched.
- 2026-09-01 — corrective checkpoint `f2b0a8f` makes unlabelled inference conservative and adds missing hostname cases; direct behavior passed but review required parse-level coverage.
- 2026-09-01 — parse-level test checkpoint `c1b3129` covers fallback inference for `src/api/validate.py#12` and explicit `File: www.example.go`; focused suite passed 18 tests and 4 subtests.
- 2026-09-01 — independent second corrective rereview APPROVED the recovery candidate after verifying hostname blocking, ordinary parse-level fallback, explicit-file authority, py_compile, diff check, and clean status.
