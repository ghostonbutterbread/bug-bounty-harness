# Hoster manual-hunter recovery integration dossier

- **Status:** corrective review required
- **Owner:** Hermes
- **Branch:** `recovery/hoster-beta-manual-hunter-20260901`
- **Base commit:** `a9db75eee30ffa8948e49c15887cc45c90afdcff`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `recovery/hoster-beta-manual-hunter-20260901`
- **Latest immutable recovery checkpoint:** `f5b845baff65020819fa24f7320fc3ad729d639e`; corrective checkpoint pending commit
- **Feature implementation commit(s):** `0719ba1111e78f2d133e5079badccc332bff07ce`; corrective commit pending
- **Inspiration / canonical references:** recovered from Hoster’s dirty `bug_bounty_harness-aiskillsync-beta` worktree.

## Intent

Recover and integrate the focused manual-finding ingestion fix found on Hoster without losing its accompanying follow-up record. The fix must avoid treating hostname fragments as source files, preserve clean Markdown-derived titles, and flag inferred finding classes.

## Implemented contract

- `FILE_HINT_RE` performs deliberately conservative unlabelled inference: it recognizes simple basenames or slash-separated source paths, and rejects hostname-shaped tokens across recognized TLD/extensions such as `www.example.com`, `.go`, `.rs`, and `.js`. Explicit `File:` values remain authoritative for unusual filenames.
- Markdown heading titles use the first meaningful line rather than joining the following prose.
- Findings with an inferred class carry `class_inferred: true` and emit an actionable warning; explicitly stated classes remain authoritative.
- `BUGFIXES.md` records the analogous `sync_reports.py` regex defect as a separate follow-up, not as silently fixed behavior.

## Evidence and review

- Tests and commands: `PYTHONPATH="$PWD" /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q agents/test_manual_hunter.py` → 16 passed, 4 hostname subtests passed; `python3 -m py_compile agents/manual_hunter.py`; `git diff --check`.
- Independent review: the initial review correctly found hostname-as-file false positives for `.go`, `.rs`, and `.js`; corrective rereview is pending.
- Replay/cohort/fixture evidence: explicit hostname, Markdown title, and inferred-class regression tests are included.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** focused repair for the separate `sync_reports.py` duplicate regex.
- **Command / fixture / environment needed:** a dedicated follow-up branch and its own unit regression.
- **Trigger to run it:** after this recovery patch is integrated or as a separately scheduled repair.
- **Why it blocks integration, activation, or promotion:** does not block this manual-hunter repair; remains a documented independent data-corruption risk in the other parser.
- **Next completion step / successor reference:** review, merge to beta, push, then fast-forward Hoster’s clean beta runtime clone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `recovery/hoster-beta-manual-hunter-20260901`
- **Latest immutable recovery checkpoint:** `f5b845baff65020819fa24f7320fc3ad729d639e`; corrective checkpoint pending commit
- **Feature implementation commit(s):** `0719ba1111e78f2d133e5079badccc332bff07ce`; corrective commit pending
- **Exact resume point:** independent reviewer must inspect `0719ba1` and this dossier-only checkpoint, then merge only after approval.
- **Working-tree state at handoff:** clean after the dossier checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** fresh Hoster clean-runtime source verification.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — recovered from Hoster dirty beta checkout; 16 focused tests passed with the canonical checkout-local environment.
- 2026-09-01 — recovered implementation checkpoint `0719ba1` is ready for independent review.
