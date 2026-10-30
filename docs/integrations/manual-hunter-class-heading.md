# Manual-hunter Class heading integration dossier

- **Status:** blocked pending independent review
- **Owner / task:** Hermes subagent, BBH t_4c4f1212 / PC-20260929-001815-14a98db0
- **Branch / worktree:** `fix/manual-hunter-class-heading` / `/home/ryushe/worktrees/bbh-manual-hunter-class-heading`
- **Base:** freshly fetched and remote-read-back `origin/beta` `47b3aff4c102bc6987ce747877d08409761b3130`
- **Intended integration target:** `beta` (integration not authorized here)
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/manual-hunter-class-heading`
- **Latest immutable recovery checkpoint:** none yet; commit containing this dossier is the checkpoint
- **Implementation commit(s):** pending checkpoint commit
- **Canonical references:** `agents/manual_hunter.py`, `agents/sync_reports.py`, `agents/test_manual_hunter.py`, `agents/test_sync_reports.py`; prior metadata fix `3fa84b8` is an ancestor of base.

## Intent and boundaries

Repair explicit Class headings misclassified by keyword inference, which can cause a duplicate-comment operation to create a second finding. Reuse the existing parser and class normalization. No live programs, real finding ledgers, traffic, credentials, stable, Hoster, activation, push, merge or closure. This is a beta-based feature; stable/ancestor propagation is not authorized and requires separate owner decision.

## Implemented contract

A Markdown Class heading consumes the first nonblank value line only, without absorbing subsequent prose; another heading or field terminates an empty heading. Existing `Class:` fields and bold/list label variants retain their parser semantics. Class values use existing normalization and remain open vocabulary; even odd explicit values remain accepted as before. Empty values preserve inference and its warning. Distinct nonempty explicit values after normalization raise an actionable `ClassConflictError` before manual file ingestion; equivalent normalized values are accepted, and empty later fields do not erase a stated class. Sync reports refuses to downgrade a class conflict to loose inference, while separately checking structured per-finding blocks to avoid conflating different findings. Keyword inference itself is unchanged; it remains unable to recognize negation.

## Evidence and review

- Base synthetic parser repro under network denial: `## Class\nbroken-access-control` produced inferred `dom-xss` from a negated DOM XSS sentence and emitted warning; `Class: broken-access-control` produced explicit `broken-access-control`.
- TDD red: isolated synthetic ledger regression with `--link-duplicate-comment` returned 0 and created D02 instead of linking D01; green returned 1, printed `Linked duplicate note to D01`, retained one finding, and stored the raw note and correct FID in the disposable comment ledger. Explicit-conflict test also failed four forms before repair; sync loose-fallback regression failed before repair.
- Final full relevant suites: `PYTHONPATH="$PWD:$TMPDIR/manual-class-core" HOME=<disposable-scratch-home> /usr/bin/python3 "$TMPDIR/manual-class-netdeny.py" /usr/bin/python3 -m unittest agents.test_manual_hunter agents.test_sync_reports -q` — **85 passed**. Existing expected inference warnings appeared. The synthetic tests use disposable `TemporaryDirectory` homes/storage only.
- Dependency: `git archive 6c36ee88a60073e1b687ec32deeade24ffafdd4f` from the local Bounty Core object database exported into `$TMPDIR/manual-class-core`, matching `requirements.txt` pin. Import provenance printed `agents.manual_hunter` and `agents.sync_reports` from this feature worktree, `bounty_core` from that pinned export.
- Network: `unshare -n` unavailable (`Operation not permitted`); scratch `manual-class-netdeny.py` uses inherited kernel seccomp denial for socket/connect/send syscalls, verified with a subprocess before tests. All suite subprocesses inherit the filter.
- `git diff --check` clean. Independent review **not yet performed**. Target has not been merged, published or activated.

## Blockers and next action

- Independent reviewer must fetch `origin/beta` again, review the exact feature tip and dossier against the base, rerun both suites with pinned core, isolated storage and inherited network denial, and explicitly inspect conflict handling in structured multi-finding sync. Reconcile if beta advanced. No integration without review and owner authorization.
- No stable propagation or activation authorized; owner must decide separately after beta integration. No real finding has been corrected by this task.

## Interruption / resume handoff

- **Ref:** `fix/manual-hunter-class-heading`
- **Recovery checkpoint:** this commit, to be recorded by a follow-up dossier-only commit.
- **Exact resume point:** independent review and reproducible rerun, not merge/push/activation.
- **Working-tree state at handoff:** intended clean after checkpoint.

## Decision gates

- **Integration:** independent review, fresh beta fetch and reconciliation, passing reruns and explicit authorization.
- **Activation:** not authorized.
- **Stable / promotion:** not authorized.

## Decision record

- 2026-10-29 — feature created from selected fetched beta; synthetic-only reproduction and offline tests completed; independent review outstanding.
