# Manual-hunter Markdown note parsing integration dossier

- **Status:** review-ready
- **Owner:** Hermes delegated implementation
- **Branch / owning ref:** `fix/manual-hunter-markdown-parse`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-manual-hunter-markdown`
- **Base commit:** `243a97bd52d970eb7d22cebcbd5f34baaf33f83e` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Latest immutable recovery checkpoint:** the implementation commit on this branch (Git cannot put a commit's own SHA in that commit; the review range is `243a97bd..fix/manual-hunter-markdown-parse`)
- **Inspiration / canonical references:** papercut `PC-20260825-225142-bf0e203f`; BUGFIXES entry on the `sync_reports` `FILE_HINT_RE` defect

## Intent

`manual_hunter.py --from-file` must ingest report-style Markdown notes (a heading
followed by `**Label:** value` lines) with the correct class, route identity, and
severity. If it cannot determine a value, it must leave it `unknown` or refuse the
note, never store a guessed value. Unchanged: plain `Label: value`
notes, explicit-`Class` precedence and conflict handling, binary-lane keyword
inference, the web route identity (origin and path, no query; `url` not stored),
and parsing before any storage is created.

## Implemented contract

- Short `Vulnerability:`, `Vulnerability class/type:`, and `Vuln class/type:`
  values supply the class only when there is no explicit `Class`. A trailing
  parenthetical such as `(CWE-79)` is dropped. A sentence (more than four tokens or
  other punctuation) raises `ClassConflictError` before any write.
- Web/api notes with no class label store `class_name=unknown`,
  `class_inferred=true`, and print a warning. They no longer use keyword
  inference, which picked source-hunt classes such as `dom-xss` or `path-traversal`.
  Binary lanes keep the documented inference.
- Severity strips `**` and backticks and accepts a leading level followed by a
  rationale (`High (CVSS 3.1: 7.1)`, `P2 - High`). Ambiguous values such as
  `Medium/High` or `Medium-High` stay `UNKNOWN` and print a warning.
- `File`, `Line`, and `Class` values drop wrapping bold, backticks, and angle
  brackets. On web/api lanes, the route comes from the one URL in `URL:`, then
  `Endpoint:`, then a URL-valued `Asset:`, so annotated or backticked URLs work.
  A bare-hostname `Asset` stays in the description and is not an identity. If
  there is no route, the "missing File" error tells the caller to add `File:` or
  `URL:`.
- Unlabelled file inference keeps leading-dot directories
  (`.webpack/renderer/preload.js`) instead of truncating them.
- `sync_reports` loose fallback: `FILE_HINT_RE` now has a trailing boundary, so
  `www.example.com` can no longer become `www.example.c`. This fallback receives
  every manual-hunter `ValueError`.

## Evidence and review

- Base reproduction (synthetic CLI ingest into a scratch `HOME`): ledger D01 had
  `class_name=dom-xss`, `class_inferred=true`, and `severity=UNKNOWN` for a note
  stating `**Vulnerability:** Reflected XSS` and `**Severity:** High (CVSS 3.1: 7.1)`.
  With backticks or annotations, the stored values were `` `src/app.js:12` `` with line 0, the class
  `` `reflected-xss` ``, and the route `https://…/search (in scope)`. The branch stores
  `reflected-xss`, `HIGH`, and the route `https://examplecloud.com/search`.
- Suites (`.venv` Python 3.11, `PYTHONPATH=<checkout>:<checkout>/agents:<bounty-core 9db8b23 worktree>`, scratch `HOME`):
  - manual_hunter (3 files) + sync_reports (2 files): base 135 passed / 71
    subtests; branch 144 passed / 91 subtests.
  - Related consumers (plus coverage_store, ledger_v2, me_ledger,
    report_source_cli, and the launcher/skill/papercut docs tests): base 221
    passed / 84 subtests / 14 failed; branch 230 passed / 104 subtests / 14 failed.
    The failures are the same on both, all in `agents/test_report_source_cli.py`
    (10 tests + 4 subtests): its `bbh` launcher needs a checkout-local `.venv`.
    With a temporary `.venv` symlink, both checkouts still fail the same 9 tests:
    `VersionedFindingsLedger` has no `import_finding`, because the shared `.venv`
    has Bounty Core `6c36ee88` installed, not the `9db8b23` pin. This is an
    environment limitation, not this change. Rerun from a checkout whose `.venv`
    is synced to `requirements.txt`.
  - The 9 new regressions fail on unchanged base (copied into a detached base worktree).
- `git diff --check` clean.
- Independent review: not run; assigned to the parent/operator.

## Blockers and deferred work

- **Kanban:** delegated child context cannot read or mutate the board
  (`kanban: delegate_task child contexts cannot mutate Kanban tasks or boards`);
  the parent owns card creation and closure.
- **`sync_reports` class inference:** `_normalize_candidate` still re-infers web
  classes with `_infer_class`, so the web `unknown` rule applies only to
  manual-hunter ingest. `_infer_class` substring matching (`rce` in `resource`) is
  recorded in `BUGFIXES.md`.
- **Activation:** none. Hoster runs beta `3f72ed81` until beta is merged and the
  Hoster checkout is fast-forwarded.

## Interruption / resume handoff

- **Exact resume point:** independent review of `243a97bd..fix/manual-hunter-markdown-parse`.
  Then a beta merge from a clean beta worktree, rerunning the listed suites, and
  removing this dossier from beta.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** reviewer acceptance plus green suites from the beta merge.
- **Activation / promotion:** not authorized.

## Decision record

- 2026-11-24: created from `origin/beta` `243a97bd`. The defect was reproduced on
  base, and the parser fix and regressions were committed.
