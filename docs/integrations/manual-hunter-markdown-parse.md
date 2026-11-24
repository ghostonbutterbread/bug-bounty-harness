# Manual-hunter Markdown note parsing integration dossier

- **Status:** review-ready (review loop 1 corrections applied)
- **Owner:** Hermes delegated implementation
- **Branch / owning ref:** `fix/manual-hunter-markdown-parse`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-manual-hunter-markdown`
- **Base commit:** `243a97bd52d970eb7d22cebcbd5f34baaf33f83e` (`origin/beta`; unchanged at the review-loop fetch)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Implementation commits:** `4430d289` (initial), then the review-loop commit that follows it on this branch (review range `243a97bd..fix/manual-hunter-markdown-parse`)
- **Inspiration / canonical references:** papercut `PC-20260825-225142-bf0e203f`; BUGFIXES entry on the `sync_reports` `FILE_HINT_RE` defect

## Intent

Manual note ingest (`--from-file`, watch, `--add`, interactive) must read
report-style Markdown notes (a heading followed by `**Label:** value` lines) with
the correct class, route identity, and severity. If it cannot determine a value,
it must leave it `unknown` or refuse the note, never store a guessed value.

Unchanged:
- `sync_reports` parsing: it calls the shared parser with `manual_note` off, so
  a raw report re-syncs under the identity it was stored with. The only sync
  change is the loose-fallback `FILE_HINT_RE` boundary.
- Explicit `Class` precedence and conflict handling.
- Binary-lane keyword inference.
- Web routes from `URL`/`Endpoint`/`File` (origin and path, no query; `url` not
  stored).
- Parsing happens before any storage is created.

## Implemented contract

`parse_finding_text(manual_note=True)` is passed by every manual-hunter ingest
entry point (`_explicit_class(report_labels=True)` for class). With it on:

- **Class from labels:** a short `Vulnerability:`, `Vulnerability class/type:`, or
  `Vuln class/type:` value supplies the class only when there is no explicit
  `Class`. A trailing `(CWE-79)` is dropped. `N/A`, `TBD`, `Unknown`, `none`,
  and `-` count as absent. A sentence (more than four tokens or other
  punctuation) raises `ClassConflictError` before any write.
- **Unclassified web notes:** web/api notes with no class store
  `class_name=unknown` and `class_inferred=true`, and print a warning. They no
  longer get a keyword guess. Binary lanes keep inference.
- **Severity:** `**` and backticks are stripped, and a leading level followed by
  a rationale is accepted (`High (CVSS 3.1: 7.1)`, `P2 - High`). Values naming two
  levels (`Medium/High`, `Medium-High`, `High | Medium`, `High - Medium`) stay
  `UNKNOWN` with a warning.
- **Markup:** `File`, `Line`, and `Class` values drop wrapping bold, backticks,
  and angle brackets.
- **Web identity is not the same as base:**
  - `URL:` and `Endpoint:` values now yield the one URL they contain, so
    annotated, backticked, or `<…>` URLs give a clean route.
  - An `Asset:` URL is used only when the note has no `URL`/`Endpoint`/`File`
    (checked before unlabelled file inference), and only when it has a non-root
    path without `*`.
  - A hostname, site origin, or wildcard Asset is never a route. A path-only
    Endpoint beside an origin Asset is refused as on base; it is not composed.
- **Missing fields:** "missing File/Description/Source" raises
  `MissingNoteFieldError` (a `ValueError` subclass, so sync's loose fallback
  still receives it). `python -m agents.manual_hunter` prints it as one
  `[manual_hunter] …` line and exits 1, like `ClassConflictError`.
- **sync_reports loose fallback:** `FILE_HINT_RE` now has a trailing boundary,
  so `www.example.com` can no longer become `www.example.c`. This changes
  identity for names that were truncated before (`config.json`, `index.html`,
  `main.cpp`); see BUGFIXES.

Removed after review: the leading-dot directory change to
`manual_hunter.FILE_HINT_RE`. That pattern is shared with sync, so the change
would re-key raw reports. It is now an open BUGFIXES entry.

## Evidence and review

- Base reproduction (synthetic CLI ingest into a scratch `HOME`): ledger D01 had
  `class_name=dom-xss`, `class_inferred=true`, and `severity=UNKNOWN` for a note
  stating `**Vulnerability:** Reflected XSS` and `**Severity:** High (CVSS 3.1: 7.1)`.
  The branch stores `reflected-xss`, `HIGH`, and route `https://examplecloud.com/search`.
- **Review loop 1 BLOCK (independent review of `4430d289`):**
  - B1: an Asset URL outranked File/Endpoint and collapsed routes onto `/`.
  - B2: class-label handling leaked into `sync_reports`, re-keying raw reports
    and failing sync on sentence labels.
  - Both are fixed. The new regressions are
    `test_explicit_route_file_wins_over_origin_asset`,
    `test_explicit_source_file_wins_over_asset_url`,
    `test_path_only_endpoint_with_origin_asset_is_refused`,
    `test_resync_keeps_base_class_identity_for_manual_note_labels`, and
    `test_sentence_vulnerability_label_does_not_fail_sync`. They fail on
    `4430d289` and pass on base `243a97bd` and the branch.
  - Nit regressions: `test_placeholder_vulnerability_is_absent_not_a_class`,
    `test_two_named_severity_levels_stay_unknown`, and
    `test_direct_cli_missing_file_is_one_line_without_traceback`.
- Suites (`.venv` Python 3.11, `PYTHONPATH=<checkout>:<checkout>/agents:<bounty-core 9db8b23 worktree>`, scratch `HOME`):
  - manual_hunter (3 files) + sync_reports (2 files): base 135 passed / 71
    subtests; branch 151 passed / 102 subtests.
  - Related consumers (plus coverage_store, ledger_v2, me_ledger,
    report_source_cli, and the launcher/skill/papercut docs tests): base 221
    passed / 84 subtests / 14 failed; branch 237 passed / 115 subtests / 14 failed.
    The FAILED and SUBFAILED sets are identical (apart from temp paths), all in
    `agents/test_report_source_cli.py`. Its `bbh` launcher needs a checkout-local
    `.venv`, and the shared `.venv` has Bounty Core `6c36ee88` installed, not the
    `9db8b23` pin. This is an environment limitation. Rerun from a checkout whose
    `.venv` is synced to `requirements.txt`.
- `git diff --check` clean.

## Blockers and deferred work

- **Cross-version re-sync smoke not run:** syncing synthetic raw reports with the
  base code and then the branch code into one scratch ledger. An approval gate
  timed out on the command, so it was not retried. The unit regressions above
  cover the class identity; file and route identity are unchanged by
  construction because `manual_note` is off for sync. Trigger: before the beta
  merge, run `resync_cross.py`-style base→branch syncs on scratch storage and
  require an equal row count.
- **Kanban:** delegated child context cannot read or mutate the board; the
  parent owns card creation and closure.
- **Open BUGFIXES entries:** `_infer_class` substring matching,
  `FILE_HINT_RE` leading-dot truncation, and `FIELD_URL_RE` parentheses/IPv6.
- **Activation:** none. Hoster runs beta `3f72ed81` until beta is merged and the
  Hoster checkout is fast-forwarded.

## Interruption / resume handoff

- **Exact resume point:** re-review the review-loop commit (range
  `4430d289..fix/manual-hunter-markdown-parse`), run the deferred cross-version
  re-sync smoke, then merge into beta from a clean beta worktree, rerun the
  suites, and remove this dossier from beta.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** reviewer acceptance of the corrections plus green suites
  from the beta merge.
- **Activation / promotion:** not authorized.

## Decision record

- 2026-11-24: created from `origin/beta` `243a97bd`; the defect was reproduced on
  base, and the parser fix and regressions were committed (`4430d289`).
- 2026-11-24: independent review returned BLOCK (B1 Asset precedence, B2 sync
  leak, and nits). Corrections were committed on the same branch, with no beta
  movement to merge.
