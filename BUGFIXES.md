# Known defects awaiting their own task

## Resolved integration dossier triggers the documentation lane check

**Location:** `docs/integrations/broad-goal-map-reconciliation.md:24`.

**Evidence:** `test_skill_command_lane_safety` reports direct script invocation
examples in this retained integration dossier. The identical failure reproduces
on unchanged beta at `aa99c3e02e84f94ae8b9c6ec5626bea2abc11f8f` and on the
AI-action-guard feature branch.

**Impact:** the broad documentation lane check is not green independently of the
AI policy fix. The owning task should reconcile/remove its resolved dossier
under the branch lifecycle, then rerun that test. Not fixed in this policy slice.

## `agents/sync_reports.py` — FILE_HINT_RE matches an extension inside a longer word

**Location:** `agents/sync_reports.py:41` (its own copy of the pattern, independent of
`agents/manual_hunter.py`).

**Evidence:** the alternation includes bare `c`/`h`/`go`/`rs` with no trailing boundary, so
`www.example.com` matches as the path `www.example.c`:

```python
re.search(FILE_HINT_RE, "Asset: www.example.com")   # -> 'www.example.c'
```

**Impact:** a note whose only "path-shaped" text is a hostname gets a corrupted `file`
value instead of being rejected, and `file` feeds finding identity/dedup. Observed in
`manual_hunter` as finding D03 (superdrug), whose asset was stored as
`www.superdrugmobile.c`.

**Fix shape:** same one applied to `manual_hunter.FILE_HINT_RE` — append
`(?![A-Za-z0-9_])` after the extension group. Better still, share one pattern between the
two modules rather than keeping duplicate copies.

**Not fixed here** because it is outside the manual_hunter ingest-parser fix scope.

## Runtime dependency test expects a different Bounty Core revision

**Location:** `tests/test_runtime_dependencies.py:18` and
`requirements-bounty-core.txt:2`.

**Evidence:** the focused test expects Bounty Core
`f3d02453f26a4e221632466c26742dfb55368f28`, while the runtime manifest pins
`1bba64b557aa3b604092b5bad47689fcb40cc0f7`. The failure reproduces on unchanged
beta `5ef9b5b304fa3ce995e3700d32f3e7d4789539ee`.

**Impact:** the complete `tests/` suite remains red independently of the Hoster
script-authority guidance. The owning dependency task must decide which reviewed
revision is canonical and update the test or manifest coherently.
