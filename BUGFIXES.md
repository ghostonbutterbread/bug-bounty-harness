# Known defects awaiting their own task

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
