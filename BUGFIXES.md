# Known defects awaiting their own task

## Legacy report-layout assertions fail against stable FID packets

**Location:** two tests in `agents/test_sync_reports.py`, one in `agents/test_base_team_ledger_writes.py`, one in `agents/test_base_team_review.py`.
**Evidence:** all four expect `reports/findings/...` while the canonical writer now uses `reports/<FID>/REPORT.md`; they fail identically on unchanged BBH beta when tested with the same installed Bounty Core revision.
**Impact:** related reporting suites remain red despite a working FID packet. Update the tests to assert canonical paths in a separate bounded task; do not revive legacy duplicate report files.

## ScopeManager does not load explicit exclusions

**Location:** `agents/scope_manager.py:17-27`, `_load_domains`, `_load_urls`,
and `is_in_scope`.

**Evidence:** initialization loads only allow domains/URLs and policy metadata;
its candidate scope filenames omit `out-of-scope.txt` and `excluded.txt`.
`is_in_scope` returns on allow matches without checking any exclusion collection.

**Impact:** an explicitly excluded host can still be accepted by ScopeManager
when it matches an allow. This is separate from ScopeValidator's annotation
parsing defect and is intentionally not fixed in that bounded parser task.

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

## Runtime dependency test expects a different Bounty Core revision — resolved

**Location:** `tests/test_runtime_dependencies.py:18` and
the former split runtime manifest (now `requirements.txt`).

**Evidence:** the focused test expects Bounty Core
`f3d02453f26a4e221632466c26742dfb55368f28`, while the runtime manifest pins
`1bba64b557aa3b604092b5bad47689fcb40cc0f7`. The failure reproduces on unchanged
beta `5ef9b5b304fa3ce995e3700d32f3e7d4789539ee`.

**Resolution:** single-manifest packaging preserves the existing manifest's
`1bba64b557aa3b604092b5bad47689fcb40cc0f7` pin and updates the regression to assert
the complete preserved dependency set. No Bounty Core upgrade or downgrade is
part of this fix.

## `master` recon-ry wrapper does not pass `--scope-file`

**Location:** `agents/recon_ry.py`, `start_remote`, on the `master` branch.

**Evidence:** `origin/master` and `origin/beta` have diverged (master is not an
ancestor of beta; beta is 323 commits ahead), and both carried the same gap:
the wrapper derived `urls.txt`/`wild.txt` seeds from saved scope but never
passed `--scope-file`/`--out-scope-file` to recon-ry. The beta copy is fixed;
master is untouched because the branches are not in an ancestor relationship
and beta is the active lane.

**Impact:** a `master`-lane recon-ry launch runs without scope containment, so
tool input, crawler reach and promoted artifacts are unfiltered. Backport the
beta fix if the master lane is used for recon.

## urlparse accepts a backslash-userinfo host that Go tooling rejects

**Location:** `agents/scope_validator.py` `_extract_host`, via `urlparse`.

**Evidence:** `https://login.epicgames.com\@api.epicgames.com` parses with
hostname `api.epicgames.com`, so scope says in-scope, while the visually
leading host is the explicitly excluded `login.epicgames.com`. Go-based tools
reject the backslash; browsers treat `\` as `/`. Pre-existing: reproduces
identically before the scope normalization change.

**Impact:** a parser differential between the scope gate and the tools it
gates. Not exploitable through the current corpus, but the gate should agree
with whatever actually issues the request. Needs its own task.

## Proxy-store private-ancestor fence can never pass under `/tmp`

**Location:** `skills/chromium-test/scripts/proxy_store.py:60-78`,
`_open_private_parent`.

**Evidence:** the loop reads each ancestor's mode *before* descending, and raises
`PermissionError: Proxy store ancestor is group/world writable` when
`mode & 0o022` and `private_fence` is still unset. `/` is `0755` so it does not
set the fence (`mode & 0o011` is nonzero); the next component is `/tmp` at
`1777`, which trips the check. The `0700` directory that would set the fence
(e.g. `/tmp/pytest-of-ryushe`) is deeper and never reached. Confirmed by reading
the traversal and by `stat /tmp` = `1777`. Introduced by `5fbb569` / `a0717c4`;
reproduces on unchanged beta, independent of the XSS sink-inventory fix.

**Impact:** `agents/test_proxy_store.py` fails against pytest's own basetemp, and
**any real run whose proxy store resolves under `/tmp` is blocked**, however
private the store directory itself is. The default store at
`~/.local/share/ghost/proxy-store/` is unaffected. Needs its own task: either set
the fence from a later `0700` component or evaluate the final directory rather
than failing on the first world-writable ancestor.

## Canonical findings file not written where sync_reports asserts

**Location:** `agents/test_sync_reports.py:787`; writer under the manual
finding-tiers path.

**Evidence:** import reports success (`ADDED D01`, `Imported: 1 new findings`)
but `canonical_reports` is empty, so the canonical findings `.md` is absent from
the asserted location. Reproduces on unchanged beta; distinct from the legacy
report-layout assertions already recorded above, which are path-expectation
failures rather than a missing write.

**Impact:** a successful-looking import can leave no canonical report on disk,
so a finding may be silently unrecoverable from the reports tree. Needs its own
task on the owning branch.
