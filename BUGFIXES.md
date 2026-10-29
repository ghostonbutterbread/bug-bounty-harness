# Known defects awaiting their own task

## Stack-to-program script index and upload assertion drift

**Location:** `skills/stack-to-program/scripts/README.md:11`, its script record,
and `tests/test_upload_surface_skill.py:34`.

**Evidence:** unchanged beta `2f5a204` reproduces the command-lane check's
rejection of a direct checkout invocation, the script-index check's missing
`**Outputs:**` / `**Mutates:**` fields, and the upload test's obsolete
`Before even a baseline upload` expectation (the skill says `Before a baseline
upload`). Deserialization-depth focused checks do not touch those paths.

**Impact:** three documentation/contract assertions prevent an unfiltered green
`tests/` run. Repair under their owners in a separate bounded task; do not
weaken the lane or script-index checks to release an unrelated skill change.

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

## Recon-Ry scope-filter and containment limitations

**Location:** `agents/recon_ry.py`, `start_remote` and `queue_remote`.

**Evidence:** The cached `origin/master` source at immutable
`7c2194a1eff3a100e53a90a9302980441f5f10e0` stages host scope files for
`start` when `--allow-unscoped` is not set and usable allow lines exist; it adds
the out-scope argument only when deny lines exist. `queue` does not stage these
files. The separate local `master` at `b046e03a0105a218db5effaeab23c19e3e37a26d`
lacks start scope-file arguments. These are local refs, not a fresh remote check.

**Impact:** filters and seed checks are not request-level containment; redirects,
browser subresources and nested tools can contact unauthorized destinations.
Queue's host-oriented behavior does not establish exclusion enforcement.
Separately verify request containment before active use. Reconcile affected
branches deliberately; do not describe host filters as a full egress fix.

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

## Browser transfer/fixture suites fail en masse; cause not yet separated

**Location:** `agents/test_browser_transfer_begin_uncertainty.py` (28),
`test_browser_transfer_activation_boundary.py` (28),
`test_browser_transfer_source_end_uncertainty.py` (24),
`test_browser_fixture_promotion_ticket.py` (21),
`test_browser_fixture_peer_generation.py` (11),
`test_browser_auth_site_contract.py` (10),
`test_browser_transfer_end_uncertainty.py` (4) — **126 failures**.

**Evidence:** a full `pytest agents/` sweep on beta `d196c1c` reported 150 failed /
1987 passed / 30 skipped; this cluster is 126 of the 150. Failures are assertion-
shaped rather than permission-shaped — `assert [] == ['source']` and
`DID NOT RAISE CancelledError` at
`test_browser_transfer_begin_uncertainty.py:101,103` — so they are **not** the
`/tmp` proxy-store fence recorded above. Pre-existing: unrelated to the XSS
sink-inventory change, which touches only `agents/js_analyzer.py` and
`agents/xss_sink_sites.py` and whose only coupled suites pass fully.

**Cause is ambiguous and should be separated before any repair.** Either the
transfer/fixture subsystem is genuinely broken, or these suites require a
browser/CDP environment the sweep did not provide. Counter-evidence for the
"genuinely broken" reading: on 2026-10-05/06 several live runs provisioned browser
leases successfully on this same checkout — cleared Fastly challenges, solved an
image CAPTCHA, read mounted asset lists, and released leases verifying
`state: stopped` with CDP unreachable. So the runtime lease path demonstrably
works even while these suites fail.

**Impact:** beta's suite health cannot be read as a signal while this cluster is
red, and a genuine regression in browser transfer would be masked by it. First
task is to run this cluster **with** a provisioned CDP browser and record whether
the failures persist; only then decide whether it is a code defect.
