# Known defects awaiting their own task

## Legacy unfenced task-proxy finish can affect a newer generation

**Location:** `skills/chromium-test/scripts/browser_provisioner.py`,
`finish_proxy` and the `task-proxy-finish`/`task-proxy-recover` parsers.
**Evidence:** independent offline review on receipt base `75515046` sent a
finish identified only by agent/run while a newer lane existed and observed
that newer lane finished. The compatible `--expected-lane` fence protects only
callers that retain and supply their original lane; legacy syntax still permits
the old behavior. An interrupted startup may leave no receipt for the caller.
**Impact and follow-up:** migrate remaining external clients to the lane fence;
consider a separately coordinated breaking change to require it. An operator
must establish ownership independently before recovering an unreceipted startup.

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

## ScopeManager does not load explicit exclusions — resolved

**Location:** `agents/scope_manager.py:17-27`, `_load_domains`, `_load_urls`,
and `is_in_scope`.

**Evidence:** initialization loads only allow domains/URLs and policy metadata;
its candidate scope filenames omit `out-of-scope.txt` and `excluded.txt`.
`is_in_scope` returns on allow matches without checking any exclusion collection.

**Impact:** an explicitly excluded host can still be accepted by ScopeManager
when it matches an allow. This is separate from ScopeValidator's annotation
parsing defect and is intentionally not fixed in that bounded parser task.

**Resolution:** ScopeManager now builds a ScopeValidator over the same canonical
and legacy roots and refuses any target `is_out_of_scope` reports, so exclusion
files, canonical-over-legacy precedence, annotations, wildcard/URL-path deny-wins
matching and invalid-exclusion deny-all are shared rather than reimplemented.
Allow files and the `domains`/`urls` attributes are unchanged. An unreadable
exclusion file now raises `ScopeExclusionReadError` at construction. Regression:
`tests/test_scope_gate_exclusions.py`.

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

## urlparse accepts a backslash-userinfo host that Go tooling rejects — resolved

**Location:** `agents/scope_validator.py` `_extract_host`, via `urlparse`.

**Evidence:** `https://login.epicgames.com\@api.epicgames.com` parses with
hostname `api.epicgames.com`, so scope says in-scope, while the visually
leading host is the explicitly excluded `login.epicgames.com`. Go-based tools
reject the backslash; browsers treat `\` as `/`. Pre-existing: reproduces
identically before the scope normalization change.

**Impact:** a parser differential between the scope gate and the tools it
gates. Not exploitable through the current corpus, but the gate should agree
with whatever actually issues the request. Needs its own task.

**Resolution:** ScopeValidator's `_extract_host` already refuses backslashes,
userinfo, percent escapes, control characters and malformed ports (`db9f27dc`).
ScopeManager kept its own `urlparse` copy with the same differential; it now
uses the shared `_extract_host`, as do the two checks in the next entry.
Regression: `tests/test_scope_gate_exclusions.py`.

## Suffix scope checks outside the subdomain agent use unparsed hosts — resolved

**Location:** `harness_core.py` `HarnessConstraints.is_in_scope` / `enforce`;
`agents/recon/asset_intelligence.py` `host_from_value` / `scope_matches`.

**Evidence:** found while auditing PC-20261030-002207-67d5e107 on beta
`3f72ed81` (the subdomain agent itself is fixed; see
`tests/test_subdomain_suffix_scope_matrix.py`). `HarnessConstraints` suffix-matches
`urlparse(url).netloc`, so `https://evil.test\.target.com/` is in scope for
`target.com`, while `requests`/urllib3 2.7 prepare it as
`https://evil.test/%5C.target.com/`. No in-repo `enforce()` caller was found
(docstring example only). `scope_matches('*.target.com', v)` splits non-URL
values only on `/` and `:`, so `evil.test?x=.target.com` and
`evil.test#.target.com` are labeled in-scope; that module sends no
per-candidate requests.

**Impact:** conditional. An external caller that gates `requests` traffic with
`enforce()` can reach another authority. Asset-graph records can carry a wrong
`in-scope` label. Fix each under its own task by reusing the parsed-host check
(`scope_validator._extract_host` / `subdomain_agent.is_target_host`).

**Resolution:** both use ScopeValidator's `_extract_host`/`_safe_host`.
`HarnessConstraints` keeps its contract (http(s) in any letter case, port
80/443, suffix match) and lets a scope-module import failure propagate instead
of denying silently. Asset labels read a bare value as an http authority, so
`host:port` keeps its label and `evil.test?x=.target.com` labels as
`evil.test`; an unparseable URL/host labels out-of-scope when exclusions exist.

The real fuzz caller was also ungated: `run_campaign.py run --agent fuzz` built
`FuzzAgent(campaign)` without a program, so `FuzzAgent.is_in_scope` returned
True and `HarnessConstraints` (campaign domain list, no exclusions) was the only
check; `in-scope.txt` `x.com` plus `out-of-scope.txt` `admin.x.com` let
`https://admin.x.com` through. Even with a program, only the target was checked:
wordlist entries such as `admin` reached ffuf under a `https://x.com/admin`
exclusion, and a target with `?query`/`#fragment` put `FUZZ` beside, not under,
an allowed path. `run_fuzz` now passes the campaign's recorded
`program_config.program` and refuses to run (exit 1, no requests) without a
valid one; `FuzzAgent` without a program raises; an empty saved scope raises
from `run()`. The program's ScopeValidator (allows and exclusions, path
exclusions case-insensitively) now checks the target and each concrete URL
handed to ffuf (`<target path>/<entry>`, query/fragment dropped), and
HarnessConstraints checks the target's domain. What ffuf does after sending a
URL (redirects) is not gated; see the ffuf redirect entry. A campaign without a
recorded program needs a new campaign (`init --campaign <new-id> --program
<program>`); `--force` on the old one resets its findings and fuzz state.
Regression: `tests/test_scope_gate_exclusions.py`.

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

**Additional isolated evidence:** on fetched `origin/beta` at `ffbf641c`,
`test_browser_transfer_source_end_uncertainty.py -k lost-end-unit-active`
reproduces `destination='disposed'` versus expected `cleanup-incomplete` using
baseline provisioner code loaded in memory. This synthetic test mocks
`unit_active` but not `unit_inactive`; `stop_recorded` checks `stopped()` via
`unit_inactive`, so a missing/inactive host unit can prove stopped despite the
mocked active state. Six analogous `unit-active` cases fail in this feature's
focused sweep. This is a separate deterministic fixture-model inconsistency,
not evidence that the new generic path disposed an active browser.

**Impact:** beta's suite health cannot be read as a signal while this cluster is
red, and a genuine regression in browser transfer would be masked by it. First
task is to run this cluster **with** a provisioned CDP browser and record whether
the failures persist; only then decide whether it is a code defect.

## Recon-Ry start-port suite fails after the portable-import test in one run

**Location:** `agents/test_portable_import_paths.py:31-42` and
`tests/test_recon_ry_start_ports.py:109`.

**Evidence:** the portable-import test pops `scope_validator` from
`sys.modules`; a later start-port test reads
`sys.modules[recon_ry.ScopeValidator.__module__]` and raises
`KeyError: 'scope_validator'`. Running both in one pytest session on beta
`3f72ed81` gives 264 start-port failures; the start-port file alone passes 608.

**Impact:** combined scope-suite receipts show 264 false failures that can mask
a real regression. Fix the test isolation (restore the popped module or resolve
the class's module without `sys.modules`) in its own task.

## HarnessConstraints never matches wildcard campaign scope entries

**Location:** `harness_core.py` `HarnessConstraints.is_in_scope`;
`program_config._load_in_scope_domains` feeds it `in-scope.txt` host lines.

**Evidence:** an entry such as `*.example.com` is compared as a literal host
or `.*.example.com` suffix, so it grants nothing; only bare-domain entries
grant subdomains. `agents/fuzz_runner.py` therefore raises `HarnessViolation`
for a wildcard-only target that ScopeValidator accepts (same on beta `3f72ed81`).

**Impact:** fails closed (lost fuzz coverage, not a scope escape). Decide
whether `*.` entries should grant subdomains before changing it.

## Asset-intelligence URL-path exclusions are bypassed by path spellings

**Location:** `agents/recon/asset_intelligence.py` `scope_matches` (URL-pattern
branch), used by `classify_scope`.

**Evidence:** with in-scope `*.x.test` and exclusion `https://x.test/admin`,
`https://x.test:443/admin`, `https://x.test//admin`, `https://x.test/%61dmin`,
`http://x.test/admin`, `https://x.test/admin;x` and bare `x.test/admin` are all
labeled `in-scope` (lexical prefix match on the raw string). ScopeValidator's
exclusion matching treats these as excluded.

**Impact:** labels only (the module sends no per-candidate requests), but
`target_intel` can rank an excluded path as in scope. Reuse ScopeValidator's
URL-pattern exclusion matching in its own task. Relatedly, exotic spellings of an
excluded host that are not URL/domain-shaped (e.g. bare `user@admin.x.test`)
label `unknown` rather than `out-of-scope`.

## ffuf redirect following is not scope-contained

**Location:** `agents/fuzz_runner.py` `_execute_ffuf` (`-r` when
`rate_limit_events > 0`).

**Evidence:** after any rate-limit event the fuzz agent passes `-r`, so ffuf
follows each response's redirects itself. Only the URLs BBH hands to ffuf are
scope-checked; a redirect from an in-scope URL to an excluded or third-party
destination is followed without a check.

**Impact:** request containment gap during rate-sensitive fuzzing. Drop `-r`
(record 3xx `Location` as a finding instead) or verify ffuf's redirect behavior
under a scope-enforcing proxy, in its own task.

## ScopeValidator accepts only lowercase http(s) schemes

**Location:** `agents/scope_validator.py` `_extract_host` (`startswith("http://")`).

**Evidence:** `HTTPS://api.example.com/` yields no host, so ScopeValidator,
ScopeManager and every consumer refuse it even when `api.example.com` is in
scope. HarnessConstraints and asset labels lowercase the scheme first.

**Impact:** fails closed (lost coverage for uppercase-scheme inputs, no escape).
Lowercase the scheme in `_extract_host` in its own task if those inputs matter.

## ScopeManager URL allows ignore the port

**Location:** `agents/scope_manager.py` `is_in_scope` (base-URL check).

**Evidence:** with allow `https://app.x.org`, ScopeManager accepts
`https://app.x.org:8443/` because the base URL is rebuilt from scheme and host
only; ScopeValidator refuses it (allows do not extend to another port).

**Impact:** the two gates disagree on allows. No production caller uses
`ScopeManager.is_in_scope` (`scripts/program_init.py` reads only
`domains`/`urls`), so this is latent.

## ScopeManager mixes canonical and legacy allow files

**Location:** `agents/scope_manager.py` `_load_domains` / `_load_urls` /
`_candidate_files`.

**Evidence:** ScopeManager unions allows from canonical and legacy
`in-scope.txt`/`domains.txt`/`scope.txt`; ScopeValidator uses only the first
present allow file. With canonical `in-scope.txt` plus legacy `domains.txt`
`legacy.x.io`, ScopeManager accepts `legacy.x.io` and ScopeValidator refuses it.

**Impact:** the gates can disagree on allows; latent, since no production caller
uses `ScopeManager.is_in_scope`. `program_init` recon seeds also include the
legacy allows. Decide whether ScopeManager should adopt ScopeValidator's
allow-file selection.
