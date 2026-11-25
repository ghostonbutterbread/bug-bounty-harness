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

## Same-run second browser cannot reuse its own task proxy under a new purpose

**Location:** `skills/chromium-test/scripts/browser_provisioner.py`
`start_proxy` (reuse check comparing `(account, purpose)`).
**Evidence:** Hoster 2026-11-24, run `bunny-pinterest-runtime-20261124T030000Z`:
after releasing browser 1, a `request --task-owned --recover-profile` for the
same agent/run but a different `--purpose` returned `proxy-conflict` "task
listener unavailable or belongs to another request"; the still-running lane
had the first request's purpose. The agent had to `task-proxy-finish` and
re-request, losing the shared capture continuity.
**Impact:** the fixed detail does not say *which* field differs, and an exact
purpose string is an unexpectedly strict ownership key within one agent/run.
Decide in the proxy-lifecycle owner's task whether purpose should be part of
the reuse key; at minimum report a fixed `reason` category.

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

## `agents/sync_reports.py` — FILE_HINT_RE matches an extension inside a longer word — resolved

**Resolution:** branch `fix/manual-hunter-markdown-parse` appends the trailing
`(?![A-Za-z0-9_])` boundary and adds
`TestLooseFallbackFileHint` (hostname note returns no loose finding; dotted
directories and `jquery.min.js`-style stems still resolve). This matters because
`_flexible_findings_for_file` sends any manual-hunter `ValueError` (for example
"missing File") to `_loose_markdown_fallback`. The patterns stay separate: the
manual-hunter pattern rejects dotted file stems to avoid matching hostnames,
which would drop the loose importer's existing `vendor/jquery.min.js` support.
A hostname with a source-like TLD (`example.py`) can still match the loose
pattern. **Identity change:** the old pattern stopped at the first matching
extension. Plain names (`config.json`, `index.html`, `main.cpp`) were already
resolved by manual_hunter's own pattern first, but multi-dot names reaching the
loose fallback (for example `vendor/app.config.json` stored as
`vendor/app.config.js`) get the full name, and so a new ledger identity, on
their next re-sync. Reconcile any duplicate by FID; do not hand-edit the ledger.

**Location:** `agents/sync_reports.py:52` (its own copy of the pattern, independent of
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

Originally deferred from the first manual_hunter ingest-parser fix.

## `manual_hunter.FILE_HINT_RE` truncates leading-dot directories

**Location:** `agents/manual_hunter.py` `FILE_HINT_RE` (unlabelled file inference
in `parse_finding_text`, shared by manual ingest and `sync_reports`).
**Evidence:** "Observed in .webpack/renderer/preload.js:4" infers
`renderer/preload.js`. The `(?<![\w.-])` lookbehind rejects a match starting at
`.webpack`, so the match starts at the next segment.
**Impact:** an unlabelled dotted path gets a truncated `file` identity. A fix
(`(?:\.?[\w-]+/)*`) changes identity for already-imported raw reports on
re-sync, so it needs its own compatibility decision. It was taken out of the
manual-hunter Markdown parse fix for that reason.

## `manual_hunter.FIELD_URL_RE` drops parenthesised paths and IPv6 hosts

**Location:** `agents/manual_hunter.py` `FIELD_URL_RE` / `_declared_url`
(manual-note URL, Endpoint, and Asset values).
**Evidence:** the token class excludes `()[]`, so
`https://host/wiki/A_(b)` is cut to `https://host/wiki/A_`, and
`http://[::1]:8080/x` yields no URL.
**Impact:** such a declared route is stored truncated or refused as "missing
File". Parentheses were excluded so that `(in scope)` annotations and Markdown
links are dropped; a fix must keep those cases.

## `_infer_class` matches keyword tokens inside longer words

**Location:** `agents/manual_hunter.py` `_infer_class` (also used by
`agents/sync_reports.py` `_loose_markdown_fallback` and `_normalize_candidate`).
**Evidence:** tokens are plain substrings, so `"rce"` matches `source`,
`resource`, and `force`; `"shell"` matches `PowerShell`. A note with no class token
except "the API returns another user's resource" infers `exec-sink-reachability`.
**Impact:** binary-lane manual notes and every sync_reports import without an
explicit class can store a specific wrong class (still flagged `class_inferred`
by manual_hunter). Web/api manual notes no longer use keyword inference. A fix
needs word boundaries for acronyms while keeping identifier prefixes such as
`readFileSync`.

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

## Further pre-existing browser/task-proxy suite failures on beta `3f72ed81`

**Location:** `agents/test_browser_selection.py` (15),
`agents/test_browser_resources.py` (10), `agents/test_cdp_handoff_receipt.py` (1),
`agents/test_task_proxy_mount_selection.py` (1), `tests/test_task_proxy_incident.py`
(9), `tests/test_task_proxy_incident_fence.py` (3),
`tests/test_task_proxy_incident_process.py` (12).

**Evidence:** an unchanged detached `origin/beta` 3f72ed81 worktree, run per
module with the BBH `.venv` and a short scratch `--basetemp` (longer basetemps
add `AF_UNIX path too long` failures), produced exactly these failures; the
`fix/browser-leak-swap-admission` branch produced the identical failing test
IDs. Several selection/resources cases receive `status: profile-unavailable`
from `require_safe_running_profile` where the test expects selection or
`driving-mode-mismatch`; others fail with `PipeBrowser` lacking
`meaningful_count`. Cause not separated (fixture drift vs. environment).

**Impact:** these modules cannot currently gate browser changes by an
unfiltered green run; compare failing IDs against the base instead. Repair in a
separate task on the owning branch.

## Malformed `ledger.json` is silently replaced by an empty ledger on write — resolved

**Resolution:** Bounty Core beta `5f5a66ac` (merge `c943ad3`, reviewed) makes every ledger read fail closed with `LedgerReadError` on unreadable, malformed or unsupported-schema storage before any write, preserving the bytes; BBH now pins that revision.

**Location:** Bounty Core `bounty_core/ledger.py` `_read_payload` /
`_locked_payload` (pinned revision `9db8b23d`), reached from every exclusive
writer: `patch_finding_by_fid` (`manual_hunter.py --edit-finding`,
`--set-submission`), `import_finding`, `ledger_add`, team reservations.
**Evidence:** on synthetic storage, a truncated `ledger.json` followed by one
`patch_finding_by_fid` call returned `None` and rewrote the file as
`{"version": 2, ..., "findings": []}`. `_read_payload` maps a JSON decode error
to the default payload and `_locked_payload` writes it back atomically.
**Impact:** one Board edit on a partially synced or corrupted ledger erases every
finding in that lane. `manual_hunter.py --delete-finding` checks the raw file
under the lock and fails closed (`agents/ledger_tombstones.py`), but the other
writers do not. Fix in Bounty Core (raise on an unparseable existing ledger),
then bump the BBH pin; tracked separately from the ledger-delete feature.

## Bounty Core appends `findings.jsonl` rows outside the ledger lock

**Location:** Bounty Core `bounty_core/ledger.py` `add_finding`, EVIDENCE_ONLY
branch (`ledger.py:1831-1832` at pin `9db8b23d`): `_append_jsonl_event` runs
after `_locked_payload` has been released.
**Evidence:** reviewer repro `e.py` (section B), on synthetic storage. A row
appended during `manual_hunter --delete-finding` was dropped by the sidecar
rewrite before the rewrite started re-reading the file just ahead of
`os.replace`.
**Impact:** BBH now re-plans from the file's current bytes immediately before
the replace (`agents/ledger_tombstones.py` `_apply_sidecar_scrub`), which leaves
only a sub-millisecond read-to-rename window. A row appended in that window
can still be lost. Fix upstream by appending under the ledger lock; there are
no BBH callers of this path today.

## Bounty Core storage normalizers accept `.` and `..` program/lane names

**Location:** Bounty Core `bounty_core/storage.py` `normalize_program` and
`normalize_lane` (pinned `9db8b23`), reached through `resolve_storage` and BBH's
`agents.storage_resolver` / `agents.attempts.resolve_attempts_path`.
**Evidence:** both normalizers keep `.` in their allowed set, so
`normalize_program("..") == normalize_lane(" .. ") == ".."`. In a disposable
root, `resolve_storage("..", lane="web", create=True)` scaffolded
`<root>/web/{reports,ledgers,context,...}` and `<root>/shared` beside
`web_bounty/`; `resolve_storage("example", lane="..", create=True)` scaffolded
lane directories directly inside `web_bounty/example/`.
**Impact:** any BBH caller passing an unchecked program or lane can scaffold or
write outside the program tree (for example `~/Shared/shared`). The
`scripts/append_attempt.py` CLI now rejects empty, `.`, `..`, and path-like
values before resolving, but other callers remain exposed. Repair in Bounty Core
(reject dot-segment names in both normalizers) with a BBH pin bump; do not
patch around it per caller.

## `append_attempt` counts null required fields as present

**Location:** `agents/attempts.py`, `append_attempt` required-field check.
**Evidence:** `str(None).strip()` is `"None"`, so `{"tool": None, ...}` passes the
BBH check; Bounty Core then rejects the alias with
`event missing required fields: producer`, naming the Core field rather than
the BBH one. Non-string values such as `5` or `[]` pass both checks and are
stored. The shell CLI rejects null and non-string required fields itself.
**Impact:** Python callers get a confusing error for null fields and can store
non-string required fields (schema drift). Decide in a separate task whether
the library should require nonempty strings for the five fields.

## Dormant-split navigation assertion expects a bare-FID packet link

**Location:** `agents/test_dormant_split.py:586`,
`TestSharedDormantSubtierPreservation.test_promotion_and_reporting_preserve_dormant_subtier_labels`.
**Evidence:** fails identically on unchanged beta `0821e438` and on
`fix/ledger-write-hot-path` with Bounty Core at the requirements pin `9db8b23d`.
The test asserts `D01/EVIDENCE|D01]]`, but the reserved packet is
`D01-<title-slug>/` and the navigation link is
`[[../../D01-dormant-active-dom-sink/EVIDENCE|D01]]`.
**Impact:** one red test in the ledger-adjacent suites. Update the assertion to
match the titled packet in a separate bounded task. Do not change packet naming
to satisfy it.

## MapStore consumers do not follow supersede chains

**Location:** `agents/hypothesis_ledger.py` `_public_lead`; Application Behavior
`observation_paths` in `agents/map_store.py` (`write_behavior`, `query_behaviors`).
**Evidence:** found in review of `fix/mapstore-update-in-place`. A titled MapStore
re-write archives the prior entry with `superseded_by`. `_public_lead` resolves an
exact lead path including archived entries and returns the superseded card
without its successor. Behavior records keep the archived path in
`observation_paths`; only `behavior show` displays the forward link.
**Impact:** a follow-up or behavior lookup can start from superseded evidence.
In a separate task, decide whether these consumers should resolve or surface
`superseded_by` (for example a warning naming the current path), without
rewriting stored IDs implicitly.
