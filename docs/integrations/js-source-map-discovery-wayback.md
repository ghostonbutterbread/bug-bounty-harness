# JavaScript source-map discovery and Wayback recovery

- **Status:** four release blockers repaired and locally exercised; fresh independent release review pending; not integrated
- **Owner / task:** Hermes / t_9b4400cf
- **Branch / owning feature ref:** fix/js-source-map-discovery-wayback
- **Worktree:** /home/ryushe/projects/bug_bounty_harness/.worktrees/t_9b4400cf
- **Base commit:** 73d83c730cef6343e0c61d5d0ddcc70a416490d3
- **Intended integration target:** beta (origin/beta), never stable in this task
- **Last updated:** 2026-10-22 (PDT)
- **Latest immutable recovery checkpoint:** d61afe41070c5f41ed6c9d7ed90355d266401866 (implementation plus parent corrections, guidance and verified receipts)
- **Feature implementation commits:** 62e0420635b666c7b919fc9121bb85290b348d8a and d61afe41070c5f41ed6c9d7ed90355d266401866; current branch tip includes a later dossier-only handoff commit
- **Inspiration:** Discord thread 1563053963534930045; authorized patch message 1563055701704843277. Parent checked ECMA-426 section 11 and the official wayback-cdx-server README. These are protocol references, not program-testing authority.
- **Successor:** fresh independent release review of the corrected checkpoint and current-beta compatibility. Parent guidance and initial edge-case corrections are included in d61afe41070c5f41ed6c9d7ed90355d266401866. This temporary dossier must not remain on beta after any later accepted integration.

## Defect and implementation

The previous lexer sliced the last 3,000 characters and reset lexical state. A cut inside a long quote hid a real trailing declaration; a cut inside a string, regex or template could admit decoys. Parent observed 117 affected URL records in a retained inventory; this implementation did not access or mutate that private corpus.

`agents/js_analyzer.py` now scans the already-loaded body linearly from its known initial lexical context, preserves last actual-comment selection and legacy `@` directives, and tracks nested template frames conservatively. Existing else/control-regex regressions remain intact. This is not a complete ECMAScript parser and does not adopt other new extraction semantics.

Response `SourceMap` takes precedence over legacy `X-SourceMap`, then comments. Invalid or external authoritative headers do not silently select a comment instead. Relative declarations resolve against the original generated-code URL. URL-specific ledger entries retain the selected response-header value and name across cached JS reuse, including identical bytes at different URLs.

The public fetch tuple arities/unpacking/equality remain compatible. `HttpResult`, a tuple subclass, adds selected map-header metadata, a stable transport reason and payload-read budget accounting; it does not retain response cookies/authentication headers. `http_get_limited` adds the explicit `include_program_headers=False` call path used by archive requests. HTTP error bodies are discarded; exceptions are categorized without logging raw error strings.

Source-map module budgets now check projected chunk count, module count and expanded bytes *before* allocating chunk lists. Names remain inventoried when packet/materialization budgets prevent extraction.

## Exact CLI contract for parent-owned documentation

Existing `--source-maps auto|off` remains `auto` by default. New inventory flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--source-map-wayback off|auto` | `off` | Explicit archive opt-in; `auto` attempts historical recovery only if a live map was not downloaded/cached. Disabled by `--source-maps off`. Original asset URLs are disclosed to Internet Archive only after opt-in. |
| `--source-map-wayback-max-requests` | `20` | Run-wide archive request budget, including CDX and snapshots. Zero disables acquisition through the budget. |
| `--source-map-wayback-max-captures` | `2` | Maximum exact CDX rows per asset lookup; reject a response exceeding the requested limit. Not exhaustive and not a latest-capture guarantee. |
| `--source-map-wayback-max-bytes` | `8388608` | Per-response archive byte cap. CDX has an additional 256 KiB cap; maps also obey `--source-map-max-bytes`. |
| `--source-map-wayback-max-total-bytes` | `33554432` | Run-wide archive transfer budget, including oversize probes. |

Existing timeout/delay and source-map module/packet/expanded-byte limits also apply to historical acquisition/materialization. Per-response limits can each consume one oversize-probe byte; that byte is reserved inside the total budget. `bytes_read` counts returned payloads plus consumed probes; Content-Length rejection before a payload read charges zero. Any failed read with uncertain consumption conservatively charges its whole permitted read (including incomplete chunked responses); partial bytes are never accepted as an artifact. `--skip-cached-processing` retains its existing meaning: skipped assets have no processing, archive recovery, or new metadata. `--refresh` bypasses successful historical cache reuse as well as existing live caches.

Archive lookup checks the exact missing declared map URL first, then selected archived snapshots of the exact original bundle URL to recover other declarations. It never performs domain-wide discovery. CDX uses `matchType=exact`, `output=json`, `fl=timestamp,original,statuscode,digest`, `filter=statuscode:200`, and a bounded `limit`. Every returned row must have the exact original URL, status 200, a valid 14-digit calendar timestamp and a base32 digest (or the documented missing-digest marker). Replay URLs are constructed only from the validated timestamp and the previously scoped original, never from a returned arbitrary URL.

Original bundle and map URLs must be HTTP(S), in the explicit target/page-derived scope, and lack userinfo, wildcard characters, whitespace and inline fragments. With no scope hosts, archive queries are refused. Archive requests send only their own User-Agent/Accept; no `EXTRA_HTTP_HEADERS`, cookies, bearer/attribution headers or custom Host. Default urllib TLS verification and environment proxy handlers stay enabled. Redirects remain disabled for both live maps and archive acquisitions. HTTP 429 stops all further archive network attempts for that run. Other failures are bounded and retained; failed retrievals and indexes are not blindly retried within the run. HTTP 503 is recorded, not retried at the same retrieval URL, but is not a global stop condition.

## Metadata and cache contract

New live-map fields on each metadata record:

- `source_map_discovery`: `SourceMap`, `X-SourceMap`, `comment`, or empty.
- `source_map_reason`: `ok`, `http_<status>` (including 404/429/redirect statuses), `tls`, `timeout`, `transport`, `invalid`, `oversize`, `out_of_scope`, `disabled`, `invalid_declaration`, or `not_detected`.
- `source_map_http_status`: observed live map status, or null when unavailable/not fetched (also null on cached map reuse).

Existing `source_map_status` values remain usable (`downloaded`, `cached`, `fetch_failed`, `invalid`, `too_large`, `external_not_fetched`, `disabled`, `not_detected`). Historical recovery never turns these into a claim of current source-map success.

`source_map_history` is a separate per-record result:

- `status`: `disabled`, `not_needed`, `not_recovered`, `recovered`, or `cached`; `reason` distinguishes failure/budget/empty-index/invalid-index outcomes.
- `historical: true`, `original_bundle_url`, `current_bundle_sha256` (empty when live bytes unavailable), `archived_bundle_sha256` (empty for map-only recovery), `current_bundle_match_verified`.
- Successful recovery: `original_map_url`, `map_archive_timestamp`, `map_retrieval_url`, `map_sha256`, `map_artifact_path`; for archived-JS recovery also `bundle_archive_timestamp`, `bundle_retrieval_url`, `bundle_artifact_path`.
- `module_count`, `modules_with_content`, `embedded_source_recovered`, `packet_count` distinguish names-only maps from embedded originals and packet output. Lowered cache caps clear recovery/packet counters for that run.
- `attempts`: bounded acquisition diagnostics with operation, retrieval URL, reason and HTTP status; reused failures/indexes are explicitly marked. No raw errors or response error bodies.

Map-only recovery is always unverified against the current bundle. Exact archived JS SHA256 equality can verify only archived-vs-current *bundle bytes*. Neither a matching basename, a map's existence, nor even identical JS bytes proves map-to-build correspondence. Rendered historical packets explicitly state this distinction, include a HISTORICAL banner, capture/retrieval identity, and warn when current-byte binding is unverified.

`source_map_modules.jsonl` rows carry `historical` and `source_map_history`. Historical packet rows use `artifact_kind: historical_source_map_module` plus those fields. Names-only maps retain source names with `has_content: false`, `packet_status: no_content`, no packets and `embedded_source_recovered: false`.

Content-addressed map bytes use the existing sourcemaps directory; archived JS bytes live beneath its `historical_bundles` subdirectory. Only successful historical results are cached, under `ledger.historical_source_maps`, keyed by original bundle URL/current-byte hash/live declaration. Archived maps are **never** inserted in `ledger.source_maps` under the live map URL. Cached map bytes are bounded, hash-checked and validated before reuse. Unavailable/error live bundle responses are not added to the live URL cache. Historical packet paths are separated from live packet paths.

Manifest additions: `source_map_wayback` (`mode`, `requests`, `bytes_read`, `stopped_reason`, `max_requests`, `max_captures`, `max_bytes`, `max_total_bytes`); `historical_source_maps_recovered`, `historical_source_maps_reused`, `historical_source_map_packets`. Existing live-map counters exclude historical successes; the combined module inventory and total packet inventory include clearly labelled historical rows.

## RED → GREEN receipts

All commands ran in this isolated worktree with the worktree first on `PYTHONPATH`. Initial lexer run used system Python; after parent provisioned the task-local environment, all subsequent/final tests used `.venv/bin/python`.

The task environment's installed bounty-core direct_url commit was independently read back as `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, matching requirements.txt. No dependency manifests changed. The parent provisioned ignored `.venv`/config.env; neither is staged.

Vertical test-first slices in `agents/test_js_analyzer_wayback.py`:

| Slice / selector | Observed RED | Observed GREEN |
| --- | --- | --- |
| Initial cutoff + long decoys (8 cases) | 7 failed, 1 passed in 0.11s | Together with existing JS suite: 230 passed in 25.42s |
| `-k header` | 4 failed in 3.29s | 4 passed, 8 deselected in 3.37s |
| `-k 'diagnostics or wrapped'` | 10 failed, 12 deselected in 4.94s | Accumulated 22 passed in 7.89s |
| `-k archived_bundle` (first historical tracer) | 1 failed (missing CLI), 22 deselected in 0.24s | 1 passed, 22 deselected in 0.72s |
| `-k 'exact_missing or exact_archived'` | 3 failed, 23 deselected in 0.98s | Accumulated 26 passed in 16.13s |
| `-k 'nested_template or unavailable_live'` | 3 failed, 26 deselected in 0.14s | 3 passed, 26 deselected in 0.93s |
| `-k 'archived_map_failure or expansion_budgets or archive_transport'` | 1 failed, 8 passed, 56 deselected in 5.49s (stale lowered-cap packet count) | Included in focused green below |
| `-k 'not_retried or expansion_budgets'` | 1 failed, 1 passed, 64 deselected in 1.90s (duplicate failed TLS map fetch) | Accumulated focused suites: 288 passed in 56.15s |
| `-k 'incomplete or honors or never_enables'` | 1 failed, 3 passed, 66 deselected in 3.21s (IncompleteRead escaped) | Included in final focused green below |
| `-k before_chunk_allocation` | 3 failed, 70 deselected in 0.42s | Included in final focused green below |

Primary defect RED was also re-exercised on a scratch `git archive` export of the exact unchanged base implementation, overlaying only the final test module: selector `arbitrary_old_tail_boundary or long_lexical_decoys_do_not_override_comment` returned **7 failed, 1 passed, 65 deselected in 0.23s**. The final test file and reachable base make that reproduction recoverable without the transient scratch export.

Final focused command: `PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short --show-capture=no` → **295 passed in 61.25s**. This includes all 222 original tests and 73 added offline cases.

Related command: `PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_offline_campaign.py agents/test_xss_sink_sites.py agents/test_xss_source_sites.py agents/test_xss_source_integration.py tests/test_bbh_launcher.py tests/test_runtime_dependencies.py tests/test_production_path_safety.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py -q --tb=short --show-capture=no` → **221 passed in 3.38s**.

An earlier unfiltered broader combination, additionally including `tests/test_skill_command_lane_safety.py` and `tests/test_script_policy.py`, returned **538 passed, 2 failed in 68.09s** before the final three budget-allocation cases. These are not claimed as an all-green broad suite. Exact failures:

1. `tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly`: existing direct-checkout command in the stack-to-program README.
2. `tests/test_script_policy.py::test_each_skill_index_has_complete_nonstale_records`: same README lacks Outputs/Mutates fields.

Both exact node IDs were rerun with the same task interpreter against an unchanged `git archive` base export and returned **2 failed in 0.17s**, with identical offending README evidence. No exclusions were used in the unfiltered combination. These unrelated documentation failures are left untouched per assigned ownership. The parent/reviewer owns their release disposition.

Final unfiltered broader command: `PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py agents/test_js_offline_campaign.py agents/test_xss_sink_sites.py agents/test_xss_source_sites.py agents/test_xss_source_integration.py tests/test_bbh_launcher.py tests/test_runtime_dependencies.py tests/test_skill_command_lane_safety.py tests/test_production_path_safety.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py tests/test_script_policy.py -q --tb=short --show-capture=no` → **541 passed, 2 failed in 67.54s**. This ran after all implementation/test edits and the initial dossier contract; its only failures are the same two exact node IDs reproduced on unchanged base above. No exclusions or deselections were used. This is not an unfiltered green suite.

`git diff --check` passed. Implementation source-root and pinned dependency identity were verified. The immutable candidate checkpoint is recorded in the recovery section after the implementation commit.

## Boundaries and residual evidence

- No program requests, real Wayback requests, credentials, private corpus writes, Hoster changes or runtime activation occurred. HTTP fixtures intercepted all acquisitions in new tests.
- Live archive availability and actual recovery for the parent's retained inventory remain unverified. Parent previously observed archive rate limiting; this patch does not claim archived maps exist for that program. A separately authorized live smoke is the trigger for that deferred evidence.
- Archive discovery is capped exact-asset fallback, not exhaustive crawling or a latest-capture guarantee; first usable historical map per bundle is returned. Maps without sourcesContent cannot recover original text.
- New tests cover credential stripping, default TLS/environment proxy retention, disabled redirects, strict CDX rows, failure categories, run budgets, 429 global stop, failed-request non-retry, successful history/cache reuse, no-content maps, source and packet limits and lowered-cap cache behavior.
- The lexer is deliberately conservative for template contents and retains existing regex-disambiguation heuristics; it is not an ECMAScript parser or a proof of complete source-map coverage.
- Upstream beta advanced after the assigned immutable base; no rebase/merge was attempted. Parent must preflight the exact implementation against current beta and obtain the separately dispatched independent release verdict.
- Parent owns user-facing prompts/js-playbook.md and skills/js-pull/SKILL.md documentation. No prompt/skill/policy/dependency/unrelated source was edited here. No nested reviewer, Kanban lifecycle write, merge, push or deployment was performed.

## Parent reconciliation and candidate gate

Parent independently reran the builder checkpoint's focused suites: **295 passed in 67.90s**. Parent then added the user-facing archive invocation, defaults, failure interpretation and historical-evidence qualifications to `skills/js-pull/SKILL.md` and `prompts/js-playbook.md`.

Two concrete edge cases were corrected before independent release review:

- A valid empty CDX JSON array (`[]`) is now `empty_index`, not `invalid_index`.
- Original URLs containing userinfo are rejected even when the username is empty (password-only or empty-userinfo authority). This prevents accidental URL-credential disclosure in archive queries.

The parent added three parameter cases to the existing offline tests and observed **3 failed, 14 passed, 59 deselected in 11.16s**, specifically the diagnostic mismatch and two unexpected archive calls. After the minimal owning-boundary fixes, the same selector `archive_index_failures or archive_original_scope` returned **17 passed, 59 deselected in 8.27s**.

The exact unfiltered broader command from the builder receipt, rerun after all parent code/test/guidance edits, returned **544 passed, 2 failed in 75.57s**. Parent independently reproduced both exact failing node IDs on an unchanged `git archive` of base `73d83c730cef6343e0c61d5d0ddcc70a416490d3` with the same pinned interpreter: **2 failed in 0.17s**. The two stack-to-program README defects are already recorded under `BUGFIXES.md` and are out of scope; no test was excluded, weakened, or relabelled as green. Independent release review must verify this disposition and reject new failures.

An offline, read-only check ran the candidate's exact detector definition against the retained Krisp records previously marked `not_detected`: **199 inspected; 117 now detected; 82 still undetected**. It made no requests to the program, no artifact writes and no runtime changes. This proves declaration recovery, not that the referenced maps are retrievable or archived. No private source bytes were committed.

Current fetched `origin/beta` at reconciliation was `f98f538`, with unrelated script-routing changes since the feature base. No source conflict or integration is implied; the release owner must fetch again and preflight the actual candidate against current clean beta.

## Recovery / review

Implementation checkpoint `62e0420635b666c7b919fc9121bb85290b348d8a` contains the initial implementation, directly associated test module and dossier. Subsequent parent code/test/guidance corrections are recorded in a coherent feature commit, followed by a dossier-only immutable checkpoint update. Reconcile both implementation and guidance against the actual feature tip.

Resume after the blocked independent review below: parent repairs the four owning boundaries with regression coverage, then requests a fresh independent review. Never promote stable or activate Hoster. The parent retains Kanban completion and exact external-state readback responsibility.

## Independent release gate — BLOCKED (superseded candidate; repair receipts below)

### Exact candidate and execution identity

- Reviewed feature tip: `4c24552a04decefab3701b71885cc3363070e80f`; reviewed feature tree: `b349d8656eb4636640e08acbbbf9389659b36347`.
- Implementation/guidance checkpoint: `d61afe41070c5f41ed6c9d7ed90355d266401866`; its tree is `0c669be5e024ffdafc9be0a8c3bc2cb3bdfa588f`. The subsequent candidate commit changes only this dossier.
- Source import resolves to this feature's `agents/js_analyzer.py`; interpreter is this feature's `.venv/bin/python`. Installed bounty-core direct_url revision is `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, exactly the requirement pin. No root/shared interpreter was used.
- Fresh `git fetch origin beta` succeeded; `origin/beta` is `f98f538344a4c0673b48052b519c87446bc605d1`. Owning root integration checkout remains local beta `73d83c730cef6343e0c61d5d0ddcc70a416490d3`, without tracked modifications. Its unrelated nested worktree directories were not touched.
- Substantive blockers stop acceptance before beta preflight: beta compatibility is **not established**, no beta fast-forward/merge, push, activation, Kanban write, or retirement was performed.

### Independently rerun supplied checks

The exact unfiltered broader command recorded above returned **544 passed, 2 failed in 70.52s**, with no exclusions. Both failures are the same exact stack-to-program README nodes listed above. The same pinned interpreter reran those two nodes from `/home/ryushe/.hermes/cache/scratch/js-map-review-base-73d83c7`: **2 failed in 0.15s**, with identical failure text. `git hash-object` of the baseline export's analyzer, both test modules, and offending README exactly matches their `git ls-tree` blobs at the immutable base. The export is not a Git checkout; attempted Git status commands there were inapplicable, and baseline identity was checked with repository object hashes instead. These are verified baseline-only failures, not a green broad suite. `git diff --check 73d83c7..4c24552` passed.

Additional independent offline regression probes are saved at `/home/ryushe/.hermes/cache/scratch/test_js_map_release_review.py`. From this feature worktree:

```bash
PYTHONPATH="$PWD" .venv/bin/python -m pytest /home/ryushe/.hermes/cache/scratch/test_js_map_release_review.py -q -s --tb=short
```

Final result: **4 failed in 1.97s**. All acquisition is intercepted; there are no real program/archive calls. An initial lexer probe used duplicate `let` declarations, was rejected by `node --check`, and was corrected to repeated `var` declarations before recording the real lexer finding. No invalid fixture is counted as product evidence.

### Required parent repairs and focused regressions

1. **Historical cache retains a false current-bundle binding after a failed live fetch** — `WaybackRecovery.cache_key/recover`, approximately lines 1042–1073. The key includes URL/body hash/declaration but not successful-current-response availability, and reuse copies the old entire history. Offline two-run fixture: first serve HTTP 200 `b'const current = true;'`, replay identical archived JS with `SourceMap: app.js.map`, and return a valid archived map. Remove only the first run's live download CAS file to force the next live fetch while keeping history. Then return HTTP 403 with those same body bytes. The second record has status 403 but cached history still has a nonempty `current_bundle_sha256`, `current_bundle_match_verified: true`, and its rendered packet says `Archived bundle matches current bytes (SHA256 verified).` No archive request is made on reuse. Recompute all current-binding fields from the current record's valid live-byte availability when reusing history (and/or distinguish successful current bytes from error-body hashes in the key); an error body must not prove current-source equality. Preserve usable archived evidence but mark current binding unverified. Regression must assert the failed-current status clears the current hash and verified flag, including rendered packet wording.

2. **Unavailable current bundles are synthesized into ordinary live artifacts/packets and download counts** — `command_inventory`, approximately lines 2328–2345, 2424–2439, 2561–2579, 2627. With archive mode enabled, an empty failed live fetch now continues into SHA256(empty), writes a zero-byte `.js` download, chunks it, emits an ordinary non-historical packet, and increments `js_downloaded` via `len(records)`. A timeout plus successful archived recovery yielded `status: null`, `byte_count: 0`, `js_downloaded: 1`, one ordinary live packet plus one historical packet, and an existing empty live artifact. The nested history correctly leaves current hash empty, but the ordinary inventory contradicts that qualification. Gate live hashing/materialization/chunking/counting on real usable current bytes; retain a separate unavailable-current metadata record so archive fallback can still work. Regression must assert zero live downloads/packets for unavailable-current recovery and no fake current CAS artifact; do not suppress historical packets or poison the live URL ledger.

3. **Whole-body lexer introduces a genuine detection regression on postfix division** — `last_source_map_directive`, approximately lines 801–818, 838–844. Reproducer text is `'let x=4, y=2; x++ / y;\n' + 'var a=1;\n' * 500 + '//# sourceMappingURL=real.map\n'`. `node --check` returns 0. Extracting and executing the exact baseline detector definition returns `real.map`; the candidate returns an empty declaration. The two plus tokens incorrectly allow a regex at the following division slash, and the scan consumes the real trailing directive. Starting at the full body makes the formerly irrelevant early construct swallow the tail. Correct postfix expression context without reverting to an arbitrary tail cut; add decrement/member-division cases as appropriate and retain quote/template/regex decoy regressions. This is concrete valid JavaScript lost relative to base, not a request for a complete ECMAScript parser.

4. **Partial archive reads bypass the new run-wide byte budget** — `http_get_limited` exception handling, approximately lines 594–602, and `WaybackRecovery.fetch` line 973. A native `http.client.HTTPResponse` over an in-memory fake socket receives a valid chunked response containing one complete eight-byte chunk, then EOF before the next chunk size. Its read raises `IncompleteRead` with eight partial bytes; the handler discards those bytes and returns an empty transport failure, which is charged as zero. With total cap 10, two distinct fetch URLs each read eight payload bytes: 16 observed, `bytes_read: 0`, `requests: 2`, read sizes `[10, 10]`. Preserve/count consumed partial bytes separately from artifact validity, or conservatively reserve the permitted read amount on uncertain failed reads; keep the failure category and never accept incomplete bytes as a map. Regression must prove total transfer accounting bounds these failures as well as successful/oversized responses. The existing incomplete-read test checks only non-crashing diagnostics and misses budget accounting.

No implementation, tests, prompts, skills, dependencies, or unrelated files were changed by the reviewer. Only this branch-local dossier is updated for a recoverable blocked handoff. Parent should port the scratch probes into `agents/test_js_analyzer_wayback.py`, repair these four defects, rerun the exact broad command plus the new cases, and obtain a **fresh** independent verdict before any current-beta preflight/integration. The scratch source is convenient but the fixture contracts and observed outputs above are the durable recovery record. No acceptance is implied for unexercised live archive availability or external CDX behavior.

## Parent repair of independent review blockers

All four probes are now maintained in `agents/test_js_analyzer_wayback.py`, with additional unavailable-current, cached-binding and prefix/member/decrement/division variants. The pre-repair selector `unavailable_bundle_has_no or rechecks_current_binding or never_trusts_old_current or postfix_division or partial_archive_reads or uncertain_failed_archive` returned **11 failed, 3 passed, 76 deselected** on the blocked implementation. Unchanged positive variants were not counted as new defects.

Owning-boundary repairs:

- Cache reuse derives `current_bundle_sha256` and `current_bundle_match_verified` from the present successful current retrieval, never from an earlier cached claim.
- Unavailable current bytes retain status/history metadata with blank live hash/path and zero byte/chunk counts. They create no live CAS artifact, chunk set, packet, URL alias or SQLite live-file entry. Historical packets retain the archived bundle hash. `js_downloaded` counts real live artifacts; additive `js_unavailable` counts unavailable-current records processed for fallback. Console output says unavailable, not downloaded.
- `++`/`--` preserve prefix/postfix operand context, so valid postfix division cannot swallow the real declaration. Full-body scanning and existing decoy protections remain.
- `HttpResult.bytes_read` reports payload accounting independently of artifact validity without changing tuple unpacking. Failed reads conservatively charge the whole allowed read because streams may consume more than their exposed partial exception bytes. Native chunked EOF and timeout regressions prove the run cannot issue another full-budget read after consuming its total reservation; incomplete artifacts remain rejected.

Vertical checks after the owning repairs: cached-binding **2 passed**; lexical/directive/decoy subset **31 passed**; read-failure/budget subset **6 passed**; combined maintained review selector **14 passed, 76 deselected in 3.15s**.

Full focused JS suites plus the reviewer's exact original scratch probes, from this feature with its pinned interpreter: `PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py /home/ryushe/.hermes/cache/scratch/test_js_map_release_review.py -q --tb=short --show-capture=no` → **316 passed in 65.70s**. The maintained cases and fixture contracts above do not depend on retaining that scratch file.

The exact unfiltered broader command already recorded above returned **558 passed, 2 failed in 71.10s**. Both failures remain the exact two baseline README nodes, not feature regressions. Parent independently reran them from the unchanged baseline export with this task interpreter: **2 failed in 0.14s**, identical output. No exclusions, skips or weakened assertions were used. The existing `BUGFIXES.md` records these unrelated defects; they remain outside this task. This is not an unfiltered green suite.

`prompts/js-playbook.md` now explains unavailable-current metadata/counts and conservative payload charging. No real archive/program requests, corpus mutations, Hoster/runtime changes or integration occurred. Next: commit the corrected implementation and dossier, pin its immutable checkpoint, then a fresh independent release owner must review the full feature, independently rerun checks, fetch/current-beta preflight and integrate only if accepted. The previous blocked verdict is not approval for these corrections.
