# JavaScript source-map discovery and Wayback recovery

- **Status:** implemented locally; independent release gate pending; not integrated
- **Owner / task:** Hermes / t_9b4400cf
- **Branch / owning feature ref:** fix/js-source-map-discovery-wayback
- **Worktree:** /home/ryushe/projects/bug_bounty_harness/.worktrees/t_9b4400cf
- **Base commit:** 73d83c730cef6343e0c61d5d0ddcc70a416490d3
- **Intended integration target:** beta (origin/beta), never stable in this task
- **Last updated:** 2026-10-22 (PDT)
- **Latest immutable recovery checkpoint:** pending initial implementation commit; a subsequent dossier-only commit will record its verified SHA
- **Feature implementation commits:** pending initial implementation commit
- **Inspiration:** Discord thread 1563053963534930045; authorized patch message 1563055701704843277. Parent checked ECMA-426 section 11 and the official wayback-cdx-server README. These are protocol references, not program-testing authority.
- **Successor:** parent-owned js-playbook/js-pull documentation update and a fresh independent release reviewer on this feature ref. This temporary dossier must not remain on beta after accepted integration.

## Defect and implementation

The previous lexer sliced the last 3,000 characters and reset lexical state. A cut inside a long quote hid a real trailing declaration; a cut inside a string, regex or template could admit decoys. Parent observed 117 affected URL records in a retained inventory; this implementation did not access or mutate that private corpus.

`agents/js_analyzer.py` now scans the already-loaded body linearly from its known initial lexical context, preserves last actual-comment selection and legacy `@` directives, and tracks nested template frames conservatively. Existing else/control-regex regressions remain intact. This is not a complete ECMAScript parser and does not adopt other new extraction semantics.

Response `SourceMap` takes precedence over legacy `X-SourceMap`, then comments. Invalid or external authoritative headers do not silently select a comment instead. Relative declarations resolve against the original generated-code URL. URL-specific ledger entries retain the selected response-header value and name across cached JS reuse, including identical bytes at different URLs.

The public fetch tuple arities/unpacking/equality remain compatible. `HttpResult`, a tuple subclass, adds only selected map-header metadata and a stable transport reason; it does not retain response cookies/authentication headers. `http_get_limited` adds the explicit `include_program_headers=False` call path used by archive requests. HTTP error bodies are discarded; exceptions are categorized without logging raw error strings.

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

Existing timeout/delay and source-map module/packet/expanded-byte limits also apply to historical acquisition/materialization. Per-response limits can each consume one oversize-probe byte; that byte is reserved inside the total budget. `bytes_read` conservatively charges an oversize probe even when Content-Length permits rejecting without reading it. `--skip-cached-processing` retains its existing meaning: skipped assets have no processing, archive recovery, or new metadata. `--refresh` bypasses successful historical cache reuse as well as existing live caches.

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

## Recovery / review

Before stopping, commit exactly the implementation, its directly associated test module, and this branch-local dossier. Follow with a dossier-only commit naming the immutable implementation SHA. Resume at the parent-owned independent release gate, reconciling the exact candidate diff against this contract and the two base-reproduced unrelated documentation failures. Integration, clean-beta preflight, push and activation are not authorized to this child.
