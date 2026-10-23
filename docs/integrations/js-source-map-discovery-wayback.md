# JavaScript source-map discovery and Wayback recovery

- **Status:** Content-Length completion blocker repaired with bounded draining and maintained decoder regressions; locally verified, fresh independent release review pending. Not integrated or activated.
- **Owner / task:** Hermes / t_9b4400cf
- **Feature:** fix/js-source-map-discovery-wayback
- **Worktree:** /home/ryushe/projects/bug_bounty_harness/.worktrees/t_9b4400cf
- **Base commit:** 73d83c730cef6343e0c61d5d0ddcc70a416490d3
- **Intended target:** beta (origin/beta), never main/stable in this task
- **Last updated:** 2026-10-23 (PDT)
- **Latest immutable implementation checkpoint:** e1d3e20035e3509ccc7a3c8b1a4003008c1dd3f4 (bounded parser, completion-aware transport, all prior acquisition/provenance repairs, maintained tests and guidance); the current feature tip contains a later dossier-only handoff update.
- **Historical full handoff:** a7edf58211e1524da9be336a6432ee5bf01ea051:docs/integrations/js-source-map-discovery-wayback.md. This reachable dossier-only commit preserves all previous implementation/review receipts; historical no-new-dependency and handwritten-lexer descriptions are superseded below.
- **Authority / inspiration:** Discord thread 1563053963534930045; explicit patch authorization 1563055701704843277. Repair existing JS acquisition, not a new hunting path. Protocol references checked earlier were ECMA-426 section 11 and the official wayback-cdx-server README, not testing authority.

## Defect and current owning implementation

The baseline cut the last 3,000 characters and reset lexical context. A cut inside a long string could hide a real trailing declaration or admit a decoy. Whole-body handwritten scanning repaired that cutoff but independent valid-JavaScript cases exposed deeper keyword/member, postfix/division and statement/declaration brace errors. The current correction removes those handwritten grammar heuristics rather than adding more exceptions.

`last_source_map_directive` now uses pinned Tree-sitter JavaScript comment nodes over the whole candidate-bearing source. A cursor visits nodes in source order without materializing all captures; complete template subtrees remain conservatively excluded. Last actual-comment selection and legacy `@` declarations are preserved. Bundles without the literal marker need no AST. This parses syntax; it does not execute JavaScript, validate a build or verify map-to-build association. The selected grammar and its recovery behavior do not promise support for all future syntax.

Response `SourceMap` takes precedence over legacy `X-SourceMap`, then comments. Header declarations bypass comment parsing entirely, including its budget and dependency availability. Invalid/external authoritative headers never silently fall back to a comment. Relative declarations resolve against the original generated-code URL. Selected header value/name remain cached per URL, including aliases sharing identical bytes.

### Parser dependency, resource and failure contract

- Root `requirements.txt` adds exactly `tree-sitter==0.26.0` and `tree-sitter-javascript==0.25.0`; the single-manifest/runtime contract test is updated. No Node production dependency or alternate downloader is introduced.
- Provision the selected checkout with `bash setup.sh --install-python-deps` before relying on its environment. This exact installer completed in the feature; resolved parser versions and bounty-core direct_url pin `6c36ee88a60073e1b687ec32deeade24ffafdd4f` were read back. Source imports resolve beneath this feature worktree, using its `.venv/bin/python`.
- `--source-map-parse-max-bytes` defaults to **8 MiB of UTF-8 bundle input** for live and archived comment scans. Positive values only, checked before path/I/O setup. This deliberately bounds AST input, not live-download size, RSS or wall time. Raise it only for a selected bundle with available memory. Headers bypass it; no-marker bundles need no parsing.
- An omitted/failed scan is `source_map_status: scan_failed`, with `source_map_reason` of `parse_limit`, `parser_unavailable` or `parser_memory`. It is never relabelled `not_detected`, and there is no fallback to the known-broken handwritten scanner. Missing dependencies name the real installer in the diagnostic. Collection of usable current JS can still complete with this explicit map-coverage gap.
- Manifest `source_map_parse_max_bytes` records the cap and `source_map_scans_failed` counts incomplete live scans. Archived declaration attempts preserve the same failure categories in `source_map_history`.
- Existing map/module/packet/expanded-source limits remain independent. Module expansion checks happen before chunk-list allocation; names stay inventoried when content/packet budgets omit work.

## Live retrieval, historical fallback and evidence

Public fetch tuple arities remain compatible. `HttpResult` sidecars retain only the selected map header, stable failure category and payload-budget accounting, not authentication/cookie headers. HTTP/TLS/timeout/transport/invalid/oversize failures remain distinguishable; map response status is retained when observed.

`--source-maps auto|off` remains default `auto`. `--source-map-wayback off|auto` is **off by default**; `--source-maps off` also prevents archive requests. Opt-in discloses original scoped asset URLs to Internet Archive. Fallback first checks the exact missing declared map URL, then selected archived captures of the exact bundle, resolving declarations against the original bundle rather than the archive wrapper. It is not domain-wide discovery or a latest-capture guarantee.

Archive defaults are 20 requests/run, two captures/lookup, 8 MiB/response and 32 MiB total; CDX additionally has a 256 KiB cap. Existing timeout/delay and map limits apply. Request/capture/response/total overrides are the matching `--source-map-wayback-max-*` flags. CDX uses exact original-URL matching, JSON timestamp/original/statuscode/digest fields, status-200 filtering and bounded results. Returned originals, real calendar timestamps and digests are validated before constructing replay URLs. HTTP 429 stops all remaining archive network attempts; other failures are bounded and recorded, not blindly retried at the same URL in the run.

Original URLs must be scoped HTTP(S) and lack userinfo (including empty usernames), wildcards, whitespace and inline identities. No scope hosts means no archive lookup. Archive requests use only their own User-Agent/Accept, no program headers/cookies/custom Host; default TLS verification and environment proxy transport stay intact. Redirects remain disabled. Content-Length rejection before payload reading charges zero; successful reads and oversize probe bytes count. Failed reads with uncertain progress conservatively reserve their entire permitted read, never accepting incomplete bytes as an artifact. Content-Length-framed responses must deliver the declared body; a short EOF is `transport`, discards the partial payload and charges its known consumed bytes. Bounded draining preserves valid short reads and close-delimited bodies; native chunked framing takes precedence over an irrelevant Content-Length header. The total-byte counter is charged payload accounting, not a claim of exact wire traffic.

Historical results use a separate cache, `source_map_history`, original/retrieval URLs, capture timestamps and hashes, historical counters and rendered **HISTORICAL** banners. Map-only recovery never claims a current-byte binding. Equal archived/current bundle hashes prove those bytes, not map-to-build association. Cache reuse recomputes current-binding fields from the present successful current retrieval instead of copying an old verified claim. Names without `sourcesContent` are not recovered original source text.

Unavailable current retrieval retains status/history metadata with blank live hash/path and zero live bytes/chunks. It creates no fake empty live artifact, ordinary packet, live URL alias or live-file SQLite row. Historical packets use the archived bundle hash. `js_downloaded` counts actual current artifacts; `js_unavailable` counts unavailable-current records processed for fallback. Source-map diagnostics and historical counts remain distinct from live success. `--skip-cached-processing` still skips processing/recovery; `--refresh` bypasses live and successful historical cache reuse.

## Recoverable test and review evidence

Initial implementation checkpoints are `62e0420635b666c7b919fc9121bb85290b348d8a`, `d61afe41070c5f41ed6c9d7ed90355d266401866`, `e259847b055d2eed6537ec038ea8925bac4b180b` and `c8b48440f7ff92cb0076b7949fe69380b36cd641`. Historical independent blocked verdicts are reachable in dossier-only commits `d07318676e427c47583db6e35bbc9ee427fc9260`, `c8d31bcf819da27d210984baa59620e8690ff80a` and `a7edf58211e1524da9be336a6432ee5bf01ea051`. Their exact candidate/tree/reproducer contracts remain in Git history; none is approval for the current correction.

All previous blocker contracts are maintained: stale history binding after failed current fetch, fake live artifacts on unavailable retrieval, postfix/division, partial read accounting, member keywords and statement/declaration contexts. The third review's optional-catch, labelled-block and exported declaration cases, plus export-default-class and ASI controls, were ported before replacement: **7 failed, 19 passed, 255 deselected in 0.30s**. The parser prototype then passed **510 focused/prior-probe tests in 69.89s** before production integration. New budget/dependency/error consumers initially returned **5 failed, 2 passed, 281 deselected in 0.78s**; after repair and additional dependency/positive-limit variants the selected contract tests returned **10 passed, 283 deselected in 3.45s**. Node syntax checks pass for all 26 maintained block/expression variants (including module exports); Node is only a verification convenience, not a production or maintained-suite prerequisite.

Unfiltered broader command (parser-checkpoint receipt; latest transport correction below):

```bash
PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py agents/test_js_offline_campaign.py agents/test_xss_sink_sites.py agents/test_xss_source_sites.py agents/test_xss_source_integration.py tests/test_bbh_launcher.py tests/test_runtime_dependencies.py tests/test_skill_command_lane_safety.py tests/test_production_path_safety.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py tests/test_script_policy.py -q --tb=short --show-capture=no
```

**759 passed, 2 failed in 75.09s.** No exclusions or weakened assertions. Both failures are independently reproduced on the unchanged hash-verified base, already recorded in `BUGFIXES.md`:

1. `tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly` — existing direct-checkout command in the stack-to-program README.
2. `tests/test_script_policy.py::test_each_skill_index_has_complete_nonstale_records` — the same README lacks Outputs/Mutates.

This is baseline-only disposition, **not an unfiltered green suite**. The unchanged base export is `/home/ryushe/.hermes/cache/scratch/js-map-review-base-73d83c7`; it is not a Git checkout. Compare its bytes with base blobs from the real repository, and use the same pinned interpreter with base source first on PYTHONPATH. All three reviewers independently reproduced the exact failures (latest **2 failed in 0.14s**); no unrelated README repair is folded into this task.

The initial parser checkpoint's three original reviewer suites run together: **15 passed in 2.18s**. Optional scratch conveniences are `test_js_map_release_review.py`, `test_js_map_corrected_release_review.py` and `test_js_map_third_release_review.py` under the scratch root. Maintained cases and historical fixture contracts remain recoverable without scratch. `git diff --check` and actual CLI `inventory --help` passed.

### Bounded synthetic resource receipt

The real detector (not a substituted response) parsed an 8,388,608-byte source consisting of repeated `var x = 1;` lines and the final real declaration: **real.map, 3.3741 s, 629424 KiB peak RSS**. A 1,048,572-byte comment-dense source returned **real.map, 0.1028 s, 52220 KiB peak RSS**. Each ran in a separate offline process under a **benchmark-only** 1,073,741,824-byte address-space limit. This is an observed synthetic receipt, not a worst-case RSS guarantee, latency requirement or production sandbox.

Optional executable receipt: `/home/ryushe/.hermes/cache/scratch/js_map_parser_resource_check.py`. If pruned, reconstruct either source with a `//# sourceMappingURL=real.map` footer, repeat `var x = 1;\n` up to the default cap or `// padding\n` up to 1 MiB, and call the real detector in a separately address-space-limited process. Raising the parser cap is the trigger to repeat resource measurement before broad use.

## Release / activation boundary and exact next action

No real program/archive requests, private corpus mutations, beta changes, pushes or Hoster/runtime activation occurred. Package provisioning affected only the owned task environment. Actual Wayback availability and private-corpus map recovery remain unverified; a separately authorized scoped live smoke is required to establish that evidence. Earlier private-corpus detector counts concern an older heuristic checkpoint, not a new claim for this parser.

Current resume point: immutable implementation `e1d3e20035e3509ccc7a3c8b1a4003008c1dd3f4` plus the later dossier-only feature tip. All fourth-gate transport regressions have repair receipts below. Obtain a fresh independent release verdict before beta compatibility/integration. The old candidate `d300b610c770a1ebfab1a3583d917bb6639cd96e` remains historically BLOCKED; that verdict does not approve the corrected code. `origin/beta` was fetched again as `f98f538344a4c0673b48052b519c87446bc605d1`; the root integration checkout remains local beta `73d83c730cef6343e0c61d5d0ddcc70a416490d3`, with no tracked edits and unrelated untracked nested checkouts preserved. No beta preflight or integration mutation was attempted because feature acceptance failed.

Only if accepted, follow the normal clean/current-beta preflight, remove this temporary dossier from the target, verify staged tree/checks, then perform the intentional beta-only merge and `git push origin beta` from beta's integration worktree. No helper lane, HEAD:beta, force push or main promotion. Material code conflict resolution needs its own independent review; do not nest a reviewer. Record final verdict and residual live evidence on the feature before accepted integration. The parent retains remote readback, Kanban closure and clean contained feature cleanup. Runtime/skill activation remains a separate explicit decision; provision the selected runtime's root manifest and verify actual source/env before any later activation.

## Fourth independent gate — historical BLOCKED candidate

Candidate `d300b610c770a1ebfab1a3583d917bb6639cd96e` / tree `345a375e61758c38d4fe7019c4f259b9ce0443b3` passed the exercised parser contracts but accepted premature Content-Length EOF as complete map/bundle bytes. The independent real-HTTP-decoder reproducer returned **3 failed, 1 passed**. Full original fixture, candidate checks, all 910 baseline-export blob verification and known baseline failure disposition remain reachable in `59054611ab7c9511671f9df4e2af9cfe604a5bcf:docs/integrations/js-source-map-discovery-wayback.md` (verdict commit `05a481e95cdd81c428445362b9244b3d891c6dce`). Neither historical verdict approved the corrected implementation below, and neither mutated beta.

## Parent completion-aware transport repair

The owning `http_get_limited` now drains bounded short reads until the decoder's declared body is complete, EOF is reached or the existing oversize-probe allowance is exhausted. The decoder's chunked framing ignores a conflicting Content-Length. A declared-length short EOF discards its payload, reports `transport`, retains observed HTTP status and charges known consumed bytes. Exceptions with uncertain read progress still reserve the whole original permitted read, not an extra budget per iteration. Complete Content-Length and close-delimited responses remain usable. No syntax/JSON-valid-prefix check substitutes for acquisition completion.

The maintained native HTTPResponse fixture covers incomplete map, bundle and CDX index nonpublication, exact-length success, close-delimited success, tiny valid short reads, conflicting Content-Length with real chunked decoding, and timeout after initial progress. Negative cases assert no historical map, bundle, packet or cache publication. These extend the previous incomplete-chunked and run-byte-budget regressions. Initial new selector: **8 failed, 1 passed, 291 deselected in 2.18s**. Final focused selection including the original fourth-gate probes and retained redirect test: **18 passed, 510 deselected in 4.04s**.

An intermediate broad run returned **769 passed, 3 failed in 86.23s**: the two known baseline README failures plus the old redirect-handler fixture. That fixture returned `b"{}"` forever regardless of read amount, i.e. an infinite non-EOF stream; the completion-aware implementation correctly exhausted its cap instead of pretending it was a complete two-byte document. The fixture now uses BytesIO/EOF without changing its tuple assertion or no-redirect assertion. No product assertion was weakened or failure excluded.

After all code/test corrections, the exact unfiltered broader command above returned **770 passed, 2 failed in 78.14s**. Only the same independently base-reproduced README nodes fail; this is **not an unfiltered green suite**. All four original reviewer scratch suites together returned **19 passed in 4.16s**. Maintained tests and the reachable historical fixture contracts remain sufficient if scratch is pruned. `git diff --check` passed. Parser/resource/dependency contracts from the previous implementation are unchanged; only transport, directly associated maintained tests, the corrected old fixture and playbook/dossier guidance changed.

No real program/archive requests, private-corpus mutation, beta preflight/merge/push, stable promotion or runtime activation occurred. The parser-only implementation checkpoint was `41f90e331e0010cd21cbc4d09956cb123db51d29`. The latest completion-aware implementation is `e1d3e20035e3509ccc7a3c8b1a4003008c1dd3f4`; its later dossier-only tip supplies the current handoff. A fresh independent full-feature verdict and current-beta exact-tree execution gate remain mandatory. Acceptance and runtime activation remain separate.
