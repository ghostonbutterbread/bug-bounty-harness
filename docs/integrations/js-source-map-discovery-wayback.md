# JavaScript source-map discovery and Wayback recovery

- **Status:** BLOCKED by fresh independent release review of candidate d300b610c770a1ebfab1a3583d917bb6639cd96e: Content-Length premature EOF is accepted as complete archive evidence. Parser checks pass, but acquisition correctness blocks integration. Not integrated or activated.
- **Owner / task:** Hermes / t_9b4400cf
- **Feature:** fix/js-source-map-discovery-wayback
- **Worktree:** /home/ryushe/projects/bug_bounty_harness/.worktrees/t_9b4400cf
- **Base commit:** 73d83c730cef6343e0c61d5d0ddcc70a416490d3
- **Intended target:** beta (origin/beta), never main/stable in this task
- **Last updated:** 2026-10-23 (PDT)
- **Latest immutable implementation checkpoint:** 41f90e331e0010cd21cbc4d09956cb123db51d29 (bounded parser replacement, all previous acquisition/provenance repairs, maintained tests and user guidance); the current feature tip contains a later dossier-only handoff update.
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

Original URLs must be scoped HTTP(S) and lack userinfo (including empty usernames), wildcards, whitespace and inline identities. No scope hosts means no archive lookup. Archive requests use only their own User-Agent/Accept, no program headers/cookies/custom Host; default TLS verification and environment proxy transport stay intact. Redirects remain disabled. Content-Length rejection before payload reading charges zero; successful reads and oversize probe bytes count. Failed reads with uncertain progress conservatively reserve their entire permitted read, never accepting incomplete bytes as an artifact. The total-byte counter is charged payload accounting, not a claim of exact wire traffic.

Historical results use a separate cache, `source_map_history`, original/retrieval URLs, capture timestamps and hashes, historical counters and rendered **HISTORICAL** banners. Map-only recovery never claims a current-byte binding. Equal archived/current bundle hashes prove those bytes, not map-to-build association. Cache reuse recomputes current-binding fields from the present successful current retrieval instead of copying an old verified claim. Names without `sourcesContent` are not recovered original source text.

Unavailable current retrieval retains status/history metadata with blank live hash/path and zero live bytes/chunks. It creates no fake empty live artifact, ordinary packet, live URL alias or live-file SQLite row. Historical packets use the archived bundle hash. `js_downloaded` counts actual current artifacts; `js_unavailable` counts unavailable-current records processed for fallback. Source-map diagnostics and historical counts remain distinct from live success. `--skip-cached-processing` still skips processing/recovery; `--refresh` bypasses live and successful historical cache reuse.

## Recoverable test and review evidence

Initial implementation checkpoints are `62e0420635b666c7b919fc9121bb85290b348d8a`, `d61afe41070c5f41ed6c9d7ed90355d266401866`, `e259847b055d2eed6537ec038ea8925bac4b180b` and `c8b48440f7ff92cb0076b7949fe69380b36cd641`. Historical independent blocked verdicts are reachable in dossier-only commits `d07318676e427c47583db6e35bbc9ee427fc9260`, `c8d31bcf819da27d210984baa59620e8690ff80a` and `a7edf58211e1524da9be336a6432ee5bf01ea051`. Their exact candidate/tree/reproducer contracts remain in Git history; none is approval for the current correction.

All previous blocker contracts are maintained: stale history binding after failed current fetch, fake live artifacts on unavailable retrieval, postfix/division, partial read accounting, member keywords and statement/declaration contexts. The third review's optional-catch, labelled-block and exported declaration cases, plus export-default-class and ASI controls, were ported before replacement: **7 failed, 19 passed, 255 deselected in 0.30s**. The parser prototype then passed **510 focused/prior-probe tests in 69.89s** before production integration. New budget/dependency/error consumers initially returned **5 failed, 2 passed, 281 deselected in 0.78s**; after repair and additional dependency/positive-limit variants the selected contract tests returned **10 passed, 283 deselected in 3.45s**. Node syntax checks pass for all 26 maintained block/expression variants (including module exports); Node is only a verification convenience, not a production or maintained-suite prerequisite.

Latest actual-production unfiltered broader command:

```bash
PYTHONPATH="$PWD" .venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py agents/test_js_offline_campaign.py agents/test_xss_sink_sites.py agents/test_xss_source_sites.py agents/test_xss_source_integration.py tests/test_bbh_launcher.py tests/test_runtime_dependencies.py tests/test_skill_command_lane_safety.py tests/test_production_path_safety.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py tests/test_script_policy.py -q --tb=short --show-capture=no
```

**759 passed, 2 failed in 75.09s.** No exclusions or weakened assertions. Both failures are independently reproduced on the unchanged hash-verified base, already recorded in `BUGFIXES.md`:

1. `tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly` — existing direct-checkout command in the stack-to-program README.
2. `tests/test_script_policy.py::test_each_skill_index_has_complete_nonstale_records` — the same README lacks Outputs/Mutates.

This is baseline-only disposition, **not an unfiltered green suite**. The unchanged base export is `/home/ryushe/.hermes/cache/scratch/js-map-review-base-73d83c7`; it is not a Git checkout. Compare its bytes with base blobs from the real repository, and use the same pinned interpreter with base source first on PYTHONPATH. All three reviewers independently reproduced the exact failures (latest **2 failed in 0.14s**); no unrelated README repair is folded into this task.

All three original reviewer suites run together against the production replacement: **15 passed in 2.18s**. Optional scratch conveniences are `test_js_map_release_review.py`, `test_js_map_corrected_release_review.py` and `test_js_map_third_release_review.py` under the scratch root. Maintained cases and historical fixture contracts remain recoverable without scratch. `git diff --check` and actual CLI `inventory --help` passed.

### Bounded synthetic resource receipt

The real detector (not a substituted response) parsed an 8,388,608-byte source consisting of repeated `var x = 1;` lines and the final real declaration: **real.map, 3.3741 s, 629424 KiB peak RSS**. A 1,048,572-byte comment-dense source returned **real.map, 0.1028 s, 52220 KiB peak RSS**. Each ran in a separate offline process under a **benchmark-only** 1,073,741,824-byte address-space limit. This is an observed synthetic receipt, not a worst-case RSS guarantee, latency requirement or production sandbox.

Optional executable receipt: `/home/ryushe/.hermes/cache/scratch/js_map_parser_resource_check.py`. If pruned, reconstruct either source with a `//# sourceMappingURL=real.map` footer, repeat `var x = 1;\n` up to the default cap or `// padding\n` up to 1 MiB, and call the real detector in a separately address-space-limited process. Raising the parser cap is the trigger to repeat resource measurement before broad use.

## Release / activation boundary and exact next action

No real program/archive requests, private corpus mutations, beta changes, pushes or Hoster/runtime activation occurred. Package provisioning affected only the owned task environment. Actual Wayback availability and private-corpus map recovery remain unverified; a separately authorized scoped live smoke is required to establish that evidence. Earlier private-corpus detector counts concern an older heuristic checkpoint, not a new claim for this parser.

Current resume point: implementation owner must correct the premature-EOF defect below on this feature branch, preserve its RED receipt, add maintained positive/negative regressions, and request a fresh independent gate of the new implementation commit. No implementation repair was made by this reviewer. Candidate `d300b610c770a1ebfab1a3583d917bb6639cd96e` remains BLOCKED. The later feature-tip commit changes only this dossier. `origin/beta` was fetched again as `f98f538344a4c0673b48052b519c87446bc605d1`; the root integration checkout remains local beta `73d83c730cef6343e0c61d5d0ddcc70a416490d3`, with no tracked edits and unrelated untracked nested checkouts preserved. No beta preflight or integration mutation was attempted because feature acceptance failed.

Only if accepted, follow the normal clean/current-beta preflight, remove this temporary dossier from the target, verify staged tree/checks, then perform the intentional beta-only merge and `git push origin beta` from beta's integration worktree. No helper lane, HEAD:beta, force push or main promotion. Material code conflict resolution needs its own independent review; do not nest a reviewer. Record final verdict and residual live evidence on the feature before accepted integration. The parent retains remote readback, Kanban closure and clean contained feature cleanup. Runtime/skill activation remains a separate explicit decision; provision the selected runtime's root manifest and verify actual source/env before any later activation.

## Fresh independent gate — 2026-10-23: BLOCKED

- Reviewed candidate commit `d300b610c770a1ebfab1a3583d917bb6639cd96e`, tree `345a375e61758c38d4fe7019c4f259b9ce0443b3`, against base `73d83c730cef6343e0c61d5d0ddcc70a416490d3`. Read the complete current dossier, all seven changed paths, local instructions and current-beta changes. Verified object types, implementation/base ancestry, and that implementation checkpoint `41f90e331e0010cd21cbc4d09956cb123db51d29` to candidate is dossier-only.
- Independent interpreter/import readback selects this feature's `agents/js_analyzer.py` and `.venv/bin/python`; installed tree-sitter 0.26.0 / tree-sitter-javascript 0.25.0 match root pins, bounty-core direct_url commit is `6c36ee88a60073e1b687ec32deeade24ffafdd4f`. Manifest mtime 1792738605.5454807 precedes environment config mtime 1792738639.7383986; resolved versions, not mtime alone, establish the match.
- Exact unfiltered broader command above: **759 passed, 2 failed in 72.16s**. Independently hash-compared all **910** exported baseline blobs against `git ls-tree -r` IDs from the real feature repository: no mismatches. Same feature interpreter, baseline cwd and baseline source FIRST on PYTHONPATH reproduced the exact two known stack-to-program nodes: **2 failed in 0.14s**. These are baseline-only, not an unfiltered green receipt.
- Original three reviewer suites: **15 passed in 1.83s**. CLI `inventory --help` and `git diff --check` pass. No parser regression found in exercised contracts; this is not a future-syntax or private-corpus guarantee.

### Concrete blocker: premature Content-Length EOF publishes incomplete archive bytes

Owner: `agents/js_analyzer.py:599-600` (`http_get_limited`), consumed by `WaybackRecovery.fetch`, `recover_map`, and archived-bundle `recover`.

`resp.read(max_bytes + 1)` uses an explicit amount. A real `http.client.HTTPResponse` can return fewer bytes on premature EOF without raising `IncompleteRead` for a Content-Length-framed response. The helper only compares against the maximum and never checks declared completion. Thus a body shorter than Content-Length returns status 200 / reason `ok`. The existing exception-only partial-read handling does not cover this path. The old limited-fetch helper also used an amount; the release blocker is the new archive evidence path and its explicitly promised incomplete-artifact rejection, not a claim that the primitive first appeared in this candidate.

Offline reproducer patches only `OpenerDirector.open` with a **real standard-library HTTPResponse** over an in-memory HTTP wire fixture; no program/archive network traffic occurs. It declares exactly 100 bytes more than delivered. This is adversarial test input, not claimed live evidence.

Observed on this candidate:

1. Limited fetch accepts **85 delivered bytes** with reason `ok` despite Content-Length **185**. The same decoder/fixture with exact Content-Length is a passing positive control.
2. Exact archived-map recovery publishes that incomplete response as a content-addressed `.map`, records `status=recovered`, `reason=ok`, `embedded_source_recovered=true`, and emits one historical source packet.
3. Archived-bundle recovery similarly hashes/writes the incomplete JavaScript prefix as the archived bundle, follows its declaration, and records successful historical recovery/packet output. A syntactically usable prefix is not proof of complete acquisition.

Command (feature cwd and feature source first):

```bash
PYTHONPATH="$PWD" .venv/bin/python -m pytest /home/ryushe/.hermes/cache/scratch/test_js_map_fourth_release_review.py -q --tb=short --show-capture=no
```

Result: **3 failed, 1 passed in 2.01s**. Failing nodes:

- `test_content_length_completion_checked_by_limited_fetch[100]`
- `test_incomplete_archive_payload_is_not_published[map]`
- `test_incomplete_archive_payload_is_not_published[bundle]`

Required follow-up is completion-aware bounded transport handling: reject/discard incomplete payloads while retaining safe diagnostics and charged consumed/reserved budget; do not repair this by trusting JSON/JS validity or relaxing tests. Add maintained regressions for map, bundle and index completion with complete-response controls, retaining existing chunked/uncertain-read and oversize/budget behavior. Then rerun focused and exact broader checks and obtain a fresh independent feature verdict. No beta compatibility receipt, staged tree, merge or push exists for this blocked candidate; target parent remains the fetched beta above. Live archive/private-corpus evidence remains separately authorized and deferred. No activation occurred.

### Recoverable exact fourth-gate fixture

If scratch is pruned, write the following block to a scratch `test_js_map_fourth_release_review.py` and run the command above from the feature checkout. It imports only maintained test helpers plus standard-library/pytest modules. This source is preserved in the dossier-only verdict commit; its RED assertions must not be silently relabelled as passing observations.

```python
"""Offline release gate: premature EOF with Content-Length using real HTTPResponse.
No sockets or live requests: patch only opener.open, not transport decoding.
"""
import http.client
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from agents import js_analyzer as J
from agents.test_js_analyzer_wayback import BUNDLE, MAP, STAMP, Response, cdx, inventory, replay


class WireSocket:
    def __init__(self, body, declared_length):
        self.wire = (f'HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\n'
                     'Content-Type: application/json\r\n\r\n').encode() + body

    def makefile(self, *args):
        return io.BytesIO(self.wire)


def wire_response(body, missing=0):
    response = http.client.HTTPResponse(WireSocket(body, len(body) + missing))
    response.begin()
    return response


@pytest.mark.parametrize('missing', [0, 100])
def test_content_length_completion_checked_by_limited_fetch(missing):
    response = wire_response(MAP, missing)
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=response):
        result = J.http_get_limited(replay(BUNDLE + '.map'), timeout=1, max_bytes=4096,
                                    include_program_headers=False)
    if missing:
        assert result[0] == b'', f'incomplete HTTP payload accepted: {len(result[0])} bytes, reason={J.fetch_reason(result)}'
        assert J.fetch_reason(result) == 'transport'
    else:
        assert result[0] == MAP and J.fetch_reason(result) == 'ok'


@pytest.mark.parametrize('partial_kind', ['map', 'bundle'])
def test_incomplete_archive_payload_is_not_published(tmp_path, partial_kind):
    archived_js = b'const old=true;\n//# sourceMappingURL=app.js.map\n'
    map_url = BUNDLE + '.map'

    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            if partial_kind == 'map':
                return Response(b'//# sourceMappingURL=app.js.map')
            return Response(b'const current=true;')
        if url == map_url:
            raise J.urllib.error.HTTPError(url, 404, '', {}, io.BytesIO())
        if '/cdx/' in url:
            original = J.urllib.parse.parse_qs(J.urllib.parse.urlsplit(url).query)['url'][0]
            # Only map exists for the map-only path; both exist for bundle recovery.
            stamps = [STAMP] if partial_kind == 'bundle' or original == map_url else []
            return Response(cdx(original, *stamps))
        if url == replay(BUNDLE):
            return wire_response(archived_js, missing=100)
        assert url == replay(map_url)
        return wire_response(MAP, missing=100 if partial_kind == 'map' else 0)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto')
    history = rows[0]['source_map_history']
    artifacts = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*.map'))
    assert history['status'] == 'not_recovered', (
        f'premature EOF in {partial_kind} published: history={history!r}; map_artifacts={artifacts!r}')
    assert manifest['historical_source_maps_recovered'] == 0
    assert not artifacts
    assert any(a['reason'] == 'transport' for a in history['attempts'])
```

