# Automatic Wayback source-map recovery

- Task: `t_1f629ac7`; owner: parent / default.
- Authorization: Ryu, Discord thread `1563053963534930045`, message `1563240467821502605`: automatically check Wayback when live maps repeatedly 404 or are invalid. This supersedes the previous manual archive opt-in default, not program-specific prohibitions or provenance fences.
- Branch: `fix/js-wayback-automatic`.
- Worktree: `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_1f629ac7`.
- Base: `720e3e2ca8960837d891c3bfdc44396c63c139ef`; target: `beta` only.
- Status: locally implemented/exercised; fresh independent release gate pending. The immutable implementation checkpoint is pinned in a later dossier-only handoff before dispatch.

## Implemented contract

`inventory` now defaults `--source-map-wayback` to `auto`. The existing recovery path runs when no usable live map is available (404, invalid map body, missing declaration, other supported unavailable states); no arbitrary failure-count threshold or agent-side opt-in is required. A usable live/cached map still wins without archive lookup. `--source-map-wayback off` disables archive work, and `--source-maps off` disables both acquisition paths. Program policy and confidential original URLs can require the explicit off switch.

The only production-code change is the existing CLI default/help. Recovery transport, source-map reader, scope, credential isolation, cache/current-byte binding, complete-response checks, parser and expansion limits are unchanged. Tests exercise default live404/invalid recovery, invalid first map/bundle capture followed by a usable older snapshot, many404 maps sharing default/custom request budgets, default429 stop, history caching, header isolation, names-only recovery, live-map priority and both off controls. `skills/js-pull/SKILL.md` and `prompts/js-playbook.md` now teach automatic recovery and its safeguards together.

Captured maps must pass the existing reader; HTML/error documents, malformed JSON and wrong versions are not accepted. Other selected snapshots are tried within existing caps. Format acceptance is not a VLQ/build/execution proof. A map without `sourcesContent` is names-only, not necessarily invalid. Historical packets retain timestamps/original/replay URLs and hashes; map-only recovery does not establish a current-build match. Default20 requests/two captures per lookup/8MiB response/32MiB total, exact-original scope checks, no program headers to Archive, verified TLS/proxy transport and run-wide429 stopping remain unchanged. Coverage gaps stay visible when budgets stop recovery.

## Scope and non-goals

No new downloader, domain crawl, blanket archive enumeration, new failure counters or schema, runtime/installed-skill projection, stable promotion, real archive/program probes, or private-corpus access. Hoster/Krisp remain outside this release operation. Live archive availability/recovery remains deferred to separately authorized validation; no offline fixture receipt is presented as live success.

## Environment and RED-to-GREEN

`bash setup.sh --install-python-deps` succeeded in this task checkout. Imported `agents.js_analyzer` resolves beneath the feature worktree. Installed Tree-sitter0.26.0/JavaScript0.25.0 and Bounty Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f` match the unchanged root manifest.

First vertical regression `test_default_inventory_recovers_a_404_map_from_wayback` failed because the actual manifest mode was `off`: **1 failed in1.21s**. After the CLI default/help change it passed: **1 passed in0.89s**. That maintained regression was then expanded/renamed `test_default_inventory_recovers_unavailable_or_invalid_map_from_wayback` to include404, HTML, wrong map version and error JSON. All fixtures use real inventory paths with exact mocked HTTP responses, not simulated inventory results.

Changing the default exposed legacy live-only fixtures that mocked JS but not archive transport. The guarded first focused run had8 failures/517passes; remaining broad run had2 such fixture failures plus2 baseline README failures (776passes/4failures). Legacy live-only test invocations now explicitly pass `--source-map-wayback off`, without changing their assertions. Default-on/off, capture and budget behavior remains exercised in the dedicated Wayback suite, including tests previously using explicit `auto`. No failure was excluded or product assertion weakened. An early mistyped broader path caused zero tests to run; it is not a receipt.

## Final verification receipts

Final default/recovery/control selection: **19 passed,291 deselected in27.99s**:

```bash
PYTHONPATH="$PWD" .venv/bin/python /home/ryushe/.hermes/cache/scratch/js-wayback-auto-offline-tests.py agents/test_js_analyzer_wayback.py -q --tb=short --show-capture=no -k 'default_inventory or default_recovery or many_404 or explicit_off or exact_missing_map or response_header_precedes or archive_429 or archive_run_budgets'
```

Exact unfiltered broader selection: **778 passed,2 failed in129.70s** (prior same selection94.21s). This is **not unfiltered green**:

```bash
PYTHONPATH="$PWD" .venv/bin/python /home/ryushe/.hermes/cache/scratch/js-wayback-auto-offline-tests.py agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py agents/test_js_offline_campaign.py agents/test_xss_sink_sites.py agents/test_xss_source_sites.py agents/test_xss_source_integration.py tests/test_bbh_launcher.py tests/test_runtime_dependencies.py tests/test_skill_command_lane_safety.py tests/test_production_path_safety.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py tests/test_script_policy.py -q --tb=short --show-capture=no
```

Only these independently baseline-reproduced nodes fail:
- `tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly`: existing direct-checkout command in stack-to-program README.
- `tests/test_script_policy.py::test_each_skill_index_has_complete_nonstale_records`: same README missing Outputs/Mutates fields.

Fresh `git archive` export of exact base to `/home/ryushe/.hermes/cache/scratch/js-wayback-auto-baseline-t_1f629ac7`, using the same feature interpreter with baseline source first, reproduced **2 failed in0.17s**. README and both test files were verified against exact Git blob IDs by path, and feature leaves them unchanged. The initial verifier compared Git-sorted paths with input-order hashes and failed on ordering; path-keyed comparison resolved the harness error without changing source/export bytes. Baseline export is non-Git: perform object/ref operations from the actual repository.

`git diff --check` and actual `inventory --help` passed; help advertises `auto` and explicit off/disclosure controls.

### Reproducible offline guard

The scratch runner is not required for product use and may be pruned. Recreate this bounded test-only runner when absent; it denies unmocked live DNS/socket I/O within pytest while exact mocked urllib responses remain usable:

```python
import socket
import sys
from unittest.mock import patch
import pytest

def deny_network(*args, **kwargs):
    raise AssertionError('Offline test attempted unmocked live DNS/socket I/O')

with patch.object(socket, 'getaddrinfo', side_effect=deny_network), \
     patch.object(socket.socket, 'connect', side_effect=deny_network), \
     patch.object(socket.socket, 'connect_ex', side_effect=deny_network):
    raise SystemExit(pytest.main(sys.argv[1:]))
```

This is a process-local offline test guard, not a production sandbox or a guarantee about arbitrary child processes. Final broad run had no denied-network failures; no real archive/program requests were sent.

## Release/closeout gate

Pin the implementation commit in a dossier-only successor. Obtain one fresh independent full-diff review, rerun tests, and verify exact current-beta execution compatibility using beta source first with the manifest-matching feature interpreter. Preserve the normal reviewed beta merge; exclude this branch-local dossier from its tree and confirm staged/final tree identity and tests before pushing beta. No activation or stable promotion. Parent retains remote readback, Kanban closeout and contained feature cleanup. Finish interpreter-dependent checks before completing the card, which may retire the task worktree. If review blocks, return a dossier-only recoverable checkpoint and concrete reproducer rather than repairing implementation or launching nested review.
