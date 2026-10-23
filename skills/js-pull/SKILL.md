---
name: js-pull
description: Use when collecting, deduplicating, and packetizing scoped JavaScript evidence.
---

# JavaScript Pull

This skill owns the **existing** JavaScript acquisition path, not the security
interpretation. Run it for an explicit collection request or as the prerequisite
when `/js-hunt` has no suitable current inventory. The canonical detail is in
`prompts/js-playbook.md` (inventory, source maps, provenance, scope, and artifact
contracts); do not create a second downloader or copy bundles into prompts.

## Inputs and Scope

1. Resolve a page URL, scope-checked `aggregated/jsfiles.txt`, proxy/recon
   references, or a prior run. Check the `_library/` URL/hash ledger first:
   reuse present artifacts unless freshness is deliberately requested.
   JS acquisition is cheap relative to its value, so bias toward re-pulling.
   Browser-observed scripts with a non-JS suffix (for example `chunk.php`)
   need the explicit `--input` URL plus a matching `--provenance-input` row;
   see `prompts/js-playbook.md` for the evidence fields and response checks.
   Apply an **age edge: re-pull any artifact whose `last_seen` is older than the
   staleness window regardless of whether its URL is still mapped.** Seven days
   is the default window; a program may set its own. When the operator asks for
   a full re-pull of everything rather than a refresh of the current set, use
   `--refresh` and ignore the cache entirely. Derive the stale subset instead of
   refetching wholesale when only part of the corpus has aged:

   ```sql
   -- stale artifacts to re-pull; feed the URLs to inventory --input
   -- strftime keeps the Z-suffixed ISO-8601 comparison exact; bare datetime()
   -- yields a space separator that mis-sorts on same-date boundaries
   SELECT DISTINCT js_url FROM js_url_aliases
   WHERE last_seen < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-7 days');
   ```
2. Apply program scope and the normal live-testing policy before any download;
   inventory fetches and source-map retrieval are network requests. Use
   `--target-host` to constrain what is fetched. Extracted third-party URLs are
   integration context, not permission to test them.
3. Preserve the page/flow that loaded each JS URL, initiator/referrer, source,
   and nearby scoped requests when available. An inline `#inline-script-N`
   identity is an artifact, **not** a URL to fetch; extensionless script assets
   and executable inline scripts belong in page inventory.

## Inventory

For a scoped page, use `terminal(command="bbh agents/js_analyzer.py inventory
<program> --page '<scoped-page-url>' --page-context '<flow>' --target-host
'<approved-host>'")`. For an existing file list, use
`terminal(command="bbh agents/js_analyzer.py inventory <program> --input
'<jsfiles-path>' --target-host '<approved-host>'")`. Read the specific command
help before changing limits, provenance input, or `--refresh`. If early packet
review is intended, set an explicit run ID or output root so the consumer knows
where completed packets appear.

The helper hashes/deduplicates bodies, records URL aliases, creates bounded
packets, and retrieves bounded in-scope maps from response headers or actual
comment declarations. Review `source_map_modules.jsonl` and
`source_map_packets/` for original modules with embedded text; a module name
alone does not establish that source text exists or that the module ran. Use
`/jsluice` on *selected local files* for AST-derived leads if available; its
output is not an endpoint contract.

### Missing maps and Wayback recovery

Do not equate `not_detected` or `fetch_failed` with maps never having existed.
Read `source_map_discovery`, `source_map_reason`, and `source_map_http_status`
first: 404, rate limits, TLS failures, invalid data and size caps need different
follow-ups. `scan_failed` means comment discovery was incomplete, not that a map
was absent: check `parse_limit`, `parser_unavailable` or `parser_memory`. The
pinned parser comes from the checkout's root requirements; provision it with
`bash setup.sh --install-python-deps` before selecting that checkout for use.
Keep `--source-map-parse-max-bytes` at its 8 MiB default unless a selected bundle
justifies more AST memory. Response headers bypass comment parsing and its cap.
Reprocessing existing cached JS uses the repaired detector; omit
`--skip-cached-processing` when checking map coverage.

The inventory automatically tries bounded Wayback recovery when a usable live
map is unavailable, including 404s, invalid map bodies, and missing declarations.
Do not wait for a particular number of 404s or ask agents to opt in manually:
`--source-map-wayback auto` is the default. A valid live or cached map takes
priority and causes no archive lookup. This sends scoped original asset URLs
to Internet Archive; use `--source-map-wayback off` where program policy or URL
confidentiality prohibits that disclosure. `--source-maps off` disables both
live-map and archive work.

The fallback checks exact declared map URLs, then archived versions of the exact
bundle for historical declarations. It validates retrieved map bodies and skips
invalid captures to try other returned snapshots within the existing limits;
a 200 response alone is not a valid source map. It does not crawl the whole
domain or prove a historical map matches the current build. It sends no program
headers to the archive, retains the normal proxy/TLS transport, and stops further
archive requests on 429. The default run budget is 20 requests, with two captures
per lookup; read help before raising budgets. Repeated failures that exhaust a
budget remain an explicit coverage gap, not a reason to disable fallback or
claim the archive was exhausted.

Read `source_map_history`, manifest `source_map_wayback` diagnostics, and
`historical_source_maps_*` counters. Historical rows and packets are labelled;
preserve capture timestamps, retrieval/original URLs, and hashes. Map-only
recovery does not verify a match to current bundle bytes. Even equal archived
and current JS hashes do not independently verify the map-to-build binding.
Names without `sourcesContent` are not recovered source text. Report blocked,
capped, or unattempted archive work as a gap, not an empty archive. Canonical
limits and examples are in `prompts/js-playbook.md`.

## Handoff and Verification

- Read `manifest.json`, `metadata.jsonl`, `packets.jsonl`,
  `js_provenance.jsonl`, and `source_map_modules.jsonl` when present. The
  append-only `_library/metadata.jsonl`, `_library/provenance.jsonl`, and
  `_library/observations.jsonl` are durable evidence; `js_info.sqlite` is a
  rebuildable lookup index. Preserve JS URL, sha256, packet path, source-map
  hash, and loading page/flow when handing off.
- Name omitted/truncated modules, failed fetches, historical-only URLs, and
  page or flow coverage gaps. Inventory completion means artifacts are ready,
  **not a finding** and not `deep_reviewed` coverage. Load `/bb-script-rules`
  for script-run coverage judgment.
- **Record coverage in the index, keyed by content.**
  `bbh agents/js_analyzer.py observe <program> --input <rows.jsonl>` appends
  review rows to `_library/observations.jsonl` and rebuilds `js_observations`.
  Rows carry `sha256`, `js_url`, `packet_path`, `lens`, `run_id`, `agent_id`,
  `title`, `summary`, `status`, `confidence`, `evidence[]`, `next_action`;
  `observation_id` is derived from row identity, so re-submitting upserts rather
  than duplicating. An observation is a **depth claim, not a done flag**; set
  `status` explicitly (the writer currently defaults omitted status to
  `observed` and does not validate it):

  - `swept`: deterministic extraction, regex, or cluster triage only; code not read.
  - `triaged`: skimmed for relevance and routed; no function-level trace.
  - `deep_reviewed`: code read at function level; behavior or source-to-consumer
    trace attempted and supported by evidence pointers.
  - `exhausted`: deep review with a defensible bounded conclusion for the stated
    lens/flow, not a claim that the whole app or chunk can never yield a lead.

  Record the **lowest honest depth**; cite inspected functions/packets for deep
  claims rather than counting worker self-reports as proof. Older `observed` or
  other unrecognized statuses remain unfinished until their evidence is checked;
  do not silently reinterpret or rewrite the append-only record. Distinct
  observations may cover different lenses of the same hash: one deep review is
  not proof that every lens/flow was exhausted. Keying on sha256 makes a re-pull
  cheap to reason about: unchanged bytes retain their observations at their
  recorded depth, while changed bytes get a new hash with no observation and
  reappear as unobserved. Deep claims may also be reopened on new evidence.
  Content addressing also means a chunk resurfacing at a rotated URL adds an
  alias row, not a second copy.
- If the user requested only collection, report the artifact root, counts from
  the manifest, provenance quality, and gaps. Otherwise load `/js-hunt` with
  the run root; do not silently stop at a list of URLs or strings.
