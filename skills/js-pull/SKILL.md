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
packets, and retrieves bounded in-scope maps when declared. Review
`source_map_modules.jsonl` and `source_map_packets/` for original modules with
embedded text; a module name alone does not establish that source text exists or
that the module ran. Use `/jsluice` on *selected local files* for AST-derived
leads if available; its output is not an endpoint contract.

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
  than duplicating. Keying on sha256 is what makes a re-pull cheap to reason
  about: unchanged bytes keep their hash and stay reviewed, while changed bytes
  get a new hash with no observation and correctly reappear as unreviewed.
  Content addressing also means a chunk resurfacing at a rotated URL adds an
  alias row, not a second copy.
- If the user requested only collection, report the artifact root, counts from
  the manifest, provenance quality, and gaps. Otherwise load `/js-hunt` with
  the run root; do not silently stop at a list of URLs or strings.
