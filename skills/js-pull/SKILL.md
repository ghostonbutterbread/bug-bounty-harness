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
- If the user requested only collection, report the artifact root, counts from
  the manifest, provenance quality, and gaps. Otherwise load `/js-hunt` with
  the run root; do not silently stop at a list of URLs or strings.
