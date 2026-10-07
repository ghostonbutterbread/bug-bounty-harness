---
name: jsluice
description: Use when parsing local JavaScript with upstream JSLuice for URL, request, secret, or syntax-tree leads.
---

# JSLuice Tool

Use this focused tool skill after `/js` has selected local JavaScript artifacts.
BishopFox's upstream `jsluice` is a separate CLI, not a BBH script or an
automatic inventory dependency. It uses syntax-tree matching to extract URL
and path patterns with request context; other modes find secret signals, inspect
trees, run Tree-sitter queries, or format JS. Upstream documentation lives at
`https://github.com/BishopFox/jsluice/tree/main/cmd/jsluice`.

## When to Use

- `urls`: find URL/path patterns and, where recognized, request methods,
  query/body parameters, and call type across concatenated expressions.
- `secrets`: inspect selected bundles for secret-like values; handle any actual
  credential under `/credential-exposure-validation`, not as a wordlist item.
- `query` or `tree`: inspect a focused syntax construct when normal packet
  review points to it. These are not automatic source-to-sink analyzers.
- `format`: inspect hard-to-read JavaScript, keeping the original artifact as
  the evidence source.

## Offline Procedure

1. Select a bounded set of already downloaded artifacts from the `/js` run's
   `metadata.jsonl`. Retain each `artifact_path`, original `url`, `sha256`,
   `run_id`, and page/flow provenance; inline `#inline-script-N` identities are
   not fetchable URLs. Check the artifact still matches its recorded hash
   before attributing results to it.
2. Check `command -v jsluice` and `jsluice --help`. If it is unavailable,
   record a skipped optional pass and continue packet review; do not install it
   as part of inventory or fall back to a BBH wrapper.
3. Pass an **existing local file**, never an HTTP URL, to the chosen mode:

   ```bash
   jsluice urls "$LOCAL_JS_FILE"
   jsluice secrets "$LOCAL_JS_FILE"
   jsluice query -q '(string) @matches' "$LOCAL_JS_FILE"
   ```

   The first two modes are independent; run only those needed for the selected
   lens. The `query` example finds syntax strings, not dangerous sinks. JSLuice
   accepts remote URL arguments and can make requests if given one; keep this
   pass offline. For large bundles, keep output on disk and review bounded rows
   rather than piping the whole stream into an agent prompt.
4. Preserve raw JSONL locally with the inventory URL/hash/provenance and cite
   selected records in the `/js` review. Redact usable secrets from shared notes
   and route complete credential evidence through the owning validation skill.
   Do not silently merge parser output into inventory metadata or call a match
   a verified endpoint.

## Interpretation

`EXPR` is a placeholder for a computed value, not a replayable URL. Method and
parameter fields describe detected source usage, not a confirmed server
contract. A path may refer to an out-of-scope integration, and zero matches do
not establish absence or complete coverage. For source-to-sink or DOM impact,
trace control and transforms in the original code and hand a concrete lead to
`/dom-xss` or the appropriate specialist; JSLuice's URL/secret output alone is
not proof of a sink or vulnerability.
