# JS source-map evidence bounds — branch-local integration dossier

- **Status:** cache-cap review blocker repaired and locally verified; independent rereview pending; not merged or pushed
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/js-source-map-evidence-bounds-20261008`
- **Worktree:** `/home/ryushe/worktrees/bbh-source-map-safe-subset-20261008`
- **Fetched base commit:** `53152595838d7add9d6b552d0b79770878126605`
- **Intended integration target:** `beta` (`origin/beta` fetched at the same SHA)
- **Last updated:** 2026-10-08
- **Latest immutable recovery checkpoint before this repair:** `322af58613657efaf12e878b1f8e3c9a9177f705` (dossier-only successor to implementation `3995a4b`); cache-cap repair is committed with this updated dossier at the current feature-branch tip
- **Feature implementation commit(s):** `3995a4bc2722d2d73a3583429a0a0b4437e366d5`
- **Inspiration:** separable packet/provenance/cached-cap repairs from blocked `fix/js-source-map-flow-20261008` (`5214852`); its directive parser, regex, scanner and directive tests are deliberately excluded.

## Intent and implemented contract

For byte-identical JS bundles at different URLs, bundle packets use URL-hashed names; source-map review packets additionally partition by map digest and bundle URL digest. Cached map artifacts are read at most current `--source-map-max-bytes` + 1 bytes; an oversized present cache yields an explicit oversized loader result and `too_large` without hash/JSON validation, downstream parsing, packetization or refetch. Its per-run metadata has empty source-map SHA/path and zero modules; the too-large counter increments without counting reuse. Within-cap cache reads still verify digest, successful status and source-map shape; invalid within-cap cache can refetch as before. An oversized present artifact is not refetched even if its contents or ledger status would fail validation—no attempt is made to prove either beyond the cap. Per-URL metadata includes only that URL's packet paths and provenance, while deduplicated download/chunk/module artifacts can remain shared. JSONL keys and metadata schema remain unchanged. Published `SOURCE_MAP_RE` and `extract_signals` remain byte-for-byte identical to fetched beta. No scanner, block-directive or last-directive behavior is introduced.

## Evidence / review packet

- Strict vertical TDD on the earlier safe subset: four behavioral tests each observed failing against the preceding state (packet path collision, bundle filename collision, provenance row-count 2 instead of 1, cached status `cached` instead of `too_large`), then passing. The map collision case also runs with identical and distinct map bytes, checking packet headers and metadata/artifact-links isolation.
- Cache-cap review repair RED→GREEN: extended the existing lowered-cap two-run fixture before production changes. RED failed because `is_source_map_body` was called on the oversized cached map (and the instrumented file reader would have observed an unbounded read). GREEN: validator not called, one `read(11)` for cap 10, one initial download and no second map fetch, `too_large`/counter 1, reuse 0, empty SHA/path and zero module rows. `python -m pytest agents/test_js_analyzer.py::test_cached_source_map_obeys_lowered_byte_cap_without_refetch -q`: 1 passed.
- `python -m pytest agents/test_js_analyzer.py -q`: 194 passed after repair.
- `python -m pytest agents/test_xss_sink_sites.py agents/test_js_offline_campaign.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py -q`: 146 passed after repair.
- Bounded call-site search found only `command_inventory`; no other loader caller needs the new required cap. `git diff 5315259 -- agents/js_analyzer.py` contains no `SOURCE_MAP_RE`, `extract_signals`, or scanner hunk; `git diff --check` clean. Earlier bounded reference search found metadata packet consumers in analyzer's metadata/SQLite writer and the tested JS skill guidance; no fixed packet filename consumer.
- Review changed paths only: `agents/js_analyzer.py`, `agents/test_js_analyzer.py`, this temporary dossier. Check negative evidence, per-URL ownership and unchanged directive extraction; rerun both suite commands above and inspect `git diff 5315259..HEAD` before any beta merge.
- Integration lineage: feature branch starts at current fetched beta tip `5315259`; no push/merge authorized.

## Residual limits / deferred work

- Cached map reads are now bounded to the configured cap + 1, with hash/JSON validation only for within-cap bodies; this is a read/parse bound, not a strict peak-process-memory guarantee (other JS bodies, map module expansion and parser allocations have separate behavior). A corrupt oversized present cache is classified `too_large` and not refetched, intentionally preserving the no-refetch cap contract; reduce/remove the artifact or raise the cap for validation.
- Existing source-map directive extraction is intentionally unchanged, including its heuristic false positives/line-only and first-match semantics. Block/last directive lexical scanner from the blocked branch is not safe to promote as-is; reconsider only with an independently reviewed parser and regression cases around control-flow regex literals.
- Source-map module files remain content-addressed and shared by identical map bytes; only review packet headers/paths are per bundle URL.
- No live-target or production cohort run; offline synthetic fixtures are the verification boundary. Trigger live validation only under separately authorized scope/policy and test data.

## Decision gates and handoff

- **Integration:** independent review of task diff and receipts; selected beta may advance and then needs deliberate reconciliation/retest. Remove this dossier from the beta integration tree on accepted merge; do not merge/push here.
- **Activation/promotion:** not requested; no runtime activation or stable promotion implied.
- **Exact resume point:** review original implementation checkpoint `3995a4bc2722d2d73a3583429a0a0b4437e366d5`, the dossier checkpoint `322af58613657efaf12e878b1f8e3c9a9177f705`, and the subsequent local cache-cap repair at current feature-branch tip; inspect the complete committed diff and rerun owning/adjacent suites before any integration decision. Parent agent owns independent rereview and integration; this subtask does not push or merge.
- **Working tree at handoff:** expected clean after local commit.
- **2026-10-08 decision:** retain only packet identity, metadata/provenance ownership and cached-cap behavior; explicitly reject directive changes from blocked branch.
