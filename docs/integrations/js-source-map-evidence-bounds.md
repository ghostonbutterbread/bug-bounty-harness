# JS source-map evidence bounds — branch-local integration dossier

- **Status:** review-ready for independent review; not merged or pushed
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/js-source-map-evidence-bounds-20261008`
- **Worktree:** `/home/ryushe/worktrees/bbh-source-map-safe-subset-20261008`
- **Fetched base commit:** `53152595838d7add9d6b552d0b79770878126605`
- **Intended integration target:** `beta` (`origin/beta` fetched at the same SHA)
- **Last updated:** 2026-10-08
- **Latest immutable recovery checkpoint:** pending task commit; see branch tip after commit
- **Feature implementation commit(s):** pending task commit
- **Inspiration:** separable packet/provenance/cached-cap repairs from blocked `fix/js-source-map-flow-20261008` (`5214852`); its directive parser, regex, scanner and directive tests are deliberately excluded.

## Intent and implemented contract

For byte-identical JS bundles at different URLs, bundle packets use URL-hashed names; source-map review packets additionally partition by map digest and bundle URL digest. Cached map bodies above the current `--source-map-max-bytes` become `too_large` without refetch, parsing or packetization. Per-URL metadata includes only that URL's packet paths and provenance, while deduplicated download/chunk/module artifacts can remain shared. JSONL keys and metadata schema remain unchanged. Published `SOURCE_MAP_RE` and `extract_signals` remain byte-for-byte identical to fetched beta. No scanner, block-directive or last-directive behavior is introduced.

## Evidence / review packet

- Strict vertical TDD: four new behavioral tests, each observed failing against the preceding state (packet path collision, bundle filename collision, provenance row-count 2 instead of 1, cached status `cached` instead of `too_large`), then passing after its minimal fix. The map collision case also runs with identical and distinct map bytes, checking packet headers and metadata/artifact-links isolation.
- `python -m pytest agents/test_js_analyzer.py -q`: 194 passed (final run, including both map-byte variants).
- `python -m pytest agents/test_xss_sink_sites.py agents/test_js_offline_campaign.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py -q`: 146 passed.
- `git diff 5315259 -- agents/js_analyzer.py` contains no `SOURCE_MAP_RE`, `extract_signals`, or scanner hunk; `git diff --check` clean. Bounded reference search found metadata packet consumers in analyzer's metadata/SQLite writer and the tested JS skill guidance; no fixed packet filename consumer.
- Review changed paths only: `agents/js_analyzer.py`, `agents/test_js_analyzer.py`, this temporary dossier. Check negative evidence, per-URL ownership and unchanged directive extraction; rerun both suite commands above and inspect `git diff 5315259..HEAD` before any beta merge.
- Integration lineage: feature branch starts at current fetched beta tip `5315259`; no push/merge authorized.

## Residual limits / deferred work

- Cache loader still reads the entire stored map into memory before checking the current cap; the fix bounds downstream parsing/packetization, not peak cache-read allocation. A bounded cache read would require a separate tested change; revisit if memory-cap enforcement is required.
- Existing source-map directive extraction is intentionally unchanged, including its heuristic false positives/line-only and first-match semantics. Block/last directive lexical scanner from the blocked branch is not safe to promote as-is; reconsider only with an independently reviewed parser and regression cases around control-flow regex literals.
- Source-map module files remain content-addressed and shared by identical map bytes; only review packet headers/paths are per bundle URL.
- No live-target or production cohort run; offline synthetic fixtures are the verification boundary. Trigger live validation only under separately authorized scope/policy and test data.

## Decision gates and handoff

- **Integration:** independent review of task diff and receipts; selected beta may advance and then needs deliberate reconciliation/retest. Remove this dossier from the beta integration tree on accepted merge; do not merge/push here.
- **Activation/promotion:** not requested; no runtime activation or stable promotion implied.
- **Exact resume point:** after task commit, inspect its staged/committed diff and rerun owning/adjacent suites; independent reviewer may then integrate into `beta` if current and approved.
- **Working tree at handoff:** expected clean after local commit.
- **2026-10-08 decision:** retain only packet identity, metadata/provenance ownership and cached-cap behavior; explicitly reject directive changes from blocked branch.
