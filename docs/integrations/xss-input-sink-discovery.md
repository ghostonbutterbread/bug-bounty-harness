# XSS source/sink discovery routing — integration dossier

- **Status:** independent release and narrow re-review accepted; ready for beta integration
- **Owner:** Hermes / BBH XSS
- **Branch:** `docs/xss-input-sink-discovery`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-input-sink-discovery`
- **Base commit:** `e1bf907671475004f3de268dedf5fc557b771696`
- **Intended integration target:** `beta` (`origin/beta` at the recorded base)
- **Last updated:** 2026-10-21 PDT
- **Owning feature branch/ref:** `docs/xss-input-sink-discovery`
- **Latest immutable recovery checkpoint:** `0988493bac62a7cd5ee43a02d83c6e1e31e898ec` (reviewer-led correction; this dossier update follows it)
- **Feature implementation commit(s):** `3a2d22ccce8844543c093bcd30d83b26385c7607`, `a9f34ceb7946416b79c5b92b2500a5904823bbc2`, `0988493bac62a7cd5ee43a02d83c6e1e31e898ec`
- **Inspiration / canonical references:** Ryushe's Discord request in thread `1562231426932539452`, message `1562530135226191904`; `skills/xss/SKILL.md`; `skills/xss/references/source-acquisition.md`; `skills/js-pull/SKILL.md`; `skills/dom-xss/SKILL.md`; `agents/js_analyzer.py`, `agents/xss_source_sites.py`, and `agents/xss_sink_sites.py`.

## Intent

Make XSS agents discover the existing **paired named-input and sink-site** JS inventory and combine it with authorized live application exploration, observed browser Network/Sources/DOM/request behavior, and stack-specific source/sink reasoning. These are complementary ways to find and prioritize candidate paths, not a mandatory scan quota or an exhaustive list. Keep root routing lean and retain the selected XSS lane's proof, policy, and Attempts ownership.

## Implemented contract

The `xss` router now offers an early on-demand source/sink-acquisition route and explicitly connects authorized UI navigation, dynamically loaded JS, browser Network/Sources/DOM observations, stack-specific request/render APIs and paired JS `source_sites`/`sink_sites`. `source-acquisition.md` states that `inventory --page` fetches HTML script URLs and bounded inline scripts but does not run client navigation, while browser-observed scoped JS URLs can enter the existing `--input` path **only for supported JS/extensionless URL suffixes**. A browser-loaded `chunk.php` absent from HTML remains a manual runtime lead, not a scanned artifact. The reference preserves per-page/flow provenance, source/sink truncation, stack-specific blind spots, and the distinction among inventoried script, browser-loaded script, and observed input-to-renderer path. `source_sites` are named read/getter candidates, not all request/body fields; outbound names may be only vocabulary. `skills/xss/scripts/README.md` now records both existing analyzer modules with owner/scope and verification date; neither is a standalone live scanner. No executable or target-testing code changed.

## Evidence and review

- Initial `xss` root already mentioned `source_sites`, `sink_sites`, and analyzer under late discovery/script sections, but did not explicitly connect lazy browser loading and DevTools observations to the corpus. The script map documented the named-source module but omitted a separate entry for the sink-site module.
- `js_analyzer.py inventory` accepts `--page` for an HTTP-fetched page's scripts and `--input` for a scoped JS URL list; `--page` alone is not a browser interaction or lazy-route census. Its module calls and persisted output were inspected directly.
- Focused source/sink/analyzer/XSS tests after final edit: **403 passed**, plus XSS route/script-policy focused tests **36 passed, 2 failed**; the two failures were reproduced on unchanged beta in `skills/stack-to-program/scripts/README.md` contracts. The first feature run had a task-owned wording assertion failure, corrected by restoring the existing “inventory analysis is static” phrase.
- Full `tests` suite after local `.venv` install: **307 passed, 1 skipped, 2 failed**. Same two unrelated `stack-to-program` failures reproduced on unchanged beta with the same interpreter. An initial attempt using the beta worktree's interpreter failed 15 additional launcher subprocess subtests because this worktree had no `.venv`; `./setup.sh --install-python-deps` resolved those setup failures. No live targets contacted.
- Two independent read-only audits of unchanged beta confirmed: `xss_source_sites.py` and `xss_sink_sites.py` are imported analyzer modules (not CLIs); source signatures are named getter/read sites plus unnamed hints, sink signatures are capped call-site seeds; `--page` fetches static HTML-linked/inline scripts, and live browser routes require separate observed-script capture. Runtime and stack methods existed but were hard to find from the XSS entry point. Audit feedback was incorporated in `a9f34ceb7946416b79c5b92b2500a5904823bbc2` (named-read precision, three evidence levels, conditional browser route, accurate `--page` behavior).
- After the first material correction, focused source/sink/analyzer/XSS tests: **403 passed**. Full `tests`: **307 passed, 1 skipped, the same 2 unrelated failures**. The initial independent release review was requested at that checkpoint and returned the ACCEPT verdict recorded below.
- Fresh independent review of `e1bf907..c20817e` returned **ACCEPT for beta integration** with two MINOR documentation nits: `--input` silently filters non-JS suffixes despite live-loaded script evidence, and the new sink-module script record lacked owner/scope and last verification. Corrected both in `0988493bac62a7cd5ee43a02d83c6e1e31e898ec` (also brought the paired source record to the same index fields). Focused source/sink/analyzer/XSS tests after correction: **403 passed**; full `tests`: **307 passed, 1 skipped, same 2 baseline failures**. The proposed fixture that would have asserted permanent `.php` omission was deliberately removed so future analyzer support remains possible. The subsequent narrow review accepted this correction.
- Narrow independent read-only re-review of exact tip `985aac5be9af9946fd3d188c2edd8558ff9d7886` returned **ACCEPT for beta integration**. It verified `--input` suffix handling against analyzer code, the `--page` distinction, both index records and SCRIPT_POLICY fields, and no mandatory sweep. Reviewer focused tests: **403 passed**; broader focused selection **427 passed, 1 deselected** (unrelated repository-wide index failure), `git diff --check` clean. No live target traffic.

## Blockers and deferred work

- No known implementation blocker. This task does not authorize live target traffic or Hoster rollout. The unrelated, unchanged-beta README contract failures remain a full-suite baseline exception, not a task-owned repair.
- If an intended browser collection contract is not supported by the existing analyzer, describe the gap rather than inventing a new command or claiming dynamic coverage.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-input-sink-discovery`
- **Latest immutable recovery checkpoint:** `0988493bac62a7cd5ee43a02d83c6e1e31e898ec`
- **Feature implementation commit(s):** `3a2d22ccce8844543c093bcd30d83b26385c7607`, `a9f34ceb7946416b79c5b92b2500a5904823bbc2`, `0988493bac62a7cd5ee43a02d83c6e1e31e898ec`
- **Exact resume point:** beta merge/push excluding this branch-local dossier, run integrated checks and verify local skill projection. Hoster remains a separate activation decision.
- **Working-tree state at handoff:** clean after this dossier-only follow-up commit; latest material checkpoint remains `0988493`.

## Decision gates

- **Integration gate:** a coherent committed change, focused and isolated full tests with baseline comparison, independent review, clean beta merge check, beta push and local projection verification.
- **Activation / cohort gate:** beta projection on Ghost; Hoster requires a separate requested rollout, not implied here.
- **Promotion gate:** no `main` promotion requested.

## Decision record

- 2026-10-21 PDT — task claimed; feature worktree from fetched clean beta; two independent read-only audits dispatched. No live target actions.
- 2026-10-21 PDT — rooted the two real analyzer modules, authored on-demand acquisition route and script-map entry, ran focused/source integration tests and isolated full suite; only two unchanged-beta stack-to-program failures remain. Awaiting read-only audit results and release review.
- 2026-10-21 PDT — implementation and initial dossier committed as `3a2d22ccce8844543c093bcd30d83b26385c7607`. This later dossier-only commit records the immutable checkpoint; no beta integration yet.
- 2026-10-21 PDT — reconciled both read-only audits; corrected source-site semantics, static `--page` wording, and conditional browser routing at `a9f34ceb7946416b79c5b92b2500a5904823bbc2`. Reran focused and full tests with no new failures; request fresh release review next.
- 2026-10-21 PDT — independent release review ACCEPT with two MINOR nits; clarified suffix-filtered `--input` and completed script-map owner/date fields at `0988493bac62a7cd5ee43a02d83c6e1e31e898ec`. Narrow re-review, then beta integration, remains.
- 2026-10-21 PDT — independent narrow re-review of `985aac5be9af9946fd3d188c2edd8558ff9d7886` ACCEPT; final correction and tested route are ready for beta merge. Branch-local dossier stays out of beta.
