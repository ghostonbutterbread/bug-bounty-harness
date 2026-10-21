# XSS source/sink discovery routing — integration dossier

- **Status:** implementation checkpoint; independent workflow audit pending
- **Owner:** Hermes / BBH XSS
- **Branch:** `docs/xss-input-sink-discovery`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-input-sink-discovery`
- **Base commit:** `e1bf907671475004f3de268dedf5fc557b771696`
- **Intended integration target:** `beta` (`origin/beta` at the recorded base)
- **Last updated:** 2026-10-21 PDT
- **Owning feature branch/ref:** `docs/xss-input-sink-discovery`
- **Latest immutable recovery checkpoint:** none yet; no implementation committed
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's Discord request in thread `1562231426932539452`, message `1562530135226191904`; `skills/xss/SKILL.md`; `skills/xss/references/source-acquisition.md`; `skills/js-pull/SKILL.md`; `skills/dom-xss/SKILL.md`; `agents/js_analyzer.py`, `agents/xss_source_sites.py`, and `agents/xss_sink_sites.py`.

## Intent

Make XSS agents discover the existing **paired named-input and sink-site** JS inventory and combine it with authorized live application exploration, observed browser Network/Sources/DOM/request behavior, and stack-specific source/sink reasoning. These are complementary ways to find and prioritize candidate paths, not a mandatory scan quota or an exhaustive list. Keep root routing lean and retain the selected XSS lane's proof, policy, and Attempts ownership.

## Implemented contract

The `xss` router now offers an early on-demand source/sink-acquisition route and explicitly connects authorized UI navigation, dynamically loaded JS, browser Network/Sources/DOM observations, stack-specific request/render APIs and paired JS `source_sites`/`sink_sites`. `source-acquisition.md` states that `inventory --page` fetches HTML-linked scripts but does not run client navigation, while browser-observed scoped JS URLs can enter the existing `--input` path. It preserves per-page/flow provenance, source/sink truncation, stack-specific blind spots, and the distinction among a static seed, runtime reachability and a controlled executable path. `skills/xss/scripts/README.md` now records both existing analyzer modules; neither is a standalone live scanner. No executable or target-testing code changed.

## Evidence and review

- Initial `xss` root already mentioned `source_sites`, `sink_sites`, and analyzer under late discovery/script sections, but did not explicitly connect lazy browser loading and DevTools observations to the corpus. The script map documented the named-source module but omitted a separate entry for the sink-site module.
- `js_analyzer.py inventory` accepts `--page` for an HTTP-fetched page's scripts and `--input` for a scoped JS URL list; `--page` alone is not a browser interaction or lazy-route census. Its module calls and persisted output were inspected directly.
- Focused source/sink/analyzer/XSS tests: **403 passed** (initial implementation before final documentation adjustment), plus XSS route/script-policy focused tests **36 passed, 2 failed**; the two failures were reproduced on unchanged beta in `skills/stack-to-program/scripts/README.md` contracts. The first feature run had a task-owned wording assertion failure, corrected by restoring the existing “inventory analysis is static” phrase.
- Full `tests` suite after local `.venv` install: **307 passed, 1 skipped, 2 failed**. Same two unrelated `stack-to-program` failures reproduced on unchanged beta with the same interpreter. An initial attempt using the beta worktree's interpreter failed 15 additional launcher subprocess subtests because this worktree had no `.venv`; `./setup.sh --install-python-deps` resolved those setup failures. No live targets contacted.
- Independent workflow audits and release review: pending.

## Blockers and deferred work

- No known implementation blocker. This task does not authorize live target traffic or Hoster rollout. The unrelated, unchanged-beta README contract failures remain a full-suite baseline exception, not a task-owned repair.
- If an intended browser collection contract is not supported by the existing analyzer, describe the gap rather than inventing a new command or claiming dynamic coverage.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-input-sink-discovery`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** reconcile the two read-only tooling/routing audits against the implemented route, amend any concrete gaps, rerun focused/full tests as needed, then obtain independent release review before beta integration.
- **Working-tree state at handoff:** implementation and dossier uncommitted until next checkpoint; do not infer a commit from this record.

## Decision gates

- **Integration gate:** a coherent committed change, focused and isolated full tests with baseline comparison, independent review, clean beta merge check, beta push and local projection verification.
- **Activation / cohort gate:** beta projection on Ghost; Hoster requires a separate requested rollout, not implied here.
- **Promotion gate:** no `main` promotion requested.

## Decision record

- 2026-10-21 PDT — task claimed; feature worktree from fetched clean beta; two independent read-only audits dispatched. No live target actions.
- 2026-10-21 PDT — rooted the two real analyzer modules, authored on-demand acquisition route and script-map entry, ran focused/source integration tests and isolated full suite; only two unchanged-beta stack-to-program failures remain. Awaiting read-only audit results and release review.
