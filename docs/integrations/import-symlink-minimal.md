# Minimal report-import symlink fix integration dossier

- **Status:** explicit category-directory bypass corrected and tested; same-reviewer re-review pending; raw namespace blocker remains; not integrated
- **Owner:** delegated BBH worker; parent owns review and integration
- **Branch / owning ref:** `fix/import-symlink-minimal`
- **Worktree:** `/home/ryushe/worktrees/bbh-import-symlink-minimal`
- **Base:** fetched `origin/beta` at `15a3e94d91759af8386d2e8688acb308ae691fca`
- **Target:** `beta`; no stable promotion or runtime activation authorized
- **Implementation / immutable recovery checkpoints:** `17034fcd9b87bc793c1850ba766b79f46e07b55d` (initial fix), `95858238a510abbeab25bc8dbfdd3ff9b144bfed` (first review correction), `cdf11030de9ce255b3b3a379beddd6533fd6ff63` (category guard), `6a996f8ba40f5761ec7e7502672e5461f315a357` (explicit category-directory correction and tested dossier); branch tip includes a later dossier-only handoff commit
- **Date:** 2026-11-17
- **Inspiration:** real CLI false finding caused by a Core category link; the broader `fix/promo-report-source` candidate is blocked and was not transplanted.

## Implemented contract

Automatic canonical reports-root discovery and scan skip category links only when their resolved targets are within this reports root and recognized by existing generated-output rules. Before source selection, hunter construction, or import, `sync_reports` checks the destination `categories/*/*.md` for symlinks not recognized by those rules. It refuses with an actionable diagnostic rather than lose or silently skip them, including when raw, home, or explicit sources would otherwise be selected. Relocating such a link outside the managed category namespace allows explicit import. Internal ordinary and dangling links are likewise refused. Explicit symlinks elsewhere remain supported. An explicitly selected directory anywhere within the canonical reports root, including aliases, uses the canonical root to recognize and skip generated navigation links; ordinary reports remain importable. The guard is not an atomic lock against concurrent external filesystem changes and applies to this importer, not other Core callers. Existing generated-output path/marker heuristics do not establish durable ownership of ambiguous packet-looking paths; do not claim comprehensive ownership protection.

## Evidence and review

The category loss was reproduced against the real CLI and Core. On the prior `188df48192b5056de3c903cdf972df1fac442d83`, the new refusal tests failed because both automatic and explicit-source invocations returned success and imported, allowing Core to remove the source link. After the guard they pass and compare full disposable fixture trees (file bytes, link targets and directory entries) before and after refusal. The real CLI also verifies relocation and successful explicit import; refusal for internal, dangling, and desired-FID collision links; and the canonical source-root alias case. The alias regression failed before the alias fix with a false imported D02 and passes afterward. Core-generated category links and ordinary external/raw symlinks remain covered.

Latest reviewer correction: the new real-CLI regression failed at `0ad82e9bd270bc2ddaf294eea2a298dc6db8e6ce`, with an explicit `reports/categories/idor` source importing generated `D01.md` as false `D02`; it passes after the correction. It also checks the categories parent, an alias of the category directory, preservation/import of an ordinary category report, and the existing external symlink controls. The unsafe-category refusal test now explicitly selects the unsafe category itself as well as an external source, asserting unchanged fixture trees.

- Pinned Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`: **84 tests passed, zero expected failures**.
- Freshly fetched Core `origin/beta` `6142defb3de7cef44887c1685e4f670072585785`: **84 tests passed, zero expected failures**.
- Suite: `python -m unittest -q agents.test_report_source_cli agents.test_sync_reports agents.test_report_checker agents.test_finding_report`. It exercises real `scripts/bbh` subprocesses, not mocks for these paths. Both runs used the offline Docker isolation described below, with exact `git archive` Core snapshots. Independent re-review of the complete feature diff and correction is pending.

Historical correction receipts (superseded by the above):

The initial real `scripts/bbh agents/sync_reports.py` regression showed an evidence link causing a false D02 on base; the fix uses the home source instead. Independent review then found that the initial blanket category-symlink skip silently selected a lower-priority home report over a real external category source. A real-CLI regression reproduced that failure at `dabd9c9ca678e432830e54688bb57208c477309f`; after the correction the external source wins and imports. Existing real-CLI tests positively generate an evidence link through Core, then verify it is skipped, and verify raw reports, raw links, explicit external links, and generated stubs. A further test preserves discovery of a category link to a real internal source.

- Correction suite, pinned Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`: **80 tests run, 79 pass, 1 expected failure** (the Core navigation deletion blocker below).
- Same suite, freshly fetched Core `origin/beta` at `6142defb3de7cef44887c1685e4f670072585785`: **80 tests run, 79 pass, 1 expected failure**.
- Both runs used the four modules and isolated offline Docker invocation below, with clean Core archives created from the exact commits. The negative assertion was separately run without `expectedFailure` against current Core and failed because the source symlink was deleted. The reviewer reproduction failed before the correction and passed afterward.

Historical initial-fix receipts (before reviewer correction):

- On the pinned Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`: `python -m unittest -q agents.test_report_source_cli agents.test_sync_reports agents.test_report_checker agents.test_finding_report` — **77 passed**.
- Same 77 tests also passed against the clean Core promotion worktree at `6142defb3de7cef44887c1685e4f670072585785`.
- Baseline `15a3e94d91759af8386d2e8688acb308ae691fca`, same pinned Core, same environment, without the six new tests: the three existing modules above — **71 passed**.
- All runs used `python:3.12-slim` Docker with `--network none`, an isolated copy of the BBH tree and fresh `.venv`, read-only Core source, `/work` as disposable HOME/XDG/TMPDIR, `PYTHONPATH=/bbh:/core` and `BBH_SKIP_DEP_CHECK=1`; no production store writes. The pinned Core source was extracted by `git archive` into `/home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core`. Example candidate command from the worktree:

```sh
docker run --rm --network none -v "$PWD:/source:ro" -v /home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core:/core:ro -e BBH_SKIP_DEP_CHECK=1 python:3.12-slim sh -ec 'mkdir /bbh /work; cp -a /source/. /bbh/; python -m venv /bbh/.venv; printf "/core\n" > /bbh/.venv/lib/python3.12/site-packages/core.pth; cd /bbh; export HOME=/work XDG_CONFIG_HOME=/work/config XDG_DATA_HOME=/work/data XDG_CACHE_HOME=/work/cache TMPDIR=/work PYTHONPATH=/bbh:/core; /bbh/.venv/bin/python -m unittest -q agents.test_report_source_cli agents.test_sync_reports agents.test_report_checker agents.test_finding_report'
```

Same independent reviewer must re-review the correction and its affected tests. Parent owns review, integration, and tracking.

## Category-source deletion boundary

Core's `bounty_core/reports.py` `_cleanup_stale_category_entries` unlinks every stale category symlink without checking ownership; `safe_symlink_or_link_stub` can also replace an existing symlink at a desired name. In the disposable real CLI reproduction, the external source file survived and was imported, but its `reports/categories/idor/original.md` source symlink disappeared during the subsequent Core navigation refresh. The BBH guard now refuses that state before mutation and provides a relocation remedy; it does not change Core or protect other Core entry points. Reliable provider ownership/collision handling remains a longer-term requirement. The earlier expected-failure test was replaced by real refusal, no-mutation, and successful relocation/import assertions; there is no claim that Core preserves arbitrary category links during refresh.

## Blocker: Core raw namespace collision

Pinned and current Core both accept `fid=raw` and `reserve_finding_evidence_packet` adopts existing `reports/raw` as its packet. A disposable probe made a legitimate `reports/raw/EVIDENCE.md`, called `ensure_finding_evidence_packet` for FID `raw`, and observed `same_path=True bytes_preserved=True`: Core claimed the pre-existing raw file as packet evidence without detecting the ownership collision. The probe is `/home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core-probe.py`. Byte preservation is not collision detection; the consumer cannot reliably distinguish an unregistered packet from a real source when names and bytes overlap. This branch does not silently classify the ambiguous path as a packet, and does not claim collision protection.

**Provider requirement:** reserve source/navigation namespaces including `raw`, and allocate new packets in a disjoint namespace or provide durable provider-owned file ownership. Refuse/report collisions before adopting existing files; never overwrite or silently skip them. Preserve historical ledger pointers and existing files through an explicitly reviewed collision-safe migration/reconciliation. Core owner must fix and test create/reserve/refresh and legacy cases; then rerun an unchanged end-to-end raw-collision scenario expecting both no data loss and correct source import. Do not infer ownership from arbitrary Markdown content. Until that contract is resolved, do not claim the overall collision acceptance criterion or full safe promotion is complete. Other unregistered/markerless provider packets can also remain ambiguous under existing path heuristics.

## Handoff and gates

- **Exact resume point:** parent obtains same-reviewer independent review of the complete feature range, including the explicit category-directory correction at `6a996f8ba40f5761ec7e7502672e5461f315a357`, heuristic ownership limits, no-mutation refusal, external-source controls, and current/pinned suite receipts. Reconcile fresh `origin/beta` if it moves. Coordinate the unresolved Core raw collision separately before claiming comprehensive collision safety.
- **Integration:** parent decision after review; reconcile fresh `origin/beta` if it moved. Dossier remains branch-local and should not land on beta.
- **Activation/promotion:** separate authorization; raw collision remains unresolved. No shared ref merge, push, or runtime activation performed.
