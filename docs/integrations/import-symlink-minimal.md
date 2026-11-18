# Minimal report-import symlink fix integration dossier

- **Status:** blocked for independent review and provider collision resolution; not integrated
- **Owner:** delegated BBH worker; parent owns review and integration
- **Branch / owning ref:** `fix/import-symlink-minimal`
- **Worktree:** `/home/ryushe/worktrees/bbh-import-symlink-minimal`
- **Base:** fetched `origin/beta` at `15a3e94d91759af8386d2e8688acb308ae691fca`
- **Target:** `beta`; no stable promotion or runtime activation authorized
- **Implementation / immutable recovery checkpoint:** `17034fcd9b87bc793c1850ba766b79f46e07b55d`; branch tip includes a later dossier-only commit
- **Date:** 2026-11-17
- **Inspiration:** real CLI false finding caused by a Core category link; the broader `fix/promo-report-source` candidate is blocked and was not transplanted.

## Implemented contract

Automatic canonical reports-root discovery and the subsequent import scan both ignore symlinks at Core's `categories/<category>/<fid>.md` navigation location. Existing generated-marker filtering continues to exclude marked fallback stubs. Ordinary real raw reports, raw symlinks, and explicitly selected external symlink sources remain eligible; this is not a blanket symlink ban or a Markdown-based ownership inference. The change intentionally does not claim to identify all provider packets or solve ambiguous raw packet ownership.

## Evidence and review

The real `scripts/bbh agents/sync_reports.py` test initially failed on the unmodified base: the second import selected `canonical_reports`, read the category symlink to existing evidence, and added a false D02 instead of the home source. It now selects `source_reports` and imports only the real second source. Six real CLI tests cover this, mixed canonical real-plus-link inputs, generated stub, ordinary raw file, raw symlink and explicit external symlink.

- On the pinned Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`: `python -m unittest -q agents.test_report_source_cli agents.test_sync_reports agents.test_report_checker agents.test_finding_report` — **77 passed**.
- Same 77 tests also passed against the clean Core promotion worktree at `6142defb3de7cef44887c1685e4f670072585785`.
- Baseline `15a3e94d91759af8386d2e8688acb308ae691fca`, same pinned Core, same environment, without the six new tests: the three existing modules above — **71 passed**.
- All runs used `python:3.12-slim` Docker with `--network none`, an isolated copy of the BBH tree and fresh `.venv`, read-only Core source, `/work` as disposable HOME/XDG/TMPDIR, `PYTHONPATH=/bbh:/core` and `BBH_SKIP_DEP_CHECK=1`; no production store writes. The pinned Core source was extracted by `git archive` into `/home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core`. Example candidate command from the worktree:

```sh
docker run --rm --network none -v "$PWD:/source:ro" -v /home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core:/core:ro -e BBH_SKIP_DEP_CHECK=1 python:3.12-slim sh -ec 'mkdir /bbh /work; cp -a /source/. /bbh/; python -m venv /bbh/.venv; printf "/core\n" > /bbh/.venv/lib/python3.12/site-packages/core.pth; cd /bbh; export HOME=/work XDG_CONFIG_HOME=/work/config XDG_DATA_HOME=/work/data XDG_CACHE_HOME=/work/cache TMPDIR=/work PYTHONPATH=/bbh:/core; /bbh/.venv/bin/python -m unittest -q agents.test_report_source_cli agents.test_sync_reports agents.test_report_checker agents.test_finding_report'
```

Independent review has not occurred. Parent must review the full branch diff and receipts before integration. Kanban CLI refused this delegated child context; parent owns tracking.

## Blocker: Core raw namespace collision

Pinned and current Core both accept `fid=raw` and `reserve_finding_evidence_packet` adopts existing `reports/raw` as its packet. A disposable probe made a legitimate `reports/raw/EVIDENCE.md`, called `ensure_finding_evidence_packet` for FID `raw`, and observed `same_path=True bytes_preserved=True`: Core claimed the pre-existing raw file as packet evidence without detecting the ownership collision. The probe is `/home/ryushe/.hermes/cache/scratch/bbh-import-minimal-core-probe.py`. Byte preservation is not collision detection; the consumer cannot reliably distinguish an unregistered packet from a real source when names and bytes overlap. This branch does not silently classify the ambiguous path as a packet, and does not claim collision protection.

**Provider requirement:** reserve source/navigation namespaces including `raw`, and allocate new packets in a disjoint namespace or provide durable provider-owned file ownership. Refuse/report collisions before adopting existing files; never overwrite or silently skip them. Preserve historical ledger pointers and existing files through an explicitly reviewed collision-safe migration/reconciliation. Core owner must fix and test create/reserve/refresh and legacy cases; then rerun an unchanged end-to-end raw-collision scenario expecting both no data loss and correct source import. Do not infer ownership from arbitrary Markdown content. Until that contract is resolved, do not claim the overall collision acceptance criterion or full safe promotion is complete. Other unregistered/markerless provider packets can also remain ambiguous under existing path heuristics.

## Handoff and gates

- **Exact resume point:** independently review `15a3e94d91759af8386d2e8688acb308ae691fca..fix/import-symlink-minimal`, coordinate the Core namespace contract, rerun the real CLI collision probe and focused suites against the exact combined versions.
- **Integration:** parent decision after review; reconcile fresh `origin/beta` if it moved. Dossier remains branch-local and should not land on beta.
- **Activation/promotion:** separate authorization; raw collision remains unresolved. No shared ref merge, push, or runtime activation performed.
