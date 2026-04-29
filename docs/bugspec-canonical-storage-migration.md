# Bugspec: Canonical Storage Migration

## Status

Draft: 2026-04-29

Scope: `bug_bounty_harness` migration to `bounty_core` canonical storage, ledger, report, and artifact boundaries.

This is a backlog/spec document, not an implementation patch. Each implementation pass should be bounded, covered by tests, and followed by a spawned reviewer agent focused on regressions and migration direction.

## Completed Progress

- `report_checker` now propagates explicit `--root`/`root_override` through ledger reads, markdown reads, validation report writes, and ledger refresh without falling back to default home storage.
- Status markdown detection now uses the same readable status-path rules as `report_checker`, so arbitrary canonical markdown and seeded indexes do not suppress legacy read fallback.

## Goals

- Make `bounty_core.storage` the single resolver for canonical `family/program/lane` layout.
- Make `bounty_core.ledger` the long-term source of truth for findings and finding state.
- Keep recon/raw artifacts under `recon/` or `working/`; promote only high-confidence vulnerability candidates to the ledger.
- Preserve read-only fallback from legacy `~/Shared/bounty_recon/...` during migration.
- Ensure new writes use canonical `~/Shared/<family>/<program>/<lane>/...` paths, or an explicit local root override.
- Keep migration work reviewable as small BUGSPEC items with clear tests.

## Non-Goals

- Do not rewrite all agents in one pass.
- Do not remove legacy fallback reads until all active readers have canonical equivalents and migration tests.
- Do not change finding identity or dedupe semantics without a ledger-specific review.
- Do not move high-volume recon output into `ledger.json`.
- Do not create parallel report path conventions while `bounty_core.reports` is the intended destination.
- Do not treat seeded report index markdown as user-authored raw reports.

## Current Architecture Map

| Module | Current responsibility | Canonical direction |
| --- | --- | --- |
| `agents/storage_resolver.py` | Compatibility facade over `bounty_core.storage`; exposes `resolve_storage`, `resolve_family_lane`, `StorageLayout`, context writers. | Keep as thin facade until callers import `bounty_core.storage` directly. No path policy should live here beyond compatibility glue. |
| `bounty_core.storage` | Canonical family/program/lane resolver and layout object. | Single owner of roots like `reports_root`, `ledgers_root`, `recon_root`, `working_root`, `context_root`, `notes_root`. |
| `agents/ledger.py` | Connected-team ledger wrapper; delegates to `agents.ledger_v2`. | Become thin adapter to `bounty_core.ledger`, preserving harness API while centralizing writes. |
| `agents/ledger_v2.py` | Version-aware `ledger.json` implementation with snapshot sightings and locks. | Migrate or wrap through `bounty_core.ledger`; only one module should own `ledger.json` write semantics. |
| `bounty_core.ledger` | Target source of truth for finding append/update/list/read. | Own `ledger.json`, locks, dedupe, sightings, status, provenance, and report refresh hooks. |
| `agents/report_paths.py` | Canonical and legacy report source selection; filters seeded indexes. | Collapse into `bounty_core.reports` path/index helpers, keeping legacy fallback read-only. |
| `agents/report_checker.py` | Reads ledger and markdown reports; resolves source files; can run chainer. | Read findings from ledger first; report markdown should be derived/index data unless explicitly imported. |
| `agents/report_generator.py` | Generates report output from findings. | Use `bounty_core.reports` for all canonical report paths and indexes. |
| `agents/manual_hunter.py` | Creates manual findings, reports, coverage, and sync flow. | Write findings via `bounty_core.ledger`; write raw drafts under canonical `reports/raw` or `working`, then promote. |
| `agents/sync_reports.py` | Imports markdown reports into ledger; now has `--root`/`storage_root` and `--source-root` plumbing. | Keep import path explicit; source root precedence is `--source-root`, shared-brain `target_root`, then `--source-dir` fallback. |
| `agents/coverage_store.py` | Stores source coverage indexes using canonical storage with legacy fallback. | Keep storage-root propagation explicit; coverage is supporting state, not findings ledger state. |
| `agents/shared_brain.py` | Builds and loads source indexes with canonical path plus legacy fallback. | Continue read fallback; new shared-brain writes go canonical only. |
| `agents/base_team/storage.py` | BaseTeam storage compatibility with `output_root`. | Normalize root naming and delegate resolution to `bounty_core.storage`. |
| `agents/base_team/reports.py` | Dated report index writing helpers. | Replace duplicated path rules with `bounty_core.reports`; retain compatibility indexes only as derived views. |
| `agents/base_team/review.py` | Review gate behavior. | Should consume ledger candidates and write final decisions through ledger APIs. |
| `agents/chainer.py` | Reads reports and writes chained report output; still defaults to legacy paths. | Read canonical ledger/report indexes first; write chain outputs under canonical `reports/` or `working/`. |
| Legacy recon modules | Many modules still hard-code `~/Shared/bounty_recon/...`. | Migrate durable outputs to canonical `recon/` or `working/`; legacy paths become read-only import/fallback. |

## Invariants

Every future patch must preserve these:

1. Explicit root propagation wins. Any caller given `--root`, `storage_root`, `root_override`, or equivalent must write only under that explicit root.
2. Canonical default writes go under `~/Shared/<family>/<program>/<lane>/...`, not `~/Shared/bounty_recon/...`.
3. Legacy `~/Shared/bounty_recon/...` may be read as fallback only when canonical data is absent or when a user explicitly selects a legacy source.
4. `ledger.json` is the durable findings source of truth. Markdown reports and indexes are views, import sources, or human-readable artifacts.
5. Raw recon/tool output stays in `recon/` or `working/`. The ledger receives only normalized, high-confidence candidates with provenance.
6. Seeded canonical report index placeholders are not raw user reports. `discover_report_files()` must exclude generated `index.md` placeholders.
7. Source-root resolution for sync/import is deterministic: explicit `source_root`, then shared-brain `target_root`, then source-dir/program fallback.
8. Snapshot and coverage metadata must survive promotion: preserve `snapshot_id`, `version_label`, `run_id`, `agent`, and evidence references.
9. Family/lane inference must remain explicit for non-default lanes. Unknown custom lanes must not be silently routed.
10. A migrated module must not duplicate canonical path composition once a `bounty_core` helper exists.
11. `bounty_core.reports` may generate derived views, but it must not become a second source of truth for finding state.
12. Legacy fallback paths must include a reason and a removal condition before they survive a migration PR.

## BUGSPEC-1: Normalize Root Naming

Problem: Root naming is inconsistent across `output_root`, `root_override`, `storage_root`, and CLI `--root`. The inconsistency makes it easy to drop explicit-root propagation between storage, ledger, reports, coverage, and review paths.

Why it matters: A missed root override can write test data or migration output into real `~/Shared` state, or split one run across two roots.

Acceptance criteria:

- Public CLIs use `--root` for explicit canonical storage root overrides.
- Internal APIs converge on one name, preferably `storage_root`, with compatibility aliases only at boundaries.
- Passing both `root_override` and `storage_root` with different resolved paths raises `ValueError`.
- Tests assert explicit-root writes do not create or mutate default `~/Shared/<family>/<program>/<lane>` data.

Test strategy:

- Extend `agents/test_sync_reports.py`, `agents/test_manual_hunter.py`, `agents/test_coverage_store.py`, and `agents/test_ledger_v2.py`.
- Add assertions that `--root <tmp>/storage` writes `ledgers/ledger.json`, `reports/`, and coverage files only under `<tmp>/storage`.
- Add a conflict test equivalent to `root_override=/a`, `storage_root=/b` raising `ValueError`.

Risk level: Medium. Root plumbing touches many call sites but should be behavior-preserving.

Suggested files: `agents/storage_resolver.py`, `agents/ledger.py`, `agents/ledger_v2.py`, `agents/manual_hunter.py`, `agents/sync_reports.py`, `agents/coverage_store.py`, `agents/base_team/storage.py`, `agents/test_*`.

## BUGSPEC-2: Make One Ledger Owner

Problem: `agents/ledger_v2.py` and `bounty_core.ledger` both touch `ledger.json` semantics. `agents/ledger.py` is a wrapper but still delegates to local `ledger_v2`, leaving two likely sources of truth.

Why it matters: Split ledger ownership risks incompatible locking, dedupe, sightings, migration, and report-refresh behavior.

Acceptance criteria:

- Exactly one implementation owns `ledger.json` read/write/lock/update behavior.
- Harness APIs can remain as adapters, but direct writes go through `bounty_core.ledger` or an explicitly documented temporary adapter.
- Snapshot sightings preserve current fields: `first_snapshot`, `last_snapshot`, `sightings[]`, `snapshot_id`, `version_label`, `run_id`, and `agent`.
- Existing tests for duplicate findings across snapshots still pass.
- New tests assert a finding added through the harness wrapper is visible through `bounty_core.ledger.list_findings()` and vice versa.
- Existing `ledger_v2` fixtures can be read by `bounty_core.ledger` without mutation unless an explicit migration or write occurs.
- Round-trip read/write preserves unknown and legacy fields unless a reviewed migration intentionally normalizes them.
- Historical ledger records retain existing fingerprints, statuses, review fields, sightings, and provenance.
- Locking and concurrent append behavior are tested under the final ledger owner.

Test strategy:

- Port or mirror `agents/test_ledger_v2.py` against `bounty_core.ledger`.
- Add fixture-based migration tests before replacing or wrapping `ledger_v2`.
- Add a mixed API test using one explicit storage root:
  - add via harness wrapper;
  - read via bounty-core;
  - update via bounty-core;
  - read via harness wrapper;
  - assert one `ledger.json` path.
- Add round-trip tests with legacy fixture fields and a concurrent append test against the final owner.

Risk level: High. Ledger changes affect dedupe, review state, and historical findings.

Suggested files: `agents/ledger.py`, `agents/ledger_v2.py`, `agents/findings_ledger.py`, `agents/base_team/ledger.py`, `agents/report_checker.py`, `agents/test_ledger_v2.py`, `~/projects/bounty-core/bounty_core/ledger.py`.

## BUGSPEC-3: Centralize Report Path Logic

Problem: Report path logic is duplicated across `report_paths`, `report_checker`, `report_generator`, `manual_hunter`, `base_team/reports`, and `chainer`.

Why it matters: Duplicated report rules cause inconsistent fallback order, raw/import behavior, dated index creation, and canonical-vs-legacy writes.

Acceptance criteria:

- `bounty_core.reports` owns canonical report roots, raw report paths, and derived status/type index refresh, but not finding state.
- `agents/report_paths.py` becomes a compatibility facade or disappears after callers migrate.
- Readers use canonical reports first, then explicit source paths, then legacy fallback only as read-only compatibility.
- Writers never default to `~/Shared/bounty_recon/...`.
- Seeded report indexes are excluded from raw markdown imports.
- Report regeneration is idempotent.
- Generated indexes are clearly marked as derived views and are never import sources.

Test strategy:

- Extend `agents/test_sync_reports.py` to assert seeded `reports/raw/<type>/index.md` and `reports/index/*.md` are not imported.
- Add path tests for `report_checker` and `chainer` showing canonical report roots are preferred over legacy ghost roots.
- Add regeneration tests that run refresh twice and assert stable content plus no duplicate index entries.
- Grep-style test or script check: active migrated report writers must not contain `Path.home() / "Shared" / "bounty_recon"`.

Risk level: Medium-high. Report readers and writers are widely used and user-visible.

Suggested files: `agents/report_paths.py`, `agents/report_checker.py`, `agents/report_generator.py`, `agents/manual_hunter.py`, `agents/base_team/reports.py`, `agents/chainer.py`, `agents/test_sync_reports.py`, `~/projects/bounty-core/bounty_core/reports.py`.

## BUGSPEC-4A: Define Finding Lifecycle and Status Taxonomy

Problem: Raw candidates, review decisions, and report buckets are currently described with overlapping labels.

Why it matters: Mixing lifecycle status with classifications like `novel` or derived buckets like `dormant` makes ledger filters ambiguous and risks promoting speculative data as durable findings.

Acceptance criteria:

- Define lifecycle separately from review classification and report buckets.
- Raw artifacts are a pre-ledger state stored under `recon/`, `working/`, or `reports/raw`; they are not final ledger statuses.
- Ledger lifecycle statuses are explicit and minimal, for example `candidate`, `pending_review`, `confirmed`, `rejected`, and `archived`.
- `novel` is a review classification/outcome, not a lifecycle status.
- `dormant` is a derived report bucket or review queue based on sightings/review metadata, not a canonical lifecycle status.
- Ledger list/read APIs can filter by lifecycle status without reading markdown reports.

Test strategy:

- Add tests for lifecycle filters using ledger-only data.
- Add tests that `novel` classification and `dormant` derived bucket do not overwrite lifecycle status.
- Add report-checker tests that ledger findings are sufficient even when markdown report indexes are absent.

Risk level: Medium-high. Taxonomy changes affect review queues and counts.

Suggested files: `agents/report_checker.py`, `agents/base_team/review.py`, `agents/ledger.py`, `agents/ledger_v2.py`, `~/projects/bounty-core/bounty_core/finding.py`, `~/projects/bounty-core/bounty_core/ledger.py`.

## BUGSPEC-4B: Implement Raw-to-Ledger Promotion Gates

Problem: `sync_reports.py` can parse loose markdown and promote it before the candidate has enough normalized evidence.

Why it matters: The ledger should represent durable, high-confidence candidates and reviewed findings. Raw tool output and speculative notes should not pollute dedupe or reviewer queues.

Acceptance criteria:

- Raw markdown under `reports/raw` or `working` is not automatically treated as ledger data.
- Promotion requires minimum fields: title/type, class, file or affected asset, description, evidence/provenance, source label, `run_id`, and `agent`.
- Promotion records source markdown and artifact paths in provenance without making those paths the source of truth.
- Promotion preserves `snapshot_id`, `version_label`, `run_id`, `agent`, and evidence references.
- Failed promotion leaves the raw artifact available for later review with a clear reason.

Test strategy:

- Add sync tests for markdown missing `file` or affected asset: it is skipped or left raw, not promoted.
- Add tests for promotion preserving `manual_source_label`, `run_id`, `agent`, `snapshot_id`, and evidence references.
- Add tests that failed promotion writes or returns a reason without mutating `ledger.json`.

Risk level: High. This changes what enters the ledger and can affect triage counts.

Suggested files: `agents/sync_reports.py`, `agents/manual_hunter.py`, `agents/ledger.py`, `agents/ledger_v2.py`, `~/projects/bounty-core/bounty_core/finding.py`, `~/projects/bounty-core/bounty_core/ledger.py`.

## BUGSPEC-4C: Update Sync/Manual Import Paths

Problem: Manual and generated reports can look like final findings before review, and sync/import paths still blur raw source files with ledger entries.

Why it matters: Import paths need the same promotion behavior so manual work, synced markdown, and generated candidates do not create parallel finding state.

Acceptance criteria:

- `manual_hunter` writes drafts and raw notes under canonical raw/working locations before promotion.
- `sync_reports.py` imports only explicit source roots and applies the promotion gate from BUGSPEC-4B.
- Imported ledger records point back to source markdown/artifacts through provenance, not through report path ownership.
- Legacy fallback import paths remain read-only, documented with a reason, and paired with a removal condition.
- Sync/manual flows use the lifecycle taxonomy from BUGSPEC-4A and do not write `novel` or `dormant` as lifecycle statuses.

Test strategy:

- Add manual import tests that draft/raw files stay outside the ledger until promotion succeeds.
- Add sync tests for explicit source root, shared-brain target root, and source-dir fallback.
- Add regression tests that legacy fallback reads do not create new legacy writes.

Risk level: High. Sync and manual import are user-facing and feed the canonical ledger.

Suggested files: `agents/sync_reports.py`, `agents/manual_hunter.py`, `agents/report_checker.py`, `agents/report_paths.py`, `agents/test_sync_reports.py`, `agents/test_manual_hunter.py`.

## BUGSPEC-5: Finish Source-Root and Snapshot Precedence

Problem: Source-root and snapshot resolution has recently been fixed in `sync_reports.py`, but similar logic exists in `manual_hunter`, `report_checker`, `coverage_store`, `shared_brain`, and `me_ledger`.

Why it matters: If source roots differ across import, coverage, and review, snapshot IDs and file resolution drift.

Acceptance criteria:

- Shared precedence is documented and reused: explicit `source_root`, then shared-brain `target_root`, then source-dir/program fallback.
- Coverage writes and ledger sightings use the same source root and snapshot identity for a run.
- CLI output and verbose logs show both `storage_root` and `source_root` when requested.
- Tests cover shared-brain `target_root` winning over source-dir fallback.

Test strategy:

- Extend `agents/test_sync_reports.py` with three precedence cases.
- Add a `manual_hunter` test that `_build_hunt_context()` and coverage use the explicit `source_root`.
- Add a coverage test asserting snapshot ID is derived from the selected source root, not the reports directory.

Risk level: Medium.

Suggested files: `agents/sync_reports.py`, `agents/manual_hunter.py`, `agents/report_checker.py`, `agents/coverage_store.py`, `agents/shared_brain.py`, `agents/me_ledger.py`, `agents/test_sync_reports.py`, `agents/test_manual_hunter.py`, `agents/test_coverage_store.py`.

## BUGSPEC-6: Legacy Writer Migration Batches

Problem: Many older modules still hard-code `~/Shared/bounty_recon/...` for durable outputs.

Why it matters: New writes to legacy paths keep extending the migration window and make canonical state incomplete.

Acceptance criteria:

- Each migrated module resolves storage through `bounty_core.storage` or the harness facade.
- Durable tool outputs go under canonical `recon/<tool>/...` or `working/<tool>/...`.
- Findings promoted from those outputs go through the ledger owner from BUGSPEC-2.
- Legacy paths remain only in read-only fallback functions, explicit import flags, tests that verify fallback, or historical documentation.
- Every retained legacy fallback has a documented reason and removal condition.
- A grep audit is attached to each migration PR with every remaining `bounty_recon` occurrence classified as read fallback, test fixture, doc, or not-yet-migrated module.

Test strategy:

- Add module-specific path tests for migrated tools.
- Run `rg -n "bounty_recon|Path.home\\(\\) / \"Shared\"" agents --glob '!__pycache__/**'` before and after each pass.
- For each migrated writer, assert default output path starts with the resolved canonical lane root.

Risk level: Medium. Each module can be migrated independently.

Suggested files: `agents/apk_analyzer.py`, `agents/chainer.py`, `agents/retard_collaboration.py`, `agents/google_dorker.py`, `agents/xss_browser_hunter.py`, `agents/waf_interceptor.py`, `agents/bypass_harness.py`, `agents/autonomous_recon.py`, `agents/ai_recon.py`, `agents/subdomain_agent.py`, `agents/scope_puller.py`, `agents/scope_manager.py`, `agents/scope_validator.py`, `agents/findings_ledger.py`, `agents/dynamic_agent_builder.py`.

## BUGSPEC-7: Canonical Recon Run Layout

Problem: Recon modules write different directory shapes and often mix raw artifacts, parsed candidates, reports, and findings.

Why it matters: Reviewers and future agents need a predictable place for raw data, manifests, and promotion decisions.

Acceptance criteria:

- `bounty_core.recon` or an equivalent harness facade creates:

```text
{lane}/recon/<tool>/<target>/runs/<YYYY-MM-DD>/<run_id>/
  command.txt
  stdout.txt
  stderr.txt
  raw/
  parsed/
  manifest.json
```

- `manifest.json` records command, timestamps, exit code, output files, parsed counts, promoted finding IDs, and errors.
- Every recon manifest has a stable machine-readable schema and version field.
- Raw outputs are kept even when no finding is promoted.
- Promotion links ledger findings back to `manifest.json` and source artifact paths.

Test strategy:

- Add unit tests for recon path creation and manifest shape.
- Add schema/version tests for each manifest writer.
- Migrate one low-risk recon writer first, then use its tests as the template for later modules.
- Assert no recon writer stores raw output directly under `ledgers/` or final status report indexes.

Risk level: Medium.

Suggested files: `~/projects/bounty-core/bounty_core/recon.py`, `agents/storage_resolver.py`, `agents/google_dorker.py`, `agents/ai_recon.py`, `agents/subdomain_agent.py`, `agents/autonomous_recon.py`, `agents/screenshot_tool.py`.

## BUGSPEC-8: Review and Report Derived Views

Problem: Review, report, and chain flows still rely on markdown report directories as if they were authoritative state.

Why it matters: Once the ledger is canonical, report markdown should be reproducible from ledger data and indexes should not drive core state.

Acceptance criteria:

- `report_checker` can operate from ledger records without requiring markdown status reports.
- `report_generator` and `bounty_core.reports` can regenerate status/type indexes from ledger contents.
- `chainer` reads chainable findings from ledger or an explicit JSON input, not only `reports_<hunt_type>`.
- Dated compatibility indexes remain derived and can be deleted/recreated without losing finding state.
- Generated indexes are visibly marked as derived and are not accepted as import sources.
- Report regeneration is idempotent.

Test strategy:

- Add tests with only `ledgers/ledger.json` present and no markdown reports; report-checker still lists/reviews findings.
- Add report regeneration test: delete `reports/confirmed`, run refresh, assert expected `reports/confirmed/<type>/index.md` or compatibility index is restored.
- Run report regeneration twice and assert stable output.
- Add chainer test with explicit reviewed-findings JSON and canonical storage root.

Risk level: Medium-high.

Suggested files: `agents/report_checker.py`, `agents/report_generator.py`, `agents/chainer.py`, `agents/base_team/review.py`, `agents/base_team/reports.py`, `~/projects/bounty-core/bounty_core/reports.py`, `~/projects/bounty-core/bounty_core/indexes.py`.

## Ordered Roadmap

1. Root naming and propagation (BUGSPEC-1)
   - Normalize `--root`/`storage_root` adapters.
   - Add conflict and no-default-write tests.
   - Spawn a reviewer after implementation.

2. Ledger ownership (BUGSPEC-2)
   - Decide whether `ledger_v2` moves into `bounty_core.ledger` or becomes a strict adapter.
   - Add fixture migration, mixed API, round-trip, and concurrent append tests over one `ledger.json`.
   - Spawn a reviewer after implementation.

3. Source-root/snapshot precedence (BUGSPEC-5)
   - Reuse deterministic source-root precedence across sync, manual, coverage, review, and shared-brain flows.
   - Assert shared-brain `target_root` wins over source-dir fallback.
   - Spawn a reviewer after implementation.

4. Report path centralization (BUGSPEC-3)
   - First bounded cleanup: tighten legacy status wildcard matching so `confirmed_*`, `dormant_*`, and `novel_findings_*` compatibility files are markdown-only.
   - Add a date-shaped canonical status-dir predicate, but defer enforcement unless tests explicitly prove existing non-date compatibility can be removed or safely warned.
   - Move canonical report root/index rules into `bounty_core.reports`.
   - Keep `report_paths.py` as compatibility glue.
   - Assert seeded and derived indexes are never imported as raw reports.
   - Spawn a reviewer after implementation.

5. Source-root/snapshot or ledger ownership next pass
   - Prefer BUGSPEC-5 if the next change stays path/precedence-focused: reuse source-root and snapshot precedence across sync, manual, coverage, review, and shared-brain flows.
   - Prefer BUGSPEC-2 if the next change touches finding state: consolidate ledger ownership behind one `ledger.json` implementation with migration fixtures.
   - Spawn a reviewer after implementation.

6. Review/report derived views (BUGSPEC-8)
   - Make review and report flows operate from ledger data first.
   - Keep compatibility indexes regenerable and explicitly derived.
   - Spawn a reviewer after implementation.

7. Raw-vs-ledger lifecycle taxonomy (BUGSPEC-4A)
   - Separate lifecycle statuses from review classifications and report buckets.
   - Clarify `novel` and `dormant` semantics before import behavior changes.
   - Spawn a reviewer after implementation.

8. Raw-to-ledger promotion gates (BUGSPEC-4B, BUGSPEC-4C)
   - Enforce minimum fields and provenance before promotion.
   - Update sync and manual import paths to keep raw artifacts separate.
   - Spawn a reviewer after implementation.

9. Canonical recon run layout (BUGSPEC-7)
   - Introduce stable recon run directories and versioned manifests.
   - Migrate one low-risk recon writer as a template.
   - Spawn a reviewer after implementation.

10. Legacy writer migration batches (BUGSPEC-6)
   - Migrate older hardcoded writers in small groups by domain: report/chain, recon/web, binary/APK, scope utilities.
   - Attach a classified grep audit to each PR.
   - Spawn a reviewer after each implementation batch.

## Reviewer Checklist

For every implementation pass, check:

- Did the pass modify only the intended module group?
- Are new writes canonical or under an explicit local root?
- Are legacy `~/Shared/bounty_recon/...` paths read-only fallback, explicit import input, tests, or docs?
- Does explicit `--root`/`storage_root` propagate through ledger, reports, coverage, review, and sync paths?
- Does any module manually compose a path that `bounty_core.storage` or `bounty_core.reports` should own?
- Is `ledger.json` written by only the intended ledger owner?
- Are raw artifacts kept out of the final ledger unless normalized and promoted?
- Are seeded index markdown files excluded from raw import discovery?
- Does source-root precedence match the invariant?
- Do tests cover both canonical default storage and explicit-root storage?
- Did the implementation spawn a reviewer after code changes, and were reviewer findings addressed or explicitly deferred?

## Do-Not-Touch-Yet Cautions

- Do not delete legacy fallback readers until a migration/import plan exists for historical `~/Shared/bounty_recon/...` data.
- Do not keep a legacy fallback unless it has a clear reason and removal condition.
- Do not mass-edit all `bounty_recon` references in one patch; classify and migrate by writer/reader role.
- Do not alter finding fingerprint semantics casually. Dedupe changes require historical ledger compatibility tests.
- Do not replace `ledger_v2` behavior before fixture-based migration tests prove historical ledgers are preserved.
- Do not remove dated report indexes until downstream scripts no longer depend on them; keep them as derived compatibility views first.
- Do not let `bounty_core.reports` write or infer canonical finding state; it may only render derived views from the ledger.
- Do not move source snapshots or coverage state into the findings ledger.
- Do not promote recon scanner output directly to confirmed findings without normalization, provenance, and review-tier handling.
- Do not make `bug_bounty_harness` clone or vendor `bounty-core`; keep the local editable dependency model.
