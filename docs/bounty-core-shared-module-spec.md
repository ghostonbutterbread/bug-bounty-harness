# Bounty Core Shared Module Spec

## Status

Draft: 2026-04-28

Updated: 2026-04-28 after initial `bounty-core` extraction and `bounty-tools` cleanup.

Current state:

- `~/projects/bounty-core` exists with initial storage, finding normalization, ledger append/update, report writing, and index helpers.
- `bounty-tools` has been partially migrated so migrated CLIs use canonical `family/program/lane` routing and conservative ledger promotion.
- Legacy standalone `bounty-tools` report generator modules are being removed in favor of `bounty_core.reports`.
- `bug_bounty_harness` still contains local storage/report/ledger implementations and many legacy `~/Shared/bounty_recon/...` references. This spec now treats harness migration as the next major workstream, not something to do opportunistically.

## Goal

Create a shared `bounty-core` module that lets Bug Bounty Harness and Bounty Tools use the same storage, ledger, finding, report, and agent-context logic while remaining independently cloneable repositories.

Bug Bounty Harness is the current source of truth. The first version of `bounty-core` should extract proven concepts from Bug Bounty Harness, not redesign the whole system from scratch.

## Why

We currently have two related bug bounty codebases:

- `bug_bounty_harness` — current primary autonomous hunting framework.
- `bounty-tools` — older/legacy standalone utility toolkit.

The direction is to keep these repos separate while sharing generic infrastructure:

- reporting logic
- ledger writes
- finding schema
- storage paths
- agent-readable context/indexes
- future skill/tool manifest conventions

This avoids a hard dependency like `bounty-tools -> bug_bounty_harness`, while still letting all tools write structured output into the same framework.

Preferred dependency shape:

```text
bounty-tools ───────┐
                    ├── bounty-core
bug_bounty_harness ─┘
```

## Non-goals for v1

Do not migrate all harness logic at once.

Do not change how `zero_day_team`, `apk_team`, or current BaseTeam-backed flows function until the shared APIs they need are covered by tests.

Do not force every tool to become an AI agent. Thin wrappers around existing tools are preferred.

Do not split primary ledgers by vulnerability type. Use indexes/views instead.

Do not store high-volume recon data in the primary findings ledger. Recon artifacts live under `recon/`; only high-confidence vulnerability candidates promote into the ledger.

Do not clone `bounty-core` inside either repo.

Do not keep legacy `~/Shared/bounty_recon/{program}/ghost/...` writes once a module has a canonical `family/program/lane` path.

## Repository Layout

Recommended local development layout:

```text
~/projects/bounty-core/
~/projects/bug_bounty_harness/
~/projects/bounty-tools/
```

Each repo can include setup logic that checks for `~/projects/bounty-core` and installs it in editable mode:

```bash
pip install -e ~/projects/bounty-core
```

If missing, setup may offer to clone it to `~/projects/bounty-core`, not inside the caller repo.

## Package Name

Python package import name:

```python
import bounty_core
```

Possible repo name:

```text
bounty-core
```

## Proposed v1 Package Structure

```text
bounty_core/
├── __init__.py
├── storage.py           # storage resolver and path creation
├── finding.py           # normalized finding schema and coercion
├── ledger.py            # append/update/dedupe/read/query APIs
├── reports.py           # report generation and report indexes
├── indexes.py           # agent-readable slices by type/status/active context
├── recon.py             # recon run directory + manifest helpers
├── shared_brain.py      # minimal shared brain path helpers, later richer API
└── setup_integration.py # helpers for repo setup scripts
```

Current extracted package already has `storage.py`, `finding.py`, `ledger.py`, `reports.py`, and `indexes.py`. The next shared module to add should be `recon.py` so wrappers do not each reinvent run-directory and manifest handling.

## Canonical Storage Model

The storage model should preserve the current Bug Bounty Harness direction.

Top-level families:

```text
~/Shared/
├── web_bounty/
└── binaries/
```

Default lanes:

```text
web_bounty:
  - web
  - api

binaries:
  - apk
  - exe
  - mac
```

### Routing Contract

Canonical identity is always:

```text
family / program / lane
```

Rules:

- `program` is the normalized bounty program slug.
- `--name`, `--core-program`, and legacy `--program` are input aliases only; all should resolve to canonical `program`.
- Explicit `--family` and `--lane` win over inference.
- `hunt_type=web` and `team_type=0day_team` resolve to `web_bounty/web`.
- `hunt_type=api` resolves to `web_bounty/api`.
- `hunt_type=apk`, `source`, `binary`, `binaries`, and `team_type=apk` resolve to `binaries/apk` unless explicitly overridden.
- Custom lanes require an explicit family. Do not infer unknown lanes silently.
- Compatibility aliases may remain for CLI input, but new writes must use canonical family/program/lane paths.


Example tree:

```text
~/Shared/web_bounty/{program}/
├── shared/
├── web/
│   ├── reports/
│   ├── ledgers/
│   ├── recon/
│   ├── context/
│   ├── notes/
│   └── working/
└── api/
    ├── reports/
    ├── ledgers/
    ├── recon/
    ├── context/
    ├── notes/
    └── working/

~/Shared/binaries/{program}/
├── shared/
├── apk/
│   ├── reports/
│   ├── ledgers/
│   ├── input/
│   ├── context/
│   ├── notes/
│   └── working/
├── exe/
└── mac/
```

## Recon Artifact Design

Recon artifacts are high-volume tool outputs and should be stored separately from the findings ledger.

Canonical run layout for third-party and recon wrappers:

```text
{lane}/recon/<tool>/<target>/runs/<YYYY-MM-DD>/<run_id>/
├── command.txt
├── stdout.txt
├── stderr.txt
├── raw/
├── parsed/
└── manifest.json
```

Rules:

- `tool` is the wrapper/tool name, for example `corsy`, `ffuf`, `github-dorks`, or `subdomain-takeover`.
- `target` is a safe host/asset slug.
- `runs/` is always present so humans can quickly distinguish durable per-target data from run history.
- `YYYY-MM-DD` is local-date or UTC-date, but each wrapper must choose and document one convention. Prefer local date for human workflow unless the tool is explicitly distributed.
- `run_id` should include a timestamp plus a short random suffix, for example `20260428T204200Z_ab12cd34`.
- `manifest.json` is the authoritative inventory for that run. It should include command metadata, output files, counts, exit code, promotion decisions, and links to any bounty-core findings created.
- Raw output is never discarded just because no finding was promoted.

For `web_bounty` lanes, run artifacts live under `recon/`. For `binaries` lanes, extracted apps/source inputs still live under `input/`, but analysis/tool run artifacts should also use a lane-local artifact root. Preferred v1 behavior is to add `recon_root` for binaries as well, or introduce a clearly named `artifacts_root`; do not mix APK analysis runs into `input/` unless they are durable source inputs.

Manifest minimum required fields:

- `tool`, `target`, `program`, `family`, `lane`
- `run_id`, `started_at`, `finished_at`, `exit_code`
- `command_file`, `stdout_file`, `stderr_file`
- `raw_files`, `parsed_files`
- `counts.raw_records`, `counts.parsed_records`, `counts.promotion_candidates`, `counts.promoted_findings`
- `promoted_finding_ids` or `promoted_findings` when any ledger writes occur

Promotion gate:

- Recon wrappers may call `bounty_core.add_finding()` only after a wrapper-specific high-confidence check.
- Examples: verified exploitable CORS with credentials and readable sensitive endpoint, confirmed subdomain takeover, exposed sensitive secret, or deterministic sensitive file exposure.
- Interesting-but-unverified recon stays in `recon/` and may be referenced by notes or handoffs.

## Ledger Design

Ledgers are for machines and agents.

Each program/lane should have one primary ledger:

```text
{lane}/ledgers/
├── ledger.json
├── findings.jsonl
├── archive/
│   ├── 2026-04.jsonl
│   └── 2026-05.jsonl
├── indexes/
│   ├── by_type/
│   │   ├── xss.json
│   │   ├── sqli.json
│   │   ├── ssrf.json
│   │   ├── idor.json
│   │   └── auth.json
│   ├── by_status/
│   │   ├── raw.json
│   │   ├── confirmed.json
│   │   ├── dormant.json
│   │   ├── novel.json
│   │   └── complete.json
│   └── active_slice.json
├── shared_brain/
└── traces/
```

### Ledger Rules

- `ledger.json` is the canonical machine state for current dedupe and finding status.
- `findings.jsonl` is append-only intake/history.
- `archive/` stores older JSONL chunks when active files get too large.
- `indexes/` stores small agent-readable slices.
- Agents should not ingest the full ledger by default.
- Agents should load only the relevant type/status/active context slices.

### Why not one ledger per vuln type?

Do not split primary ledgers by vulnerability type because:

- dedupe needs cross-tool awareness
- chains may connect multiple vulnerability classes
- status changes should update one source of truth
- one primary ledger per program/lane is easier to reason about

Instead, generate filtered indexes:

```text
ledgers/indexes/by_type/xss.json
ledgers/indexes/by_type/sqli.json
ledgers/indexes/by_status/confirmed.json
```

## Report Design

Reports are for human navigation.

Recommended report tree:

```text
{lane}/reports/
├── raw/
│   ├── index.md
│   ├── xss/
│   │   └── index.md
│   ├── sqli/
│   │   └── index.md
│   └── recon/
│       └── index.md
├── confirmed/
│   ├── index.md
│   ├── xss/
│   │   └── index.md
│   ├── sqli/
│   │   └── index.md
│   ├── ssrf/
│   │   └── index.md
│   └── auth/
│       └── index.md
├── dormant/
│   ├── index.md
│   ├── xss/
│   └── sqli/
├── novel/
│   ├── index.md
│   ├── auth/
│   └── chain/
├── complete/
├── archive/
└── index/
    ├── confirmed.md
    ├── dormant.md
    ├── novel.md
    ├── xss.md
    ├── sqli.md
    └── ssrf.md
```

Navigation model:

```text
status -> vulnerability type -> finding/report
```

Example:

```text
reports/confirmed/xss/index.md
reports/dormant/sqli/index.md
reports/novel/auth/index.md
```

Migration rule for current BaseTeam dated indexes:

- Current harness helpers write dated status indexes such as `reports/confirmed/<DD-MM-YYYY>/index.md`.
- During migration, bounty-core should generate the canonical status/type indexes and may also generate dated compatibility indexes.
- Do not delete dated indexes until report readers and skill docs no longer depend on them.
- Long-term canonical navigation is `reports/<status>/<type>/index.md` plus `reports/index/*.md`; dated run/report views are optional derived indexes.

## Finding Schema

`bounty-core` should define a normalized finding object. Inputs from old tools can be coerced into this shape.

Required minimum fields:

```json
{
  "program": "superdrug",
  "family": "web_bounty",
  "lane": "web",
  "type": "xss",
  "status": "raw",
  "severity": "MEDIUM",
  "title": "Reflected XSS in search parameter",
  "asset": "https://www.example.com/search",
  "evidence": [],
  "source_tool": "xss_hunter",
  "source_repo": "bug_bounty_harness",
  "agent": "xss-browser-agent",
  "created_at": "...",
  "updated_at": "..."
}
```

Recommended optional fields:

```json
{
  "url": "https://www.example.com/search?q=...",
  "method": "GET",
  "parameter": "q",
  "request": "...",
  "response_excerpt": "...",
  "repro_steps": [],
  "impact": "...",
  "remediation": "...",
  "confidence": 0.82,
  "tags": ["reflected", "browser-verified"],
  "references": [],
  "sightings": [],
  "snapshot_id": "...",
  "version_label": "..."
}
```

## Finding Identity Contract

`identity` must be stable across status, severity, report path, notes, and review updates. It must not change just because a finding is promoted from `raw` to `confirmed` or because more evidence is added.

Web/API identity should derive from stable comparable anchors such as:

```text
program, family, lane, type, asset/url, method, parameter, status_code, comparable evidence anchor
```

Source/APK identity must support file/symbol-style findings and should derive from stable anchors such as:

```text
program, family, lane, type, file, line or symbol, class_name/vuln_class, source, sink, snapshot/version context
```

Rules:

- `snapshot_id` and `version_label` belong in sightings/provenance unless they are intentionally part of the dedupe boundary.
- `update_finding()` must append an update event to `findings.jsonl`, refresh indexes, and preserve sightings/provenance.
- Existing harness FID lookup behavior must be preserved or explicitly mapped before `ledger_v2.py` is replaced.

## Agent Context Strategy

Large ledgers should not be directly injected into agents.

Agents should receive bounded context from:

```text
context/me_context.md
context/session_handoff.md
ledgers/indexes/active_slice.json
ledgers/indexes/by_type/{type}.json
reports/{status}/{type}/index.md
notes/index.md
```

Example for an XSS run:

```text
context/me_context.md
ledgers/indexes/by_type/xss.json
reports/confirmed/xss/index.md
reports/dormant/xss/index.md
notes/hypotheses/xss.md
```

## Shared Brain

Bug Bounty Harness already uses `shared_brain` concepts. `bounty-core` v1 should not replace this logic. It should only provide path helpers and basic read/write conventions.

Initial scope:

```python
from bounty_core.shared_brain import shared_brain_path, append_note, load_index
```

Later scope:

- claim/query style APIs
- conflict tracking
- delegated context anchors
- agent confidence and provenance

## Setup / Install Strategy

Each repo gets a small setup helper.

Pseudo-flow:

```text
1. Check if bounty_core is importable.
2. If yes, continue.
3. Else check ~/projects/bounty-core.
4. If present, pip install -e ~/projects/bounty-core.
5. If missing, prompt or clone to ~/projects/bounty-core.
6. Never clone bounty-core inside bounty-tools or bug_bounty_harness.
```

Possible shared helper:

```python
from bounty_core.setup_integration import ensure_bounty_core
```

But bootstrapping cannot depend on `bounty_core` before it is installed, so each repo may need a tiny vendored/bootstrap script or shell function.

## Migration Plan

This migration should proceed in small, reviewable phases. Do not start phase N+1 until phase N has tests and the spec is still accurate.

### Phase A — Freeze the contract before more implementation

Deliverables:

- Update this spec with the current state, desired recon layout, and migration boundaries.
- Review the spec with a separate reviewer agent before implementation.
- Add TODO entries for work intentionally deferred.

Acceptance:

- The spec clearly distinguishes recon artifacts from findings.
- The spec names the modules to migrate and the modules not to touch yet.
- The reviewer has no blocking ambiguity about storage paths, promotion rules, or dependency direction.

### Phase B — Finish `bounty-core` APIs needed by both repos

Add or harden shared APIs before moving Bug Bounty Harness onto them:

```text
bounty_core.storage.resolve_storage(program, family, lane, root_override=None, create=True)
  -> StorageLayout

bounty_core.ledger.add_finding(finding, program=None, family="web_bounty", lane="web", root_override=None, write_report=True, refresh=True)
  -> {"is_new": bool, "finding": dict, "layout": dict}

bounty_core.ledger.list_findings(program=None, family=None, lane=None, filters=None, root_override=None)
  -> list[dict]

bounty_core.ledger.get_finding(identity=None, report_path=None, program=None, family=None, lane=None, root_override=None)
  -> dict | None

bounty_core.ledger.update_finding(identity, patch, program, family, lane, root_override=None, refresh=True)
  -> {"ok": bool, "finding": dict, "layout": dict}

bounty_core.recon.start_run(tool, target, program, family, lane, date=None, run_id=None, root_override=None)
  -> ReconRun(layout, run_dir, manifest_path, raw_dir, parsed_dir)

bounty_core.recon.write_manifest(run, manifest)
  -> Path

bounty_core.reports.write_finding_report(layout, finding)
bounty_core.reports.refresh_report_indexes(layout, findings)
```

Acceptance:

- Unit tests cover storage, add/list/update findings, report/index refresh, and recon run manifest creation.
- APIs support `family`, `program`, and `lane` explicitly.
- `add_finding()` preserves provenance fields used by the harness: `snapshot_id`, `version_label`, `sightings`, `source_tool`, `agent`, `run_id`, and evidence references.

### Phase C — Finish `bounty-tools` canonical cleanup

Status: mostly implemented, but should be reviewed/committed separately.

Scope:

- Remove legacy report generator modules from `bounty-tools`.
- Keep any `orchestrator.findings_store` compatibility as a temporary shim only; no per-finding JSON writes.
- Ensure migrated CLIs expose `--name/--core-program`, `--family`, and `--lane`.
- Apply the dated recon run layout to existing wrappers where practical.

Acceptance:

- No migrated `bounty-tools` command writes to `~/Shared/bounty_recon/...`.
- Recon outputs for migrated wrappers use exactly `~/Shared/<family>/<program>/<lane>/recon/<tool>/<target>/runs/<YYYY-MM-DD>/<run_id>/` unless an explicit user-provided output path overrides canonical storage.
- Temporary compatibility paths are allowed only behind explicit legacy flags or read-only import code. New default writes must be canonical.
- Findings are promoted only through `bounty_core.add_finding()`.
- Checklist/inventory modules such as BAC and scope do not promote every row by default.

### Phase D — Migrate Bug Bounty Harness shared plumbing

Start with the shared BaseTeam path because `zero_day_team` and `apk_team` inherit from it.

Primary modules:

```text
agents/storage_resolver.py        -> wrapper/import facade over bounty_core.storage
agents/base_team/storage.py       -> use bounty_core.resolve_storage
agents/base_team/reports.py       -> use bounty_core.reports
agents/base_team/ledger.py        -> either call bounty_core APIs or become a thin compatibility layer
agents/ledger_v2.py               -> migrate snapshot/sighting behavior into bounty-core or wrap bounty-core
agents/base_team_core.py          -> preserve orchestration/review sequencing; delegate storage/report/ledger primitives only
agents/report_checker.py          -> use bounty_core list/update/report APIs
agents/manual_hunter.py           -> use bounty_core add/list/update APIs
agents/sync_reports.py            -> import into bounty_core rather than local ledgers
```

BaseTeam migration must preserve the current pipeline order:

```text
raw agent JSONL -> dedupe/reserve identity -> Stage 2 review -> reviewed ledger update -> report/index refresh
```

Do not call `bounty_core.add_finding()` for every raw agent candidate unless the API explicitly records it as raw intake without promoting it as a reviewed finding. The initial migration should move primitives, not orchestration semantics.

Acceptance:

- Existing BaseTeam-backed flows still run.
- Existing dedupe behavior is preserved or explicitly mapped to bounty-core identities.
- Snapshot/sighting metadata survives round trips.
- Raw/reviewed report indexes are generated by bounty-core.
- Tests cover zero-day/source and APK/binaries lane resolution.

### Phase E — Migrate individual Bug Bounty Harness tools off legacy paths

After BaseTeam is stable, migrate individual modules that still hard-code `~/Shared/bounty_recon`. Prioritize modules that generate durable artifacts or findings.

High-priority modules observed with legacy path references:

```text
agents/ai_recon.py
agents/autonomous_recon.py
agents/scope_manager.py
agents/scope_puller.py
agents/scope_validator.py
agents/subdomain_agent.py
agents/google_dorker.py
agents/xss_hunter.py
agents/xss_browser_hunter.py
agents/ssrf_escalation.py
agents/bypass_harness.py
agents/waf_interceptor.py
agents/chainer.py
agents/retard_collaboration.py
agents/apk_deep_dive.py
agents/apk_analyzer.py
agents/apk_prefingerprint.py
program_config.py
threat_map.py
run_campaign.py
```

Acceptance:

- Each migrated module takes or derives `family/program/lane`.
- Recon-heavy modules write to `recon/<tool>/<target>/runs/<date>/<run_id>/`.
- Finding-producing modules promote through bounty-core only after their existing validation/review gates.
- Legacy paths are removed from implementation after migration, not kept as default behavior.

### Phase F — Update skills, docs, and templates

Scope:

- Replace skill/docs references to `~/Shared/bounty_recon/{program}/ghost/...`.
- Document canonical locations for reports, ledgers, recon, context, notes, working, and input.
- Add third-party wrapper template guidance to the harness docs or shared docs once `bounty_core.recon` exists.

Acceptance:

- New agents receive canonical path instructions.
- Skill wrappers no longer instruct agents to write old `ghost/` paths.
- Docs describe the same storage contract as the code.

### Phase G-0 — Legacy read/import bridge

Before deleting old readers or compatibility shims, provide a read-only bridge for historical data.

Scope:

- Read old `~/Shared/bounty_recon/{program}/ghost/...` reports and ledgers.
- Import or index historical findings into canonical `~/Shared/<family>/<program>/<lane>/...` without writing new data to old paths.
- Provide tests proving old-path findings can be discovered and migrated.

Acceptance:

- Existing historical findings are not silently lost.
- New writes still go only to canonical storage.
- The bridge can be removed later after one explicit migration/audit pass.

### Phase G — Retire compatibility shims

Only after all imports have moved:

- Delete local storage/report/ledger compatibility files that only re-export bounty-core.
- Delete temporary findings-store shims.
- Remove legacy aliases except harmless input aliases such as `--program` mapping to `--name`.

Acceptance:

- Grep for `bounty_recon` in implementation files returns no active writes.
- Grep for local report generator imports returns no active imports.
- Tests pass across `bounty-core`, `bounty-tools`, and key harness modules.

## Compatibility Requirements

- Existing Bug Bounty Harness workflows keep working.
- Existing report paths should remain readable.
- Existing ledger files should migrate or be read backward-compatibly.
- `bounty-tools` can operate without cloning the entire harness.
- Agent context remains bounded and type-specific.
- Reports remain human-readable and navigable.

## Open Questions

1. Should `bounty-core` become a public GitHub repo or private local/internal repo first?
2. Should indexes be regenerated after every write or via explicit `refresh_indexes()`? Current implementation refreshes on write; confirm this remains acceptable for large ledgers.
3. What is the max active ledger size before archival is triggered?
4. Should `active_slice.json` be manually curated, automatically generated, or both?
5. Should report status buckets be promoted only by report checker/reviewer, or can tools mark confirmed directly? Default recommendation: tools write `raw`; reviewers/checkers promote.
6. Should recon run dates use local timezone or UTC? Default recommendation: local date for human navigation, UTC timestamp inside `run_id` and manifest.
7. How long should compatibility shims remain after imports migrate?

## Recommended Next Implementation Step

Do not jump straight into migrating every harness module.

Next concrete step:

1. Add missing `bounty_core.ledger` read/update APIs and `bounty_core.recon` run helpers.
2. Add tests for those APIs.
3. Then migrate `agents/storage_resolver.py` and BaseTeam storage/report/ledger plumbing behind compatibility wrappers.
4. Only after BaseTeam tests pass, start migrating individual harness tools off legacy paths.

This keeps the work bounded and gives sub-agents a concrete contract to implement against.
