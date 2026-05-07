# AppMap Playbook

## Overview

Use AppMap as a static pre-runtime step: map the application, preserve evidence-backed artifacts, and generate focused brainstorm specs. Execution remains owned by `zero_day_team --brainstorm-spec` or `apk_team --brainstorm-spec`.

## Decision Tree

1. Resolve the local target directory and target-kind hint.
2. Run static mapping with `agents/app_mapper.py`; do not launch the application.
3. Review architecture, surfaces, flows, candidates, and rejected candidates.
4. If a generated spec exists, validate it with the brainstorm spec parser.
5. Report the artifact root and the highest-signal candidate chains.
6. For promoted specs, use read-only handoff discovery, validation, and planning before runtime.
7. Hand off to team runtime only on explicit user request.

## 1. Resolve Inputs

Required:

- `program`: stable program name for generated metadata
- `target_path`: local directory containing source or extracted application files

Optional:

- `target-kind`: use `auto` unless the user gives a specific kind such as `electron-exe`
- `focus`: Phase 2 supports `rce`
- `output-mode`: `standalone` for scratch runs, `canonical` for lane storage
- `family` and `lane`: required for canonical storage
- `shared-root`: optional canonical base; defaults to `~/Shared`
- `output-root`: standalone-only custom destination
- `run-id`: use for repeatable tests or comparison runs
- `research-mode`: `local`, `web`, or `hybrid`; default is `local`
- `research-query`: words such as `electron xss`, normalized into DB-ready query metadata
- `research-seed`: repeatable local JSON/JSONL/text research artifacts
- `research-online` and `research-source-url`: opt in to bounded fetches of explicit HTTPS sources; no search or crawling
- `promote-to-brainstorm`: copies generated specs/context packets into a brainstorm area only when explicitly requested

If the target path is missing or ambiguous, ask before running the mapper.

## 2. Run The Mapper

Default command:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/app_mapper.py <program> <target_path> \
  --target-kind auto \
  --focus rce \
  --write-specs
```

With an explicit target kind:

```bash
python3 agents/app_mapper.py canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --target-kind electron-exe \
  --focus rce \
  --write-specs
```

Canonical lane output:

```bash
python3 agents/app_mapper.py canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --target-kind electron-exe \
  --focus rce \
  --write-specs \
  --output-mode canonical \
  --family binaries \
  --lane exe
```

This writes the immutable AppMap run under:

```text
~/Shared/<family>/<program>/<lane>/appmap/<run_id>/
```

Standalone mode remains backward compatible and writes under:

```text
<output-root>/appmap/<run_id>/
```

## 3. Review Artifacts

Inspect:

- `target_profile.json`: detected kind, languages, frameworks, entrypoints
- `architecture.md`: human summary and top candidates
- `surfaces.jsonl`: normalized source, boundary, transform, and sink evidence
- `flows.jsonl`: source-to-sink chains
- `candidates.jsonl`: hypotheses eligible for spec generation
- `rejected_candidates.jsonl`: explicit reasons for discarded evidence
- `generated_specs/rce-spec.md`: parser-compatible brainstorm spec when candidates exist
- `agent_contexts/*.json`: candidate-isolated handoff packets for generated hypotheses
- `manifest.json`: run metadata and artifact pointers for discovery without reading findings ledgers
- `../index.jsonl`: append-only AppMap run index under the lane or standalone `appmap/` root
- `research/research_manifest.json`: optional research manifest with provider, `research_mode`, normalized `research_query`, categories, source URL, fetch status/error, digest, and network-access metadata
- `research/sources.jsonl`: optional cited source records with URL/title/summary/content digest/citation plus `source_type`, `trust_score`, and `validation_status`
- `research/technique_packs.jsonl`: optional explicit JSON/JSONL technique packs with DB-ready query/category/status fields; fetched prose must not be converted into techniques

A candidate should have a plausible attacker-controlled source, a trust boundary, a concrete sink, file evidence, and a question agents can answer.

Agent context packets are runtime handoff inputs, not just archival artifacts. Each packet is one hypothesis + one candidate + one suggested agent. The generated spec links the candidate with `appmap-C####` evidence and may include `appmap-context:<hypothesis_id>:<candidate_id>:<agent_key>` evidence. During normal `--brainstorm-spec` conversion, the harness adapter loads the matching packet from `agent_contexts/` and replaces the broad brainstorm mental model / impact primitive prompt context with the packet.

Packet schema contract:

- `schema_version`: integer packet schema version
- `run_id`, `program`, `focus`
- `candidate`: `id`, `priority`, `score`, `question`, and `map_ids` for candidate, flow, source, boundary, transform, sink, and surface
- `target_profile`: candidate-scoped minimal profile only; do not include whole-profile `frameworks` or `detected_kinds`
- `active_target_packs`: target pack keys derived from the linked candidate evidence only
- `active_vulnerability_pack`: vulnerability pack key such as `rce`
- `hypothesis_linkage`: `hypothesis_id`, `hypothesis_title`, `candidate_id`, `agent_key`, `evidence_refs`, `surface`, `expected_chain`, and `spec_file`
- `focus_files`
- `evidence`: exact source, boundary, optional transform, and sink items with file, line, snippet, confidence, and emitting `target_pack_keys`
- `research`: optional candidate-scoped research with `technique_summaries` and cited `sources`; adapters preserve stable metadata as `appmap_research_technique_ids`, `appmap_research_source_ids`, and `appmap_research_citations`
- `next_steps`

Strict linkage rules: every AppMap hypothesis must reference exactly one `appmap-C####` candidate; missing, duplicate, unknown, or multi-candidate evidence must fail before handoff. If a hypothesis has multiple suggested agents, write one packet per agent using the same candidate evidence.

Research matching is intentionally narrow. A technique applies to a candidate only when its `vulnerability_pack` matches and it declares both matching `target_pack_keys` and matching `applicable_surface_kinds`; missing target or surface applicability is not a wildcard. The only exception is an explicit `applies_to_all: true` technique, which must be used deliberately.

Research module contract:

- Provider/query logic lives in `agents/appmap_research.py`; `agents/app_mapper.py` stays the orchestrator/importer.
- Prefer `--research-mode local|web|hybrid` and `--research-query WORD [WORD ...]`. Compatibility flags `--research-provider local-seed|web-fetch`, `--research-online`, and `--research-source-url` remain accepted where reasonable.
- `--research-query electron xss` is normalized into raw terms, normalized terms, platform candidates, vulnerability candidates, a stable `query_key`, and categories such as `platform:electron` and `vulnerability:xss`.
- `local` reads only repeatable `--research-seed` JSON/JSONL/text fixtures and never performs network I/O, even with `--research-online`.
- `web` fetches only repeatable, operator-supplied `--research-source-url` values and still requires `--research-online`.
- `hybrid` processes local seeds first. It performs the web phase only when both `--research-online` and explicit source URLs are present; otherwise it remains offline and records the skipped web phase.
- Each source URL must be absolute `https://`.
- `web-fetch` performs no search engine scraping, no crawling, no target-app probing, and enforces bounded fetch size/timeouts.
- Fetched pages become cited source records. Technique packs are accepted only from explicit JSON/JSONL research metadata; fetched prose/HTML is never transformed into a technique pack.
- `research_manifest.json` must record provider, research mode/query, categories, `network_access`, source URLs, fetch status/errors, byte counts, content digests, validation status, and artifact paths so the run is replayable from saved artifacts.

## 4. Promote Handoff Artifacts

Promotion is opt-in. It copies only generated specs and `agent_contexts/*.json` into `brainstorm/`; raw `surfaces.jsonl`, `flows.jsonl`, `candidates.jsonl`, and rejected map data stay in the AppMap run root.

Canonical promotion:

```bash
python3 agents/app_mapper.py canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --target-kind electron-exe \
  --focus rce \
  --write-specs \
  --output-mode canonical \
  --family binaries \
  --lane exe \
  --promote-to-brainstorm
```

By default, promotion creates a per-run handoff directory so repeated runs with the same hypothesis, candidate, and agent names cannot collide:

```text
~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id>-<focus>/rce-spec.md
~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id>-<focus>/agent_contexts/
```

The default `--promotion-layout flat` preserves the existing `appmap-<run_id>-<focus>/` layout. To group focus areas under one run directory, opt in with `--promotion-layout category`:

```text
~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id>/<focus>/rce-spec.md
~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id>/<focus>/agent_contexts/
```

Do not overwrite an existing hand-authored `brainstorm/spec.md`. To intentionally target a specific filename inside the per-run handoff directory, use `--promote-spec-name`; if that file exists, promotion fails unless `--overwrite-brainstorm-spec` is also set. Promoted specs resolve only their sibling `agent_contexts/` packets. Promoted specs and packets preserve `AppMap run id`, `AppMap run root`, and packet trace fields back to the originating run.

Standalone promotion requires an explicit brainstorm destination:

```bash
python3 agents/app_mapper.py demo /path/to/source \
  --write-specs \
  --promote-to-brainstorm \
  --brainstorm-root /home/ryushe/Shared/<family>/<program>/<lane>/brainstorm
```

## 5. Discover Promoted Handoffs

```bash
python3 agents/app_mapper.py --list-handoffs \
  --brainstorm-root ~/Shared/<family>/<program>/<lane>/brainstorm
```

Canonical lane discovery can derive the brainstorm root:

```bash
python3 agents/app_mapper.py <program> \
  --output-mode canonical \
  --family <family> \
  --lane <lane> \
  --list-handoffs
```

The command reads `appmap_promotions.jsonl` and scans both `brainstorm/appmap-<run_id>-<focus>/` and `brainstorm/appmap-<run_id>/<focus>/` directories for promoted specs. It does not map targets, run agents, or write findings data.

Campaign status is also read-only and combines promoted handoff validation with `brainstorm/coverage.jsonl` counts:

```bash
python3 agents/app_mapper.py --campaign-status \
  --brainstorm-root ~/Shared/<family>/<program>/<lane>/brainstorm
```

Use it after runtime handoffs to see which specs are `ready`, `running`, `review`, `complete`, `attention`, or `blocked`.

## 6. Validate Handoffs

```bash
python3 agents/app_mapper.py --validate-handoff \
  ~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id>-<focus>/rce-spec.md
```

Validation parses the spec, enumerates AppMap-linked brainstorm intents, checks that each intent resolves exactly one sibling `agent_contexts/*.json` packet, and verifies packet `run_id`, `appmap_run_root`, candidate, hypothesis, and agent linkage. It reports counts and errors only; it does not write ledgers, raw map data, coverage, or reports.

If validation fails, fix the generated spec or promoted handoff before handing it to a runtime.

## 7. Plan Runtime Handoff

```bash
python3 agents/app_mapper.py --plan-handoff <promoted-spec> --brainstorm-hypothesis H001
```

Unselected planning is allowed only when every active hypothesis in the promoted spec is AppMap-linked and has a valid sibling context packet. Prefer `--brainstorm-hypothesis` for first runtime execution so one AppMap candidate/agent lane is exercised deliberately.

Runtime adapters must preserve AppMap research packet metadata on findings and prompts using the exact fields `appmap_research_technique_ids`, `appmap_research_source_ids`, and `appmap_research_citations`. Generated evidence lines reference research techniques only as `research-technique:<id>`; citations stay in notes and packet metadata so comma-separated citation lists cannot be parsed as separate evidence items.

The output must stay on the existing runtime path:

```bash
python3 agents/zero_day_team.py <program> <target_path> --brainstorm-spec <promoted-spec> --brainstorm-only --brainstorm-hypothesis H001
```

Default runtime remains one agent per hypothesis. To reduce duplicate work only after reviewing the campaign, opt in to small AppMap clusters when assignments share the same focus files, source evidence, and sink evidence:

```bash
python3 agents/zero_day_team.py <program> <target_path> \
  --brainstorm-spec-dir ~/Shared/<family>/<program>/<lane>/brainstorm/appmap-<run_id> \
  --brainstorm-only \
  --brainstorm-cluster-size 2
```

Do not add or suggest `zero_day_team --appmap`.

## 8. Report Results

Include:

- Output directory
- Target kind and framework summary
- Surface, flow, candidate, and rejected counts
- Generated spec path, if present
- Agent context path(s), if present
- Manifest and index path
- Promoted spec/context paths, if promotion was requested
- Top candidate source, boundary, sink, and file evidence
- Any reason no spec was generated
- Handoff validation counts/errors before runtime, if a promoted spec is selected
- Planned runtime command, if a handoff is ready

## 9. Runtime Handoff

Use a generated spec with existing team commands only when requested:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py <program> <target_path> \
  --brainstorm-spec <appmap-output>/generated_specs/rce-spec.md \
  --brainstorm-only
```

The runtime adapter consumes `agent_contexts/<hypothesis_id>-<candidate_id>-<agent_key>.json` automatically for AppMap-linked hypotheses. If the packet is missing or ambiguous, fix the AppMap artifacts before running agents. AppMap does not own agent execution, findings review, coverage ledgers, or report promotion.
