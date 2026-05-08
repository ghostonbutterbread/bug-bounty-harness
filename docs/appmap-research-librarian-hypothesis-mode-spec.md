# AppMap Research Librarian Hypothesis Mode Spec

Status: draft
Owner: Ghost / Ryushe
Canonical path: `docs/appmap-research-librarian-hypothesis-mode-spec.md`
Supersedes: none
Replaced by: none
Implementation commit: 9b80fb5
Last reviewed: 2026-05-07

## Purpose

Add a generic hypothesis-generation layer between validated Research Librarian seed data and AppMap/Brainstorm dynamic-agent execution.

The current Research Librarian flow is:

```text
research scout -> validator -> validated local seed -> AppMap -> promoted brainstorm spec -> dynamic agents
```

Hypothesis Mode inserts a deterministic local join step:

```text
validated research + AppMap candidates/surfaces + vulnerability class/category
  -> concrete, target-aware chain hypotheses
```

The feature is vulnerability-class driven, not Electron/XSS-specific. For example, if the class is RCE and AppMap shows config, IPC, DLL/load, dynamic-code, deserialization, or executor surfaces, Hypothesis Mode should produce chain assignments such as:

- `config -> sanitization/load boundary -> process executor or DLL/load hijack check`
- `IPC -> sender/schema validation boundary -> privileged executor`
- `file path/custom protocol -> canonicalization boundary -> shell/open/file primitive`
- `serialized payload -> type/signature boundary -> unsafe deserialization`
- `template/config input -> transform boundary -> dynamic-code evaluation`

Electron/XSS-to-RCE remains a useful category pack, but it is only one example of the generic model.

## Motivation

Broad AppMap categories can produce correct but too-generic candidates. A candidate like `config source -> project-boundary -> process-exec sink` should not be handed to an agent as "hunt RCE" without preserving why the validated research says the chain matters.

Hypothesis Mode turns broad evidence into manually enumerable assignments:

- the concrete source/boundary/transform/sink shape AppMap observed
- the validated technique pack(s) that make the shape interesting
- the exact files and AppMap refs an agent should inspect
- explicit gaps such as missing source control, missing sender validation review, missing canonicalization proof, or missing loader/DLL control

The goal is to give Ryushe and dynamic agents a short list of chain-shaped hypotheses rather than a broad vulnerability-class label.

## Design Goal

Hypothesis Mode should answer:

> Given validated research for this vulnerability class and this target's AppMap mapping, what concrete chains should agents test?

It should support generic vulnerability classes and target technologies by joining:

- AppMap candidate source, boundary, transform, and sink kinds
- AppMap surfaces when candidate chains are incomplete and low-confidence review is requested
- validated `technique_packs`
- validated research source IDs
- campaign manifest category/focus and AppMap target profile

The implementation should remain offline and replayable. It reads local campaign and AppMap artifacts only; it does not browse, search, crawl, execute the target, or probe external infrastructure.

## Non-goals

- Do not make AppMap a crawler, browser, search engine, or live target tester.
- Do not feed raw web research directly to hunt agents without validator review.
- Do not run target apps or exploit tests as part of Hypothesis Mode.
- Do not replace Brainstorm specs or the findings ledger.
- Do not mark generated hypotheses as confirmed vulnerabilities.
- Do not hardcode the feature around Electron/XSS. Electron/XSS can be a category pack, not the architecture.

## CLI

MVP command:

```bash
python3 agents/appmap_research_librarian.py hypothesize \
  <campaign> \
  --appmap-run <run_root> \
  [--category <name>] \
  [--output <path>] \
  [--markdown-output <path>] \
  [--brainstorm-spec-out <path>] \
  [--max-hypotheses N] \
  [--surface-kind KIND] \
  [--surface-kind KIND] \
  [--require-appmap-ref] \
  [--include-low-confidence] \
  [--dry-run]
```

Defaults:

- JSONL output: `<campaign>/hypotheses.jsonl`
- Markdown report: `<campaign>/hypotheses.md`
- Category: campaign focus/category, unless `--category` is supplied
- Seed: `<campaign>/validated_research_seed.json`

Gate semantics match `plan-appmap`: local seed validation must succeed and the seed must contain at least one source and one technique pack before hypotheses are written. `--dry-run` validates and previews generation without writing hypothesis outputs.

## Inputs

### Campaign

Required:

- `manifest.json`
- `validated_research_seed.json`

The validated seed must include reviewed local data:

- `sources[]` with stable IDs and URLs or local paths
- `technique_packs[]` with `vulnerability_pack`, `target_pack_keys` or `applies_to_all`, `applicable_surface_kinds` or `applies_to_all`, and `source_ids`

### AppMap Run

Read when present:

- `manifest.json`
- `candidates.jsonl`
- `surfaces.jsonl`
- `target_profile.json`
- `architecture.md`

Artifact paths may also be resolved through the AppMap run manifest's `artifacts` mapping.

### Execution Policy

- No network access.
- No target execution.
- No browser automation.
- No probing or crawling.
- Candidate evidence is sufficient for the MVP; full code scanning belongs in AppMap or later agents.

## Output Schema

Each JSONL row is a hypothesis:

```json
{
  "schema_version": 1,
  "id": "HYP001",
  "status": "draft",
  "category": "rce-config-to-exec",
  "title": "Config-controlled value may reach process execution or unsafe loader",
  "source": "attacker-influenced config, project file, environment, or update metadata",
  "boundary": "config parse/load and sanitization boundary before privileged executor or loader code",
  "flow": "config load -> validation/sanitization check -> command, argv, environment, working directory, or DLL/library load decision -> executor",
  "sink": "process execution, updater/installer launch, unsafe load path, or DLL search-order hijack primitive",
  "why_relevant": "Validated research and AppMap evidence explain why this chain matters.",
  "appmap_refs": ["candidate:C0001", "surface:S0001"],
  "appmap_surface_refs": ["S0001", "B0001", "K0001"],
  "appmap_candidate_refs": ["C0001"],
  "research_refs": ["S0001"],
  "source_ids": ["S0001"],
  "technique_pack_refs": ["node-rce-config"],
  "focus_files": ["src/config.js"],
  "suggested_agents": ["example-rce-config-to-exec-c0001"],
  "agent_prompt": "Trace config parsing, sanitization, load-path construction, executor arguments, environment/cwd control, and DLL hijack or unsafe loader opportunities.",
  "confidence": 0.84,
  "gaps": ["Need proof config values control command, path, argv, env, cwd, or loader/DLL search behavior."],
  "mapping_signature": "stable deterministic signature"
}
```

IDs are stable within a deterministic run order: `HYP001`, `HYP002`, and so on.

## Markdown Report

`hypotheses.md` should be concise and manually enumerable. It should include:

- run metadata and network policy
- validated research sources and technique packs
- each hypothesis title, chain, refs, focus files, suggested agent key, prompt, confidence, and gaps
- enough context for Ryushe to see what agents will receive and what may be missing

## Brainstorm Spec Output

When `--brainstorm-spec-out` is supplied, Hypothesis Mode writes a brainstorm-style markdown spec with `H001`, `H002`, and later blocks mapped from JSONL hypotheses.

Each block should preserve:

- AppMap candidate and surface refs in Evidence
- research source refs in Evidence
- technique pack refs in Evidence
- original `HYPNNN` ID and mapping signature in Notes
- focus files and suggested agents
- the exact agent prompt or a close equivalent

The command only writes the spec. It does not auto-run `zero_day_team.py`.

## Generic Chain Hints

MVP hinting is heuristic and based on AppMap source/sink/surface kinds. It should be easy to extend without changing CLI behavior.

### Config To Exec Or Load

```text
config/config-file -> validation/load boundary -> process-exec, unsafe load path, DLL/library search, updater/installer launch
```

Review:

- config parsing and schema validation
- path normalization and allowlists
- command, argv, env, cwd, and shell option construction
- executable/library/DLL search paths
- updater or installer launch conditions

### IPC To Exec

```text
ipc -> sender/origin/schema boundary -> privileged dispatch -> process-exec or dynamic-code
```

Review:

- sender, origin, tenant, and privilege checks
- schema validation and type confusion
- dispatch tables and service method routing
- executor arguments influenced by IPC fields

### Path, Protocol, Shell, Custom Scheme

```text
file-path/protocol/custom-scheme/shell-open -> canonicalization boundary -> OS handler, file, shell, or navigation sink
```

Review:

- scheme allowlists
- canonicalization and path traversal
- custom protocol handlers
- shell/open APIs
- import/export/download destinations

### Dynamic Code

```text
input/template/config -> parser or transform boundary -> eval/Function/template/script compiler
```

Review:

- whether user input alters executable code
- expression language restrictions
- globals, imports, and sandbox behavior
- template injection or script compilation paths

### Deserialization

```text
serialized payload -> type/signature/allowlist boundary -> deserializer -> gadget-capable object path
```

Review:

- parser mode and object reconstruction behavior
- type allowlists and signatures before deserialization
- gadget-capable classes or revivers in scope
- privilege effects after object construction

### Auth And Session

```text
token/cookie/session/account input -> authz/session boundary -> privileged state or data access
```

Review:

- session binding
- token origin and replay properties
- ownership and tenant checks
- privilege transitions after boundary crossing

## Electron/XSS Example Category

Electron/XSS-to-RCE can be modeled as one category using the same generic mechanism.

Example chains:

- `renderer XSS -> preload/contextBridge/raw IPC -> privileged IPC/HostRpc/service sink`
- `renderer XSS -> custom protocol request/read/write -> local file/path/scheme primitive`
- `renderer XSS -> shell.openExternal/openPath -> unsafe scheme/path launch`
- `renderer XSS -> navigation/window confusion -> privileged renderer context`
- `renderer XSS -> nodeIntegration/contextIsolation/preload mistake -> Node primitive access`

This category should be implemented as data or hint logic layered on the generic source/boundary/sink model, not as the only hypothesis engine.

## Ranking Model

Transparent confidence should combine:

- AppMap candidate score or surface confidence
- source, boundary, transform, and sink kind strength
- validated research trust when available
- class-specific hint confidence
- penalties for missing candidate refs, incomplete chains, or missing prerequisites

Missing exploit prerequisites should reduce confidence and appear in `gaps`; they should not automatically suppress a useful manually reviewable chain when `--include-low-confidence` is set.

## Validator Role

Hypothesis Mode preserves the Research Librarian trust boundary:

1. Scout collects candidate sources.
2. Validator accepts, rejects, and merges sources into structured seed data.
3. AppMap consumes only local validated seed data or explicitly validated source URLs.
4. Hypothesis Mode consumes only validated seed data plus local AppMap artifacts.
5. Optional later review can mark generated hypotheses as accepted, needs manual review, too generic, blocked, or retired.

## Coverage And Auditability

Every hypothesis run should be reconstructable:

- what validated sources were used
- which technique packs matched
- which AppMap candidates and surfaces caused emission
- which files and prompts were handed to agents
- which gaps remained at generation time
- whether later agents found no issue, a gap-only primitive, or a vulnerability

Coverage ledger events should eventually distinguish:

- `tested_no_finding`
- `tested_gap_only`
- `tested_finding`
- `blocked_missing_source`
- `blocked_missing_surface`
- `manual_review_needed`

## Implementation Plan

### Phase 1 - MVP

- Add `hypothesize` to `agents/appmap_research_librarian.py`.
- Keep CLI validation gate aligned with `plan-appmap`.
- Add `agents/appmap_hypothesis.py` for artifact loading, joining, JSONL rendering, markdown rendering, and brainstorm spec rendering.
- Generate generic hypotheses from AppMap candidates and validated technique packs.
- Add focused tests for config-to-exec RCE, dry run, AppMap ref filtering, and brainstorm spec output.

### Phase 2 - Better Surface Joins

- Improve incomplete-chain handling from `surfaces.jsonl`.
- Add richer low-confidence review outputs.
- Add dedupe against prior hypotheses and coverage ledgers.

### Phase 3 - Category Packs

- Move hint logic into data or small pluggable packs if code-level heuristics grow.
- Add explicit packs for Electron/XSS-to-RCE, unsafe deserialization, path/protocol abuse, auth/session, and dynamic-code chains.

### Phase 4 - Review Gate

- Add optional hypothesis review status files.
- Support accept/reject/retire edits.
- Allow strict promotion of accepted hypotheses only.

## Maintenance Check

- Existing canonical artifact checked: `docs/brainstorm-spec-dynamic-agent-workflow.md`
- Neighboring patterns checked: `agents/appmap_research_librarian.py`, `agents/appmap_research.py`, `agents/app_mapper.py`, Research Librarian skill/playbook
- Duplicate logic/spec risk: medium
- Merge/deprecation plan: keep this as a focused extension spec because the Brainstorm spec owns dynamic-agent execution, while this spec owns pre-Brainstorm research/AppMap hypothesis generation.

## Open Questions

1. Should hint packs move to YAML/JSON once there are more than a few vulnerability classes?
2. Should generated JSONL be the primary editable artifact, or should brainstorm markdown be primary?
3. Should `--include-low-confidence` eventually emit surface-only hypotheses by default for classes where candidates are rare?
4. How should prior findings and dormant primitives be pulled in without overfitting to stale reports?
5. Should accepted hypothesis review become mandatory before `--brainstorm-spec-out` in strict mode?

## Success Criteria

- Given a validated RCE seed and AppMap config/process-exec candidate, Hypothesis Mode emits a concrete config-to-exec/load/DLL-hijack style hypothesis with AppMap and research refs.
- Given other vulnerability classes and surface kinds, Hypothesis Mode emits category-appropriate chain prompts without Electron-specific assumptions.
- The markdown report is concise enough for manual enumeration.
- Generated Brainstorm specs can be consumed by `zero_day_team.py --brainstorm-spec --brainstorm-only` without custom runtime paths.
- No raw unvalidated web research enters AppMap or agent prompts.
