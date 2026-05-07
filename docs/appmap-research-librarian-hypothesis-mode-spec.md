# AppMap Research Librarian Hypothesis Mode Spec

Status: draft
Owner: Ghost / Ryushe
Canonical path: `docs/appmap-research-librarian-hypothesis-mode-spec.md`
Supersedes: none
Replaced by: none
Implementation commit: pending
Last reviewed: 2026-05-07

## Purpose

Add a hypothesis-generation layer between validated research and AppMap/Brainstorm dynamic-agent execution.

The current AppMap Research Librarian proves the gated research flow works:

```text
research scout -> validator -> validated local seed -> AppMap -> promoted brainstorm spec -> dynamic agents
```

However, broad categories like `electron + rce` produce broad technique packs and generic source/sink matches. For Electron targets, that misses the more realistic exploitation shape: renderer injection or XSS often becomes the first primitive, then chains into preload bridges, HostRpc/service methods, custom protocols, shell/file APIs, navigation confusion, or unsafe context isolation/node integration.

Hypothesis Mode should turn:

```text
validated research + AppMap surfaces + target tech stack
```

into:

```text
concrete, target-aware chain hypotheses that dynamic agents can hunt directly
```

## Motivation

The Canva Electron RCE workflow test on 2026-05-07 showed that the pipeline works end-to-end, but the initial RCE pass was too generic:

- AppMap generated 5 RCE-oriented candidates.
- `zero_day_team.py --brainstorm-only` covered all 5.
- No confirmed/dormant/novel findings were recorded.
- The strongest process-exec-looking path was hardened: renderer-controlled input did not control command/path/argv/env/shell options and updater install was gated on verified downloaded update state.

This does not mean the target has no exploitable Electron chains. It means generic `process-exec` matching is not enough.

Ryushe's manual research note: Electron XSS can be unusually high-impact because XSS in a renderer may chain into RCE or local privilege effects when the app exposes unsafe preload, IPC, protocol, shell, file, or navigation primitives.

## Design Goal

Hypothesis Mode should help answer:

> Given this target's observed Electron surfaces and validated Electron/XSS/RCE research, what concrete XSS-to-privilege chains should agents test?

It should avoid asking agents to hunt "Electron RCE" broadly. Instead, it should create focused assignments such as:

- `XSS -> preload bridge abuse -> privileged IPC method`
- `XSS -> custom protocol response/read/write -> local data exposure or file primitive`
- `XSS -> shell.openExternal/openPath -> unsafe scheme/path launch`
- `XSS -> navigation/window confusion -> privileged renderer context`
- `XSS -> HostRpc/service method -> filesystem/auth/update/download action`
- `XSS -> local import/export path confusion -> local file write/read primitive`
- `XSS -> contextIsolation/nodeIntegration/preload mistake -> Node primitive access`

## Non-goals

- Do not make AppMap itself a crawler, browser, search engine, or live target tester.
- Do not feed raw web research directly to hunt agents without validator review.
- Do not run target apps or perform live exploit testing as part of Hypothesis Mode.
- Do not replace Brainstorm specs or the existing findings ledger.
- Do not treat every XSS as confirmed RCE; each chain still needs source, boundary, flow, sink, and exploitability evidence.

## Proposed CLI

Initial command shape:

```bash
python3 agents/appmap_research_librarian.py hypothesize \
  /home/ryushe/Shared/appmap/canva/research-librarian/electron-xss-rce-YYYYMMDD \
  --appmap-run /home/ryushe/Shared/binaries/canva/exe/appmap/<run_id> \
  --target-path /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --category xss-to-rce \
  --output hypotheses.jsonl
```

Optional flags:

```text
--brainstorm-spec-out <path>       Write a promoted brainstorm spec directly.
--max-hypotheses <n>               Limit generated hypotheses.
--include-low-confidence           Include weak hypotheses for manual review.
--surface-kind <kind>              Restrict to ipc, protocol, navigation, preload, etc.
--require-appmap-ref               Only emit hypotheses with at least one AppMap surface ref.
--dry-run                          Print plan without writing artifacts.
```

## Inputs

### Required

1. Research Librarian campaign directory
   - `manifest.json`
   - `validated_research_seed.json`
   - successful `validation_report.json`

2. AppMap run root
   - `manifest.json`
   - generated source/boundary/transform/sink/candidate artifacts
   - `agent_contexts/` when available

3. Target path/profile
   - used only for static metadata and optional architecture summaries
   - no execution of target app

### Optional

- Existing brainstorm spec to merge/extend.
- Prior coverage ledger to avoid duplicate hypothesis emission.
- Prior findings/dormant reports to cite existing impact primitives.

## Outputs

### 1. Hypothesis JSONL

Default artifact:

```text
<campaign>/hypotheses.jsonl
```

Each line:

```json
{
  "schema_version": 1,
  "id": "XRCE001",
  "status": "draft",
  "priority": "high",
  "category": "xss-to-ipc-rce",
  "title": "Renderer XSS may reach privileged HostRpc service methods through preload bridge",
  "source": "renderer XSS or attacker-controlled renderer content",
  "boundary": "preload/contextBridge/HostRpc renderer-to-main boundary",
  "flow": "XSS -> exposed bridge method -> service registry dispatch -> privileged method",
  "sink": "privileged IPC/HostRpc method with filesystem, shell, auth, update, download, or navigation impact",
  "why_relevant": "AppMap observed IPC/service registry surfaces and validated research indicates unsafe preload/raw IPC bridges are common Electron RCE pivots.",
  "appmap_surface_refs": ["S0166", "B0111"],
  "appmap_candidate_refs": ["C0001"],
  "research_refs": ["s0002", "s0003", "s0004", "s0008"],
  "technique_pack_refs": ["electron-preload-bridge-raw-ipc-rce", "electron-ipc-handler-to-privileged-sink-rce"],
  "focus_files": ["dist/main.js", "build_assets/page_preload/**/*.html"],
  "suggested_agents": ["canva-xss-preload-hostrpc-chain"],
  "agent_prompt": "Trace whether renderer script execution can invoke exposed preload/HostRpc methods that reach privileged sinks without origin/schema enforcement.",
  "confidence": 0.78,
  "gaps": ["Need concrete renderer XSS source", "Need method-level sender/origin validation review"]
}
```

### 2. Hypothesis report markdown

Human-readable review file:

```text
<campaign>/hypotheses.md
```

Purpose:

- Let Ryushe manually inspect generated chain ideas.
- Show research citations and AppMap evidence in one place.
- Make gaps explicit before agents run.

### 3. Optional brainstorm spec

When `--brainstorm-spec-out` is supplied, Hypothesis Mode writes a normal Brainstorm spec that `zero_day_team.py` can consume:

```text
/home/ryushe/Shared/binaries/<program>/<lane>/brainstorm/appmap-<run_id>-<category>-hypotheses/spec.md
```

The spec should include:

- target mental model
- validated research summary
- AppMap surface summary
- hypotheses mapped to `### HNNN` blocks
- impact primitives where applicable
- focus files and suggested agents

## Hypothesis Categories

Initial Electron categories:

### XSS-to-preload/IPC

```text
renderer XSS -> preload/contextBridge/raw IPC -> ipcMain/HostRpc/service sink
```

Research anchors:

- Electron context isolation docs
- Electron IPC docs
- Electron contextBridge docs
- Doyensec insecure preload writeup

AppMap anchors:

- preload files
- IPC sources
- renderer-to-main boundaries
- service registry dispatches

### XSS-to-custom-protocol

```text
renderer XSS -> custom protocol request/read/write -> local file/path/scheme primitive
```

Look for:

- `protocol.handle/register*Protocol`
- custom scheme URL parsing
- file path transforms
- response readability across origins
- local blob/list endpoints

### XSS-to-shell/navigation

```text
renderer XSS -> openExternal/openPath/navigation/window open -> unsafe URL/scheme/path launch or privileged context confusion
```

Look for:

- `shell.openExternal`
- `shell.openPath`
- `BrowserWindow.loadURL`
- popup pass/window trust records
- allowlist gaps around `http`, `https`, custom schemes, `file`, `data`, and OS handlers

### XSS-to-local-file/export/import

```text
renderer XSS -> import/export/download/file-drop service -> local file read/write/path confusion
```

Look for:

- export filename/path controls
- download destination controls
- import parser trust assumptions
- drag/drop or file-drop bridges
- local temporary file handling

### XSS-to-node-primitive

```text
renderer XSS -> nodeIntegration/contextIsolation/preload mistake -> Node/global/process/Buffer/require primitive
```

Look for:

- `nodeIntegration: true`
- `contextIsolation: false`
- leaked `require`, `process`, `Buffer`, `ipcRenderer`
- overly broad contextBridge exposure

## Ranking Model

Hypotheses should be prioritized by a transparent score:

```text
score = source_likelihood + boundary_strength + sink_impact + appmap_confidence + research_confidence - missing_prerequisite_penalty
```

Suggested weights:

- source likelihood: 0.0–0.2
- boundary strength: 0.0–0.2
- sink impact: 0.0–0.25
- AppMap confidence: 0.0–0.2
- research confidence: 0.0–0.15
- missing prerequisite penalty: 0.0–0.3

Important: a missing XSS source should not kill the hypothesis automatically, but it should be listed as a gap. This lets agents or Ryushe later connect a real XSS primitive to an already-mapped Electron impact path.

## Validator Role

Hypothesis Mode should preserve the trust boundary introduced by the Research Librarian:

1. Scout collects candidate sources.
2. Validator accepts/rejects/merges research into structured sources and technique packs.
3. Hypothesis Mode uses only validated seed data plus local AppMap artifacts.
4. Optional hypothesis-review step can mark hypotheses as:
   - `accepted`
   - `needs-manual-review`
   - `too-generic`
   - `blocked-missing-surface`
   - `retired`

The validator may later be extended to review generated hypotheses before promotion to Brainstorm specs.

## Brainstorm Integration

Hypothesis Mode should emit normal Brainstorm-compatible hypotheses:

```md
### H001 — Renderer XSS may reach HostRpc privileged service methods
- Status: untested
- Priority: high
- Surface: preload-ipc-hostrpc
- Entry point: renderer XSS or untrusted renderer content
- Expected chain: renderer XSS -> preload/contextBridge -> HostRpc service dispatch -> privileged sink
- Suggested agents:
  - canva-xss-preload-hostrpc-chain
- Focus files:
  - dist/main.js
  - build_assets/page_preload/**/*.html
- Tags: xss, electron, preload, ipc, hostrpc, rce-chain
- Evidence:
  - appmap:S0166
  - appmap:B0111
  - research:s0002
  - research:s0003
  - research:s0004
  - research:s0008
- Notes: Missing prerequisite is a concrete renderer XSS source; agent should report either a full chain or an impact primitive with explicit gap.
```

Dynamic agents spawned from these hypotheses must preserve:

- `hypothesis_id`
- `hypothesis_title`
- `brainstorm_spec`
- `brainstorm_agent_key`
- `appmap_surface_refs`
- `appmap_candidate_refs`
- `research_refs`
- `technique_pack_refs`

## Coverage and Auditability

Every hypothesis run should be reconstructable later:

- What research sources were accepted?
- What AppMap surfaces/candidates caused this hypothesis?
- What prompt/context did the agent receive?
- What did the agent conclude?
- Did it find a vulnerability, impact primitive, or no finding?
- What gaps remain for manual enumeration?

Coverage ledger events should distinguish:

- `tested_no_finding`: agent found no supported chain
- `tested_gap_only`: agent found an impact primitive but source or exploitability gap remains
- `tested_finding`: agent produced linked FIDs
- `blocked_missing_source`: no XSS/source primitive known yet
- `blocked_missing_surface`: AppMap has no relevant surface
- `manual_review_needed`: hypothesis too ambiguous for autonomous run

## Implementation Plan

### Phase 1 — Spec and artifact model

- Add hypothesis schema/dataclass.
- Add JSONL read/write helpers.
- Add markdown report writer.
- Add validation for required fields, IDs, refs, and safe paths.
- Unit-test schema and deterministic output.

### Phase 2 — Surface/research joiner

- Read validated research seed.
- Read AppMap manifest/candidates/surfaces/context packets.
- Join technique packs to AppMap surface kinds and target packs.
- Produce draft hypotheses with transparent scoring.

### Phase 3 — Brainstorm promotion

- Convert hypotheses to Brainstorm spec blocks.
- Preserve AppMap/research metadata in agent context packets.
- Add `--brainstorm-spec-out` and validation tests.

### Phase 4 — Review gate

- Add optional hypothesis-review status file.
- Support manual accept/reject/retire edits.
- Only promote accepted hypotheses when review file exists and strict mode is enabled.

### Phase 5 — Electron XSS chain pack

- Add first concrete category pack for `electron-xss-to-rce`.
- Include categories from this spec.
- Smoke-test against Canva Electron AppMap artifacts.

## Maintenance check

- Existing canonical artifact checked: `docs/brainstorm-spec-dynamic-agent-workflow.md`
- Neighboring patterns checked: `agents/appmap_research_librarian.py`, `agents/appmap_research.py`, `docs/brainstorm-spec-dynamic-agent-workflow.md`, Research Librarian skill/playbook
- Duplicate logic/spec risk: medium
- Merge/deprecation plan: create this as a focused extension spec because the existing brainstorm spec owns generic dynamic-agent execution, while this spec owns the pre-Brainstorm research/AppMap hypothesis-generation layer. Link from future Research Librarian docs/playbook when implemented.

## Open Questions

1. Should Hypothesis Mode be part of `appmap_research_librarian.py`, or should it become a separate `appmap_hypothesis_builder.py` with a thin librarian command wrapper?
2. Should generated hypotheses be editable JSONL first, or should markdown Brainstorm spec be the primary human-editable artifact?
3. Should missing XSS source produce runnable hypotheses or manual-review-only hypotheses by default?
4. How should prior findings/dormant impact primitives be pulled in without overfitting to stale reports?
5. Should category packs live in code, YAML/JSON, or markdown playbooks?

## Success Criteria

- Given a validated Electron/XSS/RCE research seed and AppMap run, Hypothesis Mode emits concrete chain hypotheses with AppMap and research refs.
- The output is concise enough for Ryushe to manually inspect.
- Generated Brainstorm specs can be consumed by `zero_day_team.py --brainstorm-spec --brainstorm-only` without custom runtime paths.
- Agents receive focused chain prompts rather than broad `Electron RCE` instructions.
- No raw unvalidated web research enters AppMap or agent prompts.
- Coverage logs make it clear which chains were tested, which produced no findings, and which still need manual source enumeration.
