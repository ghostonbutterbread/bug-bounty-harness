# Brainstorm Spec Dynamic Agent Workflow

## Status

Draft: 2026-04-30

Owner: Ghost / Ryushe

## Purpose

Create a target-specific brainstorm artifact that can be written collaboratively by Ryushe and Ghost, then consumed by `zero_day_team`, `apk_team`, and future harness modules to spawn dynamic agents from human + agent-generated hypotheses.

The goal is to turn brainstorms into durable hunt direction, not just chat context.

Short version:

```text
/brainstorm-spec canva
        ↓
canonical brainstorm spec markdown
        ↓
team run with --brainstorm-spec
        ↓
hypotheses become dynamic AgentSpecs
        ↓
findings go to the normal findings ledger
coverage/progress goes to a brainstorm coverage ledger
```

## Why

Current dynamic agents are mostly generated from code/app surfaces. That is useful, but it misses a major source of signal: Ryushe's target intuition, user-perspective workflows, suspicious raw findings, and chain hypotheses discovered during review.

For Canva Desktop, examples include:

- shared links as a desktop entrypoint
- import/upload/rendering surfaces as renderer-XSS candidates
- open redirects as deep-link or allowlist-bypass chain pieces
- ElectronBridge / host RPC as impact layer
- notification icon SSRF / native image decode as post-XSS primitives

These ideas should become first-class hunt inputs that teams can run, track, and revisit.

## Design Principles

1. **One source of truth for findings**
   - Vulnerability candidates produced from brainstorm agents must still write to the normal common findings ledger.
   - Do not create a second vulnerability ledger.

2. **Separate coverage/progress tracking**
   - Brainstorm execution history needs its own lightweight coverage ledger because `no finding`, `blocked`, and `tested` are valuable but are not vulnerabilities.

3. **Portable artifact, not chat-only workflow**
   - The brainstorm spec should be a markdown file stored inside the target lane.
   - Teams, skills, and manual workflows should all be able to consume the same artifact.

4. **Simple team integration**
   - Passing `--brainstorm-spec <path>` should be enough to tell a team to use it.
   - Teams may run normal static/dynamic agents plus brainstorm-derived agents in one run, or operators may run two separate passes.

5. **Bounty harness owns the skill UX**
   - The skill should live with the bug bounty harness skill set.
   - The parser/runtime logic should live in shared code so every module can use it.

## Proposed Storage Layout

Canonical per-lane layout:

```text
~/Shared/<family>/<program>/<lane>/
├── brainstorm/
│   ├── spec.md
│   ├── coverage.jsonl
│   └── generated_agents/
│       ├── H001__canva-svg-import-xss.json
│       └── H002__canva-open-redirect-deeplink.json
├── ledgers/
│   └── ledger.json
└── reports/
```

For Canva EXE this resolves to:

```text
/home/ryushe/Shared/binaries/canva/exe/brainstorm/spec.md
/home/ryushe/Shared/binaries/canva/exe/brainstorm/coverage.jsonl
```

## Brainstorm Spec Markdown Format

The markdown file should be human-editable and machine-parseable.

Recommended structure:

```md
# Brainstorm Spec: Canva Desktop EXE

## Metadata
- Program: canva
- Family: binaries
- Lane: exe
- Target kind: electron-exe
- Target path: /home/ryushe/Shared/binaries/canva/exe/input/app_asar
- Created: 2026-04-30
- Status: active

## Target mental model
Canva Desktop is an Electron application wrapping a rich design/editor web app. It handles imports, uploads, shared links, AI-generated assets, export/download flows, notifications, billing, and native desktop integrations.

## Impact primitives
### P001 — ElectronBridge host RPC access
- Source: `window.ElectronBridge.requestMessagePort`
- Impact: renderer JS can potentially reach host RPC modules if gates/origin checks are weak
- Evidence: `/home/ryushe/Shared/binaries/canva/exe/reports/dormant/30-04-2026/index.md`
- Status: active

## Hypotheses
### H001 — SVG import can create renderer script execution
- Status: untested
- Priority: high
- Surface: import-upload-render
- Entry point: user imports or pastes SVG/design asset
- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC
- Suggested agents:
  - canva-svg-import-xss
  - canva-renderer-bridge-chain
- Focus files:
  - dist/**/*.js
  - **/*svg*
  - **/*import*
- Tags: xss, import, renderer, electron-bridge

### H002 — Open redirect can pivot into desktop deep link or allowlist bypass
- Status: untested
- Priority: medium
- Surface: shared-link-navigation
- Entry point: trusted Canva link redirects to attacker-controlled or custom-protocol target
- Expected chain: trusted Canva URL -> redirect -> desktop deep link / privileged navigation / main-process fetch allowlist bypass
- Suggested agents:
  - canva-open-redirect-deeplink-chain
  - canva-redirect-allowlist-bypass
- Tags: open-redirect, deeplink, navigation, ssrf

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
```

## Hypothesis Schema

Each `### HNNN — title` block maps to one or more dynamic agent specs.

Fields:

- `Status`: `untested | queued | running | tested | blocked | retired`
- `Priority`: `critical | high | medium | low`
- `Surface`: broad target area, e.g. `import-upload-render`, `ipc`, `deeplink`, `filesystem`, `native-module`
- `Entry point`: how attacker-controlled input reaches the app
- `Expected chain`: source -> intermediate -> impact primitive
- `Suggested agents`: one or more agent keys to generate
- `Focus files`: optional glob hints
- `Tags`: vulnerability/technology tags
- `Evidence`: optional report, FID, log, or source path references
- `Notes`: free-form human context

## Dynamic Agent Generation Contract

A brainstorm-derived agent should be converted into the existing `AgentSpec` shape:

```python
AgentSpec(
    key="canva-svg-import-xss",
    name="Canva SVG Import XSS Hunter",
    description="Tests H001 from the brainstorm spec...",
    surface_type="import-upload-render",
    vuln_class="xss",
    patterns=["svg", "import", "sanitize", "innerHTML"],
    focus_files_glob=["dist/**/*.js", "**/*svg*", "**/*import*"],
    ignore_files_glob=["**/*.map", "**/node_modules/**"],
    agent_prompt_template="...",
    parent_keys=["brainstorm:H001"],
    created_by="brainstorm-spec",
    version="<target snapshot/version>",
    created_at="...",
)
```

Prompt requirements:

- Include the hypothesis ID/title.
- Include the exact expected chain.
- Include relevant impact primitives from the spec.
- Ask the agent to report findings in the normal team JSONL schema.
- Require source-backed evidence.
- Require `hypothesis_id`, `brainstorm_spec`, and `agent_key` metadata on findings.
- Tell the agent to return `no finding` explicitly if the hypothesis is not supported.

## Ledger Model

### Normal findings ledger

All vulnerability candidates go to the existing common findings ledger.

Brainstorm metadata is attached to each finding:

```json
{
  "fid": "D12",
  "type": "SVG import renderer XSS reaches ElectronBridge",
  "class_name": "xss",
  "file": "dist/main.js",
  "line": 123,
  "brainstorm_spec": "/home/ryushe/Shared/binaries/canva/exe/brainstorm/spec.md",
  "hypothesis_id": "H001",
  "hypothesis_title": "SVG import can create renderer script execution",
  "agent_key": "canva-svg-import-xss"
}
```

The common ledger remains the source of truth for:

- FID assignment
- dedupe
- review tier
- report promotion
- sighting history

### Brainstorm coverage ledger

Coverage/progress goes to a separate append-only JSONL file:

```text
brainstorm/coverage.jsonl
```

Example events:

```json
{"event":"hypothesis_loaded","hypothesis_id":"H001","status":"untested","run_id":"20260430T..."}
{"event":"agent_spawned","hypothesis_id":"H001","agent_key":"canva-svg-import-xss","run_id":"20260430T..."}
{"event":"agent_completed","hypothesis_id":"H001","agent_key":"canva-svg-import-xss","result":"no_finding","linked_fids":[],"run_id":"20260430T..."}
{"event":"agent_completed","hypothesis_id":"H002","agent_key":"canva-open-redirect-deeplink-chain","result":"finding","linked_fids":["D12"],"run_id":"20260430T..."}
```

Coverage statuses:

- `untested`: present in spec, no agent completed yet
- `queued`: selected for run
- `running`: agent spawned
- `tested_no_finding`: completed without findings
- `tested_finding`: completed with linked FIDs
- `blocked`: unable to test because prerequisite missing
- `retired`: intentionally no longer useful

## CLI Integration

Minimum team flag:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py canva <target> --brainstorm-spec <path>

cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/apk_team.py canva <target> --brainstorm-spec <path>
```

Behavior:

1. Resolve normal storage/lane.
2. Load brainstorm spec from explicit path.
3. Parse active/untested hypotheses.
4. Convert hypotheses into dynamic `AgentSpec` objects.
5. Add brainstorm-derived specs to the selected profile list.
6. Run the team normally.
7. Attach brainstorm metadata to raw findings.
8. Reserve/review/promote findings through the normal ledger/report gate.
9. Append coverage events to `brainstorm/coverage.jsonl`.
10. Update the markdown coverage table if safe.

Optional flags:

```bash
--brainstorm-only              # run only brainstorm-derived agents
--brainstorm-hypothesis H001   # run one hypothesis
--brainstorm-priority high     # run hypotheses by priority
--brainstorm-status untested   # default filter
--brainstorm-no-writeback      # do not mutate markdown spec, only write JSONL coverage
```

## Skill UX

A bounty harness skill should provide the human workflow:

```text
/brainstorm-spec canva --lane exe
/brainstorm-spec canva --add-hypothesis
/brainstorm-spec canva --summarize-gaps
/brainstorm-spec canva --from-report /path/to/report.md
```

The skill should live in the bounty harness skill set, not as a global generic-only skill.

Skill responsibilities:

- Create the canonical `brainstorm/spec.md` if missing.
- Ask Ryushe for user-perspective vectors.
- Convert rough ideas into structured hypotheses.
- Pull impact primitives from current dormant/confirmed reports.
- Summarize untested hypotheses.
- Never own the team runtime logic directly.

Core/runtime responsibilities:

- Parse spec.
- Generate `AgentSpec`s.
- Append coverage JSONL.
- Link findings back to hypotheses.
- Expose helpers to `zero_day_team`, `apk_team`, and future modules.

## Proposed Shared Module

In the near term this can live inside `bug_bounty_harness` until the `bounty_core` migration is ready. Longer-term, it should move to `bounty_core`.

Proposed module:

```text
agents/brainstorm_spec.py              # harness-local MVP
# later
bounty_core/brainstorm_spec.py         # shared implementation
```

Core API sketch:

```python
@dataclass
class BrainstormHypothesis:
    id: str
    title: str
    status: str
    priority: str
    surface: str
    entry_point: str
    expected_chain: str
    suggested_agents: list[str]
    focus_files_glob: list[str]
    tags: list[str]
    evidence: list[str]
    notes: str

@dataclass
class BrainstormSpec:
    path: Path
    metadata: dict[str, str]
    mental_model: str
    impact_primitives: list[dict[str, str]]
    hypotheses: list[BrainstormHypothesis]

class BrainstormSpecStore:
    def load(path: Path) -> BrainstormSpec: ...
    def generate_agent_specs(spec: BrainstormSpec, version: str) -> list[AgentSpec]: ...
    def append_coverage(path: Path, event: dict[str, Any]) -> None: ...
    def unresolved_hypotheses(spec: BrainstormSpec) -> list[BrainstormHypothesis]: ...
```

## BaseTeam Integration

BaseTeam should eventually own the generic orchestration hooks:

- load brainstorm specs
- merge brainstorm-derived agents with team profiles
- expose brainstorm context to prompts
- collect per-agent completion metadata
- write coverage events
- enrich findings with hypothesis metadata before reservation

Concrete teams should only supply modality-specific prompt framing, e.g. APK vs Electron vs source.

## MVP Implementation Plan

### Phase 1 — Spec artifact and parser

- Add `agents/brainstorm_spec.py`.
- Parse the markdown hypothesis format conservatively.
- Add tests for:
  - loading metadata
  - extracting hypotheses
  - preserving unknown/free-form text
  - malformed spec handling

### Phase 2 — `zero_day_team` integration

- Add `--brainstorm-spec` CLI flag.
- Generate `AgentSpec`s from untested hypotheses.
- Merge them with selected static/dynamic profiles.
- Add `--brainstorm-only` and `--brainstorm-hypothesis` if simple.
- Attach `hypothesis_id` metadata to findings.
- Append coverage events.

### Phase 3 — `apk_team` integration

- Add the same `--brainstorm-spec` flag.
- Reuse the same parser/generator.
- Add APK-specific prompt framing for Android entrypoints.

### Phase 4 — skill wrapper

- Add the bounty harness skill wrapper at the canonical source path:

```text
skills/brainstorm-spec/SKILL.md
```

- Add playbook at:

```text
prompts/brainstorm-spec-playbook.md
```

- Update `SKILL_REGISTRY.md` so provider sync targets are explicit.
- Let `./setup.sh --sync` or `./sync_skills.sh` publish from `skills/brainstorm-spec/` to Claude Code, Codex, and Ghost/OpenClaw provider directories.

### Phase 5 — migrate to `bounty_core`

Once stable, move parser/coverage helpers into:

```text
~/projects/bounty-core/bounty_core/brainstorm_spec.py
```

The skill and teams should import from the shared module once available.

## Acceptance Criteria

- A target lane can contain a human-editable `brainstorm/spec.md`.
- `zero_day_team --brainstorm-spec <path>` creates/runs dynamic agents from untested hypotheses.
- `apk_team --brainstorm-spec <path>` supports the same contract or explicitly errors with a clear TODO until implemented.
- Findings from brainstorm agents enter the normal findings ledger with `hypothesis_id` metadata.
- `brainstorm/coverage.jsonl` records at least `agent_spawned` and `agent_completed` events.
- The system can answer: “which brainstorm hypotheses remain untested?” without reading the full findings ledger.
- Existing runs without `--brainstorm-spec` behave unchanged.
- Tests cover parser behavior, dynamic AgentSpec generation, and coverage writeback.

## Non-goals

- Do not replace existing DynamicAgentBuilder surface-based generation.
- Do not create a separate vulnerability findings ledger for brainstorm findings.
- Do not require every module to support brainstorm specs in the first phase.
- Do not make markdown writeback mandatory; JSONL coverage is the durable source for execution history.
- Do not run destructive or high-volume tests just because a brainstorm hypothesis exists.

## Open Questions

1. Should the canonical spec filename always be `brainstorm/spec.md`, or should multiple brainstorm docs be allowed per lane?
2. Should generated brainstorm agents be saved into the existing program `agent_registry`, into `brainstorm/generated_agents`, or both?
3. Should markdown coverage table updates be automatic, or should JSONL be the only machine-written file?
4. Should `--brainstorm-spec` default to adding agents to normal profiles, or should it default to brainstorm-only for cost control?
5. How should conflicting hypothesis statuses be resolved when markdown and JSONL coverage disagree?

## Recommended Defaults

- Canonical default spec: `brainstorm/spec.md`.
- Allow additional specs only by explicit path.
- Save generated agents both to the run-local brainstorm folder and the existing agent registry for reuse.
- JSONL coverage is authoritative for execution history.
- Markdown table updates are best-effort.
- `--brainstorm-spec` adds brainstorm agents to normal profiles by default.
- `--brainstorm-only` exists for focused/cost-controlled runs.

## Reviewer Hardening Addendum — 2026-04-30

A Codex reviewer inspected this draft and identified several implementation risks. The following decisions are incorporated into the spec before implementation.

### 1. Explicit AgentSpec Adapter Contract

There are multiple profile/spec shapes in the harness today:

- `agents.dynamic_agent_builder.AgentSpec`
- `zero_day_team` vulnerability profiles / class profiles
- `apk_team` hunt profiles
- class-based `BaseTeam` profile/spec objects

Brainstorm parsing must therefore not assume that one `AgentSpec` object is universally accepted everywhere.

Required adapter pipeline:

```text
BrainstormHypothesis
  -> BrainstormAgentIntent       # canonical intermediate, lossless brainstorm metadata
  -> TeamProfileAdapter          # modality-specific adapter
  -> zero_day_team profile OR apk_team profile OR BaseTeam profile
```

Canonical intermediate shape:

```python
@dataclass
class BrainstormAgentIntent:
    hypothesis_id: str
    hypothesis_title: str
    agent_key: str
    name: str
    description: str
    surface: str
    vuln_class: str
    priority: str
    expected_chain: str
    focus_files_glob: list[str]
    ignore_files_glob: list[str]
    tags: list[str]
    evidence: list[str]
    prompt_context: str
    source_spec_path: Path
```

Each team adapter must document which fields are:

- preserved in the agent prompt
- preserved in raw finding metadata
- preserved in coverage events
- team-specific or dropped

Acceptance test required:

- Same hypothesis can generate a zero_day profile and an APK profile without losing `hypothesis_id`, `agent_key`, `expected_chain`, or `source_spec_path`.

### 2. Brainstorm Metadata Preservation Contract

Current finding normalization paths may drop unknown keys. Implementation must explicitly preserve brainstorm metadata through the full lifecycle.

Required metadata fields:

```text
brainstorm_spec
hypothesis_id
hypothesis_title
brainstorm_agent_key
brainstorm_surface
brainstorm_tags
```

These fields must survive:

1. agent raw JSONL output
2. `_normalize_finding` / APK normalization
3. raw findings JSONL persistence
4. ledger `check()` reservation
5. review input/output normalization
6. promotion/update into the common ledger
7. report rendering or at least ledger readback

Acceptance test required:

```text
raw brainstorm finding -> reserve FID -> review -> promote -> ledger readback
```

The test must assert that `hypothesis_id`, `brainstorm_spec`, and `brainstorm_agent_key` survive unchanged.

### 3. Coverage Event Lifecycle Contract

Coverage must distinguish outcomes more precisely than `finding` vs `no_finding`.

Required event types:

```text
hypothesis_loaded
agent_queued
agent_spawned
agent_completed_no_finding
agent_completed_with_raw_findings
agent_timeout
agent_crashed
agent_invalid_output
agent_duplicate_only
review_rejected
review_promoted
coverage_status_changed
```

Rules:

- `agent_queued` is emitted after selection but before process spawn.
- `agent_spawned` is emitted immediately after process creation succeeds.
- `agent_timeout` and `agent_crashed` are emitted from runtime/process handling.
- `agent_invalid_output` is emitted when the agent completes but no valid parseable result exists.
- `agent_completed_no_finding` is only emitted for a clean run that explicitly produced no finding or produced no valid vulnerability candidates.
- `agent_completed_with_raw_findings` links temporary raw finding signatures, not final FIDs.
- `review_rejected` is emitted after review for rejected findings.
- `review_promoted` is emitted after ledger/report promotion and must include final FIDs.
- Coverage JSONL is append-only and authoritative for execution history.

Acceptance test required:

- Coverage summary can distinguish: no finding, timeout, crash, invalid JSON, duplicate-only, review rejection, and promoted finding without reading `ledger.json`.

### 4. Canonical Storage and Registry Ownership

Brainstorm specs and coverage belong to the canonical lane root:

```text
<lane_root>/brainstorm/spec.md
<lane_root>/brainstorm/coverage.jsonl
<lane_root>/brainstorm/generated_agents/*.json
```

For generated agent caches:

- The canonical brainstorm-owned cache is `<lane_root>/brainstorm/generated_agents/`.
- Existing legacy/global registries may be written only as compatibility mirrors.
- The team runtime must read from the canonical lane-local brainstorm cache first.
- Explicit `--output-root` must route brainstorm files under the resolved storage lane, not legacy `~/Shared/bounty_recon`.

Acceptance tests required:

- Canva EXE target writes brainstorm artifacts under `/home/ryushe/Shared/binaries/canva/exe/brainstorm/`.
- Explicit `--output-root` writes brainstorm artifacts under the explicit resolved lane root.
- No new brainstorm files are written to legacy `~/Shared/bounty_recon` unless compatibility mirroring is explicitly enabled.

### 5. MVP Integration Target

MVP should patch the active procedural orchestrators first because they are what the current CLIs use:

- `zero_day_team.orchestrate_zero_day_team`
- `apk_team.orchestrate_apk_team`

BaseTeam/class integration remains required, but after procedural parity is proven.

MVP order:

1. harness-local parser + coverage writer
2. procedural `zero_day_team --brainstorm-spec`
3. procedural `apk_team --brainstorm-spec`
4. BaseTeam/class adapter hooks
5. move shared pieces to `bounty_core`

Parity acceptance:

- The same brainstorm spec must select equivalent hypotheses in `zero_day_team` and `apk_team` where modality supports them.
- Runs without `--brainstorm-spec` must produce unchanged summaries, ledger writes, report paths, and dynamic registry behavior.

### 6. Selection Semantics

Selection order when `--brainstorm-spec` is provided:

1. load normal static profiles
2. load existing dynamic profiles unless disabled by existing flags
3. load brainstorm-derived profiles
4. apply explicit filters

Filter rules:

- `--brainstorm-only`: discard non-brainstorm profiles after loading brainstorm profiles.
- `--brainstorm-hypothesis H001`: keep only brainstorm profiles linked to that hypothesis.
- existing `--class` / `--profile`: applies to all profiles by key/class after brainstorm generation.
- preflight may skip brainstorm profiles only if the skip reason is logged to coverage.
- duplicate agent keys are rejected unless they resolve to the exact same hypothesis/spec hash.
- `max_agents` applies after final selection and must write `agent_queued` only for profiles actually selected.

Acceptance tests required:

- `--brainstorm-only` runs no static profiles.
- `--class` can select a brainstorm-generated class/profile.
- duplicate suggested agent keys fail closed with a readable error.
- preflight skip produces a coverage event.

### 7. Parser Validation Requirements

Parser must reject or clearly mark invalid specs for:

- duplicate hypothesis IDs
- invalid statuses
- invalid priorities
- missing required fields
- unsafe absolute paths outside the resolved target/lane unless explicitly allowed
- duplicate suggested agent keys across active hypotheses
- malformed coverage table rows if markdown writeback is enabled

Invalid specs should fail before spawning agents.

### 8. Additional Acceptance Criteria

Add to implementation checklist:

- Coverage JSONL writes are lock-safe under parallel agents.
- Coverage summary can answer untested/blocked/tested/promoted from JSONL alone.
- `no finding` is not conflated with timeout, crash, invalid output, duplicate-only, or review rejection.
- Brainstorm metadata round-trips through common ledger and report lifecycle.
- Existing no-brainstorm runs are byte-for-byte or structurally unchanged for summary/report path behavior where practical.
