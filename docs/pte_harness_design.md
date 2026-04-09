# PTE-Informed Efficiency Design For The Bug Bounty Harness

## Goal

Add a PTE-style efficiency layer to the harness so it stops rewarding agent activity for its own sake and starts rewarding unique, review-surviving findings per unit of model and tool cost.

The harness already has the right control points:

- `agents/hybrid_preflight.py` decides which class agents are worth spawning.
- `agents/zero_day_team.py` spawns agents, runs them, deduplicates against the ledger, and sends findings to review.
- `agents/ledger_v2.py` already stores per-finding sightings keyed by `run_id`, `snapshot_id`, and `agent`.
- `~/projects/bounty-tools/subagent_logger.py` already emits JSONL step logs and is the lowest-friction place to add trace fields.

The missing piece is not observability alone. It is a decision model that converts traces into agent worth and uses that score in spawn selection.

## Design Principles

1. Measure at the span level, decide at the run and agent-profile level.
2. Keep raw telemetry out of the ledger. Store summaries in the ledger, raw spans in JSONL traces.
3. Penalize duplicate confirmation and prompt bloat, not just failures.
4. Score agents on review-surviving signal, not raw finding count.
5. Use a `PTE-lite` estimate first, then tighten it when provider-side cache signals are available.

## Why PTE Matters Here

The PTE paper's practical lesson is directly relevant to this harness: more tool calls often mean lower correctness, especially when tools are used confirmatorily, mixed without discipline, or pulled into the context window in formats the model cannot efficiently use.

That is already the failure shape of multi-agent bug bounty pipelines:

- the same surface gets scanned by overlapping agents
- long tool outputs are pasted into later model calls
- spawn-heavy topologies pay the same prefill tax repeatedly
- false positives look productive until human or second-stage review rejects them

For this harness, the right proxy metric is not "how many steps happened?" It is:

`unique reviewed value / PTE-lite`

## PTE-Lite: What To Compute

Exact PTE depends on serving details such as KV-cache reuse and eviction that the harness does not currently observe. Start with an explicit approximation:

`pte_lite = model_prefill_tokens + model_completion_tokens + replayed_tool_tokens + spawn_prefill_tokens + context_overhang_tokens`

Where:

- `model_prefill_tokens`: prompt tokens sent to a model call
- `model_completion_tokens`: completion tokens returned by the model call
- `replayed_tool_tokens`: tool output tokens later re-injected into model context
- `spawn_prefill_tokens`: inherited system prompt + repo context + prior findings context paid again by a spawned agent
- `context_overhang_tokens`: estimated penalty when rolling context exceeds a configured soft cache window

### Default estimators

If exact tokenization is unavailable:

- estimate tokens as `ceil(bytes / 4)`
- estimate `replayed_tool_tokens` only when tool output is actually included in a later prompt
- estimate `context_overhang_tokens` as `max(0, rolling_context_tokens - soft_context_limit_tokens)`
- start with `soft_context_limit_tokens = 32000` as a configurable default, not a truth claim about any provider

### Recommended stored fields

At minimum, capture:

- `prompt_tokens`
- `completion_tokens`
- `cached_tokens_read` when available
- `cached_tokens_written` when available
- `tool_output_tokens`
- `tool_output_reused`
- `context_tokens_before`
- `context_tokens_after`
- `spawn_prefill_tokens`
- `context_overhang_tokens`
- `pte_lite`

## What To Measure

### Per spawn decision

- `trace_id`
- `run_id`
- `program`
- `snapshot_id`
- `target_kind`
- `agent_name`
- `decision_source`
- `preflight_regex_score`
- `preflight_confidence`
- `historical_worth`
- `expected_pte`
- `redundancy_penalty`
- `spawned`
- `skip_reason`

### Per agent run

- `trace_id`
- `run_id`
- `parent_run_id`
- `agent_name`
- `start_ts`
- `end_ts`
- `duration_ms`
- `exit_code`
- `spawn_cold_start_ms`
- `spawn_prefill_tokens`
- `total_pte_lite`
- `model_call_count`
- `tool_call_count`
- `distinct_tool_types`
- `bytes_read`
- `bytes_written`
- `raw_findings_count`
- `deduped_findings_count`
- `reviewed_confirmed_count`
- `reviewed_dormant_active_count`
- `reviewed_dormant_hypothetical_count`
- `reviewed_rejected_count`
- `duplicate_count`

### Per model span

- `span_id`
- `parent_span_id`
- `span_type = "model"`
- `model_provider`
- `model_name`
- `phase`
- `prompt_tokens`
- `completion_tokens`
- `cached_tokens_read`
- `cached_tokens_written`
- `latency_ms`
- `context_tokens_before`
- `context_tokens_after`
- `tool_output_tokens_in_prompt`
- `spawn_prefill_tokens`
- `context_overhang_tokens`
- `pte_lite`
- `success`
- `error_class`

### Per tool span

- `span_id`
- `parent_span_id`
- `span_type = "tool"`
- `tool_name`
- `tool_category`
- `phase`
- `input_bytes`
- `output_bytes`
- `output_tokens_est`
- `latency_ms`
- `result_status`
- `fed_back_to_model`
- `reused_by_span_ids`
- `pte_replay_cost`

### Per finding outcome

- `fid`
- `trace_id`
- `run_id`
- `agent_name`
- `finding_key`
- `class_name`
- `category`
- `dedupe_status`
- `review_tier`
- `review_reason`
- `is_unique`
- `is_false_positive`
- `is_chain_enabler`
- `finding_reward`
- `allocated_pte_lite`

## Schema Recommendation

Do not create a second bespoke metrics store. Extend the existing JSONL logger shape and add a small number of summary fields to ledger sightings.

### Extend `SubagentLogger.LogEntry`

Add these optional fields:

```python
trace_id: Optional[str] = None
span_id: Optional[str] = None
parent_span_id: Optional[str] = None
span_type: Optional[str] = None  # run, spawn_decision, model, tool, finding
phase: Optional[str] = None      # preflight, agent_run, review, ledger
agent_name: Optional[str] = None
tool_name: Optional[str] = None
tool_category: Optional[str] = None
model_name: Optional[str] = None
prompt_tokens: Optional[int] = None
completion_tokens: Optional[int] = None
cached_tokens_read: Optional[int] = None
cached_tokens_written: Optional[int] = None
context_tokens_before: Optional[int] = None
context_tokens_after: Optional[int] = None
tool_output_tokens: Optional[int] = None
spawn_prefill_tokens: Optional[int] = None
context_overhang_tokens: Optional[int] = None
pte_lite: Optional[int] = None
redundancy_penalty: Optional[float] = None
historical_worth: Optional[float] = None
expected_worth: Optional[float] = None
finding_fid: Optional[str] = None
review_tier: Optional[str] = None
duplicate: Optional[bool] = None
```

### Ledger summary fields

Store summaries on `ledger_v2` sightings, not raw traces:

- `trace_id`
- `source_run_id`
- `source_agent`
- `review_tier`
- `finding_reward`
- `allocated_pte_lite`
- `duplicate`
- `chain_enabler`

This lets the profiler query historical value without scanning raw logs.

## Efficiency Scoring

### Finding reward

Use a reward table based on post-review value:

- `CONFIRMED` unique class finding: `1.00`
- `CONFIRMED` unique novel finding: `1.20`
- `DORMANT_ACTIVE`: `0.45`
- `DORMANT_HYPOTHETICAL`: `0.15`
- `REJECTED` or placeholder: `-0.60`
- duplicate of an already-known finding: `-0.35`
- chain-enabling uplift proven later: `+0.30`

### Finding-level efficiency

`finding_efficiency = finding_reward / max(allocated_pte_lite / 1000, 1)`

### Run-level worth

`run_signal = sum(finding_reward)`

`run_cost = max(total_pte_lite / 1000, 1)`

`run_worth = run_signal / run_cost`

### Agent-profile worth

Aggregate by agent plus target bucket:

- framework bucket
- language bucket
- target kind: source or web
- auth state
- WAF state
- application family if known

Recommended online estimate:

`profile_worth = 0.7 * rolling_30d_mean + 0.3 * rolling_7d_mean`

Also store:

- `fp_rate = rejected / reviewed`
- `dup_rate = duplicates / raw_findings`
- `chain_rate = chain_enablers / unique_findings`
- `median_pte_lite`

### Spawn score used by the profiler

`spawn_score = expected_profile_worth + target_match_bonus - redundancy_penalty - cost_penalty`

Where:

- `expected_profile_worth` comes from historical bucketed performance
- `target_match_bonus` comes from preflight signals
- `redundancy_penalty` comes from overlap with already-selected agents
- `cost_penalty` is driven by expected PTE-lite and wall time

Agents below threshold are skipped unless forced by exploration.

### Exploration policy

Reserve `10-15%` of budget for exploration so the profiler can learn new high-yield cases instead of freezing existing priors.

## Relation To The Profiler

The profiler should stop being only a capability detector and become a budgeted router.

Recommended policy:

1. Run preflight as today.
2. Build a target feature bucket from frameworks, language mix, target type, and signal files or endpoints.
3. Look up each candidate agent's historical `profile_worth`.
4. Apply a redundancy matrix.
5. Select the highest total spawn score under a budget.

Budget axes:

- max spawned agents
- max expected PTE-lite
- max wall-clock budget
- max browser budget

## Redundancy Matrix

Start with a hand-built matrix, then learn it from data.

Suggested initial overlap values:

- `ipc-trust-boundary` vs `node-integration`: `0.70`
- `exec-sink-reachability` vs `native-module-abuse`: `0.60`
- `exec-sink-reachability` vs `path-traversal`: `0.30`
- `unsafe-deserialization` vs `exec-sink-reachability`: `0.40`
- `xss_framework` vs `xss_hunter`: `0.75`
- `fuzz_runner` vs generic recon or endpoint discovery agents: `0.65`

If one high-overlap agent is already selected with strong preflight evidence, the other should need a materially higher expected worth to justify spawning.

## Where To Instrument In This Repo

### `agents/hybrid_preflight.py`

Log one `spawn_decision` span per candidate class:

- regex score
- LLM preflight result
- expected worth
- redundancy penalty
- final decision

### `agents/zero_day_team.py`

Instrument:

- `orchestrate_zero_day_team()`: root trace, budget, selected and skipped classes
- `_spawn_agent()`: spawn prefill estimate and cold-start cost
- `_run_agent_session()`: raw findings count, duplicate skips, total run PTE-lite
- `stage2_ghost_review()`: review spans and per-finding reward assignment

### `agents/ledger_v2.py`

When adding or updating a sighting, accept optional efficiency summaries so that historical worth is queryable by the profiler without replaying logs.

### `~/projects/bounty-tools/subagent_logger.py`

This is the correct place to add the schema because it already handles JSONL, summary files, and parent-child linkage.

## Specific Recommendations For `zero_day_team`

### 1. Treat it as a router plus reviewers, not a single agent

`zero_day_team` is really four cost centers:

- preflight
- per-class spawned Codex agents
- dedupe against ledger
- second-stage review with Claude or Codex

Measure each separately. Right now only outcomes are visible.

### 2. Penalize repeated spawn prefill

Each spawned class agent pays for:

- profile prompt
- repo context
- prior class context
- starting entry context

That repeated prefill is exactly where PTE-lite will expose hidden cost. Log `spawn_prefill_tokens` for every class agent.

### 3. Gate reviewer cost harder

Today every raw finding that survives initial dedupe can trigger expensive second-stage review. Add a cheap evidence gate first:

- reject placeholder or malformed findings before review
- skip review for exact duplicate logical keys
- only send top-ranked low-confidence findings when budget remains

### 4. Use preflight plus historical worth together

Current preflight answers "is there surface area?" It should answer "is there enough expected value to pay the spawn tax?"

For example:

- low regex score plus low historical worth should skip
- medium regex score plus high framework-specific yield should run
- high overlap classes should not both run unless both have strong independent support

### 5. Compress shared context

`get_class_context()` and shared-brain context should be compact summaries, not long finding dumps. The more prior findings are pasted verbatim, the more likely the class agent pays context tax for old information it does not need.

### 6. Learn per-class target priors

Good first priors for `zero_day_team`:

- Electron signals strongly increase worth for `ipc-trust-boundary`, `node-integration`, and `exec-sink-reachability`
- native parser and unsafe-memory signals increase worth for `memory-unsafe-parser`
- deserialization libraries increase worth for `unsafe-deserialization`
- renderer-heavy web code raises worth for `dom-xss`

These priors should reduce "fail-open run everything" behavior.

## Mapping The Four Inefficiency Patterns To This Harness

### Confirmatory Tool Usage

Likely offenders:

- `zero_day_team` class overlap on Electron surfaces
- `xss_framework` and `xss_hunter` running against the same target family
- `sync_reports` or `manual_hunter` re-asserting already-known findings
- reviewer model re-checking low-value duplicates that the ledger already knows

Fix:

- add redundancy penalties
- dedupe earlier
- reward chain uplift, not repeated confirmation

### Tool-Mixing

Likely offenders:

- `xss_framework`: discovery, Wayback, param fuzzing, browser verification, WAF bypass in one trajectory
- `llm_harness`: profiling, adaptive conversation, detection, and optional external-model adaptation
- `zero_day_team`: shared-brain lookup, multi-agent spawn, log salvage, second-stage review

Fix:

- split phases into explicit spans
- stop forwarding full outputs between unrelated phases
- score mixed trajectories on output value, not completion of all phases

### Lack Of Tool Priors

Likely offenders:

- `fuzz_runner` using generic wordlists before target-specific narrowing
- `ssrf_escalation` probing many environments before using target clues
- `llm_harness` escalating payloads without a sufficiently strong model or app profile
- `zero_day_team` failing open when LLM preflight is unavailable

Fix:

- make target priors first-class inputs
- use learned framework and target buckets
- require stronger evidence before broad exploration

### Tool Format Collapse

Likely offenders:

- spawned `zero_day_team` agents write mixed prose and JSON to logs, forcing salvage parsing
- raw review prompts can include large source excerpts and verbose finding context
- LLM harness conversation logs can accumulate low-signal text

Fix:

- enforce structured tool outputs
- keep evidence snippets bounded
- track `tool_output_tokens_in_prompt` and penalize large low-yield replays

## Example JSONL Entries

### Spawn decision

```json
{
  "timestamp": "2026-04-08T17:22:04Z",
  "level": "STEP",
  "tool": "zero_day_team",
  "trace_id": "zdt_20260408_172204_acme_7f3a",
  "span_id": "spawn_decision_dom_xss",
  "span_type": "spawn_decision",
  "phase": "preflight",
  "agent_name": "dom-xss",
  "run_id": "20260408T172204Z",
  "target": "/tmp/acme-decompiled",
  "preflight_regex_score": 9,
  "historical_worth": 0.84,
  "expected_worth": 1.11,
  "redundancy_penalty": 0.10,
  "spawned": true,
  "message": "run agent; strong renderer sink coverage and favorable prior"
}
```

### Model span

```json
{
  "timestamp": "2026-04-08T17:23:18Z",
  "level": "RESULT",
  "tool": "zero_day_team",
  "trace_id": "zdt_20260408_172204_acme_7f3a",
  "span_id": "model_review_f03",
  "parent_span_id": "run_dom_xss",
  "span_type": "model",
  "phase": "review",
  "agent_name": "dom-xss",
  "model_name": "claude",
  "prompt_tokens": 6120,
  "completion_tokens": 441,
  "context_tokens_before": 5800,
  "context_tokens_after": 6241,
  "tool_output_tokens": 950,
  "spawn_prefill_tokens": 0,
  "context_overhang_tokens": 0,
  "pte_lite": 7511,
  "duration_ms": 18234,
  "success": true,
  "finding_fid": "D07",
  "review_tier": "CONFIRMED",
  "message": "review completed"
}
```

### Finding outcome

```json
{
  "timestamp": "2026-04-08T17:23:19Z",
  "level": "RESULT",
  "tool": "zero_day_team",
  "trace_id": "zdt_20260408_172204_acme_7f3a",
  "span_id": "finding_D07",
  "span_type": "finding",
  "phase": "ledger",
  "agent_name": "dom-xss",
  "run_id": "20260408T172204Z",
  "finding_fid": "D07",
  "review_tier": "CONFIRMED",
  "duplicate": false,
  "finding_reward": 1.0,
  "pte_lite": 2330,
  "message": "unique confirmed finding recorded"
}
```

## Research Findings From Other Frameworks

### LangChain and LangSmith

What they do well:

- trace runs and child spans
- store `prompt_tokens`, `completion_tokens`, `total_cost`, `latency`, and `first_token_time`
- support alerts on cost, errors, latency, and feedback regressions

What to copy:

- run and span schema
- feedback attached to traces
- alerting on cost spikes and latency regressions

What they do not solve for us:

- they expose observability, not a bug-bounty-specific worth function
- they do not penalize duplicate confirmations by default

### CrewAI

What it does well:

- integrates with observability backends like Weave
- captures agent interactions, task flow, LLM metadata, tool usage, latency, and token usage

What to copy:

- treat agent interactions and tool calls as first-class spans
- keep evaluation and tracing tightly linked

Gap:

- tracing is descriptive; spawn-worth routing remains our responsibility

### Mastra

What it does well:

- first-class tracing, telemetry, and evals
- scorers convert qualitative output assessment into structured scores
- newer platform metrics track duration, token usage, estimated cost, scores, and errors across agents, tools, and workflows

What to copy:

- custom scorers for bug-bounty-specific quality
- dashboards that join traces with evaluation outcomes

Gap:

- its generic scoring model still needs our domain-specific rewards for duplicates, false positives, and chain value

### AutoGPT and AGBenchmark

What it does well:

- measures task success at the benchmark level
- keeps evaluation framework-agnostic across agents

What to copy:

- keep the harness evaluation portable across different agent implementations

Gap:

- benchmark-level success does not explain which step pattern wasted cost
- it is too coarse for spawn control inside a live bug bounty pipeline

## Research Findings From Agent Evaluation Papers

### PTE paper

Use as the main design inspiration:

- tool-heavy trajectories can be less correct
- tool inefficiency patterns are diagnostically useful
- context inflation and repeated prefill should be treated as real cost

### AI Agents That Matter

Takeaway:

- optimize cost and accuracy jointly, not accuracy alone
- benchmark gains can be brittle and misleading without cost controls

### Efficient Agents

Takeaway:

- additional modules show diminishing returns
- cost-of-pass is a better system metric than raw capability alone

### AgentAssay

Takeaway:

- traces can power cheap regression detection
- PASS, FAIL, and INCONCLUSIVE are better than forcing binary labels in nondeterministic agent systems

### PentestGPT

Takeaway:

- offensive security workflows are especially vulnerable to context drift
- agents are good at subtasks but weaker at long, holistic pentest state management

This is a strong argument for smaller per-agent contexts and for not replaying large tool outputs unless they directly affect the next decision.

## Bug Bounty Domain Takeaways

Public bug bounty standards already encode an efficiency lesson:

- duplicate or merely confirmatory reports have diminishing value
- chain-enabling reports can increase value if they materially change impact

That should become part of the reward model. An agent that finds five copies of a known pattern should score lower than an agent that finds one chain-enabling or review-surviving novel issue.

## Rollout Plan

### Phase 1: Schema and trace capture

- extend `SubagentLogger`
- instrument preflight, spawn, review, and ledger update points
- write JSONL traces under the existing logger path

### Phase 2: Offline scoring

- build a daily batch job that computes:
  - per-run worth
  - per-agent profile worth
  - fp rate
  - duplicate rate
  - median PTE-lite

### Phase 3: Spawn gating

- feed `profile_worth` into `run_preflight()`
- apply the redundancy matrix
- gate low-worth agents under a configurable budget

### Phase 4: Regression and alerts

- alert on:
  - spike in PTE-lite without matching signal gain
  - false-positive regressions
  - duplicate-confirmation spikes
  - agents whose worth drops below threshold for N consecutive runs

## Recommended First Dashboard

One table is enough to start:

- `agent_name`
- `target_bucket`
- `runs`
- `median_pte_lite`
- `confirmed_unique`
- `dormant_active`
- `rejected`
- `duplicates`
- `fp_rate`
- `dup_rate`
- `run_worth`
- `profile_worth`

If a metric does not change spawn policy, do not put it on the first dashboard.

## References

- PTE paper: arXiv `2604.05404`
- LangSmith run data format: https://docs.langchain.com/langsmith/run-data-format
- LangSmith alerts: https://docs.langchain.com/langsmith/alerts
- LangChain multi-agent performance comparison: https://docs.langchain.com/oss/python/langchain/multi-agent
- CrewAI observability and Weave integration: https://docs.crewai.com/en/observability/weave
- Mastra observability: https://mastra.ai/observability
- Mastra scorers: https://mastra.ai/blog/mastra-scorers
- Mastra metrics and logs: https://mastra.ai/blog/announcing-studio-metrics
- AutoGPT Benchmarks: https://github.com/Significant-Gravitas/Auto-GPT-Benchmarks
- AI Agents That Matter: https://arxiv.org/abs/2407.01502
- Efficient Agents: https://arxiv.org/abs/2508.02694
- AgentAssay: https://arxiv.org/abs/2603.02601
- PentestGPT paper page: https://pentestgpt.com/paper.html
- HackerOne platform standards on diminishing and duplicate value: https://docs.hackerone.com/en/articles/8369826-detailed-platform-standards
