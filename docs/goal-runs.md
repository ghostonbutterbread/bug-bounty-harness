# Explicit `/goal` runs

`/goal` is an explicit bug-bounty operating mode. It is not automatically loaded
for normal agent work. The BBH skill router is `bug-goals`; the BBH helper is
`scripts/goal_router.py`.

## Plan a goal

```bash
bbh scripts/goal_router.py plan \
  --program example \
  --objective "Find a new vulnerability"
```

Initialize small routing state only after choosing a run-artifact directory:

```bash
bbh scripts/goal_router.py init \
  --program example \
  --objective "Assess comment preview for XSS" \
  --url "https://app.example/comments/preview" \
  --class xss \
  --run-dir /path/to/approved/run-artifact
```

`init` creates `goal-state.json`. It contains routing/hypothesis continuity only;
it is not another source of durable target truth.

## Modes

| Mode | Trigger | Parent behavior |
|---|---|---|
| `broad-program` | Generic “find a vulnerability” objective | Hunter Loop: cold map, fresh observations, surface/lens selection, targeted retrieval, synthesis |
| `focused-surface` | URL, feature, workflow, or vulnerability class | Map the exact workflow and implementation boundary; use a specialist only when justified |
| `technology-review` | Library, framework, parser, sanitizer, source/runtime question | Source/JS/configuration and consumer-path analysis before bounded hypotheses |
| `continuation` | Warm/hot lead, roadblock, resume | Preserve Hunter Memory and select a distinct next discriminator |
| `revalidation` | Retest/repass/old issue | Prior evidence is primary but must be checked against a current baseline |

## Retrieval roles

The goal runner chooses sources contextually, rather than following a mandatory
retrieval queue.

- **MapStore:** target-specific facts, coverage, tested state, defenses, and
  dedupe after a concrete surface question exists.
- **Source/JS analysis:** implementation, versions/configuration, transformations,
  and downstream consumers.
- **ResearchMap:** portable cited mechanisms matching observed signals.
- **Preview MCP / web research:** fresh analogue write-ups, upstream source/docs,
  and technology understanding. See [`preview-mcp.md`](preview-mcp.md) for the
  local credential-safe client; never put its API key in a goal artifact.
- **Specialist skills:** methodology for a concrete observed class/boundary.

Research output produces hypotheses, not target findings. Every retrieved idea
must become an explicit, scoped discriminator before it drives live activity.

## Storage boundaries

| Information | Home |
|---|---|
| Current run’s active state, hypotheses, and next discriminator | `goal-state.json` and Hunter Memory |
| Durable target behavior, coverage, tested state, and negative results | MapStore |
| Hunt chronology, decisions, blockers, handoffs | bounty notes |
| Portable cited research mechanisms | synced ResearchMap Markdown corpus |
| Raw requests, screenshots, callback logs, and exact probe attempts | program artifact lane |

## Verification

```bash
uv run --with pytest python -m pytest tests/test_goal_router.py -q
bbh scripts/goal_router.py plan --program example --objective "Find a new vulnerability"
```
