---
name: live-map
description: "Build runtime application maps from browser exploration, proxy traffic, manual observations, or hybrid source/runtime evidence."
---

# Live Map

Use this when an agent needs to explore a live app without being told the vulnerability class.

`/live-map` complements `/appmap`:
- `/appmap` maps local source or extracted binaries.
- `/live-map` maps runtime behavior from browser navigation, proxy traffic, and manual observations.
- `/mental-map` remains the detailed flow-note workflow; `/live-map` writes the universal JSONL map that other skills can query.

## Load Order

1. Read `$HARNESS_ROOT/prompts/live-map-playbook.md`.
2. Read scope, live-testing policy, and approved account context.
3. Initialize or load `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`.
4. Capture or ingest one small exploration slice at a time.
5. Build bounded handoff packets before spawning child agents.

## Commands

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/live_map.py init <program>
python3 agents/live_map.py add-route <program> --url https://target.example/my-account?id=123 --auth-state user-a --source browser
python3 agents/live_map.py ingest <program> --input observations.jsonl --source proxy
python3 agents/live_map.py build-handoffs <program> --skill access-control
python3 agents/live_map.py summary <program>
```

## Output

Writes to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`

Primary artifacts:
- `routes.jsonl`
- `flows.jsonl`
- `objects.jsonl`
- `auth-boundaries.jsonl`
- `state-actions.jsonl`
- `hypotheses.jsonl`
- `handoffs/*.json`
- `summary.md`

## Child-Agent Rule

Do not pass page titles, lab titles, solution text, raw proxy dumps, cookies, bearer tokens, passwords, or broad app history to child agents.

Pass only the handoff packet plus the relevant skill pack. The child should treat map entries as exploration leads, not proof.
