---
name: hunter-memory
description: "Use when agents need an observe-learn-adapt memory loop during mapping, web testing, manual hunting, child-agent handoffs, or BBH team runs."
---

# Hunter Memory

Use this after `/live-map`, `/me`, `/brainstorm`, manual hunting, or any skill
handoff where the agent should remember experiments, failed attempts, learned
boundaries, next mutations, and run-local claims. A Hunter Memory claim is not
shared app memory: when it becomes stable enough to guide a future specialist,
promote one concise fact to `/map-store` and retain only the run learning plus
that pointer here.

This skill is not only for BaseTeam. BaseTeam can enable it with
`--hunter-memory`, but standalone agents can use `agents/hunter_memory_tool.py`
directly.

## Load Order

1. Read scope, account context, and the active live-testing policy.
2. Read `prompts/hunter-memory-playbook.md`.
3. If an application map exists, read the relevant packet or summary from
   `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`.
4. Start a memory run for the exact surface/idea being tested.
5. Let the selected live-testing skill own any target-directed probe and its
   canonical Attempt record.
6. Record only distilled learning, boundaries, and next actions in Hunter
   Memory; link an existing canonical `attempt_id` or stream path when one
   motivated the learning.
7. Do not use Hunter Memory to discover, create, query, or retain raw Attempt
   history.

## Commands

```bash

bbh agents/hunter_memory_tool.py start <program> \
  --vulnerability xss \
  --surface avatar-upload \
  --goal "Learn whether avatar upload reaches a stored render context" \
  --agent-id scout \
  --prompt-out /tmp/hunter-memory-prompt.md

bbh agents/hunter_memory_tool.py claim \
  --run-path <run-path> \
  --agent-id scout \
  --claim "Profile render HTML-escapes the avatar filename, but admin/email/export contexts are untested" \
  --status needs_followup \
  --confidence medium

bbh agents/hunter_memory_tool.py harvest \
  --run-path <run-path> \
  --agent-id scout \
  --log <agent-log-path>
```

## BaseTeam Mode

```bash
bbh agents/zero_day_team.py <program> <target> --hunter-memory
bbh agents/apk_team.py <program> <apk-or-extracted-root> --hunter-memory
bbh agents/base_team_core.py --program <program> --target-path <target> --team-type 0day_team --hunter-memory
```

## Output

Default storage is:

`$HARNESS_SHARED_BASE/{program}/hunter_memory/{vulnerability}/{surface}/{run_id}/`

Important files:
- `RUN.md`
- `shared_summary.md`
- `claims.jsonl`
- `agents/{agent-id}/goal_state.json`
- `agents/{agent-id}/attempts.jsonl` — legacy Hunter Memory action-log filename;
  it is **not** target-directed Attempt evidence and must not receive raw probe
  rows. Treat it as deprecated internal compatibility until its separate rename
  migration is scheduled.
- `agents/{agent-id}/observations.md`
- `agents/{agent-id}/hypotheses.md`
- `agents/{agent-id}/final_summary.md`

## Rules

- Store learning, not raw traffic dumps.
- Failed payloads become scoped boundaries, not global vuln-class rejections.
- Do not store raw cookies, bearer tokens, API keys, passwords, credentials, or
  private headers.
- Keep claims reusable and scoped to a surface/context.
- Promote to a finding only when the normal skill proof standard is met.
