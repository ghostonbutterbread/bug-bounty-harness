---
name: hunter-memory
description: "Use when agents need an observe-learn-adapt memory loop during mapping, web testing, manual hunting, child-agent handoffs, or BBH team runs."
---

# Hunter Memory

Use this after `/live-map`, `/me`, `/brainstorm`, manual hunting, or any skill
handoff where the agent should remember experiments, failed attempts, learned
boundaries, next mutations, and reusable claims.

This skill is not only for BaseTeam. BaseTeam can enable it with
`--hunter-memory`, but standalone agents can use `agents/hunter_memory_tool.py`
directly.

## Load Order

1. Read scope, account context, and the active live-testing policy.
2. Read `$HARNESS_ROOT/prompts/hunter-memory-playbook.md`.
3. If an application map exists, read the relevant packet or summary from
   `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`.
4. Start a memory run for the exact surface/idea being tested.
5. Record distilled attempts, observations, boundaries, and next actions.

## Commands

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"

python3 agents/hunter_memory_tool.py start <program> \
  --vulnerability xss \
  --surface avatar-upload \
  --goal "Learn whether avatar upload reaches a stored render context" \
  --agent-id scout \
  --prompt-out /tmp/hunter-memory-prompt.md

python3 agents/hunter_memory_tool.py attempt \
  --agent-dir <agent-path> \
  --goal "Learn whether avatar upload reaches a stored render context" \
  --action "Uploaded benign png baseline" \
  --result "inconclusive" \
  --observation "Upload accepted and profile rendered image tag" \
  --learning "PNG path is accepted; filename render still untested" \
  --next-action "Check filename, metadata, admin, and email render contexts"

python3 agents/hunter_memory_tool.py claim \
  --run-path <run-path> \
  --agent-id scout \
  --claim "Profile render HTML-escapes the avatar filename, but admin/email/export contexts are untested" \
  --status needs_followup \
  --confidence medium

python3 agents/hunter_memory_tool.py harvest \
  --run-path <run-path> \
  --agent-id scout \
  --log <agent-log-path>
```

## BaseTeam Mode

```bash
python3 agents/zero_day_team.py <program> <target> --hunter-memory
python3 agents/apk_team.py <program> <apk-or-extracted-root> --hunter-memory
python3 agents/base_team_core.py --program <program> --target-path <target> --team-type 0day_team --hunter-memory
```

## Output

Default storage is:

`$HARNESS_SHARED_BASE/{program}/hunter_memory/{vulnerability}/{surface}/{run_id}/`

Important files:
- `RUN.md`
- `shared_summary.md`
- `claims.jsonl`
- `agents/{agent-id}/goal_state.json`
- `agents/{agent-id}/attempts.jsonl`
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
