---
name: race
description: Test for race conditions and concurrent workflow flaws
---
# Race Condition Testing

Test for race conditions, state desynchronization, and concurrent workflow flaws.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (race items only)
4. `todo.md` (race items only)

## Primary Harness

Use `agents/bypass_harness.py` in `--type race` mode for first-pass concurrent replay. Set `--concurrency` above the module burst size so the harness does not artificially serialize the race.

```bash
python agents/bypass_harness.py --target https://target.com/api/redeem \
  --type race --program target --concurrency 20 --rps 20
```

## Mode Matrix

| Mode | Use When | What It Tests |
|------|----------|---------------|
| `single-use` | Token, coupon, or invite should be consumed once | Duplicate acceptance before invalidation |
| `limit` | Quotas or redemption limits should gate actions | Pre-check bypass under concurrency |
| `toctou` | Read-then-write checks gate value changes | Stale authorization, balance, or inventory windows |
| `workflow` | Multiple endpoints change the same object state | Conflicting transitions and ordering bugs |

## Primary Commands

```bash
# Default race pass
python agents/bypass_harness.py --target https://target.com/api/redeem \
  --type race --program target --concurrency 20 --rps 20
```

## CLI Notes

### `agents/bypass_harness.py`

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target URL (required) |
| `--type`, `-T` | Use `race` |
| `--program` | Program name for shared storage |
| `--output-dir`, `-o` | Override raw artifact directory |
| `--timeout` | Request timeout in seconds |
| `--concurrency`, `-c` | Max parallel requests; keep above the race burst |
| `--rps` | Requests per second |
| `--verbose`, `-v` | Verbose debug output |
| `--quiet`, `-q` | Show hits only |

## Stop Conditions

- Stop if behavior risks irreversible financial impact or harms real user data.
- Stop if the only effect is duplicate responses with no duplicated state change.
- Stop if the target becomes unstable.

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/race-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **Race Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/race/findings.md`
- **Bypass Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/race-playbook.md`.
3. Run `agents/bypass_harness.py` in `--type race` mode for duplicate-request testing.
4. Confirm any promising result by proving duplicated or inconsistent state, not just varied responses.
5. Write findings to `agent_shared/findings/race/findings.md`.
6. Update race entries in `checklist.md`, `todo.md`, and relevant notes.
