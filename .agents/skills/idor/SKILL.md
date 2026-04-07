---
name: idor
description: Test for Insecure Direct Object Reference vulnerabilities
---
# IDOR Testing

Test for Insecure Direct Object Reference vulnerabilities.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (IDOR items only)
4. `todo.md` (IDOR items only)

## Primary Harness

Use `agents/bypass_harness.py` in `--type idor` mode for first-pass ID swapping and header-trick coverage. Expand manually for multi-step workflows, write actions, and role-bound objects once you identify a promising reference.

```bash
python agents/bypass_harness.py --target https://target.com/api/v1/orders/123 \
  --type idor --program target --concurrency 5 --rps 2
```

## Mode Matrix

| Mode | Use When | What It Tests |
|------|----------|---------------|
| `horizontal-read` | One user can see another user's object | Read access control on object fetches |
| `horizontal-write` | Mutable resources exist | Update or delete authorization on peer objects |
| `vertical` | Admin or privileged resources are exposed via IDs | Role boundary enforcement |
| `workflow` | IDs appear across multi-step flows | Ownership checks at each transition |

## Primary Commands

```bash
# Path-based ID swapping
python agents/bypass_harness.py --target https://target.com/api/v1/orders/123 \
  --type idor --program target --concurrency 5 --rps 2

# Query-parameter ID swapping
python agents/bypass_harness.py --target https://target.com/api/v1/order?id=123 \
  --type idor --program target --concurrency 5 --rps 2
```

## CLI Notes

### `agents/bypass_harness.py`

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target URL (required) |
| `--type`, `-T` | Use `idor` |
| `--program` | Program name for shared storage |
| `--output-dir`, `-o` | Override raw artifact directory |
| `--timeout` | Request timeout in seconds |
| `--concurrency`, `-c` | Max parallel requests |
| `--rps` | Requests per second |
| `--verbose`, `-v` | Verbose debug output |
| `--quiet`, `-q` | Show hits only |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/idor-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **IDOR Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/idor/findings.md`
- **Bypass Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/idor-playbook.md`.
3. Run `agents/bypass_harness.py` in `--type idor` mode for first-pass coverage.
4. Confirm promising cases manually with baseline captures and multi-account comparison.
5. Write findings to `agent_shared/findings/idor/findings.md`.
6. Update IDOR entries in `checklist.md`, `todo.md`, and relevant notes.
