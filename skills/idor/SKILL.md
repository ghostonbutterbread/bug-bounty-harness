---
name: idor
description: Use when testing Insecure Direct Object Reference, IDOR, broken object-level authorization, cross-account access, tenant isolation, user ID tampering, or resource ownership checks.
---
# IDOR Testing

Test for Insecure Direct Object Reference vulnerabilities.

For broader broken access control work, start with `/access-control`. Use `/idor` when the observed surface is specifically object-level authorization, BOLA, cross-account object access, tenant/object ID swapping, or hidden object handles.

## Required Preflight

Follow the Cold-Start Doctrine from `agents/index.md`:

1. **Scope Gate** — Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Look at the target object/endpoint with fresh eyes.
   Observe object IDs, auth boundaries, and response patterns directly.
   Do NOT query MapStore or prior attempts yet.
3. **Novelty Quota** — Identify 3-5 fresh object references, ID patterns, role
   differences, or auth boundaries from direct observation before pulling
   prior state.
4. **Memory Overlay** — Now read shared state in this order:
   - `/account-management` registry at
     `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json`
   - `notes/summary.md`
   - `notes/observations.md`
   - `checklist.md` (IDOR items only)
   - `todo.md` (IDOR items only)

Use the registry to identify owned account aliases, user IDs, PwnFox colors,
resource IDs, owner relationships, and destructible/cleanup status before
swapping any object identifier.

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
2. Read `prompts/access-control-context-pack.md` if the request is broader than direct object references.
3. Read `prompts/idor-playbook.md`.
4. Run `agents/bypass_harness.py` in `--type idor` mode for first-pass coverage.
5. Confirm promising cases manually with baseline captures and multi-account comparison from `/account-management` owned records.
6. Write findings to `agent_shared/findings/idor/findings.md`.
7. Record newly observed owned IDs/resources in `/account-management`.
8. Update IDOR entries in `checklist.md`, `todo.md`, and relevant notes.
