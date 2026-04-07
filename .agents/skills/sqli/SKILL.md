---
name: sqli
description: Test for SQL Injection vulnerabilities
---
# SQL Injection Testing

Test for SQL Injection vulnerabilities.

**Caution:** Non-destructive tests only. Do not extract data.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (SQLi items only)
4. `todo.md` (SQLi items only)

## Primary Harness

There is no dedicated `agents/sqli_hunter.py` in this repo. Treat your browser/proxy request replay workflow as the primary execution surface and use `agents/payload_mutator.py` to generate context-aware SQLi variants after you have classified the sink.

```bash
python agents/payload_mutator.py "' OR 1=1--" --type sqli --count 12
```

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/sqli-playbook.md`
- **Payload Catalog:** `$HARNESS_ROOT/prompts/sqli-payloads.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **SQLi Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/sqli/findings.md`
- **SQLi Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/sqli/`

## Mode Matrix

| Mode | Use When | What It Confirms |
|------|----------|------------------|
| `error` | Input causes syntax changes or stack traces | Whether the backend leaks parser or database fingerprints |
| `boolean` | Response changes without explicit errors | Whether the query logic is injectable without noisy output |
| `time` | Output is blind but the request timing is observable | Whether a delay primitive is reachable safely |
| `union` | The sink appears to return query results inline | Whether result-shaping and column control are possible without extraction |

## Helper Command

Use the mutator only after you know which lane you are in.

```bash
python agents/payload_mutator.py "' OR 1=1--" --type sqli --count 12
```

## CLI Notes

### `agents/payload_mutator.py`

| Option | Description |
|--------|-------------|
| `payload` | Seed payload to mutate |
| `--type` | One of `xss`, `sqli`, or `generic` |
| `--count` | Number of variants to emit |
| `--all-encodings` | Include heavier encoding and obfuscation variants |

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/sqli-playbook.md`.
3. Use `prompts/sqli-payloads.md` only after you have chosen the correct lane.
4. Replay requests manually with the minimum payload needed for that lane.
5. Write findings to `agent_shared/findings/sqli/findings.md`.
6. Update SQLi entries in `checklist.md`, `todo.md`, and relevant notes.
