---
name: fuzz
description: Discover hidden endpoints, parameters, and files
---
# Web Fuzzing

Discover hidden endpoints, parameters, and files through enumeration.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (fuzz items only)
4. `todo.md` (fuzz items only)

## Primary Harness

Use `ffuf` as the primary operator-facing harness. `agents/fuzz_runner.py` exists as a campaign-managed helper class, but it does not expose a stable CLI in this repo.

```bash
ffuf -u https://target.com/FUZZ \
  -w ~/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,307,401,403,405 -fc 404 -rate 5 -c -v
```

## Mode Matrix

| Mode | Use When | What It Finds |
|------|----------|---------------|
| `content` | Mapping hidden paths and endpoints | Directories, files, panels, APIs |
| `extensions` | Static file or backup exposure is likely | `.bak`, `.old`, config, env, and source artifacts |
| `params` | Interesting endpoints exist already | Hidden parameters and debug switches |
| `vhost` | Shared infrastructure or wildcard hosting is suspected | Alternate virtual hosts and shadow apps |

## Primary Commands

```bash
# Path and endpoint discovery
ffuf -u https://target.com/FUZZ \
  -w ~/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,307,401,403,405 -fc 404 -rate 5 -c -v

# Parameter discovery on a known endpoint
ffuf -u 'https://target.com/api/search?FUZZ=test' \
  -w ~/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all -fc 404 -fs 0 -rate 3 -c -v
```

## CLI Notes

### `ffuf`

| Option | Description |
|--------|-------------|
| `-u` | Target URL with `FUZZ` marker |
| `-w` | Wordlist path |
| `-mc` | Match status codes |
| `-fc` | Filter status codes |
| `-fs` | Filter by response size |
| `-rate` | Requests per second |
| `-c` | Colored output |
| `-v` | Verbose output |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/fuzz-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **Fuzz Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/fuzz/findings.md`
- **Fuzz Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/fuzz/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/fuzz-playbook.md`.
3. Run `ffuf` with the smallest wordlist that answers the current question.
4. Promote only interesting hits into the findings workflow.
5. Write findings to `agent_shared/findings/fuzz/findings.md`.
6. Update fuzz entries in `checklist.md`, `todo.md`, and relevant notes.
