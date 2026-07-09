---
name: fuzz
description: Use when discovering hidden endpoints, parameters, files, routes, directories, request fields, or undocumented application surface through fuzzing.
---
# Web Fuzzing

Discover hidden endpoints, parameters, and files through enumeration.

## Routing Trigger

Load this skill whenever the agent plans to discover unknown application
surface by trying candidates, even if the word "fuzz" is not used.

Route these phrases and tasks here:

- guess parameters, hidden parameters, parameter discovery, try parameter names
- enumerate request fields, JSON keys, form fields, headers, cookies, or query keys
- brute-force paths, files, extensions, vhosts, routes, GraphQL fields, or API actions
- try many likely values to discover reachable surface or behavior switches
- build or run a wordlist against one bounded host, route, workflow, or request shape

Do not create a separate policy path for these cases. Once `/fuzz` is loaded,
the fuzz skill owns the depth, rate-limit, scoping, filtering, artifact, and
handoff rules for the run.

## Required Preflight

Read the relevant notes for the concrete surface when they exist:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (fuzz items only)
4. `todo.md` (fuzz items only)

## Primary Harness

Use `ffuf` as the primary operator-facing harness. `agents/fuzz_runner.py` exists as a campaign-managed helper class, but it does not expose a stable CLI in this repo.

```bash
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,307,401,403,405 -fc 404 -rate 5 -c -v
```

For multi-list or target-tailored campaigns, load `/use-wordlists` first. It
owns temporary wordlist composition, fuzz history, Telegram progress updates,
and URL-ingest handoff.

## Depth Policy

Fuzzing is allowed to go deep when the target is in scope, rate limits are
clear, and the run is paced. Do not cap ideas just because the wordlist is
large. A 50,000-candidate parameter or path campaign is acceptable when it is:

- scoped to a specific host/route/workflow
- rate-limited with `ffuf -rate` or equivalent pacing
- tracked with a run manifest and progress checkpoints
- filtered against wildcard/catch-all responses before promotion
- routed through the agent MITM proxy when request history matters

Depth is not permission for destructive payloads, lockout-prone login spraying,
state-changing spam, or testing outside scope.

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
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,307,401,403,405 -fc 404 -rate 5 -c -v

# Parameter discovery on a known endpoint
ffuf -u 'https://target.com/api/search?FUZZ=test' \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
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
- **Fuzz History:** `~/Shared/web_bounty/{program}/web/recon/fuzz_history/fuzz_runs.jsonl`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/fuzz-playbook.md`.
3. For tailored or multi-list campaigns, load `/use-wordlists`.
4. Run `ffuf` with the smallest wordlist set that answers the current question.
5. Record the URL pattern, date, wordlists, output path, and outcome in fuzz history.
6. Promote only interesting hits into the findings workflow.
7. Write findings to `agent_shared/findings/fuzz/findings.md`.
8. Update fuzz entries in `checklist.md`, `todo.md`, and relevant notes.
