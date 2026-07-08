---
name: bounty-tools
description: Use when running external bug bounty tooling such as nmap, ffuf, dirbuster, gobuster, dalfox, dursgo, ssrfmap, nuclei, httpx, katana, gau, or one-off recon/fuzz/mapping commands so outputs, manifests, rate limits, and ingest handoffs land in canonical directories.
---

# Bounty Tools

Use this skill before running external security tools for recon, mapping,
fuzzing, probing, or vulnerability-lane discovery. It owns the common run
contract: output directory, run metadata, raw artifacts, parsed artifacts,
rate/concurrency defaults, stop conditions, and ingest handoff.

## When To Load

Load `/bounty-tools` whenever an agent will run a tool such as:

- network and service discovery: `nmap`, `naabu`, `httpx`
- content and parameter discovery: `ffuf`, `dirbuster`, `gobuster`, `arjun`
- crawlers and URL collectors: `katana`, `gau`, `waybackurls`
- vulnerability helpers: `dalfox`, `dursgo`, `ssrfmap`, `nuclei`, `sqlmap`
- any custom script that emits reusable recon, fuzz, or mapping artifacts

Specialist skills still own their proof standards. `/bounty-tools` only
standardizes tool execution and artifact handling.

## Required Preflight

1. Resolve `program`, `family`, and `lane`. For normal web bounty work, use:
   `family=web_bounty`, `lane=web`.
2. Read `prompts/bounty-tools-playbook.md`.
3. Check program scope, auth state, and interpreted rate limits before live
   traffic.
4. Pick a bounded tool goal, target, and stop condition.
5. For tools that emit reusable URL-like recon data, use `tool-run <program> --
   <command>` so the run root, manifest, and promotion are handled
   consistently.

## Canonical Run Root

Default web run root:

```text
~/Shared/web_bounty/<program>/web/recon/tools/<tool>/runs/YYYY-MM-DD/<run-id>/
```

Tool-level cumulative root:

```text
~/Shared/web_bounty/<program>/web/recon/tools/<tool>/global/
```

Cross-tool service inventory:

```text
~/Shared/web_bounty/<program>/web/recon/services/
```

Cross-tool URL aggregate:

```text
~/Shared/web_bounty/<program>/web/recon/aggregated/
```

Use the same pattern for other families/lanes:

```text
~/Shared/<family>/<program>/<lane>/recon/tools/<tool>/runs/YYYY-MM-DD/<run-id>/
```

## Required Run Files

Every tool run should write:

- `manifest.json` — tool, version, command, target, scope/rate source, paths,
  status, started/finished timestamps, and counts.
- `command.txt` — exact sanitized command and working directory.
- `raw/` — original tool output, unmodified.
- `parsed/` — parsed JSONL/CSV/TXT extracted from raw output.
- `normalized/` — normalized URL/host/param lists ready for ingest.
- `summary.md` — what ran, why, rate/concurrency, findings/leads, stop reason,
  and next handoff.
- `handoff.json` — optional route packets for specialist agents.

Never store live cookies, bearer tokens, passwords, API keys, private headers,
or full sensitive proxy dumps in these artifacts. Use credential references and
sanitized command examples.

## Rate And Scheduling Defaults

Program policy wins. If a program publishes a lower rate limit, use that limit.
If the program is silent and the target is stable, use `15 rps` as the maximum
live HTTP budget for the current host or app area.

- hard cap: `min(program_rate_limit, 15 rps)` per host or app area
- default scheduler: one noisy live tool at a time per host or app area
- separate root domains or clearly independent app areas may run in parallel
  when each has its own rate budget and run root
- passive/offline parsers can run in parallel because they do not touch the
  target
- authenticated or fragile flows should start at `1-3 rps` even when the global
  cap is higher
- fuzzing tools: set explicit flags such as `ffuf -rate <rps>`
- crawlers: depth `1-2`, concurrency `1-3` until the map proves safe
- `nmap`: avoid aggressive timing; use scoped hosts and non-disruptive scripts

Use a run lock before starting live target traffic:

```text
~/Shared/<family>/<program>/<lane>/recon/tools/.locks/<host-or-area>.lock
```

If a live run lock exists for the same host or app area, queue the next noisy
tool until the active one finishes. Release stale locks only after checking the
manifest and process state.

Do not stop on a single noisy response. Slow down, add better scoping, or switch
mode when appropriate. Stop and report when the run hits a repeated-block
threshold: persistent `429`, CAPTCHA, WAF/bot challenge, account friction,
elevated `5xx`, or messy responses that make hundreds of requests produce no
usable signal. Record what was tried, whether cookies/headed mode/proxy context
would likely help, and the recommended next step. Route WAF/rate behavior to
`/waf` or ask Ryushe before continuing.

## Ingest Handoff

After preserving raw output:

1. Prefer `tool-run <program> -- <command>` for spawned tools. The wrapper
   creates the canonical run root, captures stdout/stderr, writes a manifest,
   and promotes known outputs when the command exits successfully.
2. Write URL-like artifacts into `normalized/` using known names such as
   `urls.txt`, `alive.txt`, `params_raw.txt`, `jsfiles.txt`, `hosts.txt`, and
   `dirs.txt`. Treat `params_raw.txt` as the only canonical parameter write
   target; `params.txt` is regenerated from it with URO.
3. For immediate agent discoveries, run `scripts/recon_bus.py append` so new
   URLs, alive URLs, params, JS URLs, dirs, and hosts land in the aggregate
   store without waiting for a full tool run.
4. For completed tool run directories that were not launched through
   `tool-run`, run `scripts/recon_bus.py promote-run <program> --run-root
   <run-root>`. For long-running or delayed jobs, use
   `scripts/recon_bus.py watch-runs <program> --root <recon-or-tool-root>`.
5. Keep tool-specific global files under `tools/<tool>/global/`, except
   service and port facts. Normalize service/port facts from producers such as
   `naabu`, `nmap`, and `httpx` into `recon/services/` so target scoring and
   agents have one current inventory.
6. Use specialist lanes for validation and findings. Tool output alone is not a
   confirmed vulnerability.

## Related Skills

- `/url-ingest` — triage large URL lists, narrow scope, queue agent review, and
  answer whether a URL or parameter has already been inspected for a given
  lane, skill, or test family.
- `/bounty-notes` — durable notes, scratch artifacts, hypotheses, and handoffs.
- `/use-wordlists` and `/fuzz` — wordlist composition and fuzz campaign rules.
- `/waf` and `/error-triage` — rate-limit, WAF, CAPTCHA, and block handling.
