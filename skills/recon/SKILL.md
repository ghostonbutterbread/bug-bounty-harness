---
name: recon
description: Reconnaissance - enumerate targets, discover endpoints, map attack surface
---
# Reconnaissance

Enumerate targets, discover endpoints, map attack surface.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (recon items only)
4. `todo.md` (recon items only)

## Primary Harness

Use `agents/autonomous_recon.py` for the default one-shot recon pipeline. It handles discovery, crawling, technology fingerprinting, JS extraction, secret scanning, and artifact organization.

```bash
python agents/autonomous_recon.py --target https://target.com --program target
```

## Mode Matrix

| Mode | Use When | What It Produces |
|------|----------|------------------|
| `discover` | You need host, port, header, and WAF fingerprints | Ports, services, tech, and headers |
| `crawl` | You need reachable pages, forms, params, and JS files | URLs, forms, parameters, and JS references |
| `analyze` | You need follow-up signal from fetched content | Secrets, API endpoints, and interesting paths |
| `organize` | You need durable artifacts for later modules | Shared recon output files and summary |

## Primary Commands

```bash
# Full recon run
python agents/autonomous_recon.py --target https://target.com --program target

# Let the script derive the program from the host
python agents/autonomous_recon.py --target https://app.target.com
```

## CLI Notes

### `agents/autonomous_recon.py`

| Option | Description |
|--------|-------------|
| `--target` | Target URL or domain (required) |
| `--program` | Program name for shared storage; derived from host if omitted |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/recon-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **Recon Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/recon/findings.md`
- **Recon Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/recon/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/recon-playbook.md`.
3. Run `agents/autonomous_recon.py` for the target host or domain.
4. Promote only durable surface-mapping outcomes into findings.
5. Write findings to `agent_shared/findings/recon/findings.md`.
6. Update recon entries in `checklist.md`, `todo.md`, and relevant notes.
