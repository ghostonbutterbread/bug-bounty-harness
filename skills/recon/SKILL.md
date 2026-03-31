---
name: recon
description: Reconnaissance - enumerate targets, discover endpoints, map attack surface
---
# Reconnaissance

Enumerate targets, discover endpoints, map attack surface.

## Usage

```bash
python agents/autonomous_recon.py --target https://target.com --program target
```

## Tools

- Crawler: `~/workspace/scripts/url_probe.py`
- Screenshot: `agents/screenshot_tool.py`
- Subdomain: `agents/subdomain_agent.py`

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/recon-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/recon/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
