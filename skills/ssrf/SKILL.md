---
name: ssrf
description: Test for Server-Side Request Forgery vulnerabilities
---
# SSRF Testing

Test for Server-Side Request Forgery vulnerabilities.

## Usage

```bash
python agents/ssrf_hunter.py --target https://target.com/fetch --program target
```

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/ssrf-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssrf/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
