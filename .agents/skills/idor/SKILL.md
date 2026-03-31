---
name: idor
description: Test for Insecure Direct Object Reference vulnerabilities
---
# IDOR Testing

Test for Insecure Direct Object Reference vulnerabilities.

## Usage

```bash
python agents/idor_hunter.py --target https://target.com/api --program target
```

## Options

| Option | Description |
|--------|-------------|
| `--target` | Target URL or API endpoint |
| `--program` | Program name for findings |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/idor-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/idor/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
