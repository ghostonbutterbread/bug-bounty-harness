---
name: sqli
description: Test for SQL Injection vulnerabilities
---
# SQL Injection Testing

Test for SQL Injection vulnerabilities.

**Caution:** Non-destructive tests only. Do not extract data.

## Usage

```bash
python agents/sqli_hunter.py --target https://target.com/search --program target
```

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/sqli-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/sqli/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
