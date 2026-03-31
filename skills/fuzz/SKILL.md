---
name: fuzz
description: Discover hidden endpoints, parameters, and files
---
# Web Fuzzing

Discover hidden endpoints, parameters, and files through enumeration.

## Usage

```bash
python agents/fuzz_runner.py --target https://target.com --program target
```

## Tools

- ffuf: `ffuf -u TARGET/FUZZ -w WORDLIST -mc 200,204,301,302,307,401,403 -fc 404 -c -v`
- Wordlists: `~/wordlists/SecLists/Discovery/Web-Content/common.txt`

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/fuzz-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/fuzz/`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
