---
name: ssrf
description: Test for Server-Side Request Forgery vulnerabilities
---
# SSRF Testing

Test for Server-Side Request Forgery vulnerabilities.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (SSRF items only)
4. `todo.md` (SSRF items only)

## Primary Harness

Use `agents/bypass_harness.py` in `--type ssrf` mode for most SSRF work. It already carries localhost, metadata, parser-confusion, and alternate-scheme probes and writes raw results under shared storage.

```bash
python agents/bypass_harness.py --target https://target.com/fetch?url=x --type ssrf \
  --param url --program target --concurrency 5 --rps 2
```

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/ssrf-playbook.md`
- **Reference:** `$HARNESS_ROOT/prompts/ssrf-reference.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **SSRF Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssrf/findings.md`
- **Bypass Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`

## Mode Matrix

| Mode | Use When | What It Tests |
|------|----------|---------------|
| `localhost` | Direct fetch parameter is obvious | Loopback and RFC1918 access |
| `metadata` | Cloud-hosted target or metadata clues exist | AWS, GCP, Azure, and ECS metadata paths |
| `parser` | Allowlist or hostname validation is present | Userinfo, dotted, decimal, octal, and rebinding variants |
| `scheme` | Non-HTTP backends may be reachable | `gopher`, `dict`, `file`, and related schemes |

## Primary Commands

```bash
# Default SSRF pass
python agents/bypass_harness.py --target https://target.com/fetch?url=x --type ssrf \
  --param url --program target --concurrency 5 --rps 2

# Lower-noise pass against a webhook or import feature
python agents/bypass_harness.py --target https://target.com/webhook?callback=x --type ssrf \
  --param callback --program target --concurrency 3 --rps 1
```

## CLI Notes

### `agents/bypass_harness.py`

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target URL (required) |
| `--type`, `-T` | Use `ssrf` |
| `--param`, `-p` | Parameter name to inject into |
| `--program` | Program name for shared storage |
| `--output-dir`, `-o` | Override raw artifact directory |
| `--timeout` | Request timeout in seconds |
| `--concurrency`, `-c` | Max parallel requests |
| `--rps` | Requests per second |
| `--verbose`, `-v` | Verbose debug output |
| `--quiet`, `-q` | Show hits only |

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/ssrf-playbook.md`.
3. Use `prompts/ssrf-reference.md` when adapting internal target classes or parser-confusion variants.
4. Run `agents/bypass_harness.py` in `--type ssrf` mode.
5. Write findings to `agent_shared/findings/ssrf/findings.md`.
6. Update SSRF entries in `checklist.md`, `todo.md`, and relevant notes.
