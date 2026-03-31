---
name: xss
description: Test for Cross-Site Scripting vulnerabilities
---
# XSS Testing

Test for Cross-Site Scripting vulnerabilities.

## Required Preflight

Read shared state in this order before testing:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (XSS items only)
4. `todo.md` (XSS items only)

## Primary Harness

Use `agents/xss_framework.py` for most XSS work. It handles discovery, reflection screening, reflected/stored/DOM lanes, and optional browser verification.

```bash
python agents/xss_framework.py --target https://target.com/search?q=test --program target --mode full --rate-limit 2
```

## Mode Matrix

| Mode | Use When | What It Does |
|------|----------|--------------|
| `full` | Default full run | Discovery, reflection screening, reflected testing, stored testing, and DOM analysis |
| `reflected` | Query/form/header reflection suspected | Discovery, reflection screening, and reflected XSS testing only |
| `stored` | You have a render location | Discovery, reflection screening, and stored XSS testing for `--stored-url` targets |
| `dom` | Client-side flow is the main lead | DOM source-to-sink analysis only |

## Primary Commands

```bash
# Full pipeline
python agents/xss_framework.py --target https://target.com/search?q=test --program target --mode full --rate-limit 2

# Reflected only
python agents/xss_framework.py --target https://target.com/search?q=test --program target --mode reflected --rate-limit 2

# Stored only
python agents/xss_framework.py --target https://target.com/post --program target --mode stored \
  --stored-url https://target.com/forum/thread/1 --rate-limit 1

# DOM only with browser verification
python agents/xss_framework.py --target https://target.com/app --program target --mode dom \
  --browser-verify --rate-limit 1
```

## Secondary Harness

Use `agents/xss_hunter.py` for a narrower quick scan when you already know the target URL and want a shallow or deep parameter-focused pass.

```bash
python agents/xss_hunter.py --target https://target.com/search?q=test --program target --depth shallow --rate-limit 5
```

## CLI Notes

### `agents/xss_framework.py`

| Option | Description |
|--------|-------------|
| `--target` | Target URL or domain (required) |
| `--program` | Program name for shared storage (default: `adhoc`) |
| `--mode` | One of `full`, `reflected`, `stored`, `dom` |
| `--stored-url` | Render locations for stored XSS verification |
| `--rate-limit` | Requests per second |
| `--browser-verify` | Verify execution with Playwright |
| `--browser-bypass` | Use browser automation when WAF blocks HTTP requests |
| `--output` | Write JSON findings to a specific path |

### `agents/xss_hunter.py`

| Option | Description |
|--------|-------------|
| `--target` | Target URL or domain (required) |
| `--program` | Program name for shared storage (default: `test`) |
| `--depth` | Scan depth: `shallow` or `deep` |
| `--rate-limit` | Requests per second |
| `--output` | Output file for findings (JSON) |
| `--verbose` | Print traceback on failures |

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/xss-playbook.md`
- **Payload Catalog:** `$HARNESS_ROOT/prompts/xss-payloads.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **XSS Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/xss/findings.md`
- **XSS Scan Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/xss/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/xss-playbook.md`.
3. Use `prompts/xss-payloads.md` when adapting payloads to context, WAF behavior, or frontend framework sinks.
4. Run `agents/xss_framework.py` unless a quick targeted `agents/xss_hunter.py` pass is enough.
5. Write findings to `agent_shared/findings/xss/findings.md`.
6. Update XSS entries in `checklist.md`, `todo.md`, and relevant notes.
