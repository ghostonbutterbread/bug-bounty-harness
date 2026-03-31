# XSS Testing

Test for Cross-Site Scripting vulnerabilities.

## Usage

**With a URL (lab or specific target):**
```bash
python agents/xss_hunter.py --target https://example.com/lab --program lab
```

**With a program name (uses shared knowledge):**
```bash
python agents/xss_hunter.py --target https://superdrug.com --program superdrug
```

## Options

| Option | Description |
|--------|-------------|
| `--target` | Target URL or domain (required) |
| `--program` | Program name for findings storage (default: adhoc) |
| `--depth` | Scan depth: shallow/medium/deep (default: shallow) |
| `--rate` | Requests per second (default: 5) |

## Files (from config or env vars)

- **Playbook:** `$HARNESS_ROOT/prompts/xss-playbook.md`
- **Findings:** `$HARNESS_SHARED_BASE/{program}/ghost/skills/xss/findings.md`
- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`

## Workflow

1. Read the playbook: `prompts/xss-playbook.md`
2. If program exists: Read `knowledge.md` for what's already tested
3. Run XSS scan against target
4. Update findings and knowledge

## Examples

```bash
# Test a specific lab URL
python agents/xss_hunter.py --target http://localhost:8080/xss-lab --program xss-lab

# Test a single endpoint
python agents/xss_hunter.py --target https://api.target.com/endpoint --program target

# Full program scan
python agents/xss_hunter.py --target https://target.com --program target
```
