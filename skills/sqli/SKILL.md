# SQL Injection Testing

Test for SQL Injection vulnerabilities.

**Run:** `/sqli {program}`

**Files (from config.env or env vars):**
- Playbook: `$HARNESS_ROOT/prompts/sqli-playbook.md`
- Findings: `$HARNESS_SHARED_BASE/{program}/ghost/skills/sqli/findings.md`
- Knowledge: `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`

**Caution:** Non-destructive tests only. Do not extract data.

**Workflow:**
1. Read the playbook
2. Read knowledge.md for what's already tested
3. Execute tests
4. Update findings and knowledge
