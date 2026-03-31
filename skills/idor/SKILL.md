# IDOR Testing

Test for Insecure Direct Object Reference vulnerabilities.

**Run:** `/idor {program}`

**Files (from config.env or env vars):**
- Playbook: `$HARNESS_ROOT/prompts/idor-playbook.md`
- Findings: `$HARNESS_SHARED_BASE/{program}/ghost/skills/idor/findings.md`
- Knowledge: `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`

**Workflow:**
1. Read the playbook
2. Read knowledge.md for what's already tested
3. Execute tests
4. Update findings and knowledge
