# Web Fuzzing

Discover hidden endpoints, parameters, and files through enumeration.

**Run:** `/fuzz {program}`

**Files (from config.env or env vars):**
- Playbook: `$HARNESS_ROOT/prompts/fuzz-playbook.md`
- Findings: `$HARNESS_SHARED_BASE/{program}/ghost/skills/fuzz/findings.md`
- Knowledge: `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`

**Tools:** ffuf, wordlists at `$HARNESS_WORDLISTS`

**Workflow:**
1. Read the playbook
2. Read knowledge.md for what's already fuzzed
3. Execute fuzzing
4. Update findings and knowledge
