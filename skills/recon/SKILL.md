# Reconnaissance

Enumerate targets, discover endpoints, map attack surface.

**Run:** `/recon {program}`

**Files (from config.env or env vars):**
- Playbook: `$HARNESS_ROOT/prompts/recon-playbook.md`
- Findings: `$HARNESS_SHARED_BASE/{program}/ghost/skills/recon/findings.md`
- Knowledge: `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`

**Tools:** url_probe.py, screenshot_tool.py, subdomain_agent.py

**Workflow:**
1. Read the playbook
2. Read knowledge.md for what's already discovered
3. Execute recon
4. Update findings and knowledge
