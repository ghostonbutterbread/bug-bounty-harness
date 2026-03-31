# Bug Bounty Harness — Agent Instructions

Use this file as a prompt to bootstrap any agent (Claude Code, Codex, Ghost) for bug bounty hunting.
Paste relevant sections when spawning an agent.

---

## Universal Data Store

Every finding goes to the program's knowledge file:
```
~/Shared/bounty_recon/{program}/ghost/knowledge.md
```

**Read this FIRST** before starting any work. It tells you:
- What's been tested
- What was found
- What's left to do
- WAF/filter behavior

**Write findings IMMEDIATELY** as you discover them. Don't wait until the end.

---

## Skill Playbooks

Each vulnerability type has a playbook in `prompts/`:

| Playbook | Purpose |
|----------|---------|
| `prompts/xss-playbook.md` | XSS testing methodology |
| `prompts/idor-playbook.md` | IDOR testing methodology |
| `prompts/sqli-playbook.md` | SQL injection testing |
| `prompts/ssrf-playbook.md` | SSRF testing |
| `prompts/fuzz-playbook.md` | Web fuzzing |
| `prompts/recon-playbook.md` | Reconnaissance |

---

## Skill-Specific Findings

After testing, update the specific findings file:

```
~/Shared/bounty_recon/{program}/ghost/skills/{skill}/findings.md
```

| Skill | File |
|-------|------|
| XSS | `skills/xss/findings.md` |
| IDOR | `skills/idor/findings.md` |
| SQLi | `skills/sqli/findings.md` |
| SSRF | `skills/ssrf/findings.md` |
| Fuzz | `skills/fuzz/findings.md` |
| Recon | `skills/recon/findings.md` |

---

## Spawning Sub-Agents

When spawning Codex or other sub-agents, include this context:

```
PROGRAM: {program_name}
SCOPE: {in-scope domains}
KNOWLEDGE_FILE: ~/Shared/bounty_recon/{program}/ghost/knowledge.md
SKILL: {xss/idor/etc}
PLAYBOOK: prompts/{skill}-playbook.md
FINDINGS_FILE: ~/Shared/bounty_recon/{program}/ghost/skills/{skill}/findings.md
```

---

## Finding Format

When documenting a vulnerability, include:

```markdown
## {Vuln Type} - {Brief Description}
- **URL**: https://target.com/endpoint
- **Parameter**: param_name
- **Type**: Reflected/Stored/Inferential/etc
- **Payload**: {what you used}
- **PoC**: {how to reproduce}
- **Impact**: {security impact}
- **WAF Bypass**: {yes/no/technique used}
- **Status**: confirmed/potential
- **Tested by**: {agent name}
- **Date**: {ISO date}
```

---

## Tool Locations

| Tool | Location |
|------|----------|
| Fuzzer | `~/workspace/scripts/url_probe.py` |
| Screenshot | `~/projects/bug_bounty_harness/agents/screenshot_tool.py` |
| Browser Block Bypass | `~/projects/bug_bounty_harness/agents/browser_block_fix.py` |
| Subagent Logger | `~/projects/bounty-tools/subagent_logger.py` |
| Wordlists | `~/wordlists/` |

---

## Rate Limiting

- Default: 10 req/sec
- If WAF blocks: drop to 1 req/sec
- If 429 received: wait 60 seconds, then continue

---

## Workflow

1. **Read** `~/Shared/bounty_recon/{program}/ghost/knowledge.md`
2. **Check** what's been tested, what's pending
3. **Pick a task** from "What's Next"
4. **Read** relevant playbook from `prompts/`
5. **Execute** tests
6. **Document** findings in both:
   - `knowledge.md` (summary)
   - `skills/{skill}/findings.md` (detailed)
7. **Git commit** if using CLI tools

---

*For more details, see README.md*
