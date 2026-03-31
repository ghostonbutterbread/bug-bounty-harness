# Bug Bounty Harness

Multi-agent bug bounty hunting framework. Supports XSS, IDOR, SQLi, SSRF, fuzzing, and recon.

---

## Architecture

```
bug_bounty_harness/
├── prompts/                    # Playbooks (shared source of truth)
│   ├── xss-playbook.md
│   ├── idor-playbook.md
│   ├── sqli-playbook.md
│   ├── ssrf-playbook.md
│   ├── fuzz-playbook.md
│   └── recon-playbook.md
├── skills/                    # Skill wrappers (shared)
│   ├── xss/SKILL.md
│   ├── idor/SKILL.md
│   ├── sqli/SKILL.md
│   ├── ssrf/SKILL.md
│   ├── fuzz/SKILL.md
│   └── recon/SKILL.md
├── .claude/skills/           # Claude Code (synced from skills/)
├── .agents/skills/            # Codex (synced from skills/)
├── shared/
│   └── knowledge-template.md   # Program knowledge base template
├── agents/                    # Python harness modules
│   ├── xss_hunter.py
│   ├── idor_hunter.py
│   └── ...
├── SKILL_REGISTRY.md          # Master index of all skills
├── INSTRUCTIONS.md            # Agent bootstrap prompt
├── sync_skills.sh            # Sync skills to provider dirs
└── README.md
```

---

## Quick Start

### 1. Set up a program
```bash
mkdir -p ~/Shared/bounty_recon/{program}/ghost/skills/{xss,idor,sqli,ssrf,fuzz,recon}
cp shared/knowledge-template.md ~/Shared/bounty_recon/{program}/ghost/knowledge.md
# Edit knowledge.md with program scope and details
```

### 2. Run a skill
```bash
python agents/xss_hunter.py --program superdrug
```

### 3. Spawn Codex for heavy lifting
```python
python agents/spawn_codex.py --skill xss --program superdrug
```

---

## Available Skills

| Skill | Command | Description |
|-------|---------|-------------|
| **xss** | `/xss {program}` | Cross-Site Scripting |
| **idor** | `/idor {program}` | Insecure Direct Object Reference |
| **sqli** | `/sqli {program}` | SQL Injection |
| **ssrf** | `/ssrf {program}` | Server-Side Request Forgery |
| **fuzz** | `/fuzz {program}` | Web fuzzing / directory enumeration |
| **recon** | `/recon {program}` | Reconnaissance / endpoint discovery |

---

## For Agents

### Bootstrap Any Agent
Copy `INSTRUCTIONS.md` content when spawning an agent. It tells them:
- Where to read/write findings
- How to invoke skills
- What playbooks to use

### Skill Index
See `SKILL_REGISTRY.md` for:
- All available skills
- How to invoke each
- Finding file locations
- How to create new skills

### Agent Workflow
1. Read `~/Shared/bounty_recon/{program}/ghost/knowledge.md`
2. Pick a task from "What's Next"
3. Read relevant playbook from `prompts/`
4. Execute tests
5. Update findings in `skills/{skill}/findings.md`
6. Update `knowledge.md` with progress

---

## Syncing Skills

After adding/updating skills, sync to provider directories:
```bash
./sync_skills.sh
```

This copies skill wrappers to:
- `.claude/skills/` (for Claude Code)
- `.agents/skills/` (for Codex)

---

## File Locations

| Purpose | Location |
|---------|----------|
| Program knowledge | `~/Shared/bounty_recon/{program}/ghost/knowledge.md` |
| XSS findings | `~/Shared/bounty_recon/{program}/ghost/skills/xss/findings.md` |
| IDOR findings | `~/Shared/bounty_recon/{program}/ghost/skills/idor/findings.md` |
| SQLi findings | `~/Shared/bounty_recon/{program}/ghost/skills/sqli/findings.md` |
| SSRF findings | `~/Shared/bounty_recon/{program}/ghost/skills/ssrf/findings.md` |
| Fuzz findings | `~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md` |
| Recon findings | `~/Shared/bounty_recon/{program}/ghost/skills/recon/findings.md` |

---

## Creating New Skills

1. Create playbook: `prompts/{name}-playbook.md`
2. Create skill wrapper: `skills/{name}/SKILL.md`
3. Create harness: `agents/{name}_hunter.py`
4. Add to `SKILL_REGISTRY.md`
5. Run `./sync_skills.sh`

See `SKILL_TEMPLATE.md` for anatomy of a skill file.

---

## Tools

| Tool | Purpose |
|------|---------|
| `screenshot_tool.py` | Batch screenshot URLs |
| `browser_block_fix.py` | Bypass Akamai/Cloudflare |
| `url_probe.py` | Probe URLs for liveness |
| `payload_mutator.py` | Generate WAF bypass payloads |

---

*For detailed architecture, see SPEC.md*
