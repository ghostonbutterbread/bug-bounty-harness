# Skill Registry

Universal index of all available bug bounty skills. Used by the orchestrator (Ghost) to route tasks to the correct skill module.

---

## Available Skills

| Skill | Playbook | Findings File | Status |
|-------|----------|---------------|--------|
| **xss** | `prompts/xss-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/xss/findings.md` | Ready |
| **idor** | `prompts/idor-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/idor/findings.md` | Ready |
| **sqli** | `prompts/sqli-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/sqli/findings.md` | Ready |
| **ssrf** | `prompts/ssrf-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/ssrf/findings.md` | Ready |
| **fuzz** | `prompts/fuzz-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md` | Ready |
| **recon** | `prompts/recon-playbook.md` | `~/Shared/bounty_recon/{program}/ghost/skills/recon/findings.md` | Ready |

---

## How to Invoke

### Slash Commands (Claude Code / Ghost)
```
/xss superdrug
/idor superdrug
/sqli superdrug
/ssrf superdrug
/fuzz superdrug
/recon superdrug
```

### Agent Spawn (for Codex)
```python
spawn_codex(
    task=f"Hunt for {skill} on {program}",
    context={
        "skill": "{skill}",
        "program": "{program}",
        "playbook": f"prompts/{skill}-playbook.md",
        "findings": f"~/Shared/bounty_recon/{program}/ghost/skills/{skill}/findings.md",
        "knowledge": f"~/Shared/bounty_recon/{program}/ghost/knowledge.md"
    }
)
```

### Direct Execution (Python harness)
```python
from agents.{skill}_hunter import {Skill}Hunter
hunter = {Skill}Hunter(program="{program}")
hunter.run()
```

---

## Provider Skill Locations

Skills are synced to provider-specific directories:

| Provider | Location |
|----------|----------|
| Claude Code | `.claude/skills/{skill}/SKILL.md` |
| Codex | `.agents/skills/{skill}/SKILL.md` |
| Ghost | `skills/{skill}/SKILL.md` |

**Sync command** (run after updating skills):
```bash
./sync_skills.sh
```

---

## Program Knowledge

The orchestrator maintains a per-program knowledge file:
```
~/Shared/bounty_recon/{program}/ghost/knowledge.md
```

**Must read before starting any work.**

Contains:
- What's been tested
- What's been found
- What's next
- WAF/filter observations
- Authentication details

---

## Creating New Skills

1. Create playbook: `prompts/{name}-playbook.md`
2. Create skill wrapper: `skills/{name}/SKILL.md`
3. Create harness: `agents/{name}_hunter.py`
4. Add to this registry
5. Sync to provider directories: `.claude/skills/` and `.agents/skills/`

See `SKILL_TEMPLATE.md` for anatomy of a skill file.

---

## Sync Script

To sync skills to provider directories:
```bash
#!/bin/bash
# sync_skills.sh
for skill in xss idor sqli ssrf fuzz recon; do
    cp skills/$skill/SKILL.md .claude/skills/$skill/SKILL.md
    cp skills/$skill/SKILL.md .agents/skills/$skill/SKILL.md
done
```

---

*Last updated: 2026-03-31*
