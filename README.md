# Bug Bounty Harness

Multi-agent bug bounty hunting framework. Supports XSS, IDOR, SQLi, SSRF, fuzzing, and recon.

---

## Quick Start

```bash
# First time setup (creates dirs + syncs skills)
./setup.sh --init

# Sync skills after updating
./setup.sh --sync

# Show current config
./setup.sh --config
```

---

## Configuration

Paths are configured via `config.env` or environment variables.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HARNESS_ROOT` | Bug bounty harness repo | `~/projects/bug-bounty-harness` |
| `HARNESS_SHARED_BASE` | Bounty recon data | `~/Shared/bounty_recon` |
| `HARNESS_WORDLISTS` | Wordlists | `~/wordlists` |
| `CLAUDE_SKILLS_DIR` | Claude Code skills | `~/.claude/skills` |
| `CODEX_SKILLS_DIR` | Codex skills | `~/.codex/skills` |

### Edit config.env

```bash
HARNESS_SHARED_BASE="${HOME}/Shared/bounty_recon"
HARNESS_ROOT="${HOME}/projects/bug-bounty-harness"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
CODEX_SKILLS_DIR="${HOME}/.codex/skills"
```

### Override with Environment

```bash
HARNESS_ROOT=/custom/path ./setup.sh --sync
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

## Architecture

```
bug_bounty_harness/
├── config.env              # Config (edit for your paths)
├── setup.sh               # Setup script
├── sync_skills.sh         # Sync skills to providers
├── prompts/               # Playbooks (shared source of truth)
├── skills/                # Skill wrappers (source)
├── .claude/skills/       # Claude Code (synced)
├── .agents/skills/        # Codex (synced)
└── shared/
    └── knowledge-template.md
```

---

## For Agents

### Bootstrap Any Agent

Copy `INSTRUCTIONS.md` content when spawning an agent, or reference the skill paths.

### Skill Index

See `SKILL_REGISTRY.md` for:
- All available skills
- How to invoke each
- Config options
- How to create new skills

### Agent Workflow

1. Read `{$HARNESS_SHARED_BASE}/{program}/ghost/knowledge.md`
2. Pick a task from "What's Next"
3. Read relevant playbook from `prompts/`
4. Execute tests
5. Update findings in `skills/{skill}/findings.md`
6. Update `knowledge.md` with progress

---

## Syncing Skills

```bash
./setup.sh --sync           # Sync all
./setup.sh --sync --claude  # Claude Code only
./setup.sh --sync --codex   # Codex only
./setup.sh --sync --dry-run # Preview
```

Skills are synced to:
- `~/.claude/skills/` (Claude Code)
- `~/.codex/skills/` (Codex)
- `.agents/skills/` (repo-specific)

---

## File Locations

| Purpose | Location |
|---------|----------|
| Program knowledge | `{HARNESS_SHARED_BASE}/{program}/ghost/knowledge.md` |
| XSS findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/xss/findings.md` |
| IDOR findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/idor/findings.md` |
| SQLi findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/sqli/findings.md` |
| SSRF findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/ssrf/findings.md` |
| Fuzz findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/fuzz/findings.md` |
| Recon findings | `{HARNESS_SHARED_BASE}/{program}/ghost/skills/recon/findings.md` |

---

## Creating New Skills

1. Create playbook: `prompts/{name}-playbook.md`
2. Create skill wrapper: `skills/{name}/SKILL.md`
3. Create harness: `agents/{name}_hunter.py`
4. Add to `SKILL_REGISTRY.md`
5. Run `./setup.sh --sync`

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
