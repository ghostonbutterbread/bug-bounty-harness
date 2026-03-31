# Skill Registry

Universal index of all available bug bounty skills.

---

## Configuration

Skills use paths from `config.env` or environment variables.

**Note:** `config.env` is gitignored. Run `./setup.sh --init` to create it from `config.env.example`.

### Environment Variables (override config.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `HARNESS_ROOT` | Bug bounty harness repo root | `~/projects/bug_bounty_harness` |
| `HARNESS_SHARED_BASE` | Base for bounty recon data | `~/Shared/bounty_recon` |
| `HARNESS_WORDLISTS` | Wordlists directory | `~/wordlists` |
| `CLAUDE_SKILLS_DIR` | Claude Code skills directory | `~/.claude/skills` |
| `CODEX_SKILLS_DIR` | Codex skills directory | `~/.codex/skills` |

### Config File

First time setup:
```bash
./setup.sh --init  # Creates config.env from config.env.example
```

Edit `config.env` in the repo root:
```bash
HARNESS_SHARED_BASE="${HOME}/Shared/bounty_recon"
HARNESS_ROOT="${HOME}/projects/bug_bounty_harness"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
CODEX_SKILLS_DIR="${HOME}/.codex/skills"
```

### Setup Commands

```bash
# First time setup
./setup.sh --init

# Sync skills after updating
./setup.sh --sync

# Show current config
./setup.sh --config

# Override with env vars
HARNESS_ROOT=/custom/path ./setup.sh --sync
```

---

## Available Skills

| Skill | Command | Playbook |
|-------|---------|----------|
| **xss** | `/xss {program}` | `prompts/xss-playbook.md` |
| **idor** | `/idor {program}` | `prompts/idor-playbook.md` |
| **sqli** | `/sqli {program}` | `prompts/sqli-playbook.md` |
| **ssrf** | `/ssrf {program}` | `prompts/ssrf-playbook.md` |
| **fuzz** | `/fuzz {program}` | `prompts/fuzz-playbook.md` |
| **recon** | `/recon {program}` | `prompts/recon-playbook.md` |
| **csrf** | `/csrf {program}` | `skills/csrff/SKILL.md` |

---

## How to Invoke

### Slash Commands
```
/xss superdrug
/idor superdrug
/sqli superdrug
/ssrf superdrug
/fuzz superdrug
/recon superdrug
/csrf superdrug
```

### Agent Spawn
```python
spawn_codex(
    task="Hunt for xss on superdrug",
    context={
        "program": "superdrug",
        "playbook": "$HARNESS_ROOT/prompts/xss-playbook.md",
        "findings": "$HARNESS_SHARED_BASE/superdrug/ghost/skills/xss/findings.md",
        "knowledge": "$HARNESS_SHARED_BASE/superdrug/ghost/knowledge.md"
    }
)
```

---

## Provider Skill Locations

| Provider | Directory |
|----------|-----------|
| Claude Code | `~/.claude/skills/` (or `$CLAUDE_SKILLS_DIR`) |
| Codex | `~/.codex/skills/` (or `$CODEX_SKILLS_DIR`) |
| Repo-specific | `{HARNESS_ROOT}/.agents/skills/` |

Sync with: `./sync_skills.sh` or `./setup.sh --sync`

---

## Program Knowledge

Per-program knowledge file:
```
{HARNESS_SHARED_BASE}/{program}/ghost/knowledge.md
```

**Read before starting any work.** Contains:
- What's been tested
- What's been found
- What's next
- WAF/filter observations
- Authentication details

---

## Creating New Skills

1. Create skill wrapper: `skills/{name}/SKILL.md`
2. Create playbook if needed: `prompts/{name}-playbook.md`
3. Create harness if needed: `agents/{name}_hunter.py`
4. Add to this registry
5. Run `./setup.sh --sync`

---

## File Structure

```
bug_bounty_harness/
├── config.env              # Config (edit for your paths)
├── setup.sh               # Setup script (--init, --sync, --config)
├── sync_skills.sh         # Sync skills to providers
├── prompts/               # Playbooks
│   ├── xss-playbook.md
│   └── ...
├── skills/                # Skill wrappers (source)
│   ├── xss/SKILL.md
│   └── ...
├── .claude/skills/        # Synced for Claude Code
├── .agents/skills/        # Synced for Codex (repo-specific)
└── SKILL_REGISTRY.md      # This file
```

---

*Last updated: 2026-03-31*
