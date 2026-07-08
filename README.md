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

**Note:** `config.env` is gitignored. Copy `config.env.example` to create your own.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HARNESS_ROOT` | Bug bounty harness repo | `~/projects/bug_bounty_harness` |
| `HARNESS_SHARED_BASE` | Bounty recon data | `~/Shared/bounty_recon` |
| `HARNESS_WORDLISTS` | Wordlists | `~/wordlists` |
| `CLAUDE_SKILLS_DIR` | Claude Code skills | `~/.claude/skills` |
| `CODEX_SKILLS_DIR` | Codex skills | `~/.agents/skills` |

### Setup (First Time)

```bash
./setup.sh --init
# This creates config.env from config.env.example
# Then edit config.env with your paths
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
- Which template to use for executable harness modules vs RAG-style skills

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
- `~/.agents/skills/` (Codex)

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

1. Read `SKILL_TEMPLATE.md` and choose a track.
2. For executable Python modules, use `docs/executable-harness-template.md`.
3. For RAG-style skills, use `docs/rag-skill-template.md`.
4. For router skills that hand off to child lanes, also use `docs/skill-tree-handoff-template.md`.
5. Create the lean skill wrapper: `skills/{name}/SKILL.md`.
6. Put verbose method in `prompts/{name}-playbook.md` or lane-specific `references/`.
7. Create `agents/{name}_hunter.py` only when the skill needs executable harness code.
8. Add the skill or module to `SKILL_REGISTRY.md`.
9. Run `./setup.sh --sync`.

See `SKILL_TEMPLATE.md` for the template chooser.

## Directory Conventions

BBH code is being cleaned up incrementally. New reusable implementation code
should live in responsibility-owned packages under `agents/`. Update in-repo
imports to canonical package paths and delete old flat wrappers when tests and
review show no known consumers remain. Keep temporary shims only for known
public compatibility needs. See `docs/directory-conventions.md` before moving
modules or adding new harness helpers.

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
