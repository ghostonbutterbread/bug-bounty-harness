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

## ResearchMap

ResearchMap is the local CLI for a synced, Markdown-authoritative portable AppSec
research corpus. It complements target-specific MapStore observations: use it to
retrieve cited mechanisms and code signals when a plausible surface needs fresh
hypotheses.

```bash
python3 scripts/research_map.py init
python3 scripts/research_map.py validate
python3 scripts/research_map.py index
python3 scripts/research_map.py query --terms "sanitizer svg" --class xss
```

The default corpus is `~/notes/appsec/research/`; the SQLite index is generated
locally from Markdown cards. Cards have a deliberately high admission bar: one
narrow, cited technology-specific vector (for example, an endpoint/header or
parser differential), its recognition signals, a small discriminating check,
and its limits. Broad methodology, tool descriptions, architecture guidance,
and mindset material belong outside ResearchMap. See [docs/research-map.md](docs/research-map.md).

## Nightly Learning (beta)

The passive learning loop restores the legacy curated-source model without
turning external material into agent instructions. Its synced source registry
is `~/notes/appsec/research/sources/learning-sources.yaml`; the runner fetches
only whitelisted HTTPS source indexes through `safe-fetch`, deduplicates their
content hashes in a local SQLite ledger, and emits an auditable review digest.

```bash
python3 scripts/nightly_learning.py validate
python3 scripts/nightly_learning.py beta
```

Beta is deliberately report-only: it never creates cards, notes, skills, or
target actions. Review an artifact first, then promote concrete portable
mechanisms into cited ResearchMap cards. Reports and the rebuildable seen ledger
live under `~/.hermes/learning/nightly/`.

## Explicit `/goal` runs

The explicit `/goal` workflow is opt-in: `goal_router.py` classifies the stated
bug-bounty objective and
selects a broad-program, focused-surface, technology-review, continuation, or
revalidation route without changing ordinary agent behavior.

```bash
python3 scripts/goal_router.py plan --program example --objective "Find a new vulnerability"
python3 scripts/goal_router.py init --program example --objective "Assess preview for XSS" \
  --class xss --run-dir /tmp/example-goal
```

See [docs/goal-runs.md](docs/goal-runs.md).

---

## Automated Recon

Scheduled reconnaissance, queue orchestration, authenticated FFUF/Arjun execution,
and smart-fuzzing automation live in the dedicated private repository:

```text
https://github.com/ghostonbutterbread/auto-recon
```

Bug Bounty Harness remains the general-purpose research and testing harness.

### JavaScript module status

The JavaScript module is currently **artifact-only**. It prepares local packet,
brainstorm, and MapStore-candidate artifacts, but is intentionally disconnected
from `zero_day_team` and does not invoke a deep-recon/runtime agent path.

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
