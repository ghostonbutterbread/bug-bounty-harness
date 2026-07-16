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

## Scheduled Recon Queue

The cron orchestrator is intentionally safe by default: planning/enqueueing does not run scanners, and live jobs remain subject to program scope, rate, state, and manual-approval gates.

```bash
# Validate a program and inspect the deterministic plan.
PYTHONPATH="$PWD" python3 agents/cron_orchestrator.py validate flourish
PYTHONPATH="$PWD" python3 agents/cron_orchestrator.py plan flourish

# Queue prepared work; workers remain separate per run type.
PYTHONPATH="$PWD" python3 agents/cron_orchestrator.py run flourish --enqueue
PYTHONPATH="$PWD" python3 agents/cron_orchestrator.py queue-worker flourish --run-type fuzz
```

### Optional bounded AI review

`target_selection.agent_review.response_file` may contain JSON produced by an external AI/analyst. The orchestrator accepts a decision only if `selected_target` exactly identifies a target it already discovered and scope-filtered. It accepts only configured `wordlist_groups`; it never accepts commands, URLs outside that candidate set, or changed rate/scope policy. Missing or invalid review files fall back to deterministic ranking.

```json
{
  "selected_target": "https://api.example.com",
  "reason": "OpenAPI and authenticated route evidence",
  "wordlist_groups": ["api", "graphql"]
}
```

Completed FFUF and Arjun runs normalize local artifacts into reviewable status/403/parameter queues and reports. Arjun is fed a per-run, value-free endpoint queue shaped from `aggregated/params.txt`: only HTTP(S) URLs on the selected scoped host are retained, query values are removed, and the queue is bounded by `max_endpoints_per_run`.

Naabu is the initial common-port discovery layer: it consumes the program’s canonical `aggregated/alive.txt` and `aggregated/urls.txt` host evidence, reuses existing aggregated Naabu output when a host is already covered, and writes new results back to the aggregated service inventory. Each normalized JSONL row retains `input_host`, `resolved_ip`, `host` (the Nmap-safe hostname when present), `attribution`, `port`, `run_id`, and `observed_at`. If Naabu reports only an IP, normalization compares it with the run’s planned hostname inputs and uses it only when exactly one hostname currently resolves to that IP; shared/ambiguous IPs remain `unattributed_ip`. Nmap is gated behind a Naabu nonstandard-port signal; it then performs the user-approved full-range `-p-` service classification for that scoped hostname. Historical Naabu rows whose host is not currently in saved scope—including unattributed bare-IP rows—are excluded from Nmap target selection and counted in `dropped_out_of_scope_naabu_records`.

Cron configuration is program-scoped: `programs/<slug>.yaml` is loaded only for the selected `<slug>`, and values containing `<program>` expand to that slug at load time (for example, `~/Shared/web_bounty/<program>/...`). Scope, targets, rules, and any program-specific technology sources still must be explicitly reviewed in each program configuration; only the pipeline shape and storage layout are reusable.

Inspect reports and generated batches before escalating into deeper manual testing.

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
